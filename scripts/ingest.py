"""Verify data normalization, install its mapping, run finite Logstash ingestion, validate
live data.
"""

import argparse
import os
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import (  # noqa: E402
    INDEX,
    ROOT,
    TEMPLATE,
    compose,
    load_json,
    request,
    save_json,
    service_json,
)
from src.preprocessing.preprocess import digest  # noqa: E402
from src.preprocessing.verify_processed import verify_processed  # noqa: E402


def verify_phase3(root=ROOT, verifier=verify_processed):
    manifest = load_json(root / "analysis/normalization-manifest.json")
    summary = load_json(root / "analysis/preprocessing_summary.json")
    if (
        summary["counts"]["processed_events"],
        summary["counts"]["rejected_events"],
        summary["timestamp_quality"]["explicit_utc"],
        summary["timestamp_quality"]["unresolved"],
    ) != (102011, 0, 90601, 11410) or manifest["counts"] != summary["counts"]:
        raise ValueError("data normalization counts differ from the authorized release")
    result = verifier(root / "dataset/raw", root / "dataset/processed", root / "analysis")
    if (
        not all(
            result[key]
            for key in (
                "raw_hashes_match",
                "output_and_report_hashes_match",
                "all_rows_accounted_for",
                "all_original_rows_reconstructed",
                "offline_mapping_contract_passed",
            )
        )
        or result["processed_events"] != summary["counts"]["processed_events"]
    ):
        raise ValueError("data normalization verification failed")
    return manifest, summary, result


def build_template(mapping):
    if (
        mapping.get("dynamic") != "strict"
        or mapping["properties"]["@timestamp"]["type"] != "date_nanos"
    ):
        raise ValueError("data normalization strict date_nanos contract required")
    return {
        "index_patterns": ["windows-apt-events-*"],
        "priority": 200,
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": mapping,
        },
    }


def install_template(root=ROOT, client=request):
    template = build_template(load_json(root / "dataset/processed/elastic-mapping.json"))
    path = root / "elasticsearch/templates/windows-apt-events-template.json"
    save_json(path, template)
    client(f"/_index_template/{TEMPLATE}", template, method="PUT")
    existing = client(f"/{INDEX}/_mapping", allow_missing=True)
    if existing is None:
        client(f"/{INDEX}", {}, method="PUT")
    elif existing[INDEX]["mappings"] != template["template"]["mappings"]:
        raise ValueError("Existing index mapping differs; investigate before a deliberate reset")
    return template


def pipeline_metrics():
    stats = service_json("logstash", "/_node/stats/pipelines/main")
    return stats, stats["pipelines"]["main"]


def output_metrics(pipeline):
    return {p["id"]: p for p in pipeline["plugins"]["outputs"]}


def wait_for_ingestion(expected, timeout):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            stats, pipeline = pipeline_metrics()
        except (RuntimeError, KeyError, ValueError, subprocess.TimeoutExpired):
            time.sleep(5)
            continue
        events = pipeline["events"]
        counts = (events["in"], events["out"])
        if counts != last:
            print(f"Logstash input/output: {counts[0]:,} / {counts[1]:,}", flush=True)
            last = counts
        if events["in"] > expected:
            raise ValueError("Logstash read more records than the verified input")
        if counts == (expected, expected):
            return stats
        time.sleep(5)
    raise TimeoutError("Logstash did not drain within the time limit; data retained for inspection")


def run(reset=False, timeout=1200):
    request("/")
    print("Verifying all data normalization evidence before ingestion...", flush=True)
    manifest, summary, guard = verify_phase3()
    if reset:
        # Explicit option deletes this exact project index only. No wildcard/volume deletion.
        compose("stop", "logstash")
        request(f"/{INDEX}", method="DELETE", allow_missing=True)
    install_template()
    existing = request(f"/{INDEX}/_count")["count"]
    run_id = uuid.uuid4().hex
    env = os.environ.copy()
    env.update(WINDOWS_APT_INPUT="/dataset/windows-apt-events.ndjson", WINDOWS_APT_RUN=run_id)
    directory = ROOT / "analysis/ingestion"
    observation = {
        "run_id": run_id,
        "status": "running",
        "index": INDEX,
        "started_at_utc": datetime.now(UTC).isoformat(),
        "index_count_before": existing,
        "reset_requested": reset,
        "phase3_verification": guard,
        "phase3_manifest_sha256": digest(ROOT / "analysis/normalization-manifest.json"),
        "processed_sha256": manifest["processed_output_sha256"]["windows-apt-events.ndjson"],
        "implementation_sha256": {
            name: digest(ROOT / name)
            for name in (
                "logstash/pipeline/windows-apt.conf",
                "logstash/scripts/preserve_event.rb",
                "logstash/config/logstash.yml",
                "docker-compose.yml",
                "scripts/ingest.py",
            )
        },
    }
    run_path = directory / "runs" / f"{run_id}.json"
    save_json(run_path, observation)
    started = time.monotonic()
    try:
        compose("up", "-d", "--no-deps", "--force-recreate", "logstash", env=env, timeout=90)
        stats = wait_for_ingestion(summary["counts"]["processed_events"], timeout)
        observation.update(
            status="ingested",
            ingestion_seconds=round(time.monotonic() - started, 2),
            logstash_stats=stats,
            completed_at_utc=datetime.now(UTC).isoformat(),
        )
        request(f"/{INDEX}/_refresh", method="POST")
        save_json(run_path, observation)
        save_json(directory / "latest-run.json", observation)
        from scripts.validate_ingestion import validate

        validation = validate(observation=observation)
        observation["status"] = "passed" if validation["passed"] else "failed_validation"
        observation["index_count_after"] = validation["event_count"]["actual"]
        save_json(run_path, observation)
        save_json(directory / "latest-run.json", observation)
        if not validation["passed"]:
            raise ValueError(
                "Live validation failed; see analysis/ingestion/ingestion-validation.json"
            )
        print(f"Validated {validation['event_count']['actual']:,} indexed events.", flush=True)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        observation.update(status="failed", error=str(error))
        save_json(run_path, observation)
        save_json(directory / "latest-run.json", observation)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset", action="store_true", help=f"Deliberately delete only {INDEX} first"
    )
    parser.add_argument("--timeout", type=int, default=1200, help="Maximum ingestion seconds")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    try:
        run(args.reset, args.timeout)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Ingestion failed: {error}\n")


if __name__ == "__main__":
    main()
