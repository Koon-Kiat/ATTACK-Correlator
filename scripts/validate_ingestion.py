"""Validate the actual local index against data normalization counts and deterministic source
samples.
"""

import argparse
import copy
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import (  # noqa: E402
    INDEX,
    ROOT,
    TEMPLATE,
    load_json,
    request,
    save_json,
    service_json,
)
from scripts.ingest import build_template, output_metrics, verify_phase3  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402


def exists(field):
    return {"exists": {"field": field}}


def term(field, value):
    return {"term": {field: value}}


def every(*queries):
    return {"bool": {"filter": list(queries)}}


def comparison(expected, actual):
    return {"expected": expected, "actual": actual, "passed": expected == actual}


def get_field(document, field):
    value = document
    for key in field.split("."):
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def timestamp_key(value):
    """Compare explicit UTC instants to nanoseconds, including insignificant trailing zeros."""
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    if match is None:
        raise ValueError("Expected a complete UTC nanosecond timestamp")
    return match[1] + "." + (match[2] or "").ljust(9, "0") + "Z"


def evidence_equal(expected, actual):
    left, right = copy.deepcopy(expected), copy.deepcopy(actual)
    for document in (left, right):
        if "@timestamp" in document:
            document["@timestamp"] = timestamp_key(document["@timestamp"])
    return left == right


def template_matches(actual, expected):
    # Elasticsearch returns settings in canonical index.* form and adds server dates.
    settings = actual["template"]["settings"]
    settings = settings.get("index", settings)
    return (
        actual["index_patterns"] == expected["index_patterns"]
        and actual.get("priority") == expected["priority"]
        and actual.get("composed_of", []) == []
        and "data_stream" not in actual
        and actual["template"]["mappings"] == expected["template"]["mappings"]
        and settings == {"number_of_shards": "1", "number_of_replicas": "0"}
    )


def representative_queries():
    process = every(term("event.provider", "Microsoft-Windows-Sysmon"), term("event.code", "1"))
    return {
        "process_execution": {
            "query": process,
            "kql": 'event.provider: "Microsoft-Windows-Sysmon" and event.code: "1"',
        },
        "command_line": {"query": exists("process.command_line"), "kql": "process.command_line: *"},
        "parent_child": {
            "query": every(
                process, exists("process.parent.entity_id"), exists("process.entity_id")
            ),
            "kql": 'event.provider: "Microsoft-Windows-Sysmon" and event.code: "1" '
            "and process.parent.entity_id: * and process.entity_id: *",
        },
        "file": {"query": exists("file.path"), "kql": "file.path: *"},
        "registry": {"query": exists("registry.path"), "kql": "registry.path: *"},
        "network": {
            "query": every(exists("source.ip"), exists("destination.ip")),
            "kql": "source.ip: * and destination.ip: *",
        },
        "dns": {"query": exists("dns.question.name"), "kql": "dns.question.name: *"},
        "attack_annotation": {
            "query": exists("windows_apt.annotations.attack.ids"),
            "kql": "windows_apt.annotations.attack.ids: *",
        },
        "scenario": {
            "query": exists("windows_apt.scenario.attribution_strength"),
            "kql": "windows_apt.scenario.attribution_strength: *",
        },
        "valid_timestamp": {"query": exists("@timestamp"), "kql": "@timestamp: *"},
        "unresolved_timestamp": {
            "query": every(
                term("windows_apt.quality.timestamp", "unresolved"),
                {"bool": {"must_not": [exists("@timestamp")]}},
            ),
            "kql": 'windows_apt.quality.timestamp: "unresolved" and not @timestamp: *',
        },
    }


def choose_samples(path):
    """First matching record in immutable NDJSON order; no random or label-based sampling."""
    predicates = {
        "process_execution": lambda d: (
            get_field(d, "event.provider") == "Microsoft-Windows-Sysmon"
            and get_field(d, "event.code") == "1"
        ),
        "command_line": lambda d: get_field(d, "process.command_line") is not None,
        "parent_child": lambda d: get_field(d, "process.parent.entity_id") is not None,
        "file": lambda d: get_field(d, "file.path") is not None,
        "registry": lambda d: get_field(d, "registry.path") is not None,
        "network": lambda d: get_field(d, "source.ip") is not None,
        "dns": lambda d: get_field(d, "dns.question.name") is not None,
        "fractional_timestamp": lambda d: bool(re.search(r"\.\d{7,9}Z$", d.get("@timestamp", ""))),
        "unresolved_timestamp": lambda d: (
            get_field(d, "windows_apt.quality.timestamp") == "unresolved"
        ),
        "attack_annotation": lambda d: bool(get_field(d, "windows_apt.annotations.attack.ids")),
        "scenario": lambda d: get_field(d, "windows_apt.scenario.id") is not None,
        "original_message": lambda d: get_field(d, "event.original") is not None,
        "normalization_warning": lambda d: bool(
            get_field(d, "windows_apt.quality.normalization_warnings")
        ),
    }
    selected = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            for name, predicate in predicates.items():
                if name not in selected and predicate(event):
                    selected[name] = event
            if len(selected) == len(predicates):
                break
    if len(selected) != len(predicates):
        raise ValueError("Expected representative source examples are missing")
    return selected


def spot_checks(samples, client=request):
    ids = sorted({event["event"]["id"] for event in samples.values()})
    docs = client(f"/{INDEX}/_mget", {"ids": ids}, method="POST")["docs"]
    indexed = {doc["_id"]: doc.get("_source") for doc in docs}
    # Query date_nanos doc values, not just stored _source strings, to verify indexed precision.
    date_hits = client(
        f"/{INDEX}/_search",
        {
            "size": len(ids),
            "query": {"ids": {"values": ids}},
            "_source": False,
            "docvalue_fields": [
                {"field": "@timestamp", "format": "strict_date_optional_time_nanos"}
            ],
        },
        method="POST",
    )["hits"]["hits"]
    dates = {hit["_id"]: hit.get("fields", {}).get("@timestamp", []) for hit in date_hits}
    checks = []
    for name, expected in samples.items():
        doc_id = expected["event"]["id"]
        actual = indexed.get(doc_id)
        expected_date = expected.get("@timestamp")
        date_values = dates.get(doc_id, [])
        dates_pass = (
            (
                len(date_values) == 1
                and timestamp_key(date_values[0]) == timestamp_key(expected_date)
            )
            if expected_date
            else not date_values
        )
        metadata = {
            field: actual is not None
            and expected["windows_apt"][field] == actual.get("windows_apt", {}).get(field)
            for field in ("provenance", "annotations", "scenario", "quality", "original")
        }
        equal = actual is not None and evidence_equal(expected, actual)
        checks.append(
            {
                "category": name,
                "document_id": doc_id,
                "source_file": expected["windows_apt"]["provenance"]["source_file"],
                "source_row_index": expected["windows_apt"]["provenance"]["source_row_index"],
                "source_exact_equal": actual == expected,
                "evidence_equal": equal,
                "source_timestamp": expected_date,
                "indexed_source_timestamp": actual.get("@timestamp") if actual else None,
                "indexed_timestamp_doc_values": date_values,
                "nanosecond_value_passed": dates_pass,
                "metadata_exact_equal": metadata,
                "passed": equal and dates_pass and all(metadata.values()),
            }
        )
    return checks


def validate(observation=None, root=ROOT, client=request, output_directory=None):
    directory = root / "analysis/ingestion"
    observation = observation or load_json(directory / "latest-run.json")
    manifest = load_json(root / "analysis/normalization-manifest.json")
    summary = load_json(root / "analysis/preprocessing_summary.json")
    if (
        digest(root / "analysis/normalization-manifest.json")
        != observation["phase3_manifest_sha256"]
    ):
        raise ValueError("data normalization manifest differs from the ingestion run")
    # Recheck source artifacts without re-running preprocessing or changing evidence.
    for name, sha in manifest["processed_output_sha256"].items():
        if digest(root / "dataset/processed" / name) != sha:
            raise ValueError(f"Changed data normalization artifact: {name}")
    for name, sha in manifest["report_sha256"].items():
        if digest(root / "analysis" / name) != sha:
            raise ValueError(f"Changed data normalization report: {name}")
    client(f"/{INDEX}/_refresh", method="POST")
    query_checks = representative_queries()
    # event.original deliberately has index:false/doc_values:false in the data
    # normalization contract.
    fields = {
        key: value
        for key, value in summary["ecs_fields_populated"].items()
        if key != "event.original"
    }
    filters = {f"ecs:{field}": exists(field) for field in fields}
    filters.update({f"query:{name}": check["query"] for name, check in query_checks.items()})
    filters.update(
        {
            f"quality:{quality}": term("windows_apt.quality.timestamp", quality)
            for quality in summary["timestamp_quality"]
        }
    )
    filters["missing_timestamp"] = {"bool": {"must_not": [exists("@timestamp")]}}
    filters["unresolved_with_timestamp"] = every(
        term("windows_apt.quality.timestamp", "unresolved"), exists("@timestamp")
    )
    filters["assigned_scenario"] = exists("windows_apt.scenario.id")
    filters.update(
        {
            f"scenario_strength:{strength}": term(
                "windows_apt.scenario.attribution_strength", strength
            )
            for strength in summary["scenario_strengths"]
        }
    )
    for field in ("source_file", "source_row_index", "original_id", "source_sha256", "row_sha256"):
        filters[f"provenance:{field}"] = exists(f"windows_apt.provenance.{field}")
    result = client(
        f"/{INDEX}/_search",
        {
            "size": 0,
            "track_total_hits": True,
            "aggs": {
                "coverage": {"filters": {"filters": filters}},
                "time_range": {"stats": {"field": "@timestamp"}},
            },
        },
        method="POST",
    )
    if result.get("timed_out") or result["_shards"]["failed"]:
        raise ValueError("Incomplete Elasticsearch search response")
    buckets = result["aggregations"]["coverage"]["buckets"]

    def count(key):
        return buckets[key]["doc_count"]

    ecs = {field: comparison(expected, count(f"ecs:{field}")) for field, expected in fields.items()}
    total = comparison(summary["counts"]["processed_events"], result["hits"]["total"]["value"])
    timestamps = {
        quality: comparison(expected, count(f"quality:{quality}"))
        for quality, expected in summary["timestamp_quality"].items()
    }
    timestamps["with_timestamp"] = comparison(
        summary["ecs_fields_populated"]["@timestamp"], count("ecs:@timestamp")
    )
    timestamps["without_timestamp"] = comparison(
        summary["timestamp_quality"]["unresolved"], count("missing_timestamp")
    )
    timestamps["unresolved_with_timestamp"] = comparison(0, count("unresolved_with_timestamp"))
    provenance = {
        key.split(":")[1]: comparison(total["expected"], count(key))
        for key in filters
        if key.startswith("provenance:")
    }
    for name, check in query_checks.items():
        check.update(count=count(f"query:{name}"), passed=count(f"query:{name}") > 0)
    annotations = comparison(
        summary["enrichment"]["attack_annotated_events"], count("query:attack_annotation")
    )
    scenarios = comparison(
        summary["enrichment"]["scenario_enriched_events"], count("query:scenario")
    )
    scenario_strengths = {
        strength: comparison(expected, count(f"scenario_strength:{strength}"))
        for strength, expected in summary["scenario_strengths"].items()
    }
    assigned_scenarios = comparison(
        sum(value for key, value in summary["scenario_strengths"].items() if key != "UNRESOLVED"),
        count("assigned_scenario"),
    )
    mapping = client(f"/{INDEX}/_mapping")[INDEX]["mappings"]
    expected_template = build_template(load_json(root / "dataset/processed/elastic-mapping.json"))
    installed_template = client(f"/_index_template/{TEMPLATE}")["index_templates"][0][
        "index_template"
    ]
    settings = client(f"/{INDEX}/_settings")[INDEX]["settings"]["index"]
    contract = {
        "mapping_exact_equal": mapping == expected_template["template"]["mappings"],
        "template_contract_equal": template_matches(installed_template, expected_template),
        "normal_index": "data_stream" not in installed_template,
        "one_primary_zero_replicas": settings["number_of_shards"] == "1"
        and settings["number_of_replicas"] == "0",
    }
    samples = choose_samples(root / "dataset/processed/windows-apt-events.ndjson")
    checks = spot_checks(samples, client)
    es = client("/")
    health = client(f"/_cluster/health/{INDEX}")
    kibana = service_json("kibana", "/api/status")
    live_stats = service_json("logstash", "/_node/stats/pipelines/main")
    pipeline = live_stats["pipelines"]["main"]
    outputs = output_metrics(pipeline)
    rejected = outputs["phase4_rejects"]["events"]["in"]
    documents = outputs["phase4_elasticsearch"].get("documents", {})
    # Plugin counters are created on first increment; absent failure counters mean zero.
    failures = documents.get("non_retryable_failures", 0)
    successes = documents.get("successes")
    dlq = pipeline.get("dead_letter_queue", {})
    failures_check = {
        "malformed_or_guard_rejected": rejected,
        "elasticsearch_non_retryable_failures": failures,
        "elasticsearch_successful_operations": successes,
        "dead_letter_queue": dlq,
        "dead_letter_queue_note": "An empty Logstash DLQ has a one-byte segment header.",
        "logstash_input_events": pipeline["events"]["in"],
        "logstash_output_events": pipeline["events"]["out"],
        "passed": rejected == 0
        and failures == 0
        and successes == total["expected"]
        and pipeline["events"]["in"] == pipeline["events"]["out"] == total["expected"]
        and dlq.get("queue_size_in_bytes", -1) in (0, 1)
        and dlq.get("dropped_events") == 0
        and dlq.get("expired_events") == 0
        and dlq.get("last_error") == "no errors",
    }
    index_stats = client(f"/{INDEX}/_stats/docs,store")["indices"][INDEX]
    report = {
        "phase": 4,
        "validated_at_utc": datetime.now(UTC).isoformat(),
        "index": INDEX,
        "index_pattern": "windows-apt-events-*",
        "template": TEMPLATE,
        "phase3_manifest_sha256": observation["phase3_manifest_sha256"],
        "processed_dataset": "dataset/processed/windows-apt-events.ndjson",
        "processed_sha256": manifest["processed_output_sha256"]["windows-apt-events.ndjson"],
        "mapping_sha256": manifest["processed_output_sha256"]["elastic-mapping.json"],
        "run_id": observation["run_id"],
        "phase3_verification": observation["phase3_verification"],
        "stack": {
            "elasticsearch": es["version"]["number"],
            "logstash": live_stats["version"],
            "kibana": kibana["version"]["number"],
            "kibana_status": kibana["status"]["overall"]["level"],
            "elasticsearch_index_health": health["status"],
            "logstash_status": live_stats["status"],
            "elasticsearch_tls_certificate_verified": True,
        },
        "event_count": total,
        "timestamp_counts": timestamps,
        "historical_time_range": {
            key: value
            for key, value in result["aggregations"]["time_range"].items()
            if key in {"count", "min_as_string", "max_as_string"}
        }
        | {"aggregation_precision": "milliseconds"},
        "ecs_field_counts": ecs,
        "provenance_counts": provenance,
        "attack_annotation_count": annotations,
        "scenario_count": scenarios,
        "assigned_scenario_count": assigned_scenarios,
        "scenario_strength_counts": scenario_strengths,
        "index_contract": contract,
        "representative_queries": query_checks,
        "source_to_index_checks": checks,
        "ingestion_failures": failures_check,
        "failed_rejected_document_count": rejected + failures,
        "ingestion_seconds": observation["ingestion_seconds"],
        "index_size_bytes": index_stats["total"]["store"]["size_in_bytes"],
        "index_count_before": observation["index_count_before"],
        "limitations": [
            "11,410 unresolved events have no defensible event time; "
            "time-filtered views exclude them.",
            "Logstash may canonicalize insignificant timestamp trailing zeros; instant equality "
            "is checked to nanoseconds and original source strings remain exact.",
            "event.original is intentionally unindexed; it and disabled original/annotation "
            "payloads are checked in representative _source comparisons.",
            "Source annotations and scenario attribution are metadata, "
            "not behavioural detections or independent truth.",
            "Size and duration are local operational observations, not benchmarks. "
            "No final detections or dashboard exist.",
        ],
    }
    report["passed"] = all(
        [
            total["passed"],
            all(c["passed"] for c in ecs.values()),
            all(c["passed"] for c in timestamps.values()),
            all(c["passed"] for c in provenance.values()),
            annotations["passed"],
            scenarios["passed"],
            assigned_scenarios["passed"],
            all(c["passed"] for c in scenario_strengths.values()),
            all(contract.values()),
            all(c["passed"] for c in query_checks.values()),
            all(c["passed"] for c in checks),
            failures_check["passed"],
            kibana["status"]["overall"]["level"] == "available",
            health["status"] == "green",
            live_stats["status"] == "green",
        ]
    )
    destination = Path(output_directory) if output_directory is not None else directory
    save_json(destination / "ingestion-validation.json", report)
    write_report(destination / "ingestion-report.md", report)
    return report


def write_report(path, report):
    lines = [
        "# Live ingestion validation",
        "",
        f"Validated: {report['validated_at_utc']}. Overall passed: **{report['passed']}**.",
        "",
        f"Index `{INDEX}`; template `{TEMPLATE}`; query pattern `windows-apt-events-*`.",
        f"Processed SHA-256: `{report['processed_sha256']}`.",
        "",
        f"Stack versions: Elasticsearch {report['stack']['elasticsearch']}, "
        f"Logstash {report['stack']['logstash']}, Kibana {report['stack']['kibana']}.",
        f"Expected/indexed: {report['event_count']['expected']:,} / "
        f"{report['event_count']['actual']:,}.",
        f"Ingestion (container recreation through drain): {report['ingestion_seconds']} seconds. "
        f"Index store: {report['index_size_bytes']:,} bytes.",
        f"Input count before this run: {report['index_count_before']:,}.",
        "",
        "## Failure accounting",
        "",
        "```json",
        json.dumps(report["ingestion_failures"], indent=2),
        "```",
        "",
        "## Timestamp and ECS coverage",
        "",
        "| Field/check | Expected | Actual | Passed |",
        "|---|---:|---:|---|",
    ]
    for field, result in {**report["timestamp_counts"], **report["ecs_field_counts"]}.items():
        lines.append(
            f"| {field} | {result['expected']:,} | {result['actual']:,} | {result['passed']} |"
        )
    lines += [
        "",
        "## Representative searches",
        "",
        "Executed Query DSL and exact results are in "
        "[ingestion-validation.json](ingestion-validation.json). These KQL equivalents can be used "
        "in a later data view; they are not installed detection rules.",
        "",
        "| Telemetry | KQL equivalent | Hits |",
        "|---|---|---:|",
    ]
    for name, query in report["representative_queries"].items():
        lines.append(f"| {name} | `{query['kql']}` | {query['count']:,} |")
    lines += [
        "",
        "Historical timestamps require an absolute historical time range. Use Dev Tools "
        "against the ordinary index without a time filter to include unresolved events.",
        "",
        "## Source comparisons",
        "",
        "Deterministic first matching records in processed file order; full object comparison "
        "except UTC timestamp spelling, plus nanosecond doc-value comparison. All provenance, "
        "annotations, scenario, quality and original payloads must match exactly.",
        "",
        "| Category | Source row | Exact JSON values | Evidence and date values |",
        "|---|---:|---|---|",
    ]
    for check in report["source_to_index_checks"]:
        lines.append(
            f"| {check['category']} | {check['source_row_index']} | "
            f"{check['source_exact_equal']} | {check['passed']} |"
        )
    lines += [
        "",
        "The JSON report retains source filenames, event IDs, original/indexed timestamps, "
        "per-namespace comparisons, mapping equality and metadata counts.",
        "",
        "## Limitations",
        "",
    ]
    lines.extend(f"- {item}" for item in report["limitations"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-directory",
        type=Path,
        help="Save a fresh validation separately, preserving reports referenced by later phases",
    )
    args = parser.parse_args()
    try:
        print("Verifying data normalization before live validation...", flush=True)
        verify_phase3()
        report = validate(output_directory=args.output_directory)
        print(json.dumps({"passed": report["passed"], "event_count": report["event_count"]}))
        if not report["passed"]:
            parser.exit(1, "Live ingestion validation failed; inspect generated report.\n")
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Validation failed: {error}\n")


if __name__ == "__main__":
    main()
