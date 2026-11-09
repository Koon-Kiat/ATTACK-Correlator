"""Replay saved detections and correlations against the actual prepared NDJSON offline.

This complements the live ES|QL/EQL validators; it does not claim to execute ES|QL.
Commands in source records are treated only as inert strings.
"""

import hashlib
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, load_json, save_json  # noqa: E402
from scripts.inspect_selection_relationships import compact  # noqa: E402
from scripts.run_correlation import (  # noqa: E402
    event_lookup,
    lineage_pairs,
    pair_record,
    refine_pairs,
    service_chains,
)
from scripts.run_individual_detections import (  # noqa: E402
    field,
    observed_conditions,
    source_matches,
)
from scripts.verify_technique_selection import require  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402


def run(root=ROOT):
    detection_path = root / "analysis/detections/detection-results.json"
    correlation_path = root / "analysis/correlation/correlation-results.json"
    detections, correlations = load_json(detection_path), load_json(correlation_path)
    require(detections["passed"] and correlations["passed"], "Saved validation must pass")
    path = root / "dataset/processed/windows-apt-events.ndjson"
    queries = {q: set() for q in detections["queries"]}
    source_ids, events, service_examples = set(), [], []
    timed = 0
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for line in stream:
            hasher.update(line)
            event = json.loads(line)
            event_id = field(event, "event.id")
            require(event_id and event_id not in source_ids, "Missing or duplicate event ID")
            source_ids.add(event_id)
            timed += isinstance(event.get("@timestamp"), str)
            provider, code = field(event, "event.provider"), field(event, "event.code")
            if not (
                (provider == "Microsoft-Windows-Sysmon" and code in {"1", "13"})
                or (provider == "Service Control Manager" and code == "7045")
            ):
                continue
            for query_id, matched in queries.items():
                if source_matches(query_id, event):
                    matched.add(event_id)
            if (
                event_id in queries["service_create_refined"]
                and field(event, "host.name") == "DESKTOP-DS4FBF4"
            ):
                service_examples.append(compact(event))
            if any(
                event_id in queries[q]
                for q in ("shell_baseline", "powershell_baseline", "service_installation")
            ):
                events.append(compact(event))
    require((len(source_ids), timed) == (102011, 90601), "Prepared dataset totals differ")
    for query_id, ids in queries.items():
        expected = detections["queries"][query_id]
        require(ids == set(expected["event_ids"]), f"Exact query ID set differs: {query_id}")
        require(len(ids) == expected["distinct_event_count"], f"Count differs: {query_id}")
    lookup = event_lookup(events)
    shells = [lookup[i] for i in sorted(queries["shell_baseline"])]
    children = [lookup[i] for i in sorted(queries["powershell_baseline"])]
    services = [lookup[i] for i in sorted(queries["service_installation"])]
    service_shells = {
        field(e, "event.id") for e in shells if observed_conditions(e)["service_parent_interpreter"]
    }
    counts = {}
    for window in correlations["windows_tested_seconds"]:
        broad = lineage_pairs(shells, children, window)
        refined = refine_pairs(broad, service_shells, queries["powershell_refined"])
        triples = service_chains(services, broad, lookup, window)
        saved = correlations["windows"][str(window)]
        for name, tuples in (("broad", broad), ("refined", refined), ("three_event", triples)):
            require(
                set(tuples) == {tuple(t["event_ids"]) for t in saved[name]["tuples"]},
                f"Exact correlation tuples differ: {window}s {name}",
            )
        counts[str(window)] = {
            "broad": len(broad),
            "refined": len(refined),
            "triples": len(triples),
        }
    # Stable selection matches the report and existing retained representative.
    ids = tuple(correlations["windows"]["60"]["removed_representatives"][0]["event_ids"])
    require(ids in lineage_pairs(shells, children, 60), "Example must satisfy the broad join")
    require(
        not refine_pairs([ids], service_shells, queries["powershell_refined"]),
        "Example must fail the refined join",
    )
    shell, child = [lookup[i] for i in ids]
    example = {
        "passed": True,
        "verification": "Actual prepared NDJSON; all 13 saved query ID sets and tuples agree",
        "pair": pair_record(ids, lookup),
        "shell_conditions": observed_conditions(shell),
        "child_conditions": observed_conditions(child),
        "refined_shell_service_origin": ids[0] in service_shells,
        "refined_powershell": ids[1] in queries["powershell_refined"],
        "events": [shell, child],
        "interpretation": (
            "Related process activity excluded by service-parent and PowerShell predicates; "
            "not an independently classified false positive. Encoded content is not decoded."
        ),
        "input_sha256": {
            "dataset/processed/windows-apt-events.ndjson": hasher.hexdigest(),
            "analysis/detections/detection-results.json": digest(detection_path),
            "analysis/correlation/correlation-results.json": digest(correlation_path),
        },
    }
    save_json(root / "analysis/correlation/excluded-pair-example.json", example)
    require(service_examples, "Report's refined service example is missing")
    service = min(service_examples, key=lambda e: (e["@timestamp"], field(e, "event.id")))
    save_json(
        root / "analysis/detections/refined-service-example.json",
        {
            "passed": True,
            "source": "Prepared source in the exact live-validated service_create_refined set",
            "event": service,
            "conditions": observed_conditions(service),
            "interpretation": "Separate sc.exe process match; not an additional asserted GUID edge",
            "input_sha256": example["input_sha256"],
        },
    )
    result = {
        "passed": True,
        "mode": "Offline source predicates; live ES|QL/EQL execution is recorded separately",
        "events": len(source_ids),
        "timed": timed,
        "undated": len(source_ids) - timed,
        "exact_query_id_sets": {q: len(ids) for q, ids in sorted(queries.items())},
        "exact_correlation_tuple_sets": counts,
        "input_sha256": example["input_sha256"],
        "runner_sha256": digest(Path(__file__)),
    }
    save_json(root / "analysis/evaluation/evidence-validation.json", result)
    print(json.dumps({k: v for k, v in result.items() if k != "input_sha256"}))
    return result


if __name__ == "__main__":
    run()
