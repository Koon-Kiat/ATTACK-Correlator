"""Replay technique selection evidence reads and fail on drift; never install analytics or
write to ES.
"""

import re
import sys
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, load_json, request, save_json  # noqa: E402
from scripts.inspect_selection_relationships import inspect, nanos  # noqa: E402
from scripts.inspect_technique_candidates import (  # noqa: E402
    FIELDS,
    PATTERN,
    fetch_events,
    probes,
    query_probe,
    sysmon,
)
from src.preprocessing.preprocess import digest  # noqa: E402


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_predicate(value):
    """Metadata may be returned as evidence, but may not constrain a behavioural query."""
    if isinstance(value, dict):
        for key, child in value.items():
            require(
                not key.startswith(("windows_apt.", "rule.", "threat.")),
                f"Contextual predicate is forbidden: {key}",
            )
            check_predicate(child)
    elif isinstance(value, list):
        for child in value:
            check_predicate(child)
    elif isinstance(value, str):
        require(
            not any(prefix in value for prefix in ("windows_apt.", "rule.", "threat.")),
            "Contextual field reference is forbidden in a predicate",
        )


def projections(value):
    """Collect every retained event projection, including repeated projections of one ID."""
    if isinstance(value, dict):
        if isinstance(value.get("event"), dict) and "id" in value["event"]:
            yield value
        else:
            for child in value.values():
                yield from projections(child)
    elif isinstance(value, list):
        for child in value:
            yield from projections(child)


def compare_projection(expected, actual, path=""):
    if isinstance(expected, dict):
        require(isinstance(actual, dict), f"Expected object at {path}")
        for key, value in expected.items():
            require(key in actual, f"Missing evidence field {path}/{key}")
            compare_projection(value, actual[key], f"{path}/{key}")
    elif path == "/@timestamp":
        require(nanos(expected) == nanos(actual), "Evidence timestamp differs")
    else:
        require(expected == actual, f"Evidence mismatch at {path}")


def check_cohort(cohort, queries):
    query = queries[cohort["query_key"]]
    for key in ("count", "with_timestamp", "without_timestamp", "usable_time_percent"):
        require(cohort[key] == query[key], f"Selection cohort differs: {key}")
    for field, agg in (
        ("process_guid_count", "process_guid"),
        ("parent_guid_count", "parent_guid"),
    ):
        if field in cohort:
            require(cohort[field] == query["aggregations"][agg]["doc_count"], field)


def check_selection(selection, queries):
    ids = [item["attack_id"] for item in selection["selected"]]
    require(
        len(ids) == len(set(ids)) == 3 and all(re.fullmatch(r"T\d{4}\.\d{3}", i) for i in ids),
        "Exactly three distinct sub-techniques are required",
    )
    for item in selection["selected"]:
        check_cohort(item["primary_cohort"], queries)
        for cohort in item["supporting_cohorts"]:
            check_cohort(cohort, queries)
        require(
            item["representative_event_ids"]
            == [e["event"]["event"]["id"] for e in item["representative_evidence"]],
            "Representative ID list differs from its evidence",
        )
    for item in selection["rejected_candidates"]:
        check_cohort(item["cohort"], queries)


def verify(root=ROOT, client=request):
    output = root / "analysis/selection/selection-verification.json"
    # Invalidate an earlier pass before starting a new live verification.
    save_json(output, {"passed": False, "status": "verification started"})
    state = load_json(root / "analysis/selection/live-state.json")
    selection = load_json(root / "analysis/technique_selection.json")
    queries = load_json(root / "analysis/selection/exploratory-queries.json")
    relationships = load_json(root / "analysis/selection/correlation-feasibility.json")
    for path, key in (
        ("analysis/ingestion/ingestion-validation.json", "phase4_validation_sha256"),
        ("analysis/normalization-manifest.json", "phase3_manifest_sha256"),
        ("analysis/attack_evidence.json", "phase2_evidence_sha256"),
        ("analysis/selection/exploratory-queries.json", "query_results_sha256"),
        ("analysis/inspection/selection-process-events.json", "projected_process_sha256"),
        ("analysis/inspection/selection-service-events.json", "projected_service_sha256"),
    ):
        require(digest(root / path) == state[key], f"Evidence hash changed: {path}")
    require(
        load_json(root / "analysis/ingestion/ingestion-validation.json")["passed"],
        "ingestion validation failed",
    )

    def totals():
        all_count = client(f"/{PATTERN}/_count")["count"]
        timed = client(
            f"/{PATTERN}/_count", {"query": {"exists": {"field": "@timestamp"}}}, method="POST"
        )["count"]
        counts = {"all": all_count, "timed": timed, "untimed": all_count - timed}
        require(
            counts == state["counts"] == {"all": 102011, "timed": 90601, "untimed": 11410},
            "Live counts differ from ingestion validation",
        )
        return counts

    totals()
    require(queries.keys() == probes().keys(), "Exploratory query inventory changed")
    for name, saved in queries.items():
        check_predicate(saved["request"]["query"])
        require(saved["request"]["query"] == probes()[name], f"Predicate drift: {name}")
        fresh = query_probe(saved["request"]["query"], client)
        for key in (
            "count",
            "with_timestamp",
            "without_timestamp",
            "usable_time_percent",
            "aggregations",
            "request",
        ):
            require(saved[key] == fresh[key], f"Live query result drift: {name}/{key}")
    check_selection(selection, queries)

    retained = list(projections([selection, queries, relationships]))
    ids = sorted({event["event"]["id"] for event in retained})
    live = fetch_events({"ids": {"values": ids}}, client, FIELDS + ["windows_apt.original"])
    lookup = {event["event"]["id"]: event for event in live}
    require(set(lookup) == set(ids), "A retained example is missing from Elasticsearch")
    for event in retained:
        compare_projection(event, lookup[event["event"]["id"]])

    process_events = fetch_events(sysmon("1"), client)
    service_events = fetch_events(
        probes()["service_installed"], client, FIELDS + ["windows_apt.original"]
    )
    require(len(process_events) == state["projected_process_count"], "Process pool drift")
    fresh_relationships = inspect(process_events, service_events)
    require(relationships == fresh_relationships, "Live relationship evidence changed")
    require(
        selection["correlation_feasibility"]["window_pair_counts"]
        == relationships["window_pair_counts"],
        "Selection pair counts changed",
    )
    require(
        selection["correlation_feasibility"]["strongest_chains"]
        == relationships["service_shell_powershell_chains"],
        "Selection chains changed",
    )
    report = {
        "passed": True,
        "verified_at_utc": datetime.now(UTC).isoformat(),
        "live_counts": totals(),
        "selected_ids": [item["attack_id"] for item in selection["selected"]],
        "replayed_queries": len(queries),
        "verified_event_projections": len(retained),
        "verified_unique_event_ids": len(ids),
        "fresh_process_records": len(process_events),
        "fresh_service_records": len(service_events),
        "verified_service_shell_powershell_chains": len(
            relationships["service_shell_powershell_chains"]
        ),
        "checks": [
            "Inventory, normalization, ingestion and projected cache hash continuity",
            "Exact total/timestamp/provider/code/GUID counts replayed",
            "Exactly three distinct sub-technique IDs and consistent cohort counts",
            "Every retained event projection compared with live indexed evidence",
            "All process/object joins recomputed from fresh live records",
            "No annotations, scenario or rule metadata in exploratory predicates",
            "Only explicit UTC timestamps enter ordered correlations",
        ],
        "artifact_sha256": {
            path: digest(root / path)
            for path in (
                "analysis/technique_selection.json",
                "analysis/selection/exploratory-queries.json",
                "analysis/selection/correlation-feasibility.json",
                "analysis/selection/live-state.json",
                "scripts/inspect_technique_candidates.py",
                "scripts/inspect_selection_relationships.py",
                "scripts/verify_technique_selection.py",
            )
        },
    }
    save_json(output, report)
    return report


if __name__ == "__main__":
    print(verify())
