"""Bounded review contracts and adversarial software fixtures; no dataset commands run."""

import copy

import pytest

from scripts.build_scenario_evidence import (
    CONTRACT,
    ESQL,
    EVALUATION,
    EXPECTED,
    P6,
    P7,
    REFINED,
    SCENARIO,
    SEARCH,
    SELECTED,
    provenance_status,
    scenario_queries,
    select_primary,
    select_review_units,
    source_projection,
    technique_ids,
    verify_hashes,
    verify_prerequisites,
    verify_scenario_queries,
    verify_triples,
)
from scripts.elastic_local import ROOT, load_json
from scripts.run_correlation import (
    SERVICE_IMAGE,
    chain_record,
    correlation_id,
    pair_record,
    time_ns,
)
from scripts.run_individual_detections import fetch_evidence, source_matches
from scripts.scenario_report import cell, render_evaluation, render_scenario


@pytest.fixture
def triple():
    provenance = {
        "dataset": "software-fixture",
        "dataset_version": "1",
        "source_file": "fixture.csv",
        "source_sha256": "a" * 64,
        "row_sha256": "b" * 64,
        "original_id": "fixture",
        "original_index": "fixture",
        "source_row_index": 0,
    }
    shell = {
        "@timestamp": "2024-01-01T00:00:00.010000000Z",
        "event": {"id": "shell", "provider": "Microsoft-Windows-Sysmon", "code": "1"},
        "host": {"name": "HOST"},
        "process": {
            "name": "cmd.exe",
            "entity_id": "{AAAAAAAA-BBBB-CCCC-DDDD-000000000001}",
            "command_line": r"C:\Windows\cmd.exe /c powershell.exe -nop -w hidden -c Get-Date",
            "parent": {
                "name": "services.exe",
                "entity_id": "{AAAAAAAA-BBBB-CCCC-DDDD-000000000009}",
            },
        },
        "windows_apt": {"provenance": provenance},
    }
    ps = copy.deepcopy(shell)
    ps["@timestamp"] = "2024-01-01T00:00:00.010000001Z"
    ps["event"]["id"] = "child"
    ps["process"] = {
        "name": "powershell.exe",
        "entity_id": "{AAAAAAAA-BBBB-CCCC-DDDD-000000000002}",
        "command_line": "powershell.exe -nop -w hidden -c Get-Date",
        "parent": {"name": "cmd.exe", "entity_id": shell["process"]["entity_id"].lower()},
    }
    service = {
        "@timestamp": "2024-01-01T00:00:00.000000000Z",
        "event": {"id": "service", "provider": "Service Control Manager", "code": "7045"},
        "host": {"name": "HOST"},
        "windows_apt": {
            "provenance": provenance,
            "original": {SERVICE_IMAGE: shell["process"]["command_line"]},
        },
    }
    lookup = {e["event"]["id"]: e for e in (service, shell, ps)}
    p6 = {
        "queries": {
            q: {"event_ids": [i for i, e in lookup.items() if source_matches(q, e)]}
            for q in EXPECTED
        }
    }
    chain = chain_record(["service", "shell", "child"], lookup, {"shell"}, {"child"})
    p7 = {
        "eql_endpoint_validation": {"service_origin_shell": {"event_ids": ["shell"]}},
        "windows": {
            "60": {
                "three_event": {"tuples": [chain]},
                "broad": {"tuples": [pair_record(["shell", "child"], lookup)]},
            }
        },
    }
    return p6, p7, lookup


def test_primary_selection_uses_nanoseconds_then_ids_not_host_or_labels():
    a = {
        "event_ids": ["z", "b", "c"],
        "timestamps": ["2024-01-01T00:00:00.100Z"],
        "host": "ZZZ",
        "scenario": "apparently harmless",
    }
    b = {
        "event_ids": ["a", "d", "e"],
        "timestamps": ["2024-01-01T00:00:00.100000001Z"],
        "host": "AAA",
        "scenario": "apparently malicious",
    }
    c = a | {"event_ids": ["y", "g", "h"]}
    assert select_primary([b, a, c]) == select_primary([c, b, a]) == [c, a, b]


@pytest.mark.parametrize("timestamp", [None, "2024-01-01", "2024-01-01T00:00:00"])
def test_primary_selection_rejects_undated_triples(timestamp):
    with pytest.raises(ValueError, match="explicit UTC"):
        select_primary([{"event_ids": ["a", "b", "c"], "timestamps": [timestamp]}])


def test_primary_triple_validates_case_only_guid_and_service_source(triple):
    p6, p7, lookup = triple
    got = verify_triples(p6, p7, lookup)[0]
    assert got["gaps_nanoseconds"] == [10_000_000, 1]
    assert got["phase6_membership"] == {
        "service_installation_baseline": True,
        "shell_service_origin_branch": True,
        "powershell_refined": True,
    }
    assert sorted({t for e in lookup.values() for t in technique_ids(e)}) == SELECTED
    assert "service" not in p6["queries"]["service_create_refined"]["event_ids"]
    assert "service" not in p6["queries"]["service_config_refined"]["event_ids"]


@pytest.mark.parametrize(
    "defect",
    [
        "missing",
        "same_time",
        "reversed",
        "host",
        "guid",
        "braces",
        "image",
        "no_image",
        "missing_time",
        "late",
        "not_refined",
        "provenance",
        "not_in_result",
    ],
)
def test_scenario_cannot_pass_broken_evidence(triple, defect):
    p6, p7, lookup = triple
    if defect == "missing":
        del lookup["child"]
    elif defect == "same_time":
        lookup["child"]["@timestamp"] = lookup["shell"]["@timestamp"]
    elif defect == "reversed":
        lookup["service"]["@timestamp"] = "2024-01-01T00:00:01Z"
    elif defect == "host":
        lookup["child"]["host"]["name"] = "host"
    elif defect == "guid":
        lookup["child"]["process"]["parent"]["entity_id"] = None
    elif defect == "braces":
        lookup["child"]["process"]["parent"]["entity_id"] = lookup["shell"]["process"][
            "entity_id"
        ].strip("{}")
    elif defect == "image":
        lookup["service"]["windows_apt"]["original"][SERVICE_IMAGE] += " different"
    elif defect == "no_image":
        lookup["service"]["windows_apt"]["original"] = {}
    elif defect == "missing_time":
        del lookup["shell"]["@timestamp"]
    elif defect == "late":
        lookup["child"]["@timestamp"] = "2024-01-01T00:01:00.000000001Z"
    elif defect == "not_refined":
        lookup["child"]["process"]["command_line"] = "powershell.exe -encodedCommand AAAA"
    elif defect == "provenance":
        del lookup["shell"]["windows_apt"]["provenance"]["source_file"]
    else:
        p7["windows"]["60"]["three_event"]["tuples"][0]["event_ids"][2] = "absent"
    with pytest.raises(ValueError):
        verify_triples(p6, p7, lookup)


def test_service_normalization_preserves_lexical_limits(triple):
    p6, p7, lookup = triple
    original = lookup["service"]["windows_apt"]["original"]
    original[SERVICE_IMAGE] = "  " + original[SERVICE_IMAGE].upper().replace("\\", "\\\\") + "  "
    # The prior artifact retains this spelling; validation still compares full normalized commands.
    p7["windows"]["60"]["three_event"]["tuples"][0] = chain_record(
        ["service", "shell", "child"], lookup, {"shell"}, {"child"}
    )
    assert verify_triples(p6, p7, lookup)


def test_projection_ignores_publisher_metadata_and_empty_service_cells_in_process(triple):
    p6, p7, lookup = triple
    before = {i: source_projection(e) for i, e in lookup.items()}
    for e in lookup.values():
        e["windows_apt"].update(
            {"annotations": {"attack": "T9999"}, "scenario": {"name": "malicious", "success": 100}}
        )
        e["rule"] = {"level": 99}
    lookup["shell"]["windows_apt"]["original"] = {SERVICE_IMAGE: " ", "irrelevant": "payload"}
    assert before == {i: source_projection(e) for i, e in lookup.items()}
    assert verify_triples(p6, p7, lookup)


def test_source_row_zero_is_valid_but_missing_provenance_is_reported(triple):
    e = triple[2]["shell"]
    assert provenance_status(e)["complete"]
    del e["windows_apt"]["provenance"]["source_row_index"]
    assert provenance_status(e) == {"complete": False, "missing_fields": ["source_row_index"]}


def test_exact_id_readback_rejects_missing_and_duplicate_records(triple):
    lookup = triple[2]
    for hits in ([], [lookup["shell"], lookup["shell"]]):
        calls = iter([hits, []])

        def client(*args, calls=calls, **kwargs):
            return {
                "timed_out": False,
                "_shards": {"failed": 0},
                "hits": {"hits": [{"_source": e, "sort": [e["event"]["id"]]} for e in next(calls)]},
            }

        with pytest.raises(ValueError):
            fetch_evidence(["shell"], client)


def test_queries_filter_exact_ids_and_read_originals_only_as_source():
    ids = ["a", "b", "c"]
    query, body = scenario_queries(ids)
    assert 'event.id IN ("a", "b", "c")' in query
    assert "SORT @timestamp ASC" in query
    assert body["query"] == {"ids": {"values": ids}}
    assert "windows_apt.original" in body["_source"]
    assert "windows_apt" not in query
    for invalid in (["a", "a", "b"], ["a", "b"]):
        with pytest.raises(ValueError):
            scenario_queries(invalid)


@pytest.mark.parametrize("defect", ["order", "partial", "count", "source"])
def test_scenario_query_verifier_rejects_wrong_or_partial_results(triple, defect):
    lookup = triple[2]
    ids = ["service", "shell", "child"]
    query, body = scenario_queries(ids)

    def client(path, body, method):
        if path.startswith("/_query"):
            values = list(reversed(ids)) if defect == "order" else ids
            return {
                "columns": [{"name": "event.id", "type": "keyword"}],
                "values": [[i] for i in values],
            }
        hits = [{"_id": i, "_source": copy.deepcopy(lookup[i])} for i in ids]
        if defect == "source":
            hits[0]["_source"]["host"]["name"] = "wrong"
        return {
            "timed_out": defect == "partial",
            "_shards": {"failed": 0},
            "hits": {
                "total": {"value": 4 if defect == "count" else 3, "relation": "eq"},
                "hits": hits,
            },
        }

    with pytest.raises(ValueError):
        verify_scenario_queries(ids, lookup, query, body, client)


def test_hash_drift_is_rejected(tmp_path):
    (tmp_path / "input.json").write_text("changed")
    with pytest.raises(ValueError, match="hash drift"):
        verify_hashes(tmp_path, {"input.json": "0" * 64})


def test_live_artifact_primary_and_comparison_selection_are_permutation_invariant():
    p6, p7 = load_json(ROOT / P6), load_json(ROOT / P7)
    triples = select_primary(p7["windows"]["60"]["three_event"]["tuples"])
    expected = select_review_units(p6, p7, triples)
    p7["windows"]["60"]["refined"]["tuples"].reverse()
    p7["windows"]["60"]["excluded_broad_tuples"].reverse()
    for q in p6["queries"].values():
        q["event_ids"].reverse()
    p6["techniques"].reverse()
    assert select_review_units(p6, p7, triples) == expected
    assert triples[0]["host"] == "DESKTOP-DS4FBF4"
    assert triples[0]["timestamps"][0] == "2024-11-06T09:58:51.208562600Z"
    assert len(expected) == 11


def test_completed_artifacts_keep_units_and_unsupported_metrics_separate():
    scenario = load_json(ROOT / SCENARIO)
    evaluation = load_json(ROOT / EVALUATION)
    contract = load_json(ROOT / CONTRACT)
    assert scenario["passed"] and evaluation["passed"]
    assert evaluation["review_set"]["by_type"] == {
        "event": 7,
        "ordered_pair": 3,
        "ordered_triple": 1,
    }
    assert evaluation["review_set"]["unique_event_count"] == 16
    assert len(scenario["evidence"]) == 18
    assert sorted(m["attack_id"] for m in scenario["primary_technique_mapping"]) == SELECTED
    assert scenario["primary_technique_mapping"][0]["refined_sc_process_member"] is False
    assert evaluation["ground_truth"]["independent_intent_labels_available"] is False
    assert not contract["dashboard_built"]
    unsupported = {
        "precision",
        "recall",
        "f1",
        "fpr",
        "confusion_matrix",
        "severity",
        "confidence",
        "malicious",
        "benign",
        "is_malicious",
        "risk_score",
    }

    def inspect(value):
        if isinstance(value, dict):
            keys = unsupported.intersection(value)
            if {"min_utc", "max_utc"} <= value.keys():
                # This inherited Phase 6 field describes timestamp resolution, not accuracy.
                assert value["precision"].startswith("nanoseconds;")
                keys -= {"precision"}
            assert not keys
            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    for artifact in (scenario, evaluation, contract):
        inspect(artifact)
    required = {
        "type",
        "technique_ids",
        "observable_behaviour",
        "category",
        "structural_relationship",
        "timestamp_completeness",
        "process_ancestry_completeness",
        "provenance_completeness",
        "plausible_legitimate_explanation",
        "inclusion_or_exclusion_reason",
        "uncertainty",
        "coverage_limitation",
    }
    assert all(required <= u.keys() for u in scenario["review_units"])


def test_dashboard_activity_has_exact_ids_times_and_daily_reconciliation():
    p6, result = load_json(ROOT / P6), load_json(ROOT / EVALUATION)
    rows = result["activity"]["event_rows"]
    assert len(rows) == len({(r["event_id"], r["detection_name"]) for r in rows}) == 611
    for q in REFINED:
        cohort = [r for r in rows if r["detection_name"] == q]
        assert {r["event_id"] for r in cohort} == set(p6["queries"][q]["event_ids"])
        assert len(cohort) == sum(
            r["event_count"] for r in result["activity"]["daily_utc"] if r["detection_name"] == q
        )
        assert all(time_ns({"@timestamp": r["timestamp"]}) is not None for r in cohort)
    assert result["correlation_windows"]["60"]["broad"]["unit"] == "ordered_pair"
    assert result["correlation_windows"]["60"]["three_event"]["unit"] == "ordered_triple"


def test_generated_reports_are_repeatable_and_escape_source_as_inert_text():
    scenario, result = load_json(ROOT / SCENARIO), load_json(ROOT / EVALUATION)
    assert render_scenario(copy.deepcopy(scenario)) == render_scenario(scenario)
    assert render_evaluation(copy.deepcopy(scenario), copy.deepcopy(result)) == render_evaluation(
        scenario, result
    )
    assert cell("<script>alert(1)</script>|`\n") == (
        "&lt;script&gt;alert(1)&lt;/script&gt;&#124;&#96;<br>"
    )


def test_generated_hash_chain_and_original_queries_remain_valid():
    verify_prerequisites(ROOT)
    result = load_json(ROOT / EVALUATION)
    verify_hashes(ROOT, result["input_sha256"])
    verify_hashes(ROOT, result["output_sha256"])
    verify_hashes(ROOT, result["query_sha256"])
    assert set(result["query_sha256"]) == {SEARCH, ESQL}
    scenario = load_json(ROOT / SCENARIO)
    assert scenario["primary"]["correlation_id"] == correlation_id(scenario["primary"]["event_ids"])
