"""Presentation-contract regression tests; fixtures never index or execute commands."""

import copy
import json

import pytest

from scripts.build_dashboard import definition, detection_discover_query, literal, source_event_url
from scripts.build_dashboard_data import (
    FORBIDDEN,
    INDEX,
    RULE_COUNTS,
    UNITS,
    build_documents,
    document_id,
    index_documents,
    mapping,
    no_unsupported_fields,
    prerequisites,
    validate_documents,
)
from scripts.elastic_local import ROOT, load_json, save_json
from scripts.kibana_local import http
from scripts.run_correlation import sha_json
from scripts.validate_dashboard import check_export, check_layout, subset, validate_evidence


@pytest.fixture
def inputs():
    p7 = load_json(ROOT / "analysis/correlation/correlation-results.json")
    p8 = load_json(ROOT / "analysis/evaluation/evaluation-results.json")
    scenario = load_json(ROOT / "analysis/scenarios/scenario-demonstration.json")
    # Only metadata is needed to exercise presentation assembly. Behavioural evidence
    # is independently checked by prepare() against live Elasticsearch, not these stubs.
    lookup = {
        row["event_id"]: {
            "event": {"id": row["event_id"]},
            "@timestamp": row["timestamp"],
            "host": {"name": row["host"]},
        }
        for row in p8["activity"]["event_rows"]
    }
    for event_id, value in scenario["evidence"].items():
        lookup[event_id] = {
            "event": {"id": event_id, "provider": value["provider"], "code": value["event_code"]},
            "@timestamp": value["timestamp"],
            "host": {"name": value["host"]},
            "user": value["user"],
            "process": value["process"],
            "windows_apt": {
                "provenance": value["provenance"],
                "original": {
                    "_source.data.win.eventdata." + k: v
                    for k, v in value["service_source_evidence"].items()
                },
            },
        }
    return p7, p8, scenario, lookup


@pytest.fixture
def documents(inputs):
    return build_documents(*inputs)


def test_exact_units_counts_and_source_references(documents, inputs):
    counts = validate_documents(documents)
    assert counts["record_counts"] == {
        "detection_event": 611,
        "correlation_pair": 261,
        "scenario_event": 9,
    }
    assert counts["rule_counts"] == RULE_COUNTS
    assert counts["refined_pairs"] == counts["refined_hosts"] == counts["primary_rows"] == 3
    assert counts["document_count"] == 881
    p7, p8, scenario, _ = inputs
    actual_ids = {i for d in documents.values() for i in d["source"]["event_ids"]}
    expected_ids = {r["event_id"] for r in p8["activity"]["event_rows"]}
    expected_ids |= {i for p in p7["windows"]["60"]["broad"]["tuples"] for i in p["event_ids"]}
    expected_ids |= {
        i for p in [scenario["primary"], *scenario["corroborating"]] for i in p["event_ids"]
    }
    assert actual_ids == expected_ids
    for value in documents.values():
        assert value["record"]["unit"] == UNITS[value["record"]["kind"]]
        if value["record"]["kind"] != "correlation_pair":
            assert value["source"]["event_ids"] == [value["event"]["id"]]


def test_identity_preserves_rule_and_tuple_units():
    first = document_id("detection_event", "rule-a", "event")
    assert first == document_id("detection_event", "rule-a", "event")
    assert first != document_id("detection_event", "rule-b", "event")
    assert document_id("correlation_pair", "ab") != document_id("correlation_pair", "ba")
    assert document_id("scenario_event", "triple-a", "event") != document_id(
        "scenario_event", "triple-b", "event"
    )


def test_generation_is_deterministic_and_order_independent(inputs, documents):
    p7, p8, scenario, lookup = copy.deepcopy(inputs)
    p8["activity"]["event_rows"].reverse()
    p7["windows"]["60"]["broad"]["tuples"].reverse()
    reversed_documents = build_documents(p7, p8, scenario, dict(reversed(list(lookup.items()))))
    assert reversed_documents == documents
    assert sha_json(reversed_documents) == sha_json(documents)


@pytest.mark.parametrize("kind", ["detection_event", "correlation_pair", "scenario_event"])
def test_missing_row_fails(documents, kind):
    del documents[next(key for key, d in documents.items() if d["record"]["kind"] == kind)]
    with pytest.raises(ValueError, match="count mismatch"):
        validate_documents(documents)


def test_wrong_rule_and_refined_flags_fail(documents):
    value = next(
        d for d in documents.values() if d.get("detection", {}).get("id") == "powershell_refined"
    )
    value["detection"]["id"] = "shell_refined"
    with pytest.raises(ValueError, match="Per-rule"):
        validate_documents(documents)
    value["detection"]["id"] = "powershell_refined"
    pair = next(d for d in documents.values() if d.get("correlation", {}).get("refined"))
    pair["correlation"]["refined"] = False
    with pytest.raises(ValueError, match="Refined pair"):
        validate_documents(documents)


def test_missing_source_or_timestamp_drift_fails(inputs):
    _, p8, _, lookup = inputs
    first = p8["activity"]["event_rows"][0]["event_id"]
    lookup[first]["@timestamp"] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="timestamp/host drift"):
        build_documents(*inputs)
    del lookup[first]
    with pytest.raises(KeyError):
        build_documents(*inputs)


def test_duplicate_membership_fails(inputs):
    inputs[1]["activity"]["event_rows"].append(inputs[1]["activity"]["event_rows"][0])
    with pytest.raises(ValueError, match="Duplicate presentation"):
        build_documents(*inputs)


@pytest.mark.parametrize("name", sorted(FORBIDDEN))
def test_no_invented_classification_fields(documents, name):
    next(iter(documents.values()))["analyst"] = {name: 1}
    with pytest.raises(ValueError, match="Unsupported classification"):
        no_unsupported_fields(documents)


def test_scm_nulls_and_source_only_fields_preserved(documents):
    installation = next(
        d
        for d in documents.values()
        if d.get("scenario", {}).get("primary") and d["scenario"]["position"] == 1
    )
    assert installation["process"]["name"] is None
    assert installation["user"]["name"] is None
    assert installation["service_evidence"]["accountName"] == "LocalSystem"
    assert mapping()["properties"]["service_evidence"]["enabled"] is False
    assert literal(None) == "Unavailable"
    assert literal("https://example.invalid/<script>|`example`").startswith("`` ")
    assert "\\|" in literal("x|y")


def test_phase8_hash_and_pass_guard(tmp_path, monkeypatch):
    import scripts.build_dashboard_data as builder

    monkeypatch.setattr(builder, "verify_prerequisites", lambda _: ({}, {}))
    evaluation = load_json(ROOT / "analysis/evaluation/evaluation-results.json")
    for name in ("dashboard-contract.json", "evaluation-results.json"):
        save_json(
            tmp_path / "analysis/evaluation" / name, load_json(ROOT / "analysis/evaluation" / name)
        )
    save_json(
        tmp_path / "analysis/scenarios/scenario-demonstration.json",
        load_json(ROOT / "analysis/scenarios/scenario-demonstration.json"),
    )
    evaluation["passed"] = False
    save_json(tmp_path / "analysis/evaluation/evaluation-results.json", evaluation)
    with pytest.raises(ValueError, match="scenario evaluation must pass"):
        prerequisites(tmp_path)
    evaluation["passed"] = True
    evaluation["input_sha256"] = {"changed.txt": "0" * 64}
    (tmp_path / "changed.txt").write_text("changed", encoding="utf-8")
    save_json(tmp_path / "analysis/evaluation/evaluation-results.json", evaluation)
    with pytest.raises(ValueError, match="Artifact hash drift: changed.txt"):
        prerequisites(tmp_path)


def test_live_phase8_file_contract_passes():
    assert prerequisites()[2]["passed"] is True


def test_metric_filter_regression_and_layout(documents):
    dashboard = definition(documents)
    check_layout(dashboard["panels"])
    for panel in dashboard["panels"]:
        config = panel["config"]
        if config.get("type") == "metric":
            assert config["ignore_global_filters"] is True
            assert "filter" in config["metrics"][0]
            assert "query" not in config  # Kibana ignores this with ignore_global_filters.
            assert config["metrics"][0]["subtitle"] in {
                "Distinct candidate events",
                "Ordered pairs",
                "Distinct hosts",
            }
    dashboard["panels"][1]["grid"] = dashboard["panels"][0]["grid"]
    with pytest.raises(ValueError, match="Overlapping panels"):
        check_layout(dashboard["panels"])


def test_missing_live_property_or_export_reference_fails():
    with pytest.raises(ValueError, match="Missing live property"):
        subset({"title": "expected"}, {})
    exported = (ROOT / "kibana/dashboard.ndjson").read_text(encoding="utf-8")
    check_export(exported, "9.5.3")
    rows = [json.loads(line) for line in exported.splitlines()]
    row = next(r for r in rows if r.get("type") == "dashboard")
    row["references"][0]["id"] = "absent"
    with pytest.raises(ValueError, match="Unresolved saved-object"):
        check_export("\n".join(json.dumps(r) for r in rows), "9.5.3")


def test_write_guard_and_bulk_failure(documents):
    with pytest.raises(ValueError, match="Only presentation"):
        http("/windows-apt-events-v1/_bulk", "", "POST", service="presentation_bulk")

    def client(path, *args, **kwargs):
        if path.endswith("/_mapping"):
            return {INDEX: {"mappings": mapping()}}
        return {"hits": {"total": {"relation": "eq", "value": 0}, "hits": []}}

    with pytest.raises(ValueError, match="bulk failure"):
        index_documents(documents, client, lambda *a, **kw: {"errors": True, "items": []})


def test_unowned_index_is_not_overwritten(documents):
    with pytest.raises(ValueError, match="ownership/mapping"):
        index_documents(documents, lambda *a, **kw: {INDEX: {"mappings": {"_meta": {}}}})


@pytest.mark.parametrize("defect", [None, "missing_row", "duplicate_id", "wrong_source"])
def test_evidence_exact_ids_and_source_resolution(documents, monkeypatch, defect):
    def query_rows(query, client):
        rule = next(rule for rule in RULE_COUNTS if rule in query)
        rows = [
            {"event.id": d["event"]["id"], "detection.id": rule}
            for d in documents.values()
            if d.get("detection", {}).get("id") == rule
        ]
        rows.sort(key=lambda r: r["event.id"])
        if defect == "missing_row":
            rows.pop()
        if defect == "duplicate_id":
            rows[-1] = rows[0]
        return rows

    def source_search(path, body, method):
        ids = body["query"]["terms"]["event.id"]
        return {
            "hits": {
                "total": {"value": len(ids), "relation": "eq"},
                "hits": [
                    {"_source": {"event": {"id": ("wrong" if defect == "wrong_source" else i)}}}
                    for i in ids
                ],
            }
        }

    monkeypatch.setattr("scripts.validate_dashboard.esql", query_rows)
    if defect:
        with pytest.raises(ValueError, match="mismatch"):
            validate_evidence(definition(documents), documents, source_search)
    else:
        result = validate_evidence(definition(documents), documents, source_search)
        assert {r: v["row_count"] for r, v in result.items()} == RULE_COUNTS
        assert sum(v["source_records_resolved"] for v in result.values()) == 611


def test_discover_links_preserve_scope_and_do_not_embed_space_ids():
    from urllib.parse import unquote

    source = unquote(source_event_url())
    assert source.startswith("discover#/")
    assert 'FROM windows-apt-events-* | WHERE event.id == "{{value}}"' in source
    for rule in RULE_COUNTS:
        query = detection_discover_query(rule)
        assert f'detection.id == "{rule}"' in query
        assert 'record.kind == "detection_event"' in query
        assert "2024-11-05" in query and "2024-12-15" in query
        assert "STATS" not in query and "LIMIT 1000" in query
