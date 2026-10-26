import copy
import json

import pytest

from scripts import ingest
from scripts import validate_ingestion as validation
from scripts.elastic_local import INDEX, ROOT, load_json, save_json
from src.preprocessing.preprocess import digest


def test_phase3_guard_runs_existing_verifier_and_refuses_failed_evidence(tmp_path):
    for name in ("normalization-manifest.json", "preprocessing_summary.json"):
        save_json(tmp_path / "analysis" / name, load_json(ROOT / "analysis" / name))
    calls = []

    def verifier(*paths):
        calls.append(paths)
        return dict.fromkeys(
            (
                "raw_hashes_match",
                "output_and_report_hashes_match",
                "all_rows_accounted_for",
                "all_original_rows_reconstructed",
                "offline_mapping_contract_passed",
            ),
            True,
        ) | {"processed_events": 102011}

    assert ingest.verify_phase3(tmp_path, verifier)[2]["processed_events"] == 102011
    assert calls == [
        (tmp_path / "dataset/raw", tmp_path / "dataset/processed", tmp_path / "analysis")
    ]
    with pytest.raises(ValueError, match="verification failed"):
        ingest.verify_phase3(tmp_path, lambda *args: verifier(*args) | {"raw_hashes_match": False})


def test_phase3_guard_stops_on_changed_counts_before_ingestion(tmp_path):
    summary = load_json(ROOT / "analysis/preprocessing_summary.json")
    manifest = load_json(ROOT / "analysis/normalization-manifest.json")
    summary["timestamp_quality"]["unresolved"] -= 1
    save_json(tmp_path / "analysis/preprocessing_summary.json", summary)
    save_json(tmp_path / "analysis/normalization-manifest.json", manifest)
    with pytest.raises(ValueError, match="authorized release"):
        ingest.verify_phase3(tmp_path, lambda *args: pytest.fail("Should stop before verification"))


def test_template_wraps_the_verified_mapping_without_mutation(tmp_path):
    mapping = {"dynamic": "strict", "properties": {"@timestamp": {"type": "date_nanos"}}}
    original = copy.deepcopy(mapping)
    save_json(tmp_path / "dataset/processed/elastic-mapping.json", mapping)
    requests = []

    def client(path, body=None, **kwargs):
        requests.append((path, body, kwargs))
        return None if path.endswith("/_mapping") else {}

    template = ingest.install_template(tmp_path, client)
    assert template["template"]["mappings"] == original == mapping
    assert template["index_patterns"] == ["windows-apt-events-*"]
    assert template["template"]["settings"] == {"number_of_shards": 1, "number_of_replicas": 0}
    assert requests[-1] == (f"/{INDEX}", {}, {"method": "PUT"})
    saved = load_json(tmp_path / "elasticsearch/templates/windows-apt-events-template.json")
    assert saved == template
    returned = copy.deepcopy(template)
    returned.update(composed_of=[], created_date_millis=1, modified_date_millis=2)
    returned["template"]["settings"] = {
        "index": {"number_of_shards": "1", "number_of_replicas": "0"}
    }
    assert validation.template_matches(returned, template)
    returned["template"]["mappings"]["dynamic"] = True
    assert not validation.template_matches(returned, template)


def test_normal_ingestion_does_not_reset_a_conflicting_mapping(tmp_path):
    mapping = {"dynamic": "strict", "properties": {"@timestamp": {"type": "date_nanos"}}}
    save_json(tmp_path / "dataset/processed/elastic-mapping.json", mapping)
    calls = []

    def client(path, body=None, **kwargs):
        calls.append(kwargs.get("method"))
        return {INDEX: {"mappings": {}}} if path.endswith("/_mapping") else {}

    with pytest.raises(ValueError, match="Existing index mapping differs"):
        ingest.install_template(tmp_path, client)
    assert "DELETE" not in calls


@pytest.mark.parametrize("actual", [102010, 102012, 204022])
def test_count_comparison_detects_loss_and_duplicate_inflation(actual):
    assert not validation.comparison(102011, actual)["passed"]
    assert validation.comparison(102011, 102011)["passed"]


def test_timestamp_comparison_allows_only_insignificant_spelling_change():
    base = {"@timestamp": "2025-01-01T01:00:00.1234000Z", "original": {"x": "  value  "}}
    assert validation.evidence_equal(base, base | {"@timestamp": "2025-01-01T01:00:00.123400Z"})
    assert not validation.evidence_equal(
        base, base | {"@timestamp": "2025-01-01T01:00:00.1234001Z"}
    )
    assert not validation.evidence_equal(base, base | {"original": {"x": "value"}})
    assert not validation.evidence_equal(
        {"event": {}}, {"event": {}, "@timestamp": base["@timestamp"]}
    )


def test_source_spot_checks_verify_ids_metadata_and_indexed_nanoseconds():
    expected = {
        "event": {"id": "a" * 64},
        "@timestamp": "2025-01-01T00:00:00.123456789Z",
        "windows_apt": {
            "provenance": {"source_file": "test.csv", "source_row_index": 0},
            "annotations": {},
            "scenario": {},
            "quality": {},
            "original": {"literal.dotted": "  C:\\example  "},
        },
    }

    def client(path, body=None, **kwargs):
        assert body.get("ids", body.get("query", {}).get("ids", {}).get("values")) == ["a" * 64]
        if path.endswith("/_mget"):
            return {"docs": [{"_id": "a" * 64, "_source": expected}]}
        return {"hits": {"hits": [{"_id": "a" * 64, "fields": {"@timestamp": [date]}}]}}

    date = expected["@timestamp"]
    assert validation.spot_checks({"nanoseconds": expected}, client)[0]["passed"]
    date = "2025-01-01T00:00:00.123Z"
    assert not validation.spot_checks({"nanoseconds": expected}, client)[0]["passed"]


def test_unresolved_query_requires_absence_of_timestamp():
    query = validation.representative_queries()["unresolved_timestamp"]["query"]
    assert query["bool"]["filter"] == [
        {"term": {"windows_apt.quality.timestamp": "unresolved"}},
        {"bool": {"must_not": [{"exists": {"field": "@timestamp"}}]}},
    ]


@pytest.mark.parametrize("actual,passed", [(101, True), (100, False), (202, False)])
def test_live_validator_fails_when_elasticsearch_count_differs(
    tmp_path, monkeypatch, actual, passed
):
    # Tiny synthetic API fixture; these values are never analytical evidence.
    summary = {
        "counts": {"processed_events": 101},
        "ecs_fields_populated": {"@timestamp": 90},
        "timestamp_quality": {"explicit_utc": 90, "unresolved": 11, "validated_fallback": 0},
        "enrichment": {"attack_annotated_events": 63, "scenario_enriched_events": 101},
        "scenario_strengths": {"UNRESOLVED": 6, "SHARED-WEAK": 95},
    }
    mapping = {"dynamic": "strict", "properties": {"@timestamp": {"type": "date_nanos"}}}
    save_json(tmp_path / "dataset/processed/elastic-mapping.json", mapping)
    events_path = tmp_path / "dataset/processed/windows-apt-events.ndjson"
    events_path.write_text("")
    save_json(tmp_path / "analysis/preprocessing_summary.json", summary)
    manifest = {
        "processed_output_sha256": {
            "elastic-mapping.json": digest(tmp_path / "dataset/processed/elastic-mapping.json"),
            "windows-apt-events.ndjson": digest(events_path),
        },
        "report_sha256": {
            "preprocessing_summary.json": digest(tmp_path / "analysis/preprocessing_summary.json")
        },
    }
    save_json(tmp_path / "analysis/normalization-manifest.json", manifest)
    observation = {
        "phase3_manifest_sha256": digest(tmp_path / "analysis/normalization-manifest.json"),
        "run_id": "fixture",
        "phase3_verification": {},
        "ingestion_seconds": 1,
        "index_count_before": 0,
    }
    monkeypatch.setattr(validation, "choose_samples", lambda path: {})
    monkeypatch.setattr(
        validation,
        "spot_checks",
        lambda *args: [
            {
                "category": "fixture",
                "source_row_index": 0,
                "source_exact_equal": True,
                "passed": True,
            }
        ],
    )
    pipeline = {
        "events": {"in": 101, "out": 101},
        "plugins": {
            "outputs": [
                {"id": "phase4_rejects", "events": {"in": 0}},
                {"id": "phase4_elasticsearch", "documents": {"successes": 101}},
            ]
        },
        "dead_letter_queue": {
            "queue_size_in_bytes": 1,
            "last_error": "no errors",
            "dropped_events": 0,
            "expired_events": 0,
        },
    }
    monkeypatch.setattr(
        validation,
        "service_json",
        lambda service, path: (
            {"version": {"number": "test"}, "status": {"overall": {"level": "available"}}}
            if service == "kibana"
            else {"version": "test", "status": "green", "pipelines": {"main": pipeline}}
        ),
    )

    def client(path, body=None, **kwargs):
        if path.endswith("/_search"):
            counts = dict.fromkeys(body["aggs"]["coverage"]["filters"]["filters"], 101)
            counts.update(
                {
                    "ecs:@timestamp": 90,
                    "quality:explicit_utc": 90,
                    "quality:unresolved": 11,
                    "quality:validated_fallback": 0,
                    "missing_timestamp": 11,
                    "unresolved_with_timestamp": 0,
                    "query:attack_annotation": 63,
                    "assigned_scenario": 95,
                    "scenario_strength:UNRESOLVED": 6,
                    "scenario_strength:SHARED-WEAK": 95,
                }
            )
            return {
                "hits": {"total": {"value": actual}},
                "_shards": {"failed": 0},
                "aggregations": {
                    "coverage": {"buckets": {k: {"doc_count": v} for k, v in counts.items()}},
                    "time_range": {},
                },
            }
        if path.endswith("/_mapping"):
            return {INDEX: {"mappings": mapping}}
        if path.startswith("/_index_template/"):
            template = ingest.build_template(mapping)
            template["template"]["settings"] = {
                "index": {"number_of_shards": "1", "number_of_replicas": "0"}
            }
            return {"index_templates": [{"index_template": template}]}
        if path.endswith("/_settings"):
            return {
                INDEX: {"settings": {"index": {"number_of_shards": "1", "number_of_replicas": "0"}}}
            }
        if path == "/":
            return {"version": {"number": "test"}}
        if path.startswith("/_cluster/health/"):
            return {"status": "green"}
        if path.endswith("/_stats/docs,store"):
            return {"indices": {INDEX: {"total": {"store": {"size_in_bytes": 1}}}}}
        return {}

    result = validation.validate(root=tmp_path, observation=observation, client=client)
    assert result["passed"] is passed
    assert result["event_count"] == {"expected": 101, "actual": actual, "passed": passed}
    assert (
        json.loads((tmp_path / "analysis/ingestion/ingestion-validation.json").read_text())[
            "passed"
        ]
        is passed
    )
    original_path = tmp_path / "analysis/ingestion/ingestion-validation.json"
    original_path.write_text('{"retained": "immutable Phase 4 evidence"}')
    retained = original_path.read_bytes()
    destination = tmp_path / "analysis/detections/prerequisites"
    replay = validation.validate(
        root=tmp_path, observation=observation, client=client, output_directory=destination
    )
    assert replay["passed"] is passed
    assert original_path.read_bytes() == retained
    assert (destination / "ingestion-validation.json").is_file()
    assert (destination / "ingestion-report.md").is_file()
