"""Benign software fixtures with fictional technique IDs; never analytical evidence."""

import csv
import json
from datetime import UTC, datetime, timedelta

import pytest

from src.preprocessing.correlation_inventory import relationships
from src.preprocessing.evidence_inventory import fingerprint_files, generate
from src.preprocessing.inspect_dataset import inspect_dataset
from src.preprocessing.inventory_reports import cell
from src.preprocessing.profile_values import (
    ValueProfile,
    extract_techniques,
    observed_time,
    technique_kind,
)
from src.preprocessing.windows_fields import LABEL, NAMES, TACTICS, P, S


def write_csv(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted(set().union(*(row.keys() for row in records)))
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


def tiny_release(root):
    events = []
    for i, ident in enumerate(["T9999.001", "T9999.002"]):
        events.append(
            {
                "_index": "software-test",
                "_id": str(i),
                "_source.agent.name": "lab",
                "_source.agent.id": "001",
                "_source.id": f"1000.{i}",
                "_source.@timestamp": f"Jan 1, 2025 @ 00:00:0{i}.000",
                S + "computer": "test-host",
                S + "systemTime": f"2025-01-01T00:00:0{i}Z",
                S + "eventID": "1",
                S + "providerName": "software-fixture",
                LABEL: json.dumps([ident]),
                NAMES: json.dumps([f"Fictional software fixture {i}"]),
                TACTICS: '["Test only"]',
                "_source.rule.mitre_techniques": '["T8888.001"]',
                "_source.rule.description": "Benign test application start",
                P + "image": "notepad.exe",
                P + "commandLine": "notepad.exe notes.txt",
                P + "user": "lab-user",
                P + "processGuid": "{00000000-0000-0000-0000-000000000001}",
            }
        )
    write_csv(root / "period.csv", events)
    combined = [dict(row, **{"_source.agent.id": "1"}) for row in events]
    write_csv(root / "combined.csv", combined)
    write_csv(
        root / "scenario_manifest.csv",
        [
            {
                "Scenrario_ID": "S01",
                "Scenario_Name": "Safe fixture",
                "Mitre_Groups": "Fixture",
                "Reported_Origin": "Not real",
                "Simiulated Tactics": "Test only",
                "Simulated Techniques": "T9999.001; T9999.002; T7777",
                "Expected_artifacts": "notes.txt",
                "Reference": "Software test only",
            }
        ],
    )
    write_csv(
        root / "validation_summary.csv",
        [
            {
                "Scenrario_ID": "S01",
                "Scenario_Name": "Safe fixture",
                "Total_runs": "1",
                "Expected_techniques_count": "3",
                "Avg_techniques_succeeded_per_run": "3",
                "Avg_success_ratio": "100%",
                "Anomalies_notes": "Test only",
                "Secondary_reviewed": "No",
                "Validation_checks": "Not real measurements",
            }
        ],
    )
    mapping = [
        {
            "Source_CSV": "period.csv",
            "Row_Index": str(i),
            "Timestamp": row["_source.@timestamp"],
            "Agent_Name": row["_source.agent.name"],
            "MITRE_Technique": row[LABEL],
            "Scenario_ID": "S01",
            "Scenario_Name": "Safe fixture",
            "MITRE_Group_ID": "Fixture",
            "Scenario_Posterior": "S01:1.00",
            "Derived_Label": "technique-tagged",
            "Attribution_Strength": "NARROWED",
            "Mapping_Evidence": "Test only",
            "Candidate_Scenarios": "S01",
        }
        for i, row in enumerate(events)
    ]
    write_csv(root / "scenario_mapping_supplement/log_to_scenario_mapping.csv", mapping)
    return events


def test_attack_token_boundaries_and_parent_classification():
    assert extract_techniques("T1059 T1059.001 [T1110.001] XT1059 T1059.0014 T1059.001.2") == {
        "T1059",
        "T1059.001",
        "T1110.001",
    }
    assert technique_kind("T1059") == "parent-technique"
    assert technique_kind("T1059.001") == "sub-technique"
    with pytest.raises(ValueError):
        technique_kind("TA0001")


def test_extended_timestamp_shapes_do_not_guess_missing_information():
    form, parsed = observed_time("Dec 1, 2024 @ 06:24:28.026")
    assert form == "display_month_day_year_at_time_timezone_unspecified"
    assert parsed == datetime(2024, 12, 1, 6, 24, 28, 26000)
    assert observed_time("2025-01-01T08:00:00+08:00")[1] == datetime(2025, 1, 1, tzinfo=UTC)
    assert observed_time("24:27.7") == ("partial_clock_missing_date_and_hour", None)
    assert observed_time("45627.26699") == ("numeric_time_candidate_units_unresolved", None)
    assert observed_time("11/26/2024 1:41") == ("slash_date_order_and_timezone_unresolved", None)


def test_extended_schema_discovery_nulls_duplicates_and_examples(tmp_path):
    (tmp_path / "nested").mkdir()
    write_csv(tmp_path / "plain.CSV", [{"value": "001", "missing": " "}] * 2)
    (tmp_path / "nested/object.json").write_text('[{"outer":{"x":null},"n":1},{"n":0}]')
    (tmp_path / "nested/notebook.ipynb").write_text('{"cells":[],"metadata":{}}')
    report = inspect_dataset(tmp_path)
    assert len(report["files"]) == 3
    csv_file = next(item for item in report["files"] if item["format"] == "csv")
    assert csv_file["duplicate_records"] == 1
    assert csv_file["fields"]["/value"]["examples"][0]["value"] == "001"
    assert csv_file["fields"]["/missing"]["empty_or_null_records"] == 2
    nested = next(item for item in report["files"] if item["format"] == "json")
    assert nested["fields"]["/outer/x"]["absent_records"] == 1
    assert nested["fields"]["/outer/x"]["empty_or_null_records"] == 1
    assert nested["fields"]["/n"]["distinct_nonempty_values"] == 2


def test_distinct_cap_and_truncated_samples_are_explicit():
    profile = ValueProfile(False, distinct_limit=2)
    for i, value in enumerate(["a" * 300, "b", "c"]):
        profile.add(value, i)
    report = profile.report()
    assert not report["distinct_count_exact"]
    assert report["distinct_nonempty_values"] == 2
    assert report["examples"][0]["truncated"]
    assert len(report["examples"][0]["value"]) == 240


def test_phase2_generation_is_readonly_deterministic_and_separates_references(tmp_path):
    raw, output = tmp_path / "raw", tmp_path / "analysis"
    tiny_release(raw)
    before = fingerprint_files(raw)
    first = generate(raw, output)
    assert first["corpus"]["exported_rows"] == first["corpus"]["coverage_events"] == 2
    assert first["corpus"]["mapping"]["join_checks"] == {"matched_event": 2}
    assert first["corpus"]["combined_positional_identity_matches"] == 2
    assert first["corpus"]["combined_field_difference_counts"] == {"_source.agent.id": 2}
    assert set(first["coverage"]) == {"T9999.001", "T9999.002"}
    assert "T8888.001" in first["mentions"]["technique_identifiers"]
    assert "T7777" in first["mentions"]["technique_identifiers"]
    with (output / "attack_coverage.csv").open(encoding="utf-8", newline="") as stream:
        inventory = {row["attack_id"]: row for row in csv.DictReader(stream)}
    assert json.loads(inventory["T7777"]["manifest_expected_scenarios"]) == ["S01"]
    assert inventory["T7777"]["event_count"] == "0"
    assert len(first["correlation_candidates"]) == 1
    hashes = fingerprint_files(output)
    second = generate(raw, output, reuse_schema=True)
    assert second == first
    assert fingerprint_files(output) == hashes
    assert fingerprint_files(raw) == before


def test_schema_cache_refuses_source_changes(tmp_path):
    raw, output = tmp_path / "raw", tmp_path / "analysis"
    tiny_release(raw)
    generate(raw, output)
    (raw / "new_notes.md").write_text("additional source notes")
    with pytest.raises(ValueError, match="stale"):
        generate(raw, output, reuse_schema=True)


def test_generation_refuses_missing_dataset_and_source_output(tmp_path):
    with pytest.raises(ValueError, match="No raw dataset"):
        generate(tmp_path / "raw", tmp_path / "out")
    with pytest.raises(ValueError, match="separate"):
        generate(tmp_path / "raw", tmp_path / "raw/output")


def event(ident, label, seconds, host="lab", guid="{00000000-0000-0000-0000-000000000001}"):
    return {
        "file": "safe.csv",
        "row_index": ident,
        "line": ident + 2,
        "document_id": str(ident),
        "labels": [label],
        "time": datetime(2025, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
        "host": host,
        "user": "test-user",
        "scenario": "S01",
        "strength": "NARROWED",
        "values": {P + "processGuid": guid},
    }


def test_correlation_requires_distinct_events_host_and_window():
    a, b = event(0, "T9999.001", 0), event(1, "T9999.002", 30)
    candidate = relationships([a, b])[0]
    assert candidate["relations"]["same_actor_process_guid"]["pairs_by_maximum_window_seconds"] == {
        "60": 1,
        "300": 1,
        "900": 1,
    }
    assert relationships([a, event(1, "T9999.002", 30, host="other")]) == []
    assert relationships([a, event(1, "T9999.002", 901)]) == []
    assert relationships([a, event(0, "T9999.002", 30)]) == []
    a["labels"].append("T9999.002")
    assert relationships([a]) == []
    candidate = relationships([a, b])[0]
    assert candidate["co_labelled_eligible_documents"] == 1
    assert candidate["structural_pairs_within_300_seconds"] == 1
    assert candidate["exclusive_structural_pairs_within_300_seconds"] == 0


def test_parent_child_direction_and_missing_keys():
    parent = event(0, "T9999.001", 0)
    child = event(1, "T9999.002", 1, guid="{00000000-0000-0000-0000-000000000002}")
    child["values"][P + "parentProcessGuid"] = parent["values"][P + "processGuid"]
    assert "parent_child_process_guid" in relationships([child, parent])[0]["relations"]
    child["time"] = None
    assert relationships([parent, child]) == []


def test_markdown_examples_are_inert():
    assert cell("<script>|`\n") == "&lt;script&gt;&#124;&#96;\\n"
