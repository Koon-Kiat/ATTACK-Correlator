"""Safe fixtures for Phase 3 contracts, including losslessness and invalid input paths."""

import copy
import csv
import json

import pytest
from test_evidence_inventory import tiny_release, write_csv

from src.preprocessing.clean import (
    boolean,
    csv_rows,
    guid,
    integer,
    ip,
    original_fields,
    port,
    restore_row,
    utc_timestamp,
    windows_path,
)
from src.preprocessing.elastic_contract import mapping_contract, validate_document
from src.preprocessing.evidence_inventory import fingerprint_files, generate
from src.preprocessing.normalize import SECURITY, SYSMON, normalize, parse_hashes
from src.preprocessing.preprocess import digest, preprocess, verify_sources
from src.preprocessing.verify_processed import verify_processed
from src.preprocessing.windows_fields import P, S


def sample(code="1"):
    return {
        "_index": "safe-fixture",
        "_id": "0001",
        "_source.agent.id": "003",
        S + "providerName": SYSMON,
        S + "eventID": code,
        S + "systemTime": "2024-12-01T06:24:26.902929700Z",
        P + "image": r"C:\Windows\notepad.exe",
        P + "processId": "0x220",
        P + "processGuid": "{D8AF36FB-011B-674C-6A00-000000000A00}",
        P + "parentProcessId": "00123",
        P + "parentImage": '"C:\\Windows\\Explorer.EXE"',
        P + "commandLine": '"notepad.exe" "notes.txt"',
        P + "user": r"LAB\Alice",
        P + "targetUserName": "Bob",
        P + "subjectUserName": "Carol",
        "_source.@timestamp": "Dec 1, 2024 @ 06:24:27.000",
    }


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2024-12-01T06:24:26.902929700Z", "2024-12-01T06:24:26.902929700Z"),
        ("2024-12-01T14:24:26.123456789+08:00", "2024-12-01T06:24:26.123456789Z"),
        ("2024-12-01T06:24:26Z", "2024-12-01T06:24:26Z"),
    ],
)
def test_timestamp_preserves_nanos_and_explicit_timezone(value, expected):
    assert utc_timestamp(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "45627.26699",
        "24:27.7",
        "2024-12-01T06:24:26",
        "2024-02-30T00:00:00Z",
        "2024-12-01T06:24:26.1234567890Z",
        "2024-12-01T06:24:26+08:99",
        "1900-01-01T00:00:00Z",
    ],
)
def test_ambiguous_invalid_or_out_of_range_timestamp_not_guessed(value):
    with pytest.raises(ValueError):
        utc_timestamp(value)
    row = sample()
    row[S + "systemTime"] = value
    row[P + "utcTime"] = "45627.26699"
    event = normalize(row)
    assert "@timestamp" not in event
    assert event["windows_apt"]["quality"]["timestamp"] == "unresolved"


@pytest.mark.parametrize(
    "value,name",
    [
        (r"C:\Windows\NOTEPAD.EXE", "NOTEPAD.EXE"),
        (r"C:\\Windows\\notepad.exe", "notepad.exe"),
        ('"C:\\Program Files\\Editor\\editor.exe"', "editor.exe"),
        (r"\"C:\Windows\notepad.exe\"", "notepad.exe"),
        (r"\\server\share\editor.exe", "editor.exe"),
        ("notepad.exe", "notepad.exe"),
        ("System", "System"),
    ],
)
def test_windows_executable_names(value, name):
    executable, actual = windows_path(value, True)
    assert actual == name
    if value == "System":
        assert executable is None


@pytest.mark.parametrize(
    "value",
    [
        "cmd.exe /c notes.txt",
        r"C:editor.exe",
        r"relative\editor.exe",
        r"HKLM\Software\test",
        "C:\\bad\x00.exe",
        '"C:\\bad.exe',
        r"C:\editor.exe:stream",
    ],
)
def test_invalid_executable_paths_are_not_guessed(value):
    with pytest.raises(ValueError):
        windows_path(value, True)


def test_numeric_identity_and_guid_policies():
    assert integer("0x220", 2**32 - 1) == 544
    assert integer("0007", 2**32 - 1) == 7
    assert port("00080") == 80
    assert port("65535") == 65535
    for value in ["65536", "-1", "80.0", "0x50", "true"]:
        with pytest.raises(ValueError):
            port(value)
    for value in ["-1", "1e3", "4294967296"]:
        with pytest.raises(ValueError):
            integer(value, 2**32 - 1)
    raw = sample()[P + "processGuid"]
    assert guid(raw) == raw
    with pytest.raises(ValueError):
        guid("{00000000-0000-0000-0000-000000000000}")
    event = normalize(sample())
    assert event["agent"]["id"] == "003"
    assert event["process"]["pid"] == 544
    assert event["process"]["parent"]["pid"] == 123
    assert event["process"]["entity_id"] == raw


def test_network_types_and_warnings():
    assert ip("2001:0db8::1") == "2001:db8::1"
    for value in ["999.1.1.1", "1.2.3.4/24", "fe80::1%eth0", "010.1.1.1"]:
        with pytest.raises(ValueError):
            ip(value)
    assert boolean("FALSE") is False
    with pytest.raises(ValueError):
        boolean("1")
    row = sample("3")
    row.update(
        {
            P + "sourceIp": "999.1.1.1",
            P + "sourcePort": "65536",
            P + "destinationIp": "::1",
            P + "destinationPort": "443",
            P + "protocol": "TCP",
            P + "initiated": "TRUE",
            P + "processId": "invalid",
        }
    )
    event = normalize(row)
    assert "source" not in event
    assert event["destination"] == {"ip": "::1", "port": 443}
    assert event["network"]["transport"] == "tcp"
    assert event["windows_apt"]["observed"]["flags"]["initiated"] is True
    warnings = event["windows_apt"]["quality"]["normalization_warnings"]
    assert {w["code"] for w in warnings} >= {
        "invalid_source_ip",
        "invalid_source_port",
        "invalid_process_pid",
    }
    assert row[P + "sourceIp"] == "999.1.1.1"


def test_provider_roles_and_registry_file_dns_separation():
    row = sample("13")
    row.update(
        {
            P + "targetObject": r"HKLM\Software\Fixture",
            P + "targetFilename": r"HKLM\Software\Fixture",
        }
    )
    event = normalize(row)
    assert event["registry"]["path"] == row[P + "targetObject"]
    assert "file" not in event
    assert event["user"] == {"name": "Alice", "domain": "LAB"}
    row[S + "providerName"] = SECURITY
    row[S + "processID"] = "1234"
    event = normalize(row)
    assert "process" not in event and "registry" not in event
    assert event["user"]["name"] == "Carol"
    assert "Bob" not in event["user"].values()
    row = sample("11")
    row[P + "targetFilename"] = r"C:\Temp\notes.txt"
    assert normalize(row)["file"]["path"] == row[P + "targetFilename"]
    row = sample("22")
    row[P + "queryName"] = "example.test"
    assert normalize(row)["dns"]["question"]["name"] == "example.test"
    row[S + "eventID"] = "1"
    assert "dns" not in normalize(row)
    row[P + "ipAddress"] = "127.0.0.1"
    row[P + "ipPort"] = "42"
    assert "source" not in normalize(row)


def test_hash_object_semantics_and_conflicts():
    value = "MD5=" + "A" * 32 + ",SHA256=" + "B" * 64 + ",IMPHASH=" + "C" * 32
    hashes, warnings = parse_hashes(value)
    assert hashes == {"md5": "a" * 32, "sha256": "b" * 64} and warnings == []
    row = sample()
    row[P + "hashes"] = value
    assert normalize(row)["process"]["hash"] == hashes
    row[S + "eventID"] = "7"
    assert normalize(row)["dll"]["hash"] == hashes
    assert "hash" not in normalize(row).get("file", {})
    row[S + "eventID"] = "11"
    assert "hash" not in normalize(row).get("process", {})
    parsed, warnings = parse_hashes("MD5=" + "A" * 32 + ",MD5=" + "B" * 32 + ",SHA256=bad")
    assert parsed == {}
    assert set(warnings) == {"conflicting_hash_values", "invalid_hash"}


def test_access_actor_security_process_and_dns_client_contexts():
    row = sample("10")
    row.update(
        {
            P + "sourceImage": r"C:\Windows\notepad.exe",
            P + "sourceProcessId": "0x220",
            P + "sourceProcessGUID": sample()[P + "processGuid"],
            P + "sourceUser": r"LAB\Actor",
            P + "targetUser": r"LAB\Target",
        }
    )
    event = normalize(row)
    assert event["process"]["name"] == "notepad.exe" and event["process"]["pid"] == 544
    assert event["user"]["name"] == "Actor"
    row[P + "sourceProcessGuid"] = "{15959494-69E3-674D-6102-000000001200}"
    assert "entity_id" not in normalize(row)["process"]
    row = sample("4624")
    row[S + "providerName"] = SECURITY
    row[P + "processName"] = r"C:\Windows\services.exe"
    assert normalize(row)["process"]["pid"] == 544
    row[P + "processId"] = "0x0"
    assert "pid" not in normalize(row)["process"]
    row = {
        S + "providerName": "Microsoft-Windows-DNS-Client",
        S + "eventID": "1014",
        P + "queryName": "example.test",
    }
    assert normalize(row)["dns"]["question"]["name"] == "example.test"
    row[S + "providerName"] = "Microsoft-Windows-Security-SPP"
    assert "dns" not in normalize(row)


def test_original_values_round_trip_and_controls():
    row = sample()
    row.update({"empty": "", "space": " ", "literal": "null", "extra": "x\x00y\n"})
    before = copy.deepcopy(row)
    assert restore_row(original_fields(row), list(row)) == row
    event = normalize(row)
    assert row == before
    assert event["process"]["command_line"] == row[P + "commandLine"]
    assert any(
        w["code"] == "control_characters_preserved_in_original"
        for w in event["windows_apt"]["quality"]["normalization_warnings"]
    )
    validate_document(event)
    with pytest.raises(ValueError):
        validate_document({"unexpected": "field"})
    assert mapping_contract()["properties"]["@timestamp"]["type"] == "date_nanos"


def test_csv_recoverable_reject_preserves_extra_values(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("_index,_id,value\nfixture,1,ok,extra\nfixture,2,ok\n")
    rows = list(csv_rows(path))
    assert rows[0][-1] and rows[0][-2][-1] == "extra"
    assert rows[0][1] == 0 and rows[1][1] == 1 and rows[1][-1] is None


def phase2_fixture(tmp_path, missing_id=False):
    raw, analysis = tmp_path / "raw", tmp_path / "analysis"
    events = tiny_release(raw)
    if missing_id:
        events[0]["_id"] = ""
        write_csv(raw / "period.csv", events)
    generate(raw, analysis)
    return raw, analysis, tmp_path / "processed"


def test_full_pipeline_conservation_provenance_annotations_and_reproducibility(tmp_path):
    raw, analysis, output = phase2_fixture(tmp_path)
    before = fingerprint_files(raw)
    summary = preprocess(raw, output, analysis)
    assert summary["counts"]["input_events"] == summary["counts"]["processed_events"] == 2
    assert summary["counts"]["rejected_events"] == 0
    assert summary["enrichment"]["mapping_join_matches"] == 2
    records = [
        json.loads(line) for line in (output / "windows-apt-events.ndjson").read_text().splitlines()
    ]
    headers = json.loads((output / "source-schemas.json").read_text())["headers"]
    for i, event in enumerate(records):
        custom = event["windows_apt"]
        prov = custom["provenance"]
        assert prov["source_file"] == "period.csv" and prov["source_row_index"] == i
        assert prov["original_id"] == str(i) and prov["original_index"] == "software-test"
        assert custom["annotations"]["attack"]["ids"] == [f"T9999.00{i + 1}"]
        assert custom["scenario"]["attribution_strength"] == "NARROWED"
        assert "threat" not in event and "rule" not in event
        assert len(restore_row(custom["original"], headers["period.csv"])) == len(
            headers["period.csv"]
        )
        validate_document(event)
    hashes = fingerprint_files(output)
    reports = {p.name: digest(p) for p in analysis.glob("preprocessing*")}
    manifest = digest(analysis / "normalization-manifest.json")
    assert preprocess(raw, output, analysis) == summary
    assert fingerprint_files(output) == hashes
    assert {p.name: digest(p) for p in analysis.glob("preprocessing*")} == reports
    assert digest(analysis / "normalization-manifest.json") == manifest
    assert fingerprint_files(raw) == before
    assert not (output / "rejected-events.ndjson").exists()
    assert verify_processed(raw, output, analysis)["all_original_rows_reconstructed"]


def test_missing_identity_produces_explicit_reject(tmp_path):
    raw, analysis, output = phase2_fixture(tmp_path, True)
    summary = preprocess(raw, output, analysis)
    assert summary["counts"]["input_events"] == 2
    assert summary["counts"]["processed_events"] == summary["counts"]["rejected_events"] == 1
    reject = json.loads((output / "rejected-events.ndjson").read_text())
    assert reject["provenance"]["source_row_index"] == 0
    assert reject["rejection_reason"] == "missing_source_identity"
    assert reject["parsing_error"] and reject["original_fields"]["_id"] == ""
    assert verify_processed(raw, output, analysis)["rejected_events"] == 1


def test_source_hash_guard_stops_before_writing(tmp_path):
    raw, analysis, output = phase2_fixture(tmp_path)
    (raw / "period.csv").write_text("changed")
    with pytest.raises(ValueError, match="source hash mismatch"):
        preprocess(raw, output, analysis)
    assert not output.exists()
    with pytest.raises(ValueError, match="separate"):
        preprocess(raw, raw / "processed", analysis)


def test_additional_raw_file_and_phase2_artifact_change_are_rejected(tmp_path):
    raw, analysis, output = phase2_fixture(tmp_path)
    expected = fingerprint_files(raw)
    (raw / "extra.txt").write_text("new")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_sources(raw, expected)
    (analysis / "attack_evidence.json").write_text("{}")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        preprocess(raw, output, analysis)


def test_duplicate_rows_retained_and_tampered_output_rejected(tmp_path):
    raw, analysis, output = tmp_path / "raw", tmp_path / "analysis", tmp_path / "processed"
    events = tiny_release(raw)
    write_csv(raw / "period.csv", [events[0], events[0]])
    mapping_path = raw / "scenario_mapping_supplement/log_to_scenario_mapping.csv"
    with mapping_path.open(encoding="utf-8", newline="") as stream:
        mappings = list(csv.DictReader(stream))
    mappings[1] = dict(mappings[0], Row_Index="1")
    write_csv(mapping_path, mappings)
    generate(raw, analysis)
    summary = preprocess(raw, output, analysis)
    assert summary["counts"]["processed_events"] == 2
    assert summary["counts"]["exact_duplicate_documents"] == 1
    assert summary["counts"]["distinct_source_identities"] == 1
    assert verify_processed(raw, output, analysis)["all_rows_accounted_for"]
    with (output / "windows-apt-events.ndjson").open("ab") as stream:
        stream.write(b"{}\n")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        verify_processed(raw, output, analysis)


def test_verifier_report_cannot_target_raw(tmp_path):
    with pytest.raises(ValueError, match="outside the raw"):
        verify_processed(tmp_path / "raw", tmp_path / "processed", tmp_path / "raw/analysis")
