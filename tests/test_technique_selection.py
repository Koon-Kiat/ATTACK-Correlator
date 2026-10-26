import copy

import pytest

from scripts.elastic_local import ROOT, load_json
from scripts.inspect_selection_relationships import inspect, nanos, parent_pairs
from scripts.inspect_technique_candidates import fetch_events, probes, query_probe
from scripts.verify_technique_selection import (
    check_predicate,
    check_selection,
    compare_projection,
    projections,
)


def event(event_id, guid, parent_guid=None, name="cmd.exe", time="2024-01-01T00:00:00Z"):
    return {
        "event": {"id": event_id, "provider": "Microsoft-Windows-Sysmon", "code": "1"},
        "@timestamp": time,
        "host": {"name": "TEST-HOST"},
        "process": {
            "name": name,
            "entity_id": guid,
            "command_line": name,
            "parent": {"entity_id": parent_guid},
        },
        "windows_apt": {},
    }


def test_nanos_preserves_submicrosecond_order_and_padding():
    assert nanos("2024-01-01T00:00:00.123456789Z") - nanos("2024-01-01T00:00:00Z") == 123456789
    assert nanos("2024-01-01T00:00:00.1Z") == nanos("2024-01-01T00:00:00.100000000Z")
    assert nanos(None) is None
    assert nanos("1969-12-31T23:59:59.999999999Z") == -1


@pytest.mark.parametrize(
    "value",
    [
        "2024-01-01",
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:00.1234567890Z",
        "2024-02-30T00:00:00Z",
    ],
)
def test_nanos_refuses_ambiguous_or_invalid_timestamps(value):
    with pytest.raises(ValueError):
        nanos(value)


def test_parent_join_requires_host_guid_time_and_distinct_documents():
    parent = event("p", "GUID")
    child = event("c", "child", "guid", time="2024-01-01T00:01:00Z")
    assert parent_pairs([parent, child], 60)[0][2] == 60 * 10**9
    for field, value in (
        ("host", {"name": "OTHER"}),
        ("@timestamp", None),
        ("@timestamp", "2023-12-31T23:59:59Z"),
        ("@timestamp", "2024-01-01T00:01:00.000000001Z"),
    ):
        altered = copy.deepcopy(child)
        altered[field] = value
        assert not parent_pairs([parent, altered], 60)
    child["process"]["parent"]["entity_id"] = None
    assert not parent_pairs([parent, child], 60)
    parent["process"]["parent"]["entity_id"] = "GUID"
    assert not parent_pairs([parent], 60)


def test_duplicate_document_fails_and_duplicate_identity_does_not_hide_parent():
    parent = event("p", "GUID")
    child = event("c", "child", "GUID", time="2024-01-01T00:00:01Z")
    later = event("later", "GUID", time="2024-01-01T00:00:02Z")
    pairs = parent_pairs([parent, later, child], 60)
    assert [(p["event"]["id"], c["event"]["id"]) for p, c, _ in pairs] == [("p", "c")]
    with pytest.raises(ValueError, match="Duplicate event"):
        parent_pairs([parent, parent], 60)
    with pytest.raises(ValueError, match="negative"):
        parent_pairs([], -1)


def service_fixture():
    shell = event("shell", "SHELL")
    shell["process"]["parent"]["name"] = "services.exe"
    shell["process"]["command_line"] = r"C:\Windows\cmd.exe /c echo fixture"
    ps = event("ps", "PS", "SHELL", "powershell.exe", "2024-01-01T00:00:00.000000001Z")
    service = {
        "event": {"id": "service", "provider": "Service Control Manager", "code": "7045"},
        "@timestamp": "2024-01-01T00:00:00Z",
        "host": {"name": "test-host"},
        "windows_apt": {
            "original": {
                "_source.data.win.eventdata.imagePath": r"C:\\Windows\\cmd.exe /c echo fixture",
            }
        },
    }
    return [shell, ps], [service]


def test_service_join_requires_full_object_command_and_explicit_ordered_time():
    events, services = service_fixture()
    result = inspect(events, services)
    chain = result["service_shell_powershell_chains"][0]
    assert chain["gaps_nanoseconds"] == [0, 1]
    assert chain["event_ids"] == ["service", "shell", "ps"]
    for timestamp in (None, "2024-01-01T00:00:01Z"):
        altered = copy.deepcopy(services)
        altered[0]["@timestamp"] = timestamp
        assert not inspect(events, altered)["service_shell_powershell_chains"]
    services[0]["windows_apt"]["original"]["_source.data.win.eventdata.imagePath"] = (
        r"D:\different\cmd.exe /c echo fixture"
    )
    assert not inspect(events, services)["service_shell_powershell_chains"]


def test_context_does_not_change_pair_or_chain_membership():
    events, services = service_fixture()
    original = inspect(events, services)
    for item in events + services:
        item["windows_apt"]["annotations"] = {"attack": {"ids": ["T9999.999"]}}
        item["windows_apt"]["scenario"] = {"id": "unrelated"}
    changed = inspect(events, services)
    assert changed["window_pair_counts"] == original["window_pair_counts"]
    assert changed["service_shell_powershell_chains"][0]["event_ids"] == ["service", "shell", "ps"]
    for predicate in probes().values():
        check_predicate(predicate)
    with pytest.raises(ValueError, match="Contextual"):
        check_predicate({"term": {"windows_apt.annotations.attack.ids": "T1059.001"}})
    with pytest.raises(ValueError, match="Contextual"):
        check_predicate({"exists": {"field": "windows_apt.scenario.id"}})


def test_readback_refuses_incomplete_counts_and_repeated_pages():
    result = {
        "_shards": {"failed": 0},
        "hits": {"total": {"value": 1, "relation": "gte"}, "hits": []},
        "aggregations": {"with_timestamp": {"doc_count": 1}},
    }
    with pytest.raises(ValueError, match="exact"):
        query_probe({}, lambda *args, **kwargs: result)
    result["hits"]["total"]["relation"] = "eq"
    result["aggregations"]["with_timestamp"]["doc_count"] = 2
    with pytest.raises(ValueError, match="timestamp count"):
        query_probe({}, lambda *args, **kwargs: result)
    result["hits"]["hits"] = [{"_source": event("x", "X"), "sort": ["x"]}]
    with pytest.raises(ValueError, match="Duplicate event"):
        fetch_events({}, lambda *args, **kwargs: result)
    result["_shards"]["failed"] = 1
    with pytest.raises(ValueError, match="Incomplete"):
        fetch_events({}, lambda *args, **kwargs: result)


def test_projection_compares_nested_originals_and_exact_command_evidence():
    expected = {
        "event": {"id": "id"},
        "@timestamp": "2024-01-01T00:00:00.1Z",
        "windows_apt": {"original": {"literal.key": "preserved"}},
    }
    actual = copy.deepcopy(expected)
    actual["@timestamp"] = "2024-01-01T00:00:00.100000000Z"
    actual["extra"] = True
    compare_projection(expected, actual)
    assert list(projections({"examples": [{"_source": expected}]})) == [expected]
    actual["windows_apt"]["original"]["literal.key"] = "changed"
    with pytest.raises(ValueError, match="mismatch"):
        compare_projection(expected, actual)


def test_selection_rejects_parent_ids_and_count_drift():
    selection = load_json(ROOT / "analysis/technique_selection.json")
    queries = load_json(ROOT / "analysis/selection/exploratory-queries.json")
    check_selection(selection, queries)
    altered = copy.deepcopy(selection)
    altered["selected"][0]["attack_id"] = "T1059"
    with pytest.raises(ValueError, match="three distinct"):
        check_selection(altered, queries)
    selection["selected"][0]["primary_cohort"]["count"] += 1
    with pytest.raises(ValueError, match="cohort differs"):
        check_selection(selection, queries)
