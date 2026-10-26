"""Synthetic software fixtures; no events are ingested and no commands are executed."""

import copy
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from scripts.elastic_local import ROOT, load_json
from scripts.run_correlation import (
    SERVICE_IMAGE,
    chain_record,
    check_contract,
    correlation_id,
    endpoint_census,
    eql_body,
    eql_pairs,
    event_lookup,
    exclusion_reasons,
    guard_predicate,
    guid_key,
    lineage_pairs,
    refine_pairs,
    service_chains,
    time_ns,
    tuple_summary,
    verify_eql_endpoints,
)
from scripts.run_individual_detections import observed_conditions, source_matches

ACTOR = "{AAAAAAAA-BBBB-CCCC-DDDD-000000000001}"
CHILD = "{AAAAAAAA-BBBB-CCCC-DDDD-000000000002}"


def timestamp(seconds=0, ns=0):
    dt = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ns:09}Z"


def fixture(event_id="shell", name="cmd.exe", seconds=0, ns=0):
    return {
        "event": {"id": event_id, "provider": "Microsoft-Windows-Sysmon", "code": "1"},
        "host": {"name": "TEST-HOST"},
        "@timestamp": timestamp(seconds, ns),
        "process": {
            "name": name,
            "entity_id": ACTOR,
            "command_line": r"C:\Windows\cmd.exe /c powershell.exe -Command Get-Date",
            "parent": {"name": "services.exe", "entity_id": CHILD},
        },
        "windows_apt": {
            "provenance": {"source_file": "software-fixture.csv", "source_row_index": 0}
        },
    }


def pair(seconds=1, ns=0):
    shell = fixture()
    ps = fixture("ps", "powershell.exe", seconds, ns)
    ps["process"].update(
        {
            "entity_id": CHILD,
            "command_line": "powershell.exe -nop -w hidden -c Get-Date",
            "parent": {"name": "cmd.exe", "entity_id": ACTOR.lower()},
        }
    )
    return shell, ps


@pytest.mark.parametrize("window", [60, 300, 900])
def test_exact_upper_boundary_included_and_one_nanosecond_later_excluded(window):
    shell, ps = pair(window)
    assert lineage_pairs([shell], [ps], window) == [("shell", "ps")]
    ps["@timestamp"] = timestamp(window, 1)
    assert lineage_pairs([shell], [ps], window) == []
    assert lineage_pairs([shell], [ps], None) == [("shell", "ps")]


@pytest.mark.parametrize(
    "seconds,expected", [(59, [1, 1, 1]), (61, [0, 1, 1]), (301, [0, 0, 1]), (901, [0, 0, 0])]
)
def test_all_windows_use_identical_semantics(seconds, expected):
    shell, ps = pair(seconds)
    assert [len(lineage_pairs([shell], [ps], w)) for w in (60, 300, 900)] == expected


def test_order_is_strict_and_submillisecond_order_is_preserved():
    shell, ps = pair(0)
    assert not lineage_pairs([shell], [ps], 60)
    ps["@timestamp"] = timestamp(0, 1)
    assert lineage_pairs([shell], [ps], 60)
    shell["@timestamp"] = timestamp(0, 2)
    assert not lineage_pairs([shell], [ps], 60)


@pytest.mark.parametrize(
    "change", ["other_host", "host_case", "other_guid", "missing_guid", "missing_host"]
)
def test_host_and_guid_ancestry_cannot_be_replaced_by_time(change):
    shell, ps = pair()
    if change == "other_host":
        ps["host"]["name"] = "OTHER"
    elif change == "host_case":
        ps["host"]["name"] = "test-host"
    elif change == "other_guid":
        ps["process"]["parent"]["entity_id"] = CHILD
    elif change == "missing_guid":
        del ps["process"]["parent"]["entity_id"]
    else:
        del ps["host"]
    assert not lineage_pairs([shell], [ps], 60)


def test_guid_normalizes_case_only_and_preserves_evidence():
    shell, ps = pair()
    assert lineage_pairs([shell], [ps], 60) == [("shell", "ps")]
    assert shell["process"]["entity_id"] == ACTOR
    assert guid_key(ACTOR) == ACTOR.lower()
    ps["process"]["parent"]["entity_id"] = ACTOR.strip("{}")
    assert not lineage_pairs([shell], [ps], 60)
    assert guid_key("{00000000-0000-0000-0000-000000000000}") is None
    assert guid_key("not-a-guid") is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "2024-01-01",
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:00.1234567890Z",
        "not a time",
        1234,
    ],
)
def test_only_explicit_valid_utc_times_participate(value):
    shell, ps = pair()
    ps["@timestamp"] = value
    assert time_ns(ps) is None
    assert not lineage_pairs([shell], [ps], 60)
    shell["@timestamp"] = value
    ps["@timestamp"] = timestamp(1)
    assert not lineage_pairs([shell], [ps], 60)


@pytest.mark.parametrize("window", [0, -1, 1.5, True])
def test_invalid_windows_rejected(window):
    with pytest.raises(ValueError, match="positive integer"):
        lineage_pairs([], [], window)


def test_duplicate_source_ids_fail_and_tuple_ids_are_ordered_and_stable():
    shell, ps = pair()
    with pytest.raises(ValueError, match="Duplicate"):
        lineage_pairs([shell, copy.deepcopy(shell)], [ps], 60)
    with pytest.raises(ValueError, match="distinct"):
        correlation_id(["shell", "shell"])
    assert correlation_id(["shell", "ps"]) == hashlib.sha256(b'["shell","ps"]').hexdigest()
    assert correlation_id(["shell", "ps"]) != correlation_id(["ps", "shell"])


def test_full_join_retains_fanout_and_deduplicates_tuples_without_mixing_units():
    shell, ps = pair()
    second_shell = copy.deepcopy(shell)
    second_shell["event"]["id"] = "shell2"
    second_shell["@timestamp"] = timestamp(0, 1)
    second_ps = copy.deepcopy(ps)
    second_ps["event"]["id"] = "ps2"
    second_ps["@timestamp"] = timestamp(2)
    pairs = lineage_pairs([shell, second_shell], [ps, second_ps], 60)
    assert pairs == lineage_pairs([second_shell, shell], [second_ps, ps], 60)
    assert len(pairs) == 4
    summary = tuple_summary(pairs + pairs[:1], event_lookup([shell, ps, second_shell, second_ps]))
    assert summary["tuple_count"] == 4
    assert summary["duplicate_tuples_suppressed"] == 1
    assert summary["unique_participating_events"] == 4
    assert summary["unique_first_events"] == summary["unique_last_events"] == 2
    assert summary["fan_out"]["total_event_participations"] == 8
    assert summary["fan_out"]["first_events_in_multiple_tuples"] == {"shell": 2, "shell2": 2}
    assert summary["unique_host_count"] == 1


def test_refined_endpoint_membership_and_service_origin_branch_are_required():
    shell, ps = pair()
    assert source_matches("shell_refined", shell)
    assert source_matches("powershell_refined", ps)
    assert observed_conditions(shell)["service_parent_interpreter"]
    pairs = lineage_pairs([shell], [ps], 60)
    assert refine_pairs(pairs, {"shell"}, {"ps"}) == pairs
    assert not refine_pairs(pairs, set(), {"ps"})
    assert not refine_pairs(pairs, {"shell"}, set())
    assert exclusion_reasons(pairs[0], {"shell"}, set()) == ["powershell_not_in_phase6_refined_set"]
    shell["process"]["parent"]["name"] = "explorer.exe"
    shell["process"]["command_line"] = 'cmd.exe /c sc config Fixture binPath= "powershell.exe"'
    assert source_matches("shell_refined", shell)
    assert not observed_conditions(shell)["service_parent_interpreter"]


def service_fixture():
    shell, ps = pair(2)
    shell["@timestamp"] = timestamp(1)
    service = fixture("installation")
    service["event"].update({"provider": "Service Control Manager", "code": "7045"})
    del service["process"]
    service["windows_apt"]["original"] = {
        SERVICE_IMAGE: r"  C:\\WINDOWS\\CMD.EXE /C POWERSHELL.EXE -COMMAND GET-DATE  "
    }
    return service, shell, ps


def test_service_source_readback_normalization_and_refined_exclusion_are_separate():
    service, shell, ps = service_fixture()
    lookup = event_lookup([service, shell, ps])
    pairs = lineage_pairs([shell], [ps], 60)
    chains = service_chains([service], pairs, lookup, 60)
    assert chains == [("installation", "shell", "ps")]
    record = chain_record(chains[0], lookup, {"shell"}, set())
    assert not record["satisfies_refined_endpoints"]
    assert record["exclusion_reasons"] == ["powershell_not_in_phase6_refined_set"]
    assert record["gaps_nanoseconds"] == [10**9, 10**9]
    assert record["service_image_path"] == service["windows_apt"]["original"][SERVICE_IMAGE]
    assert record["span_nanoseconds"] == 2 * 10**9


@pytest.mark.parametrize(
    "change", ["host", "object", "missing_object", "provider", "order", "span"]
)
def test_three_event_join_requires_actual_object_and_ordered_total_span(change):
    service, shell, ps = service_fixture()
    if change == "host":
        service["host"]["name"] = "OTHER"
    elif change == "object":
        service["windows_apt"]["original"][SERVICE_IMAGE] += " extra"
    elif change == "missing_object":
        service["windows_apt"].pop("original")
    elif change == "provider":
        service["event"]["provider"] = "Other"
    elif change == "order":
        service["@timestamp"] = timestamp(1)
    else:
        shell["@timestamp"] = timestamp(59)
        ps["@timestamp"] = timestamp(61)
    lookup = event_lookup([service, shell, ps])
    assert not service_chains([service], lineage_pairs([shell], [ps], 60), lookup, 60)


def test_labels_do_not_affect_correlations_or_source_object_association():
    service, shell, ps = service_fixture()
    for record in (service, shell, ps):
        record["windows_apt"].update(
            {"annotations": {"attack": {"id": "T9999.999"}}, "scenario": {"id": "arbitrary"}}
        )
    lookup = event_lookup([service, shell, ps])
    pairs = lineage_pairs([shell], [ps], 60)
    assert service_chains([service], pairs, lookup, 60) == [("installation", "shell", "ps")]
    for query in [
        'windows_apt.scenario.id == "a"',
        'threat.technique.id == "T1059.001"',
        'rule.name == "publisher"',
        "windows_apt.original.imagePath",
        "params._source",
    ]:
        with pytest.raises(ValueError, match="predicates"):
            guard_predicate(query)


def test_committed_query_request_runtime_fields_and_frozen_contracts():
    manifest = load_json(ROOT / "correlation/manifest.json")
    phase6 = load_json(ROOT / "analysis/detections/detection-results.json")
    check_contract(manifest, phase6, ROOT)
    for window in (60, 300, 900):
        body = eql_body(ROOT, "correlation/correlation.eql", window)
        assert f"maxspan={window * 1000 + 1}ms" in body["query"]
        assert body["timestamp_field"] == "correlation.time_ms"
        assert body["tiebreaker_field"] == "correlation.time_ns"
        assert body["allow_partial_search_results"] is False
        assert (
            body["runtime_mappings"]["correlation.actor_guid"]["script"]["params"]["field"]
            == "process.entity_id"
        )
    changed = copy.deepcopy(phase6)
    changed["queries"]["powershell_refined"]["distinct_event_count"] += 1
    with pytest.raises(ValueError, match="count drift"):
        check_contract(manifest, changed, ROOT)


@pytest.mark.parametrize("kind", ["partial", "running", "timeout", "capacity", "uncertain"])
def test_eql_never_accepts_incomplete_or_capped_results(kind):
    response = {
        "is_partial": False,
        "is_running": False,
        "timed_out": False,
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "sequences": [{"events": [{"_id": "s"}, {"_id": "p"}]}],
        },
    }
    if kind == "partial":
        response["is_partial"] = True
    elif kind == "running":
        response["is_running"] = True
    elif kind == "timeout":
        response["timed_out"] = True
    elif kind == "uncertain":
        response["hits"]["total"]["relation"] = "gte"
    with pytest.raises(ValueError):
        eql_pairs({"size": 1 if kind == "capacity" else 1000}, lambda *args, **kwargs: response)


def test_endpoint_census_counts_events_without_assuming_tuple_membership():
    shell, ps = pair()
    rows = endpoint_census([shell, ps])
    assert sum(row["raw_events"] for row in rows) == 2
    assert rows[0]["service_origin"] is True
    ps.pop("@timestamp")
    assert endpoint_census([shell, ps])[1]["timed_events"] == 0


def test_eql_endpoint_verification_requires_exact_ids_not_just_equal_counts():
    expected = {"shell": {"shell"}, "powershell": {"ps"}}

    def client(path, body, method):
        ids = ["shell"] if 'correlation.name_lc == "cmd.exe"' in body["query"] else ["ps"]
        return {
            "is_partial": False,
            "is_running": False,
            "timed_out": False,
            "hits": {"total": {"value": 1, "relation": "eq"}, "events": [{"_id": i} for i in ids]},
        }

    checks = verify_eql_endpoints(ROOT, expected, client)
    assert checks["powershell"]["exact_membership_verified"]
    with pytest.raises(ValueError, match="differs from exact"):
        verify_eql_endpoints(ROOT, expected | {"powershell": {"different"}}, client)
