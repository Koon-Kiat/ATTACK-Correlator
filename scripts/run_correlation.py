"""Replay individual detections, then validate historical host/GUID/time correlations."""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, load_json, request, save_json  # noqa: E402
from scripts.inspect_selection_relationships import command_key, compact, nanos  # noqa: E402
from scripts.run_individual_detections import (  # noqa: E402
    EVIDENCE_FIELDS,
    esql,
    fetch_evidence,
    field,
    lower,
    observed_conditions,
    source_matches,
)
from scripts.run_individual_detections import (
    run as run_individual,
)
from scripts.verify_technique_selection import require  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402

PATTERN = "windows-apt-events-*"
SERVICE_IMAGE = "_source.data.win.eventdata.imagePath"
GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
INPUT_QUERIES = (
    "shell_baseline",
    "powershell_baseline",
    "service_installation",
    "service_create_baseline",
    "service_config_baseline",
)
REQUIRED_FIELDS = (
    "@timestamp",
    "event.id",
    "event.provider",
    "event.code",
    "host.name",
    "process.name",
    "process.parent.name",
    "process.command_line",
    "process.entity_id",
    "process.parent.entity_id",
)


def sha_json(value):
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def correlation_id(ids):
    require(len(ids) >= 2 and len(set(ids)) == len(ids), "Tuple needs distinct event IDs")
    require(all(isinstance(i, str) and i for i in ids), "Tuple needs nonempty string event IDs")
    return sha_json(list(ids))


def time_ns(event):
    value = event.get("@timestamp")
    if not isinstance(value, str):
        return None
    try:
        return nanos(value)
    except ValueError:
        return None


def guid_key(value):
    if not isinstance(value, str):
        return None
    value = value.lower()
    if not re.fullmatch(r"(?:" + GUID + r"|\{" + GUID + r"\})", value):
        return None
    if set(value) <= set("{}-0"):
        return None
    # Keep braces, separators and the source spelling intact; normalize case only.
    return value


def join_key(event, parent=False):
    host = field(event, "host.name")
    guid = guid_key(field(event, "process.parent.entity_id" if parent else "process.entity_id"))
    return (host, guid) if isinstance(host, str) and host and guid else None


def event_lookup(events):
    lookup = {}
    for event in events:
        event_id = field(event, "event.id")
        require(isinstance(event_id, str) and bool(event_id), "Missing event ID")
        require(event_id not in lookup, f"Duplicate source event ID: {event_id}")
        lookup[event_id] = event
    return lookup


def lineage_pairs(shells, powershells, window_seconds):
    """Enumerate all distinct ordered tuples; strict before, inclusive upper boundary."""
    require(
        window_seconds is None or type(window_seconds) is int and window_seconds > 0,
        "Window must be a positive integer number of seconds",
    )
    event_lookup([*shells, *powershells])
    parents = defaultdict(list)
    for shell in shells:
        key, timestamp = join_key(shell), time_ns(shell)
        if key is not None and timestamp is not None:
            parents[key].append((shell["event"]["id"], timestamp))
    pairs = set()
    for child in powershells:
        timestamp = time_ns(child)
        if timestamp is None:
            continue
        for parent_id, start in parents.get(join_key(child, parent=True), []):
            gap = timestamp - start
            if gap > 0 and (window_seconds is None or gap <= window_seconds * 10**9):
                pairs.add((parent_id, child["event"]["id"]))
    return sorted(pairs)


def tuple_summary(tuples, lookup):
    ordered = sorted(set(tuple(ids) for ids in tuples))
    for ids in ordered:
        correlation_id(ids)
        require(all(i in lookup for i in ids), "Tuple event missing from readback")
        require(len({field(lookup[i], "host.name") for i in ids}) == 1, "Mixed-host tuple")
    participants = sorted({i for ids in ordered for i in ids})
    first, last = Counter(ids[0] for ids in ordered), Counter(ids[-1] for ids in ordered)
    hosts = sorted({field(lookup[ids[0]], "host.name") for ids in ordered})
    return {
        "tuple_count": len(ordered),
        "duplicate_tuples_suppressed": len(tuples) - len(ordered),
        "unique_first_events": len(first),
        "unique_last_events": len(last),
        "unique_participating_events": len(participants),
        "participating_event_ids": participants,
        "unique_host_count": len(hosts),
        "hosts": hosts,
        "fan_out": {
            "max_tuples_per_first_event": max(first.values(), default=0),
            "first_events_in_multiple_tuples": {i: n for i, n in sorted(first.items()) if n > 1},
            "last_events_in_multiple_tuples": {i: n for i, n in sorted(last.items()) if n > 1},
            "total_event_participations": sum(map(len, ordered)),
        },
    }


def pair_record(ids, lookup):
    shell, child = [lookup[i] for i in ids]
    return {
        "correlation_id": correlation_id(ids),
        "event_ids": list(ids),
        "host": field(shell, "host.name"),
        "timestamps": [shell["@timestamp"], child["@timestamp"]],
        "gap_nanoseconds": time_ns(child) - time_ns(shell),
        "join_keys": {
            "host.name": field(shell, "host.name"),
            "normalized_guid": join_key(shell)[1],
            "shell_process_entity_id": field(shell, "process.entity_id"),
            "powershell_parent_entity_id": field(child, "process.parent.entity_id"),
        },
    }


def refine_pairs(pairs, service_shell_ids, refined_ps_ids):
    return sorted(
        {tuple(ids) for ids in pairs if ids[0] in service_shell_ids and ids[1] in refined_ps_ids}
    )


def exclusion_reasons(ids, service_shell_ids, refined_ps_ids):
    reasons = []
    if ids[0] not in service_shell_ids:
        reasons.append("shell_not_in_phase6_service_origin_branch")
    if ids[1] not in refined_ps_ids:
        reasons.append("powershell_not_in_phase6_refined_set")
    return reasons


def service_chains(services, pairs, lookup, window_seconds):
    """Source-only full-command association, followed by an already verified GUID pair."""
    event_lookup(services)
    candidates = defaultdict(list)
    for service in services:
        if not source_matches("service_installation", service) or time_ns(service) is None:
            continue
        image = field(service, "windows_apt.original") or {}
        image = image.get(SERVICE_IMAGE)
        if isinstance(image, str) and image.strip():
            candidates[(field(service, "host.name"), command_key(image))].append(service)
    chains = set()
    for shell_id, ps_id in pairs:
        shell, ps = lookup[shell_id], lookup[ps_id]
        if lower(shell, "process.parent.name") != "services.exe":
            continue
        key = (field(shell, "host.name"), command_key(field(shell, "process.command_line") or ""))
        for service in candidates.get(key, []):
            ids = (field(service, "event.id"), shell_id, ps_id)
            if len(set(ids)) != 3:
                continue
            if (
                time_ns(service) < time_ns(shell) < time_ns(ps)
                and time_ns(ps) - time_ns(service) <= window_seconds * 10**9
            ):
                chains.add(ids)
    return sorted(chains)


def chain_record(ids, lookup, service_shell_ids, refined_ps_ids):
    installation, shell, ps = [lookup[i] for i in ids]
    reasons = exclusion_reasons(ids[1:], service_shell_ids, refined_ps_ids)
    return {
        "correlation_id": correlation_id(ids),
        "event_ids": list(ids),
        "host": field(shell, "host.name"),
        "timestamps": [e["@timestamp"] for e in (installation, shell, ps)],
        "gaps_nanoseconds": [time_ns(shell) - time_ns(installation), time_ns(ps) - time_ns(shell)],
        "span_nanoseconds": time_ns(ps) - time_ns(installation),
        "service_image_path": installation["windows_apt"]["original"][SERVICE_IMAGE],
        "shell_command_line": field(shell, "process.command_line"),
        "normalized_command": command_key(field(shell, "process.command_line")),
        "guid_join": pair_record(ids[1:], lookup)["join_keys"],
        "phase6_membership": {
            "service_installation_baseline": True,
            "shell_service_origin_branch": ids[1] in service_shell_ids,
            "powershell_refined": ids[2] in refined_ps_ids,
        },
        "satisfies_refined_endpoints": not reasons,
        "exclusion_reasons": reasons,
        "strength": "three-event corroborated candidate; intent and outcome unproven",
    }


def guard_predicate(text):
    require(
        not re.search(r"windows_apt|\bscenario\b|\bthreat\.|\brule\.|_source", text, re.I),
        "Labels or unindexed original fields cannot be search predicates",
    )
    require(not re.search(r"pending|placeholder|unassigned", text, re.I), "Unfinished query")


def check_contract(manifest, phase6, root):
    expected = ["T1059.001", "T1059.003", "T1543.003"]
    require(phase6["passed"], "individual detection must pass")
    require(
        manifest["selected_ids"] == [t["attack_id"] for t in phase6["techniques"]] == expected,
        "Selected detection contracts changed",
    )
    require(manifest["index_pattern"] == PATTERN, "Index pattern changed")
    for key, count in manifest["phase6_expected_refined_counts"].items():
        require(
            phase6["queries"][key]["distinct_event_count"] == count,
            f"individual detection count drift: {key}",
        )
    require(
        manifest["phase6_query_sha256"]
        == {q["file"]: q["query_sha256"] for q in phase6["queries"].values()},
        "individual detection query definitions changed; investigate, do "
        "not redesign for correlation",
    )
    for path, expected_hash in manifest["phase6_query_sha256"].items():
        require(digest(root / path) == expected_hash, f"individual detection query drift: {path}")


def eql_body(root, filename, window_seconds):
    body = load_json(root / "correlation/eql-request.json")
    require(
        body["query"] == (root / "correlation/correlation.eql").read_text(encoding="utf-8").strip(),
        "EQL request and query file disagree",
    )
    query = (root / filename).read_text(encoding="utf-8").strip()
    guard_predicate(query)
    guard_predicate(json.dumps(body))
    require(
        query.startswith("sequence by host.name with maxspan=60001ms\n"),
        "EQL requires host identity and documented default window",
    )
    require(
        "] by correlation.actor_guid" in query and "] by correlation.parent_guid" in query,
        "EQL must preserve GUID ancestry",
    )
    require(type(window_seconds) is int and window_seconds > 0, "Invalid window")
    body["query"] = query.replace("maxspan=60001ms", f"maxspan={window_seconds * 1000 + 1}ms", 1)
    return body


def eql_pairs(body, client=request):
    path = f"/{PATTERN}/_eql/search?filter_path=is_partial,is_running,timed_out,shard_failures,"
    path += "hits.total,hits.sequences.events._id,hits.sequences.join_keys"
    response = client(path, body, method="POST")
    require(
        all(response.get(k) is False for k in ("is_partial", "is_running", "timed_out"))
        and not response.get("shard_failures"),
        "Incomplete EQL response",
    )
    hits = response["hits"]
    require(hits["total"]["relation"] == "eq", "Uncertain EQL count")
    sequences = hits.get("sequences", [])
    require(
        hits["total"]["value"] == len(sequences) < body["size"],
        "EQL response at capacity or truncated; authoritative full sets are required",
    )
    pairs = [tuple(e["_id"] for e in seq["events"]) for seq in sequences]
    for ids in pairs:
        require(len(ids) == 2, "Expected two-event EQL sequence")
        correlation_id(ids)
    return sorted(set(pairs)), response


def verify_eql_endpoints(root, expected_sets, client=request):
    body = eql_body(root, "correlation/correlation.eql", 60)
    predicates = re.findall(r"\[any where (.*?)\n  \] by correlation\.", body["query"], re.S)
    require(len(predicates) == 2, "Cannot isolate EQL endpoint predicates for validation")
    checks = {}
    path = f"/{PATTERN}/_eql/search?filter_path=is_partial,is_running,timed_out,shard_failures,"
    path += "hits.total,hits.events._id"
    for (name, expected), predicate in zip(expected_sets.items(), predicates, strict=True):
        endpoint_body = body | {"query": "any where " + predicate}
        response = client(path, endpoint_body, method="POST")
        require(
            all(response.get(k) is False for k in ("is_partial", "is_running", "timed_out"))
            and not response.get("shard_failures"),
            "Incomplete EQL endpoint response",
        )
        hits = response["hits"]
        ids = sorted(e["_id"] for e in hits.get("events", []))
        require(
            hits["total"]["relation"] == "eq"
            and hits["total"]["value"] == len(ids) < endpoint_body["size"],
            "Incomplete EQL endpoint export",
        )
        require(
            ids == sorted(expected),
            f"EQL endpoint differs from exact individual detection set: {name}",
        )
        checks[name] = {
            "event_ids": ids,
            "count": len(ids),
            "exact_membership_verified": True,
            "request_sha256": sha_json(endpoint_body),
            "request": endpoint_body,
        }
    return checks


def endpoint_census(events):
    groups = defaultdict(list)
    for e in events:
        groups[
            (
                lower(e, "process.name"),
                source_matches("shell_baseline", e)
                and observed_conditions(e)["service_parent_interpreter"],
            )
        ].append(e)
    return [
        {
            "endpoint": name,
            "service_origin": origin,
            "raw_events": len(group),
            "timed_events": sum(time_ns(e) is not None for e in group),
            "actor_guid_events": sum(field(e, "process.entity_id") is not None for e in group),
            "parent_guid_events": sum(
                field(e, "process.parent.entity_id") is not None for e in group
            ),
        }
        for (name, origin), group in sorted(groups.items())
    ]


def run(root=ROOT, client=request, window_seconds=60):
    from scripts.correlation_report import write_report

    out = root / "analysis/correlation/correlation-results.json"
    save_json(out, {"passed": False, "status": "correlation validation started"})
    report_path = out.with_name("correlation-report.md")
    report_path.write_text("# Correlation validation pending\n", encoding="utf-8")
    manifest = load_json(root / "correlation/manifest.json")
    # An interrupted replay deliberately invalidates results. Recover by verifying frozen
    # definitions first, then rerunning the live checks; never require an old success flag.
    for path, expected_hash in manifest["phase6_query_sha256"].items():
        require(digest(root / path) == expected_hash, f"individual detection query drift: {path}")
    phase6 = run_individual(root, client)
    check_contract(manifest, phase6, root)
    before_mapping = client(f"/{PATTERN}/_mapping")
    caps = client(f"/{PATTERN}/_field_caps", {"fields": list(REQUIRED_FIELDS)}, method="POST")[
        "fields"
    ]
    for name in REQUIRED_FIELDS:
        require(
            name in caps and all(c.get("searchable") for c in caps[name].values()),
            f"Missing searchable correlation field: {name}",
        )

    ids = sorted({i for q in INPUT_QUERIES for i in phase6["queries"][q]["event_ids"]})
    lookup = event_lookup(fetch_evidence(ids, client))
    pools = {q: [lookup[i] for i in phase6["queries"][q]["event_ids"]] for q in INPUT_QUERIES}
    for q, events in pools.items():
        require(all(source_matches(q, e) for e in events), "Baseline source changed after replay")
    shells, powershells = pools["shell_baseline"], pools["powershell_baseline"]
    shell_refined = set(phase6["queries"]["shell_refined"]["event_ids"])
    ps_refined = set(phase6["queries"]["powershell_refined"]["event_ids"])
    service_shells = {
        e["event"]["id"]
        for e in shells
        if e["event"]["id"] in shell_refined
        and observed_conditions(e)["service_parent_interpreter"]
    }
    require(
        {e["event"]["id"] for e in powershells if source_matches("powershell_refined", e)}
        == ps_refined,
        "PowerShell refined membership changed during readback",
    )
    require(
        {e["event"]["id"] for e in shells if source_matches("shell_refined", e)} == shell_refined,
        "Shell refined membership changed during readback",
    )

    endpoint_checks = verify_eql_endpoints(
        root, {"service_origin_shell": service_shells, "refined_powershell": ps_refined}, client
    )
    service_ids = phase6["queries"]["service_installation"]["event_ids"]
    services = [
        compact(e)
        for e in fetch_evidence(service_ids, client, EVIDENCE_FIELDS + ["windows_apt.original"])
    ]
    lookup.update(event_lookup(services))
    census_query = (root / "correlation/correlation.esql").read_text(encoding="utf-8").strip()
    guard_predicate(census_query)
    census = esql(census_query, client)
    require(census == endpoint_census([*shells, *powershells]), "ES|QL endpoint census differs")
    require(census == esql(census_query, client), "Nonreproducible endpoint census")

    unbounded = lineage_pairs(shells, powershells, None)
    strong_unbounded = [p for p in unbounded if p[0] in service_shells]
    require(
        set(strong_unbounded) <= set(lineage_pairs(shells, powershells, window_seconds)),
        "Chosen default window misses observed service-origin lineage; investigate",
    )
    prior = load_json(root / "analysis/selection/correlation-feasibility.json")
    known_chains = {tuple(c["event_ids"]) for c in prior["service_shell_powershell_chains"]}
    windows = sorted(set(manifest["sensitivity_windows_seconds"] + [window_seconds]))
    results, examples = {}, set()
    for window in windows:
        broad = lineage_pairs(shells, powershells, window)
        require(
            broad == lineage_pairs(list(reversed(shells)), list(reversed(powershells)), window),
            "Correlation depends on readback order",
        )
        refined = refine_pairs(broad, service_shells, ps_refined)
        excluded = sorted(set(broad) - set(refined))
        chains = service_chains(services, broad, lookup, window)
        known_status = []
        for chain in sorted(known_chains):
            require(all(i in lookup for i in chain), "Known chain evidence is missing")
            status = chain_record(chain, lookup, service_shells, ps_refined)
            status["relationship_validated"] = chain in chains
            if chain not in chains:
                status["exclusion_reasons"].append(
                    "object_ancestry_order_or_window_contract_failed"
                )
            known_status.append(status)
            examples.update(chain)
        eql_results = {}
        for name, filename, expected in (
            ("broad", "correlation/baseline.eql", broad),
            ("refined", "correlation/correlation.eql", refined),
        ):
            body = eql_body(root, filename, window)
            pairs, response = eql_pairs(body, client)
            repeated, _ = eql_pairs(body, client)
            require(pairs == repeated, "EQL sequence IDs are not reproducible")
            require(
                all(i in lookup for p in pairs for i in p),
                "EQL event ID missing from live readback",
            )
            eligible = [p for p in pairs if p in expected]
            rejected = [p for p in pairs if p not in expected]
            # EQL is a sequence view, not an exhaustive join. Enumerated tuples stay authoritative.
            eql_results[name] = {
                "request": body,
                "request_sha256": sha_json(body),
                "raw_sequence_count": response["hits"]["total"]["value"],
                "returned_tuples": [list(p) for p in pairs],
                "exact_validator_accepted_count": len(eligible),
                "rejected_tuples": [list(p) for p in rejected],
                "not_returned_by_eql": [list(p) for p in sorted(set(expected) - set(pairs))],
                "all_pairs_agree_on_this_corpus": set(pairs) == set(expected),
                "replayed": True,
            }
            require(not rejected, "EQL returned a tuple outside exact contracts; investigate")
            examples.update(i for p in pairs if p in refined for i in p)
        explanations = [
            {"event_ids": list(p), "reasons": exclusion_reasons(p, service_shells, ps_refined)}
            for p in excluded
        ]
        sample_pairs = excluded[:3]
        for reason in sorted({v for e in explanations for v in e["reasons"]}):
            sample_pairs += [tuple(e["event_ids"]) for e in explanations if reason in e["reasons"]][
                :2
            ]
        for p in sample_pairs:
            examples.update(p)
        counts_by_shell = Counter(p[0] for p in broad)
        fanout_shells = sorted(i for i, count in counts_by_shell.items() if count > 1)
        fanout_examples = [p for p in broad if fanout_shells and p[0] == fanout_shells[0]]
        examples.update(i for p in fanout_examples for i in p)
        results[str(window)] = {
            "window_seconds": window,
            "broad": tuple_summary(broad, lookup)
            | {"tuples": [pair_record(p, lookup) for p in broad]},
            "refined": tuple_summary(refined, lookup)
            | {"tuples": [pair_record(p, lookup) for p in refined]},
            "candidate_tuple_volume_removed": len(excluded),
            "excluded_broad_tuples": explanations,
            "fanout_representatives": [pair_record(p, lookup) for p in fanout_examples],
            "removed_representatives": [
                pair_record(p, lookup)
                | {"reasons": exclusion_reasons(p, service_shells, ps_refined)}
                for p in sorted(set(sample_pairs))
            ],
            "three_event": tuple_summary(chains, lookup)
            | {
                "tuples": [chain_record(p, lookup, service_shells, ps_refined) for p in chains],
                "previously_observed_count": len(known_chains),
                "previously_observed_validated_count": sum(
                    c["relationship_validated"] for c in known_status
                ),
                "previously_observed_refined_count": sum(
                    c["relationship_validated"] and c["satisfies_refined_endpoints"]
                    for c in known_status
                ),
                "previously_observed_status": known_status,
            },
            "eql": eql_results,
        }
        print(
            f"Window {window}s: broad {len(broad)}, refined {len(refined)}, "
            f"service triples {len(chains)}",
            flush=True,
        )

    main = results[str(window_seconds)]
    used = set(main["refined"]["participating_event_ids"])
    missing_support = {
        "service_origin_shell_without_refined_child": sorted(service_shells - used),
        "refined_powershell_without_service_origin_shell_tuple": sorted(ps_refined - used),
        "refined_shell_in_other_service_control_branch": sorted(shell_refined - service_shells),
    }
    for missing_ids in missing_support.values():
        examples.update(missing_ids[:2])
    for technique in phase6["techniques"][:2]:
        examples.update(c["event_id"] for c in technique["comparisons"])
    missing_quality = {
        q: {
            "missing_or_invalid_utc": sum(time_ns(e) is None for e in events),
            "missing_or_invalid_actor_guid": sum(join_key(e) is None for e in events),
            "missing_or_invalid_parent_guid": sum(join_key(e, True) is None for e in events),
        }
        for q, events in (("shell_baseline", shells), ("powershell_baseline", powershells))
    }
    require(
        client(f"/{PATTERN}/_mapping") == before_mapping, "Index mapping changed during correlation"
    )
    total = client(f"/{PATTERN}/_count")["count"]
    timed = client(
        f"/{PATTERN}/_count", {"query": {"exists": {"field": "@timestamp"}}}, method="POST"
    )["count"]
    require((total, timed) == (102011, 90601), "Index counts changed during correlation")
    report = {
        "passed": True,
        "phase": 7,
        "validated_at_utc": datetime.now(UTC).isoformat(),
        "index_pattern": PATTERN,
        "live_counts": {"total": total, "timed": timed, "undated": total - timed},
        "matching_unit": manifest["matching_unit"],
        "correlation_id_algorithm": manifest["correlation_id"],
        "default_window_seconds": window_seconds,
        "windows_tested_seconds": windows,
        "windows": results,
        "unbounded_lineage_count": len(unbounded),
        "unbounded_service_origin_lineage_count": len(strong_unbounded),
        "default_captures_all_observed_service_origin_lineage": True,
        "endpoint_census": census,
        "eql_endpoint_validation": endpoint_checks,
        "missing_endpoint_fields": missing_quality,
        "missing_support": {
            k: {"count": len(v), "event_ids": v} for k, v in missing_support.items()
        },
        "all_input_event_ids_verified": len(ids),
        "mapping_unchanged": True,
        "mapping_sha256": sha_json(before_mapping),
        "evidence": {i: compact(lookup[i]) for i in sorted(examples)},
        "phase6_counts": {k: q["distinct_event_count"] for k, q in phase6["queries"].items()},
        "query_sha256": {path: digest(root / path) for path in manifest["queries"].values()},
        "prerequisite_sha256": {
            path: digest(root / path)
            for path in (
                "analysis/detections/detection-results.json",
                "detections/manifest.json",
                "analysis/technique_selection.json",
                "analysis/selection/correlation-feasibility.json",
            )
        },
        "runner_sha256": digest(Path(__file__)),
        "report_generator_sha256": digest(root / "scripts/correlation_report.py"),
        "manifest_sha256": digest(root / "correlation/manifest.json"),
        "references": manifest["references"],
        "reference_access_date_utc": manifest["reference_access_date_utc"],
        "limits": [
            "Strong structure is exact host equality, GUID case-only comparison, strict order "
            "and bounded nanosecond time; intent remains unknown.",
            "EQL uses request-local date milliseconds plus a nanosecond tiebreaker, with a "
            "one-millisecond maxspan envelope. Python enforces 0 < gap <= window exactly.",
            "EQL has one pending sequence per join key/state; Python enumerates every eligible "
            "tuple and reports any EQL omissions. Equal live counts do not prove universal "
            "equivalence.",
            "Service imagePath is retrieved original evidence only. Full-command "
            "case/backslash comparison is lexical association, not Windows command parsing or "
            "service API identity.",
            "No persistence, service survival, successful command/file outcome or malicious "
            "intent is established.",
            "Missing events, GUIDs or explicit UTC times, renamed/hosted interpreters, other "
            "parents/interpreters, direct executables and delays beyond the window can remove "
            "support.",
            "individual detection refinements exclude valid technique "
            "activity; fewer tuples are not "
            "measured FP/FN rates. Precision, recall, F1 and FPR remain unavailable.",
            "Authorized marker-file tests, administration and service wrappers remain "
            "plausible explanations for correlated candidates.",
        ],
    }
    write_report(report_path, report, root)
    save_json(out, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window", type=int, default=60, help="Default exact window in seconds")
    args = parser.parse_args()
    if args.window <= 0:
        parser.error("--window must be positive")
    result = run(window_seconds=args.window)
    print(
        f"Passed: {len(result['windows'])} windows; "
        f"{result['all_input_event_ids_verified']} live input IDs"
    )


if __name__ == "__main__":
    main()
