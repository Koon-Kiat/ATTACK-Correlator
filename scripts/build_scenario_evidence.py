"""Review a bounded historical scenario; dataset command strings are evidence only."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, load_json, request, save_json  # noqa: E402
from scripts.run_correlation import (  # noqa: E402
    PATTERN,
    SERVICE_IMAGE,
    chain_record,
    check_contract,
    correlation_id,
    event_lookup,
    exclusion_reasons,
    guard_predicate,
    guid_key,
    lineage_pairs,
    pair_record,
    service_chains,
    sha_json,
    time_ns,
)
from scripts.run_correlation import run as run_correlation  # noqa: E402
from scripts.run_individual_detections import (  # noqa: E402
    EVIDENCE_FIELDS,
    esql,
    fetch_evidence,
    field,
    observed_conditions,
    source_matches,
)
from scripts.verify_technique_selection import require  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402

P6 = "analysis/detections/detection-results.json"
P7 = "analysis/correlation/correlation-results.json"
SCENARIO = "analysis/scenarios/scenario-demonstration.json"
EVALUATION = "analysis/evaluation/evaluation-results.json"
CONTRACT = "analysis/evaluation/dashboard-contract.json"
SEARCH = "analysis/scenarios/primary-scenario-search.json"
ESQL = "analysis/scenarios/primary-scenario.esql"
SELECTED = ["T1059.001", "T1059.003", "T1543.003"]
EXPECTED = {
    "powershell_baseline": 2060,
    "powershell_refined": 290,
    "shell_baseline": 7717,
    "shell_refined": 172,
    "service_installation": 102,
    "service_create_baseline": 155,
    "service_create_refined": 41,
    "service_config_baseline": 117,
    "service_config_refined": 108,
    "service_registry": 708,
}
REFINED = {
    "powershell_refined": "T1059.001",
    "shell_refined": "T1059.003",
    "service_create_refined": "T1543.003",
    "service_config_refined": "T1543.003",
}
UNITS = {
    "event": "One distinct event.id within the named observation cohort",
    "ordered_pair": "[shell_event_id, powershell_event_id], distinct ordered IDs",
    "ordered_triple": "[service_installation_event_id, shell_event_id, powershell_event_id]",
}
SELECTION_RULE = (
    "Earliest validated triple by service-installation UTC nanoseconds; ties use the "
    "lexicographically sorted ordered event-ID tuple. Verify all three live before selection; "
    "fail on drift rather than silently substitute another scenario."
)
COMPARISON_RULE = (
    "Primary triple; the other two refined pairs; lexicographically first excluded broad pair; "
    "lowest event.id from each nonempty standalone refined PowerShell / other shell branch set; "
    "all pre-existing individual detection comparison IDs sorted by ID. No intent-based ranking."
)
LIMITS = [
    "Evidence-strength categories describe structure, never malicious/benign ground truth.",
    "Wazuh annotations, publisher success ratios and scenario mappings/names are not independent "
    "truth and are not predicates or selection keys. They are omitted from these artifacts.",
    "This small deterministic review set is illustrative, not a random or representative sample "
    "of intent; it cannot estimate population error rates.",
    "No service survival, successful persistence, completed command, requested file creation or "
    "malicious intent is established. No intermediate events are inferred.",
    "SCM imagePath is source-only evidence. Case/backslash full-command normalization is lexical "
    "association, not Windows command parsing, service API identity or proof of causality.",
    "Missing Sysmon events, actor/parent GUIDs or valid UTC timestamps can prevent correlation.",
    "Other PowerShell parents, renamed or in-process PowerShell, direct service executables, "
    "other interpreters and delays beyond the window can evade the required structure.",
    "Narrow command predicates omit some technique-consistent activity. Exclusion does not "
    "establish benignness or a confirmed false negative; keep standalone detections visible.",
    "The 60/300/900-second results describe this corpus, not an optimal production window. "
    "The 11,410 undated observations cannot enter ordered correlation.",
]
FP_REASONING = (
    "cmd.exe, PowerShell and service installation each have common administrative uses. Exact "
    "independently observed ancestry, service-origin context, ordering and refined behaviour "
    "make a much narrower candidate set. Authorized marker-file tests and service wrappers can "
    "still satisfy all conditions. Routine-looking inventory, directory and service commands "
    "remain ambiguous once parent context and unverified authorization are considered."
)
FN_REASONING = (
    "The removed encoded-only child has real cmd ancestry but lacks the refined PowerShell "
    "conditions; its shell also lacks the required service-origin branch. No encoded payload "
    "is decoded or executed. Missing support and alternate execution paths can hide valid "
    "technique activity. Standalone refined PowerShell and other-branch shell candidates remain "
    "visible; absence from a correlation is not a benign verdict."
)


def verify_hashes(root, hashes):
    for filename, expected in hashes.items():
        require(digest(root / filename) == expected, f"Artifact hash drift: {filename}")


def verify_prerequisites(root):
    p6, p7 = load_json(root / P6), load_json(root / P7)
    require(p6.get("passed") is True and p7.get("passed") is True, "Prerequisites must pass")
    manifest = load_json(root / "correlation/manifest.json")
    check_contract(manifest, p6, root)
    verify_hashes(root, p6["prerequisite_sha256"])
    verify_hashes(root, p7["prerequisite_sha256"])
    verify_hashes(root, p7["query_sha256"])
    verify_hashes(
        root,
        {
            "detections/manifest.json": p6["manifest_sha256"],
            "scripts/run_individual_detections.py": p6["runner_sha256"],
            "scripts/run_correlation.py": p7["runner_sha256"],
            "scripts/correlation_report.py": p7["report_generator_sha256"],
            "correlation/manifest.json": p7["manifest_sha256"],
        },
    )
    require(
        p6["live_counts"] == {"total": 102011, "with_timestamp": 90601, "without_timestamp": 11410},
        "Individual corpus count drift",
    )
    require(
        p7["live_counts"] == {"total": 102011, "timed": 90601, "undated": 11410},
        "Correlation corpus count drift",
    )
    for name, count in EXPECTED.items():
        q = p6["queries"][name]
        require(
            q["distinct_event_count"]
            == len(set(q["event_ids"]))
            == len(q["event_ids"])
            == count
            == p7["phase6_counts"][name],
            f"Detection count drift: {name}",
        )
        require(
            q["exact_replay_passed"] and q["raw_returned_rows"] == count,
            f"Incomplete detection replay: {name}",
        )
    require(p7["default_window_seconds"] == 60, "Expected validated default of 60 seconds")
    for window in ("60", "300", "900"):
        w = p7["windows"][window]
        for cohort, count, size, events in (
            ("broad", 261, 2, 483),
            ("refined", 3, 2, 6),
            ("three_event", 3, 3, 9),
        ):
            result = w[cohort]
            ids = [tuple(t["event_ids"]) for t in result["tuples"]]
            require(
                len(set(ids)) == len(ids) == result["tuple_count"] == count,
                f"Tuple count drift: {window}/{cohort}",
            )
            require(all(len(t) == size for t in ids), "Mixed tuple units")
            require(
                len({i for t in ids for i in t}) == result["unique_participating_events"] == events,
                "Participating-event count drift",
            )
            require(
                len({t["host"] for t in result["tuples"]}) == result["unique_host_count"] == 3,
                "Host count drift",
            )
            require(
                all(
                    t["correlation_id"] == correlation_id(t["event_ids"]) for t in result["tuples"]
                ),
                "Tuple identity drift",
            )
        service = w["three_event"]
        require(
            service["previously_observed_validated_count"]
            == service["previously_observed_refined_count"]
            == 3,
            "Known triple drift",
        )
        require(
            w["eql"]["broad"]["raw_sequence_count"] == 222
            and len(w["eql"]["broad"]["not_returned_by_eql"]) == 39,
            "EQL fan-out evidence drift",
        )
    return p6, p7


def select_primary(triples):
    require(bool(triples), "No validated triple available")
    require(
        all(time_ns({"@timestamp": t["timestamps"][0]}) is not None for t in triples),
        "Scenario selection needs explicit UTC",
    )
    return sorted(
        triples, key=lambda t: (time_ns({"@timestamp": t["timestamps"][0]}), tuple(t["event_ids"]))
    )


def source_projection(event):
    """Keep only evidence needed for review; no publisher/derived classification fields."""
    original = (
        (field(event, "windows_apt.original") or {})
        if source_matches("service_installation", event)
        else {}
    )
    prefix = "_source.data.win.eventdata."
    return {
        "event_id": field(event, "event.id"),
        "timestamp": event.get("@timestamp"),
        "host": field(event, "host.name"),
        "provider": field(event, "event.provider"),
        "event_code": field(event, "event.code"),
        "user": event.get("user"),
        "process": event.get("process"),
        "service_source_evidence": {
            k: original[prefix + k]
            for k in ("serviceName", "imagePath", "accountName", "serviceType", "startType")
            if prefix + k in original
        },
        "provenance": field(event, "windows_apt.provenance"),
        "observed_conditions": observed_conditions(event),
    }


def provenance_status(event):
    p = field(event, "windows_apt.provenance") or {}
    required = (
        "dataset",
        "dataset_version",
        "source_file",
        "source_sha256",
        "row_sha256",
        "original_id",
        "original_index",
        "source_row_index",
    )
    missing = [k for k in required if p.get(k) is None or p.get(k) == ""]
    return {"complete": not missing, "missing_fields": missing}


def verify_triples(p6, p7, lookup):
    service_shells = set(p7["eql_endpoint_validation"]["service_origin_shell"]["event_ids"])
    ps_refined = set(p6["queries"]["powershell_refined"]["event_ids"])
    verified = []
    for saved in p7["windows"]["60"]["three_event"]["tuples"]:
        ids = saved["event_ids"]
        require(all(i in lookup for i in ids), "Scenario event absent")
        service, shell, ps = [lookup[i] for i in ids]
        require(
            source_matches("shell_refined", shell)
            and observed_conditions(shell)["service_parent_interpreter"]
            and source_matches("powershell_refined", ps),
            "Refined endpoint drift",
        )
        require(
            ids[0] in p6["queries"]["service_installation"]["event_ids"],
            "Installation outside baseline",
        )
        require(
            not source_matches("service_create_refined", service)
            and not source_matches("service_config_refined", service),
            "SCM installation must remain a separate cohort",
        )
        pairs = lineage_pairs([shell], [ps], 60)
        require(
            tuple(ids) in service_chains([service], pairs, lookup, 60),
            "Service image, host, ancestry, ordering or window failed",
        )
        current = chain_record(ids, lookup, service_shells, ps_refined)
        require(current == saved, "Live triple differs from the validated correlation artifact")
        require(
            all(provenance_status(e)["complete"] for e in (service, shell, ps)),
            "Incomplete scenario provenance",
        )
        verified.append(current)
    return select_primary(verified)


def select_review_units(p6, p7, triples):
    w = p7["windows"]["60"]
    primary = triples[0]
    specs = [
        {
            "role": "primary",
            "type": "ordered_triple",
            "event_ids": primary["event_ids"],
            "category": "three_event_corroborated_candidate",
            "selection": SELECTION_RULE,
        }
    ]
    primary_pair = tuple(primary["event_ids"][1:])
    for pair in sorted(w["refined"]["tuples"], key=lambda p: p["event_ids"]):
        if tuple(pair["event_ids"]) != primary_pair:
            specs.append(
                {
                    "role": "other_refined_pair",
                    "type": "ordered_pair",
                    "event_ids": pair["event_ids"],
                    "category": "strong_structural_correlation",
                    "selection": "All refined pairs except the primary triple's pair",
                }
            )
    removed = sorted(w["excluded_broad_tuples"], key=lambda p: p["event_ids"])
    require(bool(removed), "Required broad-exclusion comparison absent")
    specs.append(
        {
            "role": "excluded_broad_pair",
            "type": "ordered_pair",
            "event_ids": removed[0]["event_ids"],
            "category": "broad_lineage_excluded_by_refinement",
            "selection": "Lexicographically first ordered excluded broad tuple",
        }
    )
    used = set(w["refined"]["participating_event_ids"])
    standalone = {
        "standalone_powershell": set(p6["queries"]["powershell_refined"]["event_ids"]) - used,
        "other_shell_branch": set(p6["queries"]["shell_refined"]["event_ids"])
        - set(p7["eql_endpoint_validation"]["service_origin_shell"]["event_ids"]),
    }
    for role, ids in standalone.items():
        require(bool(ids), f"Required standalone comparison absent: {role}")
        specs.append(
            {
                "role": role,
                "type": "event",
                "event_ids": [min(ids)],
                "category": "standalone_behavioral_candidate",
                "selection": f"Lowest event.id in the complete {role} set",
            }
        )
    comparisons = {
        c["event_id"]: c["explanation"] for t in p6["techniques"] for c in t["comparisons"]
    }
    for i, explanation in sorted(comparisons.items()):
        specs.append(
            {
                "role": "phase6_comparison",
                "type": "event",
                "event_ids": [i],
                "category": "routine_or_ambiguous_comparison",
                "selection": "All existing individual detection comparison IDs, sorted",
                "prior_explanation": explanation,
            }
        )
    return specs


def technique_ids(event):
    if source_matches("powershell_baseline", event):
        return ["T1059.001"]
    if source_matches("shell_baseline", event):
        return ["T1059.003"]
    if any(
        source_matches(q, event)
        for q in ("service_installation", "service_create_baseline", "service_config_baseline")
    ):
        return ["T1543.003"]
    raise ValueError("Reviewed event has no selected observable technique")


def review_unit(spec, lookup, p6, p7):
    ids = spec["event_ids"]
    events = [lookup[i] for i in ids]
    membership = {i: [q for q in EXPECTED if source_matches(q, lookup[i])] for i in ids}
    for i, queries in membership.items():
        for q in EXPECTED:
            require(
                (q in queries) == (i in p6["queries"][q]["event_ids"]),
                f"Source/set membership drift: {q}/{i}",
            )
    relation = None
    if len(ids) >= 2:
        pair = tuple(ids[-2:])
        require(pair in lineage_pairs([events[-2]], [events[-1]], 60), "Reviewed pair invalid")
        relation = pair_record(pair, lookup)
        saved = next(
            (p for p in p7["windows"]["60"]["broad"]["tuples"] if tuple(p["event_ids"]) == pair),
            None,
        )
        require(relation == saved, "Reviewed pair not in authoritative broad results")
    reason = {
        "primary": "SCM installation baseline plus refined shell and PowerShell; source image "
        "association and exact GUID ancestry corroborate three independent records. "
        "The 7045 event is outside both refined sc.exe process cohorts.",
        "other_refined_pair": "Both refined endpoints and exact host/GUID/order/window pass; "
        "the associated installation is retained as corroboration.",
        "excluded_broad_pair": "; ".join(
            exclusion_reasons(
                ids[-2:],
                set(p7["eql_endpoint_validation"]["service_origin_shell"]["event_ids"]),
                set(p6["queries"]["powershell_refined"]["event_ids"]),
            )
        )
        if spec["role"] == "excluded_broad_pair"
        else "",
        "standalone_powershell": "Refined retrieval/execution behaviour passes; no required "
        "service-origin refined pair contains this event.",
        "other_shell_branch": "Refined service-control/interpreter binPath branch passes; "
        "service-origin execution branch does not.",
        "phase6_comparison": spec.get("prior_explanation", ""),
    }[spec["role"]]
    if spec["role"] == "excluded_broad_pair":
        command = (field(events[-1], "process.command_line") or "").lower()
        require(
            "-encodedcommand " in command and not source_matches("powershell_refined", events[-1]),
            "Earliest excluded comparison changed; reassess encoded-only coverage claim",
        )
    legitimate = {
        "primary": "Authorized ARTService marker-file test or administrative service wrapper; "
        "the observed New-Item request does not prove the file was created.",
        "other_refined_pair": "Authorized marker-file test or service wrapper can match.",
        "excluded_broad_pair": "Encoded commands can implement approved automation or testing; "
        "encoding alone does not establish intent.",
        "standalone_powershell": "Approved retrieval/execution or security testing is possible; "
        "Public-directory splunkd.exe ancestry requires review.",
        "other_shell_branch": "Authorized Fax-service configuration/testing is possible; "
        "the command's test wording is not independent truth.",
        "phase6_comparison": spec.get("prior_explanation", ""),
    }[spec["role"]]
    return spec | {
        "review_id": sha_json({"type": spec["type"], "event_ids": ids}),
        "technique_ids": sorted({t for e in events for t in technique_ids(e)}),
        "observable_behaviour": {i: source_projection(lookup[i]) for i in ids},
        "structural_relationship": relation,
        "timestamp_completeness": {i: time_ns(lookup[i]) is not None for i in ids},
        "process_ancestry_completeness": {
            i: {
                "applicable": not source_matches("service_installation", lookup[i]),
                "actor_guid_present": guid_key(field(lookup[i], "process.entity_id")) is not None,
                "parent_guid_present": guid_key(field(lookup[i], "process.parent.entity_id"))
                is not None,
            }
            for i in ids
        },
        "provenance_completeness": {i: provenance_status(lookup[i]) for i in ids},
        "individual_query_membership": membership,
        "inclusion_or_exclusion_reason": reason,
        "plausible_legitimate_explanation": legitimate,
        "uncertainty": "Authorization, intent and outcome are unverified. Evidence structure "
        "is not an independently adjudicated intent label.",
        "coverage_limitation": "Missing events/GUIDs/times, other parents/interpreters, direct "
        "executables, delays and narrow command rules can omit activity. "
        "A standalone record does not verify a separate parent event.",
    }


def scenario_queries(ids):
    require(len(ids) == len(set(ids)) == 3, "Scenario query needs three distinct IDs")
    query = f"FROM {PATTERN}\n| WHERE event.id IN (" + ", ".join(json.dumps(i) for i in ids)
    query += ")\n| KEEP @timestamp, event.id, host.name, event.provider, event.code, user.name, "
    query += "process.name, process.command_line, process.entity_id, process.parent.entity_id\n"
    query += "| SORT @timestamp ASC, event.id ASC\n| LIMIT 10\n"
    guard_predicate(query)
    body = {
        "size": 10,
        "track_total_hits": True,
        "query": {"ids": {"values": ids}},
        "_source": EVIDENCE_FIELDS + ["windows_apt.original"],
        "sort": [{"@timestamp": "asc"}, {"event.id": "asc"}],
    }
    return query, body


def verify_scenario_queries(ids, lookup, query, body, client):
    rows = esql(query, client)
    require([r["event.id"] for r in rows] == ids, "Scenario ES|QL returned wrong ordered IDs")
    for row in rows:
        e = lookup[row["event.id"]]
        for key, value in row.items():
            if key == "@timestamp":
                require(time_ns({key: value}) == time_ns(e), "Scenario query time drift")
            else:
                require(value == field(e, key), f"Scenario query field drift: {key}")
    response = client(f"/{PATTERN}/_search", body, method="POST")
    require(
        response.get("timed_out") is False and response["_shards"]["failed"] == 0,
        "Incomplete scenario search",
    )
    hits = response["hits"]
    require(hits["total"] == {"value": 3, "relation": "eq"}, "Scenario search count mismatch")
    require([h["_id"] for h in hits["hits"]] == ids, "Scenario search ID mismatch")
    for h in hits["hits"]:
        require(
            source_projection(h["_source"]) == source_projection(lookup[h["_id"]]),
            "Scenario source readbacks disagree",
        )
    return {
        "esql_ordered_ids": ids,
        "search_ordered_ids": ids,
        "exact_fields_verified": True,
        "esql_sha256": sha_json(query),
        "search_request_sha256": sha_json(body),
    }


def live_state(client):
    total = client(f"/{PATTERN}/_count")["count"]
    timed = client(
        f"/{PATTERN}/_count", {"query": {"exists": {"field": "@timestamp"}}}, method="POST"
    )["count"]
    require((total, timed) == (102011, 90601), "Live corpus count drift")
    return {"total": total, "timed": timed, "undated": total - timed}, sha_json(
        client(f"/{PATTERN}/_mapping")
    )


def build_artifacts(p6, p7, lookup, triples, specs, input_hashes):
    """Pure rendering inputs: stable output for fixed verified sources and prerequisites."""
    units = [review_unit(s, lookup, p6, p7) for s in specs]
    review_ids = sorted({i for u in units for i in u["event_ids"]})
    primary = triples[0]
    scenario_ids = set(review_ids) | {i for t in triples for i in t["event_ids"]}
    scenario = {
        "passed": True,
        "selection_rule": SELECTION_RULE,
        "comparison_rule": COMPARISON_RULE,
        "selected_techniques": SELECTED,
        "primary": primary,
        "corroborating": triples[1:],
        "primary_technique_mapping": [
            {
                "event_id": primary["event_ids"][0],
                "attack_id": "T1543.003",
                "observation": "SCM 7045 installation baseline; source-only service object",
                "rules": ["service_installation"],
                "refined_sc_process_member": False,
            },
            {
                "event_id": primary["event_ids"][1],
                "attack_id": "T1059.003",
                "observation": "Sysmon 1 cmd.exe; services.exe parent; PowerShell command",
                "rules": ["shell_baseline", "shell_refined", "refined_guid_pair"],
            },
            {
                "event_id": primary["event_ids"][2],
                "attack_id": "T1059.001",
                "observation": "Sysmon 1 PowerShell; hidden + no profile + inline New-Item command",
                "rules": ["powershell_baseline", "powershell_refined", "refined_guid_pair"],
            },
        ],
        "evidence": {i: source_projection(lookup[i]) for i in sorted(scenario_ids)},
        "review_units": units,
        "limits": LIMITS,
        "prerequisite_validated_at_utc": p7["validated_at_utc"],
        "input_sha256": input_hashes,
    }
    counts = {
        q: {
            k: p6["queries"][q][k]
            for k in (
                "distinct_event_count",
                "unique_host_count",
                "hosts",
                "historical_time_range",
                "with_timestamp",
                "without_timestamp",
                "file",
                "query_sha256",
                "count_query",
            )
        }
        | {"unit": "event"}
        for q in EXPECTED
    }
    activity = []
    for q, attack in REFINED.items():
        cohort = [lookup[i] for i in p6["queries"][q]["event_ids"]]
        stats = p6["queries"][q]
        require(
            len(cohort) == len(event_lookup(cohort)) == stats["distinct_event_count"],
            "Activity cohort count drift",
        )
        require(
            sorted({field(e, "host.name") for e in cohort}) == stats["hosts"],
            "Activity host-set drift",
        )
        require(all(time_ns(e) is not None for e in cohort), "Activity timestamp missing")
        times = [time_ns(e) for e in cohort]
        expected_times = stats["historical_time_range"]
        require(
            min(times) == time_ns({"@timestamp": expected_times["min_utc"]})
            and max(times) == time_ns({"@timestamp": expected_times["max_utc"]}),
            "Activity historical range drift",
        )
        for i in sorted(p6["queries"][q]["event_ids"]):
            e = lookup[i]
            require(source_matches(q, e), f"Activity source no longer matches: {q}/{i}")
            require(
                time_ns(e) is not None and provenance_status(e)["complete"],
                "Activity timestamp/provenance missing",
            )
            activity.append(
                {
                    "event_id": i,
                    "timestamp": e["@timestamp"],
                    "host": field(e, "host.name"),
                    "attack_id": attack,
                    "detection_name": q,
                    "unit": "event",
                }
            )
    activity.sort(
        key=lambda r: (time_ns({"@timestamp": r["timestamp"]}), r["detection_name"], r["event_id"])
    )
    daily = Counter((r["detection_name"], r["timestamp"][:10]) for r in activity)
    windows = {
        w: {
            k: {
                key: v[k][key]
                for key in (
                    "tuple_count",
                    "unique_participating_events",
                    "unique_host_count",
                    "hosts",
                )
            }
            | {"unit": "ordered_triple" if k == "three_event" else "ordered_pair"}
            for k in ("broad", "refined", "three_event")
        }
        for w, v in sorted(p7["windows"].items(), key=lambda item: int(item[0]))
    }
    evidence_rows = []
    for unit in units:
        for i in unit["event_ids"]:
            e = lookup[i]
            evidence_rows.append(
                {
                    "review_id": unit["review_id"],
                    "unit": unit["type"],
                    "event_id": i,
                    "timestamp": e.get("@timestamp"),
                    "host": field(e, "host.name"),
                    "user": field(e, "user.name"),
                    "process": field(e, "process.name"),
                    "command_line": field(e, "process.command_line"),
                    "attack_ids": technique_ids(e),
                    "detection_names": unit["individual_query_membership"][i],
                    "correlation_id": correlation_id(unit["event_ids"])
                    if unit["type"] != "event"
                    else None,
                    "evidence_strength_category": unit["category"],
                    "service_image_path": (field(e, "windows_apt.original") or {}).get(
                        SERVICE_IMAGE
                    ),
                    "annotation_origin": "Analyst mapping from telemetry and query membership",
                }
            )
    result = {
        "passed": True,
        "phase": 8,
        "input_sha256": input_hashes,
        "prerequisite_validated_at_utc": p7["validated_at_utc"],
        "live_counts": p7["live_counts"],
        "review_unit_definitions": UNITS,
        "review_set": {
            "unit_count": len(units),
            "by_type": dict(Counter(u["type"] for u in units)),
            "by_category": dict(Counter(u["category"] for u in units)),
            "unique_event_count": len(review_ids),
            "event_ids": review_ids,
            "selection_rule": COMPARISON_RULE,
            "interpretation": "Review composition only, not class prevalence or intent",
        },
        "individual_observations": counts,
        "correlation_windows": windows,
        "candidate_volume": {
            "unit": "ordered_pair",
            "broad": 261,
            "refined": 3,
            "removed": 258,
            "interpretation": "Candidate sequence volume "
            "reduction, not measured false-positive reduction",
        },
        "eql_broad_view": {"sequences": 222, "all_pairs": 261, "fanout_pairs_omitted": 39},
        "missing_support": {k: v["count"] for k, v in p7["missing_support"].items()},
        "activity": {
            "unit": "event within named detection",
            "event_rows": activity,
            "daily_utc": [
                {"detection_name": q, "utc_date": day, "event_count": n}
                for (q, day), n in sorted(daily.items())
            ],
        },
        "evidence_rows": evidence_rows,
        "false_positive_reasoning": FP_REASONING,
        "false_negative_reasoning": FN_REASONING,
        "limits": LIMITS,
        "ground_truth": {
            "independent_intent_labels_available": False,
            "accuracy_metrics_available": False,
            "evidence_categories_are_intent_labels": False,
        },
    }
    contract = {
        "status": "validated_evidence_contract_only",
        "dashboard_built": False,
        "source_index": PATTERN,
        "timezone": "UTC",
        "selected_techniques": SELECTED,
        "individual_metrics": counts,
        "correlation_metrics": windows["60"],
        "refined_affected_hosts": sorted({r["host"] for r in activity}),
        "primary_scenario": primary,
        "panel_sources": {
            "overview": f"{EVALUATION}#/individual_observations and #/correlation_windows/60",
            "activity": f"{EVALUATION}#/activity; four existing refined ES|QL query files",
            "correlation": f"{P7}#/windows/60; scripts/run_correlation.py all-pairs output",
            "primary_scenario": f"{SCENARIO}#/primary and #/evidence; {ESQL}; {SEARCH}",
            "evidence_table": f"{EVALUATION}#/evidence_rows; {SCENARIO}#/review_units",
        },
        "historical_filter": {
            "from_utc": activity[0]["timestamp"],
            "to_utc": activity[-1]["timestamp"],
            "bounds": "inclusive",
        },
        "rules": [
            "Each individual metric counts distinct event.id within its named cohort.",
            "Do not sum installation/create/config/registry observations into service "
            "or attack counts.",
            "Correlation metric unit is an ordered pair or triple; recompute filtered tuples from "
            "all endpoints. Endpoint row counts and broad EQL 222 are not the "
            "complete denominator.",
            "Snapshot metrics describe the full historical corpus. Do not imply that arbitrary "
            "dashboard filters recompute them; label fixed scope or implement verified "
            "tuple filtering.",
            "Use exact event-ID sets or authoritative ES|QL for refined activity, not coarse KQL.",
            "Derived ATT&CK IDs, rule names, correlation IDs and evidence categories are local "
            "analytic output, not fields installed in the source index.",
            "Read service imagePath from _source or the verified artifact; never search "
            "disabled originals.",
            "Display null user/process/correlation fields as unavailable; never fabricate "
            "severity, "
            "confidence or malicious/benign labels. Source strings must be escaped as inert text.",
            "No malicious-versus-benign panel is supported; no network panel is needed "
            "for this scope.",
            "Later implementation must compare every metric, historical range and evidence link "
            "with this contract before dashboard export; no dashboard is installed by this helper.",
        ],
        "input_sha256": input_hashes,
    }
    return scenario, result, contract


def run(root=ROOT, client=request, replay=True):
    from scripts.scenario_report import write_reports

    for path in (SCENARIO, EVALUATION, CONTRACT):
        save_json(root / path, {"passed": False, "status": "scenario validation pending"})
    for path in (
        "analysis/scenarios/scenario-demonstration.md",
        "analysis/evaluation/evaluation-report.md",
    ):
        (root / path).write_text("# Validation pending\n", encoding="utf-8")
    if replay:
        run_correlation(root, client)  # Includes the complete individual detection live replay.
    p6, p7 = verify_prerequisites(root)
    before = live_state(client)
    require(before[1] == p7["mapping_sha256"], "Mapping drift since correlation validation")
    triple_ids = {i for t in p7["windows"]["60"]["three_event"]["tuples"] for i in t["event_ids"]}
    provisional = select_primary(p7["windows"]["60"]["three_event"]["tuples"])
    specs = select_review_units(p6, p7, provisional)
    ids = sorted(
        triple_ids
        | {i for s in specs for i in s["event_ids"]}
        | {i for q in REFINED for i in p6["queries"][q]["event_ids"]}
    )
    lookup = event_lookup(fetch_evidence(ids, client))
    service_ids = [i for i in ids if source_matches("service_installation", lookup[i])]
    lookup.update(
        event_lookup(
            fetch_evidence(service_ids, client, EVIDENCE_FIELDS + ["windows_apt.original"])
        )
    )
    for event_id in {i for s in specs for i in s["event_ids"]} | triple_ids:
        for prior in (p6["evidence"], p7["evidence"]):
            if event_id in prior:
                require(
                    source_projection(lookup[event_id]) == source_projection(prior[event_id]),
                    f"Reviewed source differs from prerequisite evidence: {event_id}",
                )
    triples = verify_triples(p6, p7, lookup)
    require(specs == select_review_units(p6, p7, triples), "Live selection changed")
    input_paths = (
        P6,
        P7,
        "detections/manifest.json",
        "correlation/manifest.json",
        "analysis/technique_selection.json",
        "scripts/build_scenario_evidence.py",
        "scripts/scenario_report.py",
    )
    input_hashes = {p: digest(root / p) for p in input_paths}
    scenario, evaluation, contract = build_artifacts(p6, p7, lookup, triples, specs, input_hashes)
    query, body = scenario_queries(triples[0]["event_ids"])
    query_checks = verify_scenario_queries(triples[0]["event_ids"], lookup, query, body, client)
    require(live_state(client) == before, "Live state changed during evidence review")
    verify_hashes(root, input_hashes)
    evaluation["live_validation"] = {
        "source_event_ids_verified": len(ids),
        "source_projection_sha256": sha_json({i: source_projection(lookup[i]) for i in ids}),
        "scenario_queries": query_checks,
        "mapping_unchanged": True,
        "mapping_sha256": before[1],
        "prerequisite_hashes_verified": True,
    }
    save_json(root / SEARCH, body)
    (root / ESQL).write_text(query, encoding="utf-8", newline="\n")
    evaluation["query_sha256"] = {p: digest(root / p) for p in (SEARCH, ESQL)}
    scenario["query_sha256"] = evaluation["query_sha256"]
    save_json(root / SCENARIO, scenario)
    save_json(root / CONTRACT, contract)
    evaluation["output_sha256"] = {p: digest(root / p) for p in (SCENARIO, CONTRACT)}
    write_reports(root, scenario, evaluation)
    evaluation["output_sha256"].update(
        {
            p: digest(root / p)
            for p in (
                "analysis/scenarios/scenario-demonstration.md",
                "analysis/evaluation/evaluation-report.md",
            )
        }
    )
    save_json(root / EVALUATION, evaluation)
    print(
        f"Passed: {len(triples)} live triples; primary {triples[0]['host']}; "
        f"{len(specs)} review units; {len(ids)} source IDs; "
        f"{len(evaluation['activity']['event_rows'])} refined activity rows",
        flush=True,
    )
    return evaluation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reuse-validated-prerequisites",
        action="store_true",
        help=(
            "Reuse hash-checked individual detection and event correlation "
            "outputs; still verify live evidence/state"
        ),
    )
    args = parser.parse_args()
    run(replay=not args.reuse_validated_prerequisites)


if __name__ == "__main__":
    main()
