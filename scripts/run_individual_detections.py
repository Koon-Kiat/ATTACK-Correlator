"""Run and verify historical single-event ES|QL detections; no rules/indexes are installed."""

import json
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, load_json, request, save_json  # noqa: E402
from scripts.inspect_selection_relationships import compact, nanos  # noqa: E402
from scripts.inspect_technique_candidates import FIELDS, PATTERN, fetch_events  # noqa: E402
from scripts.verify_technique_selection import require  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402

END = "\n| KEEP event.id, @timestamp, host.name\n| SORT event.id ASC\n| LIMIT 10000"
FIELD_RE = re.compile(
    r"\b(?:event|host|user|process|registry|file|dll|source|destination)\.[a-zA-Z0-9_.]+|@timestamp"
)
EVIDENCE_FIELDS = [
    field
    for field in FIELDS
    if not field.startswith(("windows_apt.annotations", "windows_apt.scenario"))
]
QUERY_IDS = {
    "powershell_baseline",
    "powershell_refined",
    "powershell_kql_review",
    "shell_baseline",
    "shell_refined",
    "shell_kql_review",
    "service_installation",
    "service_registry",
    "service_kql_review",
    "service_create_baseline",
    "service_create_refined",
    "service_config_baseline",
    "service_config_refined",
}


def field(event, name):
    value = event
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def lower(event, name):
    value = field(event, name)
    return value.lower() if isinstance(value, str) else ""


def matches(pattern, command):
    return re.fullmatch(pattern, command, re.DOTALL) is not None


def observed_conditions(event):
    """Independent source readback checks; never execute/decode dataset commands."""
    command = lower(event, "process.command_line")
    return {
        "retrieval": matches(
            r".*(invoke-webrequest|downloadstring|downloadfile|[^a-z0-9_]iwr[^a-z0-9_]).*", command
        ),
        "execution": matches(
            r".*(invoke-expression|[^a-z0-9_]iex[^a-z0-9_]|start-process).*", command
        ),
        "hidden": matches(r".*[ ]-(w|windowstyle)[ ]+hidden([ ].*)?", command),
        "no_profile": matches(r".*[ ]-(nop|noprofile)([ ].*)?", command),
        "inline_command": matches(r".*[ ]-(c|command)[ ]+.*", command),
        "service_parent_interpreter": (
            lower(event, "process.parent.name") == "services.exe"
            and matches(r".*(powershell[.]exe|pwsh[.]exe).*", command)
        ),
        "service_control_interpreter": matches(
            r".*[ ]sc([.]exe)?[ ]+(create|config)[ ]+.*binpath=.*"
            r"(cmd[.]exe|powershell[.]exe|pwsh[.]exe).*",
            command,
        ),
        "interpreter_binpath": matches(
            r".*binpath=.*(cmd[.]exe|powershell[.]exe|pwsh[.]exe).*", command
        ),
    }


def source_matches(query_id, event):
    require(query_id in QUERY_IDS, f"No independent source verifier for query: {query_id}")
    provider, code = field(event, "event.provider"), field(event, "event.code")
    process = provider == "Microsoft-Windows-Sysmon" and code == "1"
    name, command = lower(event, "process.name"), lower(event, "process.command_line")
    c = observed_conditions(event)
    if query_id == "service_installation":
        return provider == "Service Control Manager" and code == "7045"
    if query_id == "service_registry":
        return (
            provider == "Microsoft-Windows-Sysmon"
            and code == "13"
            and matches(r".*currentcontrolset.*services.*imagepath", lower(event, "registry.path"))
        )
    if query_id.endswith("_kql_review"):
        names = {
            "powershell_kql_review": {"powershell.exe", "pwsh.exe"},
            "shell_kql_review": {"cmd.exe"},
            "service_kql_review": {"sc.exe"},
        }
        # KQL keyword spelling is exact; authoritative ES|QL lowercases comparison values.
        return (
            process
            and field(event, "process.name") in names[query_id]
            and (field(event, "process.command_line") is not None)
        )
    if query_id.startswith("powershell_"):
        return (
            process
            and name in {"powershell.exe", "pwsh.exe"}
            and (
                query_id.endswith("baseline")
                or (
                    (c["retrieval"] and c["execution"])
                    or (c["hidden"] and c["no_profile"] and c["inline_command"])
                )
            )
        )
    if query_id.startswith("shell_"):
        return (
            process
            and name == "cmd.exe"
            and (
                query_id.endswith("baseline")
                or c["service_parent_interpreter"]
                or c["service_control_interpreter"]
            )
        )
    operation = "create" if "_create_" in query_id else "config"
    return (
        process
        and name == "sc.exe"
        and f" {operation} " in command
        and (operation != "config" or "binpath=" in command)
        and (query_id.endswith("baseline") or c["interpreter_binpath"])
    )


def check_manifest(manifest, selection):
    expected = [t["attack_id"] for t in selection["selected"]]
    require(
        [t["attack_id"] for t in manifest["techniques"]] == expected,
        "Detection slots must match the three selected sub-techniques",
    )
    require(manifest["index_pattern"] == PATTERN, "Unexpected index pattern")
    require(manifest["matching_unit"] == "distinct event.id", "Unexpected matching unit")
    ids = []
    for number, technique in enumerate(manifest["techniques"], 1):
        require(technique["directory"] == f"detections/technique-{number}", "Wrong slot directory")
        for query in technique["queries"]:
            require(
                Path(query["file"]).parent.as_posix() == technique["directory"],
                "Query must stay in its assigned directory",
            )
            ids.append(query["id"])
        lookup = {q["id"]: q for q in technique["queries"]}
        for key, role in (
            ("baseline_query_file", "baseline"),
            ("authoritative_refined_query_file", "refined"),
            ("kql_file", "review_filter"),
        ):
            require(
                any(
                    q["file"] == technique[key] and q["role"] == role for q in technique["queries"]
                ),
                f"Manifest query pointer or role differs: {key}",
            )
        require(technique["matching_unit"] == "distinct event.id", "Unexpected technique unit")
        for query in technique["queries"]:
            require(query["role"] != "refined" or "refines" in query, "Missing paired baseline")
            if "refines" in query:
                require(
                    query["refines"] in lookup
                    and lookup[query["refines"]]["cohort"] == query["cohort"]
                    and lookup[query["refines"]]["role"] in {"baseline", "comparison_baseline"},
                    "Refinement cannot compare different service-event cohorts",
                )
    require(len(ids) == len(set(ids)), "Duplicate query IDs")
    require(set(ids) == QUERY_IDS, "Query inventory differs from independent source verifiers")


def read_query(root, spec):
    text = (root / spec["file"]).read_text(encoding="utf-8").strip()
    require(
        text and not re.search(r"PENDING|unassigned|placeholder", text, re.I),
        "Query is still a placeholder",
    )
    require(
        not re.search(r"windows_apt|\bscenario\b|\bthreat\.|\brule\.", text, re.I),
        "Contextual labels or unindexed originals cannot be query predicates",
    )
    if spec["language"] == "kql":
        return f"FROM {PATTERN}\n| WHERE KQL({json.dumps(text)})" + END
    require(spec["language"] == "esql", "Unsupported query language")
    require(text.startswith(f"FROM {PATTERN}\n"), "Query must read the historical index")
    require(
        set(re.findall(r"\|\s*([A-Z_]+)\b", text)) <= {"WHERE", "EVAL", "KEEP", "SORT", "LIMIT"}
        and "\n| WHERE " in text,
        "Individual query must preserve a single-event matching unit",
    )
    require(
        len(re.findall(r"\|\s*LIMIT\b", text, re.I)) == 1 and text.endswith("| LIMIT 10000"),
        "Expected one final export limit",
    )
    require(text.count("\n| KEEP ") == 1, "Expected one output projection")
    return text


def esql(query, client=request):
    result = client("/_query?allow_partial_results=false", {"query": query}, method="POST")
    require(result.get("is_partial") is False, "ES|QL returned partial or uncertain results")
    columns = [column["name"] for column in result["columns"]]
    return [dict(zip(columns, row, strict=True)) for row in result["values"]]


def summarize(rows, total):
    require(len(rows) == total, "ES|QL export truncated; complete count exceeds returned rows")
    require(
        all(isinstance(row.get("event.id"), str) and row["event.id"] for row in rows),
        "Every match needs an event ID",
    )
    unique = {}
    for row in rows:
        event_id = row["event.id"]
        require(
            event_id not in unique or unique[event_id] == row, "Conflicting rows share an event ID"
        )
        unique[event_id] = row
    timestamps = [row["@timestamp"] for row in unique.values() if row.get("@timestamp")]
    hosts = sorted({row["host.name"] for row in unique.values() if row.get("host.name")})
    ids = sorted(unique)
    return {
        "raw_returned_rows": len(rows),
        "distinct_event_count": len(ids),
        "duplicate_returned_rows": len(rows) - len(ids),
        "event_ids": ids,
        "unique_host_count": len(hosts),
        "hosts": hosts,
        "with_timestamp": len(timestamps),
        "without_timestamp": len(ids) - len(timestamps),
        "historical_time_range": {
            "min_utc": min(timestamps, key=nanos) if timestamps else None,
            "max_utc": max(timestamps, key=nanos) if timestamps else None,
            "precision": "nanoseconds; absent timestamps excluded only from min/max",
        },
    }


def check_baseline(spec, result, phase5_queries):
    key = spec.get("phase5_query_key")
    if key:
        prior = phase5_queries[key]
        require(
            result["distinct_event_count"] == prior["count"],
            f"technique selection baseline count contradiction: {spec['id']}",
        )
        require(
            result["with_timestamp"] == prior["with_timestamp"],
            f"technique selection timestamp coverage contradiction: {spec['id']}",
        )


def choose_examples(ids, lookup, refined=False):
    ids = sorted(set(ids))
    chosen = set(ids[:3])
    if refined:
        # Include each observed signal family deterministically, not just one frequent command.
        for condition in observed_conditions({}):
            chosen.update([i for i in ids if observed_conditions(lookup[i])[condition]][:2])
        commands = {}
        for i in ids:
            commands.setdefault(field(lookup[i], "process.command_line"), i)
        chosen.update(list(commands.values())[:6])
    return sorted(chosen)


def verify_readback(rows, lookup, query_id):
    for row in rows:
        event_id = row["event.id"]
        require(event_id in lookup, f"Missing live event: {event_id}")
        event = lookup[event_id]
        require(source_matches(query_id, event), f"Source does not support query {query_id}")
        require(row.get("host.name") == field(event, "host.name"), "Host differs from source")
        require(
            nanos(row.get("@timestamp")) == nanos(event.get("@timestamp")),
            "Timestamp differs from source",
        )
        for key, value in observed_conditions(event).items():
            if key in row:
                require(row[key] == value, f"ES|QL/source condition mismatch: {key}")


def fetch_evidence(ids, client=request, fields=EVIDENCE_FIELDS):
    """Bound each ids query below Elasticsearch's result-window limit."""
    ordered = sorted(set(ids))
    events = []
    for start in range(0, len(ordered), 1000):
        batch = ordered[start : start + 1000]
        found = fetch_events({"ids": {"values": batch}}, client, fields)
        require(
            sorted(field(e, "event.id") for e in found) == batch,
            "A requested event ID is absent or duplicated in live evidence readback",
        )
        events.extend(found)
    return events


def run(root=ROOT, client=request):
    out = root / "analysis/detections/detection-results.json"
    save_json(out, {"passed": False, "status": "live individual detection validation started"})
    report_path = out.with_name("detection-report.md")
    report_path.write_text(
        "# individual detection verification pending\n\nA new run started; "
        "consult detection-results.json.\n",
        encoding="utf-8",
    )
    manifest = load_json(root / "detections/manifest.json")
    selection = load_json(root / "analysis/technique_selection.json")
    phase5 = load_json(root / "analysis/selection/selection-verification.json")
    check_manifest(manifest, selection)
    require(phase5["passed"], "Existing technique selection verification must pass")
    require(
        load_json(root / "analysis/ingestion/ingestion-validation.json")["passed"],
        "Existing ingestion validation must pass",
    )
    replay_path = root / "analysis/detections/prerequisites/ingestion-validation.json"
    replay = load_json(replay_path)
    require(
        replay["passed"] and replay["event_count"]["actual"] == 102011,
        "Fresh ingestion validation replay must pass; run validate_ingestion.py --output-directory "
        "analysis/detections/prerequisites",
    )
    for name, expected in phase5["artifact_sha256"].items():
        require(digest(root / name) == expected, f"technique selection artifact changed: {name}")
    phase5_state = load_json(root / "analysis/selection/live-state.json")
    require(
        digest(root / "analysis/ingestion/ingestion-validation.json")
        == phase5_state["phase4_validation_sha256"],
        "ingestion validation report changed after technique selection",
    )
    prior_queries = load_json(root / "analysis/selection/exploratory-queries.json")

    def live_totals():
        total = client(f"/{PATTERN}/_count")["count"]
        timed = client(
            f"/{PATTERN}/_count", {"query": {"exists": {"field": "@timestamp"}}}, method="POST"
        )["count"]
        require(
            (total, timed) == (102011, 90601),
            "Live index contradicts ingestion validation and technique selection",
        )
        return {"total": total, "with_timestamp": timed, "without_timestamp": total - timed}

    live_totals()
    rows_by_query, results, query_texts = {}, {}, {}
    for technique in manifest["techniques"]:
        for spec in technique["queries"]:
            query_id = spec["id"]
            query = read_query(root, spec)
            query_texts[query_id] = query
            count_query = query.split("\n| KEEP ")[0] + "\n| STATS total_rows = COUNT(*)"
            total = esql(count_query, client)[0]["total_rows"]
            rows = esql(query, client)
            result = summarize(rows, total)
            check_baseline(spec, result, prior_queries)
            require(esql(query, client) == rows, f"Non-reproducible query result: {query_id}")
            require(
                spec["role"] != "refined" or result["distinct_event_count"] > 0,
                f"Refined query has no observed evidence: {query_id}",
            )
            result.update(
                spec
                | {
                    "query": query,
                    "count_query": count_query,
                    "query_sha256": digest(root / spec["file"]),
                    "exact_replay_passed": True,
                }
            )
            results[query_id], rows_by_query[query_id] = result, rows
            print(query_id, result["distinct_event_count"], "distinct events", flush=True)

    fields = sorted(set().union(*(set(FIELD_RE.findall(q)) for q in query_texts.values())))
    caps = client(f"/{PATTERN}/_field_caps", {"fields": fields}, method="POST")["fields"]
    for name in fields:
        require(
            name in caps and all(c.get("searchable") for c in caps[name].values()),
            f"Missing or unsearchable field: {name}",
        )

    all_ids = sorted(set().union(*(set(r["event_ids"]) for r in results.values())))
    events = fetch_evidence(all_ids, client)
    lookup = {event["event"]["id"]: event for event in events}
    require(set(lookup) == set(all_ids), "A returned event ID is absent from live readback")
    for query_id, rows in rows_by_query.items():
        verify_readback(rows, lookup, query_id)
        result = results[query_id]
        result["field_missing_counts"] = {
            name: sum(field(lookup[i], name) is None for i in result["event_ids"])
            for name in sorted(set(FIELD_RE.findall(query_texts[query_id])))
        }
        if "refines" in result:
            baseline = results[result["refines"]]
            baseline_ids = set(baseline["event_ids"])
            require(set(result["event_ids"]) <= baseline_ids, "Refined events escape their cohort")
            source_ids = sorted(i for i in baseline_ids if source_matches(query_id, lookup[i]))
            require(source_ids == result["event_ids"], "Source evaluation contradicts refined set")
            require(
                result["distinct_event_count"] < baseline["distinct_event_count"],
                f"Refinement removes no candidates; investigate {query_id}",
            )
            result["candidate_volume_removed"] = len(baseline_ids) - result["distinct_event_count"]
            result["removed_example_ids"] = sorted(baseline_ids - set(result["event_ids"]))[:3]
            result["signal_counts"] = dict(
                Counter(
                    key
                    for i in result["event_ids"]
                    for key, value in observed_conditions(lookup[i]).items()
                    if value
                )
            )
            result["baseline_signal_counts"] = dict(
                Counter(
                    key
                    for i in sorted(baseline_ids)
                    for key, value in observed_conditions(lookup[i]).items()
                    if value
                )
            )
            result["branch_counts"] = (
                {
                    "retrieval_and_execution": sum(
                        observed_conditions(lookup[i])["retrieval"]
                        and observed_conditions(lookup[i])["execution"]
                        for i in result["event_ids"]
                    ),
                    "hidden_no_profile_inline": sum(
                        all(
                            observed_conditions(lookup[i])[k]
                            for k in ("hidden", "no_profile", "inline_command")
                        )
                        for i in result["event_ids"]
                    ),
                }
                if query_id == "powershell_refined"
                else result["signal_counts"]
            )

    for a, b in (
        ("service_create_baseline", "service_config_baseline"),
        ("service_installation", "service_registry"),
    ):
        require(
            not set(results[a]["event_ids"]) & set(results[b]["event_ids"]),
            "Service cohorts unexpectedly overlap; investigate before combining results",
        )

    evidence_ids = set()
    for result in results.values():
        result["representative_event_ids"] = choose_examples(
            result["event_ids"], lookup, result["role"] == "refined"
        )
        evidence_ids.update(result["representative_event_ids"])
        evidence_ids.update(result.get("removed_example_ids", []))
    for technique in manifest["techniques"]:
        evidence_ids.update(c["event_id"] for c in technique["comparisons"])
    require(evidence_ids <= set(lookup), "A comparison example is absent from observed cohorts")
    service_ids = sorted(
        i for i in evidence_ids if source_matches("service_installation", lookup[i])
    )
    if service_ids:
        originals = fetch_events(
            {"ids": {"values": service_ids}}, client, EVIDENCE_FIELDS + ["windows_apt.original"]
        )
        lookup.update({event["event"]["id"]: compact(event) for event in originals})

    completed = datetime.now(UTC).isoformat()
    for technique in manifest["techniques"]:
        technique["latest_validated_match_counts"] = {
            spec["id"]: results[spec["id"]]["distinct_event_count"] for spec in technique["queries"]
        }
        technique["validated_at_utc"] = completed
    report = {
        "passed": True,
        "phase": 6,
        "validated_at_utc": completed,
        "index_pattern": PATTERN,
        "scope": manifest["scope"],
        "live_counts": live_totals(),
        "matching_unit": "distinct event.id",
        "query_count": len(results),
        "all_match_ids_verified": len(all_ids),
        "searchable_fields_verified": fields,
        "queries": results,
        "techniques": manifest["techniques"],
        "evidence": {i: compact(lookup[i]) for i in sorted(evidence_ids)},
        "method": (
            "Full COUNT(*) before the export LIMIT guards truncation. Exact distinct IDs and "
            "hosts use complete returned sets, not approximate cardinality. Every query is "
            "replayed; all IDs and claimed fields are verified against live source projections. "
            "Refined sets are independently checked against their paired baseline source events."
        ),
        "limitations": [
            "Candidate-volume changes are not measured false-positive or false-negative changes.",
            "KQL files are coarse review filters; refined ES|QL is authoritative.",
            "No final correlation, Security rule installation or dashboard is included.",
            "Queries cover the historical corpus; null fields fail positive conditions safely.",
            "The runner fails rather than accepting an export truncated by ES|QL row limits.",
            "Service installation, create/config commands and registry units remain separate.",
            "Command patterns show visible intent; quoted strings and comments can still match.",
        ],
        "prerequisite_sha256": {
            name: digest(root / name)
            for name in (
                "analysis/ingestion/ingestion-validation.json",
                "analysis/detections/prerequisites/ingestion-validation.json",
                "analysis/selection/selection-verification.json",
                "analysis/technique_selection.json",
            )
        },
    }
    save_json(root / "detections/manifest.json", manifest)
    report["manifest_sha256"] = digest(root / "detections/manifest.json")
    report["runner_sha256"] = digest(Path(__file__))
    write_report(report_path, report)
    write_readmes(root, report)
    save_json(out, report)
    return report


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def write_report(path, report):
    lines = [
        "# Individual detection results",
        "",
        f"Validated UTC: {report['validated_at_utc']}. Live verification passed.",
        "",
        report["scope"],
        "",
        report["method"],
        "",
        "All counts below use distinct event.id; these are detection candidates, not attacks.",
        "",
        "| Query / cohort | Raw rows | Distinct IDs | Hosts | Timed / undated | First / last UTC |",
        "|---|---:|---:|---:|---|---|",
    ]
    for q in report["queries"].values():
        time = q["historical_time_range"]
        lines.append(
            f"| {q['id']} / {q['cohort']} | {q['raw_returned_rows']} | "
            f"{q['distinct_event_count']} | {q['unique_host_count']} | "
            f"{q['with_timestamp']} / {q['without_timestamp']} | "
            f"{time['min_utc']} / {time['max_utc']} |"
        )
    for technique in report["techniques"]:
        lines += [
            "",
            f"## {technique['attack_id']} — {technique['name']}",
            "",
            technique["logic"],
            "",
            f"Tactics: {', '.join(technique['tactics'])}. {technique['kql_role']}",
            "",
        ]
        for spec in technique["queries"]:
            q = report["queries"][spec["id"]]
            lines += [
                f"### {q['id']}",
                "",
                f"Query source: [{Path(q['file']).name}](../../{q['file']}). Role: {q['role']}.",
                "",
            ]
            if q["language"] == "esql":
                lines += ["```esql", q["query"], "```", ""]
            if "refines" in q:
                base = report["queries"][q["refines"]]
                lines += [
                    f"Candidate volume: **{base['distinct_event_count']} → "
                    f"{q['distinct_event_count']}** within `{q['cohort']}`; "
                    f"{q['candidate_volume_removed']} baseline events excluded. "
                    "This is not a measured false-positive reduction.",
                    "",
                    f"Observed signal/branch counts (may overlap): `{q['branch_counts']}`.",
                    "",
                ]
            lines += [
                "Representative IDs: "
                + ", ".join(f"`{i}`" for i in q["representative_event_ids"])
                + ".",
                "",
            ]
        lines += [
            "### Representative evidence and comparisons",
            "",
            "Full commands, parent fields and source-file/row/hash provenance are in "
            "[detection-results.json](detection-results.json). Excerpts below are display-only.",
            "",
            "| Event ID | UTC / host | Command or service object excerpt |",
            "|---|---|---|",
        ]
        ids = set(c["event_id"] for c in technique["comparisons"])
        for spec in technique["queries"]:
            if spec["role"] == "refined":
                ids.update(report["queries"][spec["id"]]["representative_event_ids"])
        for i in sorted(ids):
            e = report["evidence"][i]
            value = field(e, "process.command_line") or e["windows_apt"].get("original", {}).get(
                "_source.data.win.eventdata.imagePath", "No command field"
            )
            lines.append(
                f"| `{i}` | {e.get('@timestamp')} / {field(e, 'host.name')} | {cell(value[:240])} |"
            )
        lines += [""] + [
            f"- `{c['event_id']}`: {c['explanation']}" for c in technique["comparisons"]
        ]
        lines += ["", "False-positive candidates:", ""]
        lines += [f"- {text}" for text in technique["false_positive_candidates"]]
        lines += ["", "False-negative/evasion and telemetry limitations:", ""]
        lines += [f"- {text}" for text in technique["false_negative_limitations"]]
        lines += [
            "",
            "ATT&CK/CAR references (accessed "
            + technique["reference_access_date_utc"]
            + " UTC): "
            + ", ".join(
                f"[reference {i + 1}]({url})" for i, url in enumerate(technique["reference_urls"])
            )
            + ".",
            "",
        ]
    lines += ["## Limits and reproduction", ""] + [f"- {x}" for x in report["limitations"]]
    lines += [
        "",
        "From the repository root with the verified local stack running:",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe scripts/validate_ingestion.py "
        "--output-directory analysis/detections/prerequisites",
        ".\\.venv\\Scripts\\python.exe scripts/verify_technique_selection.py",
        ".\\.venv\\Scripts\\python.exe scripts/run_individual_detections.py",
        "```",
        "",
        "The separate correlation report contains the completed multi-event analysis.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def write_readmes(root, report):
    """Keep assigned specifications and exact count tables synchronized with live results."""
    for technique in report["techniques"]:
        lines = [
            f"# {technique['attack_id']} — {technique['name']}",
            "",
            f"Tactics: {', '.join(technique['tactics'])}. Validated: {report['validated_at_utc']}.",
            "",
            "## Objective and observable telemetry",
            "",
            technique["logic"],
            "",
            f"Provider/event codes: `{technique['providers_event_codes']}`.",
            "",
            technique["baseline_rationale"],
            "",
            "Predicate fields: " + ", ".join(f"`{f}`" for f in technique["predicate_fields"]) + ".",
            "",
            "Output fields: `event.id`, `@timestamp`, `host.name`; flags are returned where "
            "applicable. Process-name and installation baselines do not require command text; "
            "service-command baselines and refinements do. The shell ancestry branch also "
            "needs `process.parent.name`. Missing fields fail their positive condition "
            "without failing another independently satisfied OR branch. Missing timestamps "
            "do not prevent an individual match.",
            "",
            "Supporting evidence retains `user.name`, `process.executable`, parent command/name, "
            "process/parent entity IDs and source-file/row/hash provenance where present. "
            "These fields are context unless explicitly listed in the executable predicate.",
            "",
            "## Executable queries and counts",
            "",
            "Matching unit: **distinct event.id**. Raw rows are counted before export; full "
            "ID sets give exact host and event counts. Event observations are not attacks.",
            "",
            "| File | Role / cohort | Raw rows | Distinct events | Hosts | First / last UTC |",
            "|---|---|---:|---:|---:|---|",
        ]
        for spec in technique["queries"]:
            q = report["queries"][spec["id"]]
            time = q["historical_time_range"]
            filename = Path(q["file"]).name
            lines.append(
                f"| [{filename}]({filename}) | {q['role']} / {q['cohort']} | "
                f"{q['raw_returned_rows']} | {q['distinct_event_count']} | "
                f"{q['unique_host_count']} | {time['min_utc']} / {time['max_utc']} |"
            )
        lines += [
            "",
            technique["kql_role"],
            "",
            "## Baseline versus refinement",
            "",
            technique["refinement_tradeoff"],
            "",
        ]
        for spec in technique["queries"]:
            q = report["queries"][spec["id"]]
            if q["role"] == "refined":
                base = report["queries"][q["refines"]]
                lines += [
                    f"- `{q['cohort']}`: **{base['distinct_event_count']} → "
                    f"{q['distinct_event_count']}**, excluding {q['candidate_volume_removed']} "
                    "baseline events. This is candidate-volume reduction only.",
                    f"- Signal/branch counts (can overlap): `{q['branch_counts']}`.",
                    "- Representative event IDs: "
                    + ", ".join(f"`{i}`" for i in q["representative_event_ids"])
                    + ".",
                ]
        lines += [
            "",
            "Deterministic examples and complete queries are in the "
            "[generated report](../../analysis/detections/detection-report.md); "
            "[results JSON](../../analysis/detections/detection-results.json) retains full "
            "evidence fields, all match IDs, missing-field counts and nanosecond ranges.",
            "",
            "Routine or ambiguous comparisons:",
            "",
        ]
        lines += [f"- `{c['event_id']}`: {c['explanation']}" for c in technique["comparisons"]]
        lines += ["", "## ATT&CK and CAR grounding", ""]
        guidance = technique["attack_guidance"]
        lines += [
            f"{guidance['strategy_id']} / {guidance['analytic_id']}: {guidance['summary']}",
            "",
            guidance["present"],
            "",
            guidance["absent"],
            "",
        ]
        lines += [f"- {c['id']} ({c['name']}): {c['use']}" for c in technique["car"]]
        lines += [
            "",
            f"Official references checked {technique['reference_access_date_utc']} UTC:",
            "",
        ]
        lines += [
            f"- [MITRE reference {n}]({url})"
            for n, url in enumerate(technique["reference_urls"], 1)
        ]
        lines += ["", "## False-positive candidates", ""]
        lines += [f"- {v}" for v in technique["false_positive_candidates"]]
        lines += ["", "## False-negative, evasion and dataset limits", ""]
        lines += [f"- {v}" for v in technique["false_negative_limitations"]]
        lines += [
            "",
            "No independent event-level intent truth supports precision, recall, F1 or "
            "FPR. The corpus is lab telemetry; command text can include quoted or escaped "
            "content. A match requests review and does not establish successful execution "
            "or malicious persistence.",
            "",
            "## Historical reproduction",
            "",
            "Run the [individual detection "
            "commands](../../docs/individual-detection-implementation.md#reproduce). Queries cover "
            "`windows-apt-events-*` without a wall-clock restriction. All matched events in "
            "this validation are timed; 11,410 events elsewhere in the corpus remain undated. "
            "Standalone exports are capped at 10,000 rows; use the runner to reject truncation "
            "and partial responses. ES|QL is authoritative; no scheduled Security rules have "
            "been installed. Child-event joins and final correlation belong to event correlation.",
        ]
        (root / technique["directory"] / "README.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
        )


if __name__ == "__main__":
    result = run()
    print(
        f"Passed: {result['query_count']} queries; "
        f"{result['all_match_ids_verified']} live event IDs."
    )
