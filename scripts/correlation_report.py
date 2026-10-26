"""Concise report rendering for verified historical correlation results."""

import json

from scripts.run_individual_detections import cell, field


def write_report(path, report, root):
    default = report["windows"][str(report["default_window_seconds"])]
    broad, refined, service = [default[k] for k in ("broad", "refined", "three_event")]
    endpoint_checks = report["eql_endpoint_validation"]
    lines = [
        "# Historical event correlation results",
        "",
        f"Live validation passed: {report['validated_at_utc']}. Elasticsearch corpus: "
        f"{report['live_counts']['total']:,} events; {report['live_counts']['timed']:,} timed, "
        f"{report['live_counts']['undated']:,} undated.",
        "",
        "## Relationship and matching units",
        "",
        "Primary: a Sysmon 1 cmd.exe from services.exe, with PowerShell in its command, "
        "followed by a separate refined PowerShell "
        "process event. Require exact "
        "host equality, shell actor GUID = child parent GUID (case-only normalization), "
        "explicit UTC time, strict ordering and an inclusive upper time bound.",
        "",
        "Individual detections count distinct event.id. Correlation counts ordered tuples "
        "of distinct event IDs. Correlation IDs hash the compact UTF-8 JSON array of ordered "
        "IDs with SHA-256. They identify repeatable evidence, not maliciousness.",
        "",
        "Broad comparison retains cmd.exe → PowerShell lineage with the same structural "
        "conditions, without requiring refined endpoint behaviour.",
        "",
        "## Window sensitivity and participation",
        "",
        "| Window | Broad tuples | Shell / PowerShell / total unique events | Broad hosts | "
        "Refined tuples | Shell / PowerShell / total unique events | "
        "Refined hosts | Removed tuples |",
        "|---|---:|---|---:|---:|---|---:|---:|",
    ]
    for window, result in report["windows"].items():
        b, r = result["broad"], result["refined"]
        lines.append(
            f"| {window}s | {b['tuple_count']} | {b['unique_first_events']} / "
            f"{b['unique_last_events']} / {b['unique_participating_events']} | "
            f"{b['unique_host_count']} | {r['tuple_count']} | {r['unique_first_events']} / "
            f"{r['unique_last_events']} / {r['unique_participating_events']} | "
            f"{r['unique_host_count']} | {result['candidate_tuple_volume_removed']} |"
        )
    insensitive = (
        len(
            {
                (v["broad"]["tuple_count"], v["refined"]["tuple_count"])
                for v in report["windows"].values()
            }
        )
        == 1
    )
    lines += [
        "",
        "The observed corpus is "
        + ("insensitive" if insensitive else "sensitive")
        + " across the tested windows. This does not establish an optimal production window.",
        "",
        f"Default: **{report['default_window_seconds']}s**. It captures all "
        f"{report['unbounded_service_origin_lineage_count']} service-origin lineage tuples "
        "found without a time cutoff. The exact validator uses `0 < gap_ns <= window × 10^9`.",
        "",
        "### Fan-out",
        "",
        "| Window / cohort | Maximum tuples per shell | Shells in multiple tuples | "
        "PowerShell events in multiple tuples | Total event participations |",
        "|---|---:|---:|---:|---:|",
    ]
    for window, result in report["windows"].items():
        for name in ("broad", "refined"):
            fan = result[name]["fan_out"]
            lines.append(
                f"| {window}s / {name} | {fan['max_tuples_per_first_event']} | "
                f"{len(fan['first_events_in_multiple_tuples'])} | "
                f"{len(fan['last_events_in_multiple_tuples'])} | "
                f"{fan['total_event_participations']} |"
            )
    lines += [
        "",
        "JSON retains each fan-out event ID and multiplicity; duplicate source IDs "
        "fail verification and duplicate tuples are suppressed before accounting.",
        "",
        "## Refined ordered tuples",
        "",
        "| Correlation ID | Shell event → PowerShell event | Host | UTC times | Gap ns |",
        "|---|---|---|---|---:|",
    ]
    for pair in refined["tuples"]:
        lines.append(
            f"| `{pair['correlation_id']}` | "
            + " → ".join(f"`{i}`" for i in pair["event_ids"])
            + f" | {pair['host']} | {' → '.join(pair['timestamps'])} | {pair['gap_nanoseconds']} |"
        )
    lines += [
        "",
        "Full original and normalized GUIDs, commands, users, provenance and exact "
        "timestamps are in [correlation-results.json](correlation-results.json). Raw preserved "
        "strings are displayed/reviewed only; no dataset command is executed.",
        "",
        "## Broad sequences removed by refinement",
        "",
        f"Candidate sequence volume changes from **{broad['tuple_count']} to "
        f"{refined['tuple_count']}** at the default window. This is not a measured "
        "false-positive reduction. Requiring the service-origin branch excludes other "
        "legitimate and suspicious shell ancestry. Refined PowerShell arguments exclude "
        "some valid interpreter use.",
        "",
        "| Ordered IDs | Exclusion reasons | Shell / child command excerpts |",
        "|---|---|---|",
    ]
    for pair in default["removed_representatives"]:
        events = [report["evidence"][i] for i in pair["event_ids"]]
        commands = " / ".join(cell((field(e, "process.command_line") or "")[:210]) for e in events)
        lines.append(
            "| "
            + " → ".join(f"`{i}`" for i in pair["event_ids"])
            + f" | {', '.join(pair['reasons'])} | {commands} |"
        )
    lines += [
        "",
        "## Service installation corroboration",
        "",
        "7045 records observe installation. Their preserved original imagePath is "
        "retrieved from `_source`, never queried as an indexed field. Compare the full "
        "command after trimming outer whitespace, case folding and collapsing repeated "
        "backslashes. Require same host, installation < shell < PowerShell and a total "
        "span within the tested window, followed by the exact GUID pair. No host/time-only "
        "fallback is permitted.",
        "",
        f"Previously observed relationships: **{service['previously_observed_validated_count']} "
        f"of {service['previously_observed_count']}** validate at the default window. "
        f"**{service['previously_observed_refined_count']}** also satisfy both current "
        "refined endpoints.",
        "",
        "| Ordered installation → shell → PowerShell IDs | Host | Gaps ns | "
        "Refined endpoints | Exclusion reasons |",
        "|---|---|---|---|---|",
    ]
    for chain in service["previously_observed_status"]:
        lines.append(
            "| "
            + " → ".join(f"`{i}`" for i in chain["event_ids"])
            + f" | {chain['host']} | {chain['gaps_nanoseconds']} | "
            f"{chain['satisfies_refined_endpoints']} | "
            f"{', '.join(chain['exclusion_reasons']) or 'None'} |"
        )
    lines += [
        "",
        "The three-record association adds independent installation and process "
        "observations. It does not establish service survival, successful persistence, "
        "command completion, file creation or malicious intent. Marker-file service tests "
        "and authorized administration remain plausible.",
        "",
        "## Missing support and FP/FN candidates",
        "",
        "| Standalone refined set / excluded support | Distinct event count |",
        "|---|---:|",
    ]
    for name, info in report["missing_support"].items():
        lines.append(f"| {name} | {info['count']} |")
    lines += [
        "",
        "These counts describe absent support for this particular rule; they are "
        "not confirmed false negatives. Powershell without cmd ancestry, direct service "
        "executables, other interpreters, missing events/GUIDs/timestamps and delays can "
        "all evade a mandatory pair. Keep individual detections available.",
        "",
        "Routine/ambiguous standalone comparisons retained from individual detection:",
        "",
    ]
    for event_id in (
        "4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c",
        "013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002",
    ):
        e = report["evidence"][event_id]
        lines.append(
            f"- `{event_id}`: `{cell((field(e, 'process.command_line') or '')[:220])}`; "
            f"parent `{field(e, 'process.parent.name')}`. Routine command semantics "
            "do not certify benign ancestry or authorization."
        )
    lines += [
        "",
        "## Query languages and live verification",
        "",
        "EQL is an executable sequence view with the same endpoint command patterns. "
        "Its runtime fields are defined in [eql-request.json](../../correlation/eql-request.json) "
        "for the request only; the index mapping is unchanged. Because EQL requires a "
        "date rather than date_nanos, it uses millisecond time plus a nanosecond tiebreaker "
        "and a one-millisecond maxspan envelope. Python checks strict ordering and the "
        "exact inclusive window from preserved UTC timestamps.",
        "",
        "Both EQL endpoint predicates were independently executed over the historical corpus "
        "and their complete event-ID sets compared with individual detection: "
        f"{endpoint_checks['service_origin_shell']['count']} service-origin shells and "
        f"{endpoint_checks['refined_powershell']['count']} refined PowerShell events. "
        "The query predicates agree on all retained endpoints.",
        "",
        "EQL maintains one pending sequence per join key/state, so it is not generally "
        "an all-pairs join. The deterministic validator enumerates full "
        "individual detection sets and "
        "reports any EQL omissions; it never uses a capped EQL response as the denominator.",
        "",
        f"Broad EQL returns {default['eql']['broad']['raw_sequence_count']} sequences; complete "
        f"enumeration retains {broad['tuple_count']} tuples. "
        f"{len(broad['fan_out']['first_events_in_multiple_tuples'])} shells have multiple "
        f"children (maximum {broad['fan_out']['max_tuples_per_first_event']}). EQL omits "
        f"{len(default['eql']['broad']['not_returned_by_eql'])} valid broad pairings. Refined EQL "
        f"returns {default['eql']['refined']['exact_validator_accepted_count']} exact accepted "
        "tuples. Fan-out examples and all omitted IDs are retained in JSON.",
        "",
        "| Window / EQL view | Raw sequences | Exact accepted | Not returned by EQL | Replayed |",
        "|---|---:|---:|---:|---|",
    ]
    for window, result in report["windows"].items():
        for name, value in result["eql"].items():
            lines.append(
                f"| {window}s / {name} | {value['raw_sequence_count']} | "
                f"{value['exact_validator_accepted_count']} | "
                f"{len(value['not_returned_by_eql'])} | {value['replayed']} |"
            )
    for filename in ("correlation.eql", "baseline.eql", "correlation.esql"):
        lines += [
            "",
            f"### {filename}",
            "",
            "```" + filename.rsplit(".", 1)[1],
            (root / "correlation" / filename).read_text(encoding="utf-8").strip(),
            "```",
        ]
    lines += [
        "",
        "ES|QL supplies an endpoint coverage census, not a temporal join:",
        "",
        "```json",
        json.dumps(report["endpoint_census"], indent=2),
        "```",
        "",
        f"All {report['all_input_event_ids_verified']:,} input IDs were fetched in bounded "
        "batches and checked against current source telemetry. individual "
        "detection was replayed first. "
        "Query, request, prerequisite and mapping hashes are recorded in the JSON.",
        "",
        "## Limitations and reproduction",
        "",
    ]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines += [
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe scripts/run_correlation.py",
        ".\\.venv\\Scripts\\python.exe scripts/run_correlation.py --window 300",
        "```",
        "",
        "The default command always evaluates 60, 300 and 900 seconds. A custom window "
        "is added to those checks. See [delivery "
        "record](../../docs/event-correlation-validation.md) for tests, "
        "scope and related completed workflows.",
        "",
        f"Elastic references checked {report['reference_access_date_utc']} UTC:",
        "",
    ]
    lines += [f"- [Elastic reference {i}]({url})" for i, url in enumerate(report["references"], 1)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
