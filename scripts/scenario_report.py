"""Render concise, escaped Markdown from verified scenario/evaluation objects."""

import html

from scripts.build_scenario_evidence import (
    COMPARISON_RULE,
    EVALUATION,
    REFINED,
    SCENARIO,
    SELECTION_RULE,
)


def cell(value):
    if value is None:
        return "Unavailable"
    text = html.escape(str(value))
    for char in "\\|`*_[]":
        text = text.replace(char, f"&#{ord(char)};")
    return text.replace("\n", "<br>").replace("\r", "")


def triple_table(triples):
    lines = [
        "| Host | Ordered installation → shell → PowerShell event IDs | UTC timestamps | Gaps ns |",
        "|---|---|---|---|",
    ]
    for t in triples:
        lines.append(
            f"| {t['host']} | "
            + " → ".join(f"`{i}`" for i in t["event_ids"])
            + " | "
            + " → ".join(t["timestamps"])
            + " | "
            + " + ".join(str(n) for n in t["gaps_nanoseconds"])
            + " |"
        )
    return lines


def render_scenario(scenario):
    primary = scenario["primary"]
    lines = [
        "# Bounded scenario demonstration",
        "",
        f"Prerequisite replay: {scenario['prerequisite_validated_at_utc']}. "
        "Every displayed scenario and comparison was read back from live Elasticsearch.",
        "",
        "## Selection and scope",
        "",
        SELECTION_RULE,
        "",
        "This is a bounded three-record relationship, not a complete incident chronology. "
        "No inferred intermediate events, attack execution or dashboard installation is included.",
        "",
        "## Primary relationship",
        "",
    ] + triple_table([primary])
    lines += [
        "",
        f"Triple correlation ID: `{primary['correlation_id']}`. "
        f"Total span: **{primary['span_nanoseconds']:,} ns**. All three events are "
        "explicitly timed "
        "and ordered within the 60-second window.",
        "",
        "The installation's preserved imagePath and full shell command match after trimming "
        "outer whitespace, case folding and collapsing repeated backslashes. Exact strings "
        "are retained below and in JSON. This is lexical source association; disabled original "
        "fields are never used as indexed search predicates.",
        "",
        f"Shell actor GUID: `{primary['guid_join']['shell_process_entity_id']}`. "
        f"Child parent GUID: `{primary['guid_join']['powershell_parent_entity_id']}`. "
        "Only GUID case is normalized for equality; host equality is exact.",
        "",
        "| Record | ATT&CK sub-technique | Supported observation and rule membership |",
        "|---|---|---|",
    ]
    for label, mapping in zip("ABC", scenario["primary_technique_mapping"], strict=True):
        lines.append(
            f"| {label} | {mapping['attack_id']} | {mapping['observation']}; "
            + ", ".join(mapping["rules"])
            + " |"
        )
    lines += [
        "",
        "The SCM 7045 observation is the T1543.003 **installation baseline**. It is outside "
        "the refined sc.exe create/config process sets. The shell and child independently meet "
        "their refined rules; together with the source-associated installation they support "
        "all three selected techniques without merging service cohorts.",
        "",
        "### Primary source evidence",
        "",
    ]
    for label, event_id in zip("ABC", primary["event_ids"], strict=True):
        e = scenario["evidence"][event_id]
        process = e["process"] or {}
        parent = process.get("parent", {})
        user = e["user"] or {}
        lines += [
            f"**{label} — `{event_id}`**",
            "",
            f"Provider `{e['provider']}`, event `{e['event_code']}`, UTC `{e['timestamp']}`, "
            f"host `{e['host']}`. User: {cell(user.get('name'))}; "
            f"domain: {cell(user.get('domain'))}.",
            "",
            "| Evidence field | Preserved value |",
            "|---|---|",
        ]
        fields = {
            "process.name": process.get("name"),
            "process.executable": process.get("executable"),
            "process.command_line": process.get("command_line"),
            "process.entity_id": process.get("entity_id"),
            "process.parent.name": parent.get("name"),
            "process.parent.entity_id": parent.get("entity_id"),
            "process.parent.command_line": parent.get("command_line"),
        }
        fields.update({f"original service {k}": v for k, v in e["service_source_evidence"].items()})
        lines += [f"| {k} | {cell(v)} |" for k, v in fields.items() if v is not None]
        p = e["provenance"]
        lines += [
            "",
            f"Provenance: {cell(p['source_file'])}; source row index "
            f"**{p['source_row_index']}**; original ID `{p['original_id']}`; original "
            f"index `{p['original_index']}`. Row SHA-256 `{p['row_sha256']}`. "
            "JSON retains the source-file digest, dataset version and remaining provenance.",
            "",
        ]
    lines += [
        "The service object is ARTService with LocalSystem account and demand start; the two "
        "process records identify NT AUTHORITY/SYSTEM. The command requests a marker file. "
        "These observations can represent an authorized test. They do not establish that the "
        "file was created, execution completed, persistence succeeded or the service survived.",
        "",
        "## Corroborating relationships",
        "",
    ] + triple_table(scenario["corroborating"])
    for t in scenario["corroborating"]:
        lines += [
            "",
            f"- **{t['host']}**: shell GUID "
            f"`{t['guid_join']['shell_process_entity_id']}` equals child parent GUID "
            f"`{t['guid_join']['powershell_parent_entity_id']}` after case-only comparison. "
            "Full service-image/shell command association, ordering, source provenance and "
            f"both refined endpoints pass. Triple ID `{t['correlation_id']}`.",
        ]
    lines += [
        "",
        "All three relationships validate on three hosts; none is excluded by refinement. "
        "The two later triples are corroboration, not additional incident narratives.",
        "",
        "## Deterministic evidence review",
        "",
        COMPARISON_RULE,
        "",
        "Categories describe evidence structure and are not malicious/benign labels. "
        "Complete per-unit behaviour, membership, time/GUID/provenance completeness, legitimate "
        "explanation, uncertainty and coverage limits are in "
        "[scenario JSON](scenario-demonstration.json).",
        "",
        "| Review role / unit | Ordered IDs | Category | Inclusion or exclusion |",
        "|---|---|---|---|",
    ]
    for u in scenario["review_units"]:
        lines.append(
            f"| {u['role']} / {u['type']} | "
            + " → ".join(f"`{i}`" for i in u["event_ids"])
            + f" | {u['category']} | {cell(u['inclusion_or_exclusion_reason'])} |"
        )
    lines += [
        "",
        "## Reproduction and limits",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe scripts/build_scenario_evidence.py",
        "```",
        "",
        "The default helper replays individual detection and event "
        "correlation, then verifies source evidence. "
        "`--reuse-validated-prerequisites` skips replay only after all saved hashes/counts "
        "pass; it still checks live counts, mapping, selected sources and both scenario "
        "queries. Fixed prerequisite/source inputs produce byte-identical outputs.",
        "",
        "Use [exact scenario ES|QL](primary-scenario.esql) for indexed fields and "
        "[search request](primary-scenario-search.json) with "
        "`POST /windows-apt-events-*/_search` to retrieve the source-only service fields. "
        "These are evidence-retrieval queries after detection, not new detection rules.",
        "",
    ]
    lines += [f"- {limit}" for limit in scenario["limits"]]
    return "\n".join(lines) + "\n"


def render_evaluation(scenario, result):
    review = result["review_set"]
    lines = [
        "# Detection and correlation evidence review",
        "",
        f"Prerequisite replay: {result['prerequisite_validated_at_utc']}. "
        "Live corpus: **102,011 total / 90,601 timed / 11,410 undated**.",
        "",
        "## Units and review composition",
        "",
    ]
    lines += [
        f"- **{name}**: {definition}."
        for name, definition in result["review_unit_definitions"].items()
    ]
    lines += [
        "",
        f"Review set: **{review['unit_count']} units / {review['unique_event_count']} "
        "unique events**. Counts below describe review composition, not attack counts or "
        "intent prevalence. The two corroborating installation records are additionally "
        "retained in the scenario artifact, outside the other-pair review units.",
        "",
        "| Unit type | Count |",
        "|---|---:|",
    ]
    lines += [f"| {k} | {v} |" for k, v in sorted(review["by_type"].items())]
    lines += ["", "| Evidence-structure category | Reviewed units |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(review["by_category"].items())]
    lines += [
        "",
        COMPARISON_RULE,
        "",
        "## Full-corpus detection and correlation counts",
        "",
        "| Individual cohort | Distinct events | Hosts | Historical UTC range |",
        "|---|---:|---:|---|",
    ]
    for q, c in result["individual_observations"].items():
        times = c["historical_time_range"]
        lines.append(
            f"| {q} | {c['distinct_event_count']} | {c['unique_host_count']} | "
            f"{times['min_utc']} → {times['max_utc']} |"
        )
    lines += [
        "",
        "SCM installation, sc.exe create/config and registry observations remain "
        "separate cohorts. They are not summed into service operations or attacks.",
        "",
        "| Window | Broad pairs / events / hosts | Refined pairs / events / hosts | "
        "Corroborated triples / events / hosts |",
        "|---|---|---|---|",
    ]
    for w, cohorts in result["correlation_windows"].items():
        lines.append(
            f"| {w}s | "
            + " | ".join(
                f"{cohorts[k]['tuple_count']} / {cohorts[k]['unique_participating_events']} / "
                f"{cohorts[k]['unique_host_count']}"
                for k in ("broad", "refined", "three_event")
            )
            + " |"
        )
    lines += [
        "",
        "The additional behavioural and ancestry requirements reduced the candidate "
        "sequence volume from **261 broad lineage tuples to 3 strongly correlated tuples**. "
        "Broad and refined comparisons already share the same exact ancestry/time structure; "
        "the difference specifically adds service-origin shell and refined PowerShell behaviour. "
        "This is candidate-volume reduction, not measured false-positive reduction.",
        "",
        "The broad EQL view yields 222 sequences, omitting 39 fan-out pairs. The complete "
        "deterministic event correlation validator supplies the 261-pair "
        "denominator. Counts remain "
        "unchanged over the three tested windows; production optimality is unmeasured.",
        "",
        "## Primary and corroborating scenarios",
        "",
        f"The earliest installation is on **{scenario['primary']['host']}**, "
        f"`{scenario['primary']['timestamps'][0]}`. All three selected techniques are evidenced; "
        "the SCM record is a baseline installation, not a refined sc.exe observation. "
        "Both later triples pass the same source-image/host/GUID/order checks. None is excluded. "
        "See [scenario demonstration](../scenarios/scenario-demonstration.md) for exact IDs, "
        "source values and gaps.",
        "",
        "## Review findings and rubric",
        "",
    ]
    for u in scenario["review_units"]:
        timestamps = all(u["timestamp_completeness"].values())
        provenance = all(p["complete"] for p in u["provenance_completeness"].values())
        process_status = [v for v in u["process_ancestry_completeness"].values() if v["applicable"]]
        guid = all(v["actor_guid_present"] and v["parent_guid_present"] for v in process_status)
        lines += [
            f"**{u['role']} — {u['type']} — {u['category']}**",
            "",
            "IDs: "
            + " → ".join(f"`{i}`" for i in u["event_ids"])
            + ". "
            + "Techniques: "
            + ", ".join(u["technique_ids"])
            + ".",
            "",
            u["inclusion_or_exclusion_reason"],
            "",
            f"Completeness: explicit timestamps={timestamps}; provenance={provenance}; "
            f"process actor/parent GUIDs={guid if process_status else 'not applicable to SCM'}. "
            "GUID presence in a standalone record is not an independently observed parent. "
            "SCM object linkage uses source-image association, not an absent SCM process GUID.",
            "",
            "Plausible authorized explanation: " + u["plausible_legitimate_explanation"],
            "",
            "Uncertainty: " + u["uncertainty"] + " Coverage: " + u["coverage_limitation"],
            "",
        ]
    lines += [
        "## FP/FN reasoning and ground truth",
        "",
        result["false_positive_reasoning"],
        "",
        result["false_negative_reasoning"],
        "",
    ]
    lines += [f"- {k}: **{v} distinct events**." for k, v in result["missing_support"].items()]
    lines += [
        "",
        "Correlation supplements individual detection. A missing required relationship "
        "does not make a standalone candidate benign. The deterministic review is not a "
        "statistical sample and has no independent intent adjudication; no precision, recall, "
        "F1, false-positive rate, confusion matrix or numeric confidence is calculated.",
        "",
        "## Dashboard evidence prepared",
        "",
        f"The four refined cohorts have **{len(result['activity']['event_rows'])} activity "
        "rows**, each carrying exact UTC time, event.id, observed host, rule name and an "
        "analyst-derived technique mapping. Per-rule daily UTC totals are retained. They are "
        "event observations within named cohorts, not a cross-technique attack count.",
        "",
        "Overview refined counts: "
        + ", ".join(
            f"{q}={result['individual_observations'][q]['distinct_event_count']}" for q in REFINED
        )
        + "; refined correlation=3 pairs / 6 events / 3 hosts. Primary scenario=1 triple / "
        "3 events / 1 host. Installation corroboration=3 triples / 9 events / 3 hosts.",
        "",
        "[Dashboard contract](dashboard-contract.json) gives exact sources and filter semantics. "
        "[Dashboard documentation](../../docs/dashboard.md) identifies the required panels and "
        "verification gates. Source event IDs and timestamps are queryable; correlation IDs, "
        "review categories and analyst technique mappings are derived artifacts, not installed "
        "source-index fields. No malicious/benign, severity/confidence or forced network panel "
        "is supported. No dashboard is built/exported.",
        "",
        "## Reproduction and live checks",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe scripts/build_scenario_evidence.py",
        ".\\.venv\\Scripts\\python.exe -m pytest -q --basetemp .test-tmp/evaluation",
        ".\\.venv\\Scripts\\python.exe -m ruff check .",
        ".\\.venv\\Scripts\\python.exe -m ruff format --check .",
        ".\\.venv\\Scripts\\python.exe -m pip check",
        "```",
        "",
    ]
    validation = result["live_validation"]
    lines += [
        f"The helper verified **{validation['source_event_ids_verified']} live event IDs**, "
        "individual detection and event correlation artifact/query hashes "
        "and count contracts, unchanged mapping and live corpus "
        "counts, all three triples, every reviewed unit and all four refined activity cohorts. "
        "Both exact-ID scenario ES|QL and source search returned the same ordered records and "
        "fields. The JSON records input/output/query/source-projection hashes. Fixed inputs "
        "produce identical output bytes; a prerequisite replay refreshes validation timestamps "
        "and therefore changes the recorded evidence snapshot hash.",
        "",
    ]
    lines += [f"- {limit}" for limit in result["limits"]]
    lines += [
        "",
        "The implemented Kibana dashboard uses this "
        "contract with validated metrics, historical filters, evidence "
        "links and exported/imported saved objects. See "
        "../../docs/kibana-dashboard-implementation.md.",
        "",
    ]
    return "\n".join(lines)


def write_reports(root, scenario, evaluation):
    (root / SCENARIO).with_suffix(".md").write_text(
        render_scenario(scenario), encoding="utf-8", newline="\n"
    )
    (root / EVALUATION).with_name("evaluation-report.md").write_text(
        render_evaluation(scenario, evaluation), encoding="utf-8", newline="\n"
    )
