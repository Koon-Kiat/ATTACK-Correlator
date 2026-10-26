"""Build the project dashboard using the live Kibana 9.5 public Dashboards API."""

import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.build_dashboard_data import (  # noqa: E402
    DATA_VIEW,
    INDEX,
    PATTERN,
    RULE_COUNTS,
    RULE_NAMES,
    SPACE,
    TIME_RANGE,
    prepare,
    readback,
    validate_documents,
)
from scripts.elastic_local import ROOT, load_json, save_json  # noqa: E402
from scripts.kibana_local import kibana  # noqa: E402
from scripts.run_correlation import sha_json  # noqa: E402
from scripts.verify_technique_selection import require  # noqa: E402

DASHBOARD_ID = "attack-correlator-windows-apt-2025"
TITLE = "ATT&CK Detection & Correlation — Windows-APT 2025"
EXPORT = "kibana/dashboard.ndjson"
DEFINITION = "analysis/dashboard/dashboard-definition.json"
COLORS = ["#3173A4", "#6092C0", "#7571A6", "#50A39A"]
SCOPE_NOTE = (
    "**Fixed full historical scope: 5 November–15 December 2024 · UTC.** "
    "Overview metrics/charts and scenario snapshots retain the validated scope. "
    "The Detection Event Evidence table accepts membership and search filters within this period."
)
EVIDENCE_COLUMNS = [
    "@timestamp",
    "analyst.attack_id",
    "analyst.technique",
    "detection.name",
    "host.name",
    "user.name",
    "process.name",
    "process.command_line",
    "event.id",
]
EVIDENCE_QUERY = "record.kind: detection_event"


def discover_url(query):
    """Relative ES|QL Discover URL stays in the current space without saved-object IDs."""
    escaped = query.replace("!", "!!").replace("'", "!'")
    state = quote(f"(query:(esql:'{escaped}'))", safe="")
    time = quote(f"(time:(from:'{TIME_RANGE['from']}',to:'{TIME_RANGE['to']}'))", safe="")
    return f"discover#/?_a={state}&_g={time}"


def source_event_url():
    # Source event IDs are validated SHA-256 hex strings; substitute only the formatter value.
    url = discover_url('FROM windows-apt-events-* | WHERE event.id == "SOURCE_EVENT_ID" | LIMIT 2')
    return url.replace("SOURCE_EVENT_ID", "{{value}}")


def detection_discover_query(rule):
    require(rule in RULE_COUNTS, "Unknown detection membership")
    return (
        f'FROM {PATTERN} | WHERE record.kind == "detection_event" AND detection.id == "{rule}"'
        f' AND @timestamp >= TO_DATETIME("{TIME_RANGE["from"]}")'
        f' AND @timestamp <= TO_DATETIME("{TIME_RANGE["to"]}")'
        f" | KEEP {', '.join(EVIDENCE_COLUMNS)}, detection.id"
        " | SORT @timestamp, event.id | LIMIT 1000"
    )


def evidence_panels():
    links = " · ".join(
        f"[{RULE_NAMES[rule]} ({count})]({discover_url(detection_discover_query(rule))})"
        for rule, count in RULE_COUNTS.items()
    )
    return [
        panel(
            "detection-membership",
            "options_list_control",
            "Detection membership (evidence table)",
            (0, 33, 48, 3),
            data_view_id=DATA_VIEW,
            field_name="detection.id",
            single_select=True,
            selected_options=[],
            display_settings={"hide_exclude": True, "hide_exists": True},
            sort={"by": "_key", "direction": "asc"},
        ),
        markdown(
            "evidence-guide",
            "Inspect detection records",
            "Choose a membership above; clear other search/filter pills for its full count. "
            "No selection shows **611 event-within-rule rows**. Overview KPIs remain fixed. "
            "Expand a row for full fields. Click **Source event ID** for the original "
            "`windows-apt-events-*` record; empty cells mean unavailable.\n\n"
            "**Open historical records in Discover:** " + links + ".",
            (0, 36, 48, 8),
        ),
        panel(
            "detection-evidence",
            "discover_session",
            "Detection Event Evidence",
            (0, 44, 48, 22),
            time_range=TIME_RANGE,
            tabs=[
                {
                    "data_source": {"type": "data_view_reference", "ref_id": DATA_VIEW},
                    "query": {"language": "kql", "expression": EVIDENCE_QUERY},
                    "column_order": EVIDENCE_COLUMNS,
                    "view_mode": "documents",
                    "sort": [
                        {"name": "@timestamp", "direction": "asc"},
                        {"name": "event.id", "direction": "asc"},
                    ],
                    "sample_size": 1000,
                    "rows_per_page": 25,
                    "row_height": 3,
                    "header_row_height": "auto",
                    "column_settings": {
                        "process.command_line": {"width": 450},
                        "event.id": {"width": 480},
                    },
                    "density": "compact",
                }
            ],
        ),
    ]


def literal(value):
    """Render source strings as inert Markdown code, including URLs and payloads."""
    if value is None or value == "":
        return "Unavailable"
    value = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    ticks = "`" * (max((len(m) for m in re.findall(r"`+", value)), default=0) + 1)
    return f"{ticks} {value} {ticks}"


def panel(identifier, kind, title, grid, **config):
    return {
        "id": identifier,
        "type": kind,
        "grid": dict(zip(("x", "y", "w", "h"), grid, strict=True)),
        "config": {"title": title, **config},
    }


def markdown(identifier, title, content, grid, hide_title=False):
    return panel(
        identifier,
        "markdown",
        title,
        grid,
        content=content,
        hide_title=hide_title,
        settings={"open_links_in_new_tab": True},
    )


def esql_source(where, aggregation):
    return {
        "type": "esql",
        "query": (
            f"FROM {INDEX}\n| WHERE {where}\n"
            f'    AND @timestamp >= TO_DATETIME("{TIME_RANGE["from"]}")'
            f' AND @timestamp <= TO_DATETIME("{TIME_RANGE["to"]}")\n| {aggregation}'
        ),
    }


def metric(identifier, title, label, expression, x, color, *, unique=None):
    operation = {
        "type": "primary",
        "operation": "unique_count" if unique else "count",
        "label": title,
        "subtitle": label,
        "filter": {"language": "kql", "expression": expression},
        "color": {"type": "static", "color": color},
    }
    if unique:
        operation["field"] = unique
    return panel(
        identifier,
        "vis",
        title,
        (x, 8, 8, 8),
        type="metric",
        data_source={"type": "data_view_reference", "ref_id": DATA_VIEW},
        metrics=[operation],
        time_range=TIME_RANGE,
        ignore_global_filters=True,
        sampling=1,
        hide_title=True,
        styling={
            "density": "compact",
            "primary": {
                "position": "middle",
                "labels": {"alignment": "left"},
                "value": {"alignment": "left", "sizing": "auto"},
            },
        },
    )


def activity_chart(by_host=False):
    layers = []
    for (rule, _), color in zip(RULE_COUNTS.items(), COLORS, strict=True):
        aggregation = (
            "STATS memberships = COUNT(*) BY host.name | SORT host.name | LIMIT 100"
            if by_host
            else "EVAL day = DATE_TRUNC(1 day, @timestamp)\n"
            "| STATS memberships = COUNT(*) BY day | SORT day | LIMIT 1000"
        )
        layers.append(
            {
                "type": "bar_stacked" if by_host else "bar_stacked",
                "data_source": esql_source(
                    f'record.kind == "detection_event" AND detection.id == "{rule}"', aggregation
                ),
                "ignore_global_filters": True,
                "sampling": 1,
                "x": {
                    "column": "host.name" if by_host else "day",
                    "label": "Host" if by_host else "UTC day",
                },
                "y": [
                    {
                        "column": "memberships",
                        "label": RULE_NAMES[rule]
                        .replace("Windows Command Shell", "Command Shell")
                        .replace(" refined", ""),
                        "color": {"type": "static", "color": color},
                    }
                ],
            }
        )
    return panel(
        "activity-host" if by_host else "activity-time",
        "vis",
        "Refined activity by host" if by_host else "Refined detection activity · UTC days",
        (30, 16, 18, 17) if by_host else (0, 16, 30, 17),
        type="xy",
        layers=layers,
        time_range=TIME_RANGE,
        legend={
            "placement": "outside",
            "position": "bottom",
            "visibility": "visible",
            "layout": {"type": "list"},
        },
        axis={
            "y": {"title": {"visible": True, "text": "Event-within-rule memberships"}},
            "x": {"title": {"visible": False}, "scale": "ordinal" if by_host else "temporal"},
        },
    )


def scenario_card(row, x, triple):
    position = row["scenario"]["position"]
    source_id = row["event"]["id"]
    command = row["process"]["command_line"]
    if position == 1:
        command = row["service_evidence"].get("imagePath")
    source_type = "Service imagePath (source evidence)" if position == 1 else "Process command line"
    content = (
        f"### {position} · {row['analyst']['technique']}\n\n"
        f"**{row['analyst']['attack_id']}** · {row['scenario']['role']}\n\n"
        f"**UTC** {literal(row['timestamp_exact'])}\n\n"
        f"**Process:** {literal(row['process']['name'])}  \n"
        f"**User:** {literal(row['user']['name'])}\n\n"
    )
    if position == 1:
        content += (
            f"**Service:** {literal(row['service_evidence'].get('serviceName'))}  \n"
            f"**Service account:** {literal(row['service_evidence'].get('accountName'))}\n\n"
        )
    else:
        content += f"**Parent:** {literal(row['process']['parent']['name'])}\n\n"
    content += (
        f"**{source_type}**  \n{literal(command)}\n\n"
        f"**Source event ID**  \n{literal(source_id)}\n\n"
    )
    gap = triple["gaps_nanoseconds"][position - 1] if position < 3 else None
    content += (
        f"**Next event:** {gap:,} ns later"
        if gap is not None
        else "**End of this bounded three-event sequence.**"
    )
    return markdown(
        f"primary-{position}",
        f"Primary evidence {position}",
        content,
        (x, 49, 16, 20),
        hide_title=True,
    )


def supporting_table(documents):
    values = list(documents.values())
    # Stable examples: the two other corroborated shells and one event in each sc.exe cohort.
    selected = sorted(
        [
            d
            for d in values
            if d["record"]["kind"] == "scenario_event"
            and not d["scenario"]["primary"]
            and d["scenario"]["position"] == 2
        ],
        key=lambda d: d["event"]["id"],
    )
    for rule in ("service_create_refined", "service_config_refined"):
        selected.append(
            min(
                [d for d in values if d.get("detection", {}).get("id") == rule],
                key=lambda d: d["event"]["id"],
            )
        )
    text = (
        "Four deterministic supporting examples; sample rows are not corpus denominators. "
        "Analyst ATT&CK mappings.\n\n"
    )
    text += (
        "| UTC / host | Technique / observation | Process / user | "
        "Inert command and source identity |\n|---|---|---|---|\n"
    )
    for row in selected:
        role = row.get("scenario", {}).get("role", row.get("detection", {}).get("name"))
        triple = row.get("scenario", {}).get("id")
        text += (
            f"| {literal(row['timestamp_exact'])}<br>{literal(row['host']['name'])} "
            f"| {row['analyst']['attack_id']} · {row['analyst']['technique']}<br>{role} "
            f"| {literal(row['process']['name'])}<br>{literal(row['user']['name'])} "
            f"| {literal(row['process']['command_line'])}<br>"
            f"**Event:** {literal(row['event']['id'])}"
            f"<br>**Triple:** {literal(triple)} |\n"
        )
    return markdown(
        "supporting-evidence",
        "Supporting evidence · exact source references",
        text.replace("<br>", " · "),
        (0, 69, 48, 20),
    )


def definition(documents, root=ROOT):
    counts = validate_documents(documents)
    scenario = load_json(root / "analysis/scenarios/scenario-demonstration.json")
    triple = scenario["primary"]
    primary = sorted(
        [
            d
            for d in documents.values()
            if d["record"]["kind"] == "scenario_event" and d["scenario"]["primary"]
        ],
        key=lambda d: d["scenario"]["position"],
    )
    panels = [
        markdown(
            "scope",
            "Historical scope and analytical units",
            (
                "## ATT&CK detection & correlation\n\n"
                "**Windows-APT 2025** · T1059.001 PowerShell · "
                "T1059.003 Windows Command Shell · T1543.003 Windows Service\n\n"
                + SCOPE_NOTE
                + "\n\n**Counts represent detection candidates/evidence units, "
                "not confirmed attacks.**"
            ),
            (0, 0, 48, 8),
            hide_title=True,
        )
    ]
    for n, ((rule, _), color) in enumerate(zip(RULE_COUNTS.items(), COLORS, strict=True)):
        title = {
            "powershell_refined": "PowerShell",
            "shell_refined": "Windows Command Shell",
            "service_create_refined": "Service-create",
            "service_config_refined": "Service-config",
        }[rule]
        panels.append(
            metric(
                f"metric-{rule}",
                title,
                "Distinct candidate events",
                f'record.kind: detection_event AND detection.id: "{rule}"',
                n * 8,
                color,
            )
        )
    panels += [
        metric(
            "metric-pairs",
            "Refined correlation",
            "Ordered pairs",
            "record.kind: correlation_pair AND correlation.refined: true",
            32,
            "#315B83",
        ),
        metric(
            "metric-hosts",
            "Refined correlation hosts",
            "Distinct hosts",
            "record.kind: correlation_pair AND correlation.refined: true",
            40,
            "#315B83",
            unique="host.name",
        ),
        activity_chart(),
        activity_chart(by_host=True),
    ]
    panels.append(
        markdown(
            "candidate-volume",
            "Candidate Sequence Volume",
            (
                f"## {counts['record_counts']['correlation_pair']} broad → "
                f"{counts['refined_pairs']} refined ordered pairs\n\n"
                "**261 → 3 reflects additional behavioural and ancestry requirements; "
                "it is not a measured false-positive reduction.** "
                "Both sets already require same-host GUID ancestry, strict ordering "
                "and a 60-second window. "
                "Refinement adds service-origin shell context and refined PowerShell behaviour.\n\n"
                "**Separate corroboration unit:** 3 service → cmd → PowerShell triples / "
                "9 participating events / 3 hosts."
            ),
            (0, 33, 48, 8),
        )
    )
    panels.append(
        markdown(
            "primary-sequence",
            "Primary scenario · DESKTOP-DS4FBF4",
            (
                "### 1 installation → 2 service-origin cmd.exe → 3 PowerShell · "
                f"{triple['span_nanoseconds']:,} ns\n\n"
                "**Three-event corroborated candidate.** Shell process GUID equals "
                "the PowerShell parent GUID: "
                + literal(primary[1]["process"]["entity_id"])
                + ". The service image association was independently validated "
                "against preserved SCM source evidence "
                "(normalized full command; lexical association).\n\n"
                "**Malicious intent and final execution outcome are not independently proven.** "
                "This bounded sequence is not a complete incident timeline. "
                f"**Triple ID:** {literal(triple['correlation_id'])}"
            ),
            (0, 41, 48, 8),
        )
    )
    panels += [scenario_card(row, n * 16, triple) for n, row in enumerate(primary)]
    panels.append(supporting_table(documents))
    panels.append(
        markdown(
            "logic-limitations",
            "Correlation logic and interpretation",
            (
                "**Same host + service-origin context + exact process GUID ancestry + "
                "strict event ordering + bounded time + refined PowerShell behaviour.**\n\n"
                "Independent ancestry and SCM image evidence make the candidate more structurally "
                "supported than isolated interpreter execution. Approved administration, "
                "service wrappers and marker-file tests can still satisfy every condition. "
                "Missing native PowerShell or service telemetry, absent GUIDs, renamed/in-process "
                "interpreters, alternate parents and longer delays can prevent a match.\n\n"
                "**Coverage:** 102,011 source observations; 90,601 timed; "
                "11,410 intentionally undated and excluded from ordering. "
                "Service-create and service-config remain separate cohorts. Individual units "
                "are distinct events within a rule; pairs and triples are ordered ID tuples. "
                "No independent intent truth exists to measure precision, recall or a "
                "false-positive rate. Missing fields display as **Unavailable**."
            ),
            (0, 89, 48, 10),
        )
    )
    for item in panels:
        if item["grid"]["y"] >= 33:
            item["grid"]["y"] += 33
    panels += evidence_panels()
    return {
        "title": TITLE,
        "description": (
            "Validated presentation only. Fixed historical UTC scope; "
            "candidates and evidence units, not confirmed attacks."
        ),
        "time_range": TIME_RANGE,
        "refresh_interval": {"pause": True, "value": 0},
        "esql_approximation": False,
        "options": {
            "use_margins": True,
            "hide_panel_titles": False,
            "hide_panel_borders": False,
            "sync_colors": False,
        },
        "panels": panels,
    }


def ensure_space(space=SPACE, api=kibana):
    current = api(f"/api/spaces/space/{space}", missing=True)
    if current is None:
        api(
            "/api/spaces/space",
            {
                "id": space,
                "name": "ATT&CK Correlator",
                "description": "Validated historical project evidence; UTC.",
                "color": "#315b83",
                "initials": "AC",
                "disabledFeatures": [],
            },
            "POST",
        )
    view = api(f"/api/data_views/data_view/{DATA_VIEW}", space=space, missing=True)
    if view is None:
        api(
            "/api/data_views/data_view",
            {
                "data_view": {
                    "id": DATA_VIEW,
                    "title": PATTERN,
                    "name": "ATT&CK validated presentation",
                    "timeFieldName": "@timestamp",
                }
            },
            "POST",
            space=space,
        )
    else:
        require(
            view["data_view"]["title"] == PATTERN
            and view["data_view"]["timeFieldName"] == "@timestamp",
            "Existing data view drift",
        )
    api(
        f"/api/data_views/data_view/{DATA_VIEW}",
        {
            "data_view": {
                "fieldFormats": {
                    "event.id": {
                        "id": "url",
                        "params": {
                            "urlTemplate": source_event_url(),
                            "labelTemplate": "{{value}}",
                            "openLinkInCurrentTab": False,
                        },
                    }
                },
            }
        },
        "POST",
        space=space,
    )
    api(
        f"/api/data_views/data_view/{DATA_VIEW}/fields",
        {
            "fields": {
                name: {"customLabel": label}
                for name, label in {
                    "analyst.attack_id": "ATT&CK ID",
                    "analyst.technique": "Technique name",
                    "detection.name": "Detection / rule name",
                    "event.id": "Source event ID",
                }.items()
            }
        },
        "POST",
        space=space,
    )
    version = api("/api/status")["version"]["number"]
    require(version.startswith("9.5."), "This builder requires the verified Kibana 9.5 public API")
    # Space config is an exportable saved object. A data-view request initializes it.
    api(
        f"/api/saved_objects/config/{version}",
        {"attributes": {"dateFormat:tz": "UTC", "discover:sampleSize": 1000}},
        "PUT",
        space=space,
    )
    return version


def export_dashboard(version, root=ROOT, space=SPACE, api=kibana):
    exported = api(
        "/api/saved_objects/_export",
        {
            "objects": [
                {"type": "dashboard", "id": DASHBOARD_ID},
                {"type": "index-pattern", "id": DATA_VIEW},
                {"type": "config", "id": version},
            ],
            "includeReferencesDeep": True,
        },
        "POST",
        space=space,
        raw=True,
    )
    (root / EXPORT).write_text(exported, encoding="utf-8", newline="\n")
    return exported


def run(root=ROOT):
    documents, _ = prepare(root)
    require(readback() == documents, "Build presentation data before dashboard creation")
    version = ensure_space()
    data = definition(documents, root)
    old = kibana(f"/api/dashboards/{DASHBOARD_ID}", space=SPACE, missing=True)
    if old is not None:
        require(old["data"]["title"] == TITLE, "Existing dashboard ID belongs to another dashboard")
    result = kibana(f"/api/dashboards/{DASHBOARD_ID}", data, "PUT", space=SPACE)
    require(result["id"] == DASHBOARD_ID, "Unexpected dashboard identity")
    live = kibana(f"/api/dashboards/{DASHBOARD_ID}", space=SPACE)
    require(len(live["data"]["panels"]) == len(data["panels"]), "Dropped live dashboard panels")
    save_json(root / DEFINITION, data)
    export_dashboard(version, root)
    save_json(
        root / "analysis/dashboard/build-state.json",
        {
            "version": version,
            "dashboard_id": DASHBOARD_ID,
            "space": SPACE,
            "url": f"http://localhost:5601/s/{SPACE}/app/dashboards#/view/{DASHBOARD_ID}",
            "definition_sha256": sha_json(data),
            "panel_types": dict(Counter(p["type"] for p in data["panels"])),
        },
    )
    print(f"Built and exported {len(data['panels'])} live panels on Kibana {version}")


if __name__ == "__main__":
    run()
