"""Validate actual source, presentation records, live panels and a clean-space import."""

import argparse
import copy
import json
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.build_dashboard import (  # noqa: E402
    DASHBOARD_ID,
    DEFINITION,
    EVIDENCE_COLUMNS,
    EVIDENCE_QUERY,
    EXPORT,
    TITLE,
    definition,
    detection_discover_query,
    source_event_url,
)
from scripts.build_dashboard_data import (  # noqa: E402
    DATA_VIEW,
    INDEX,
    MANIFEST,
    PATTERN,
    RULE_COUNTS,
    SPACE,
    TIME_RANGE,
    mapping,
    no_unsupported_fields,
    prepare,
    readback,
    validate_documents,
)
from scripts.build_scenario_evidence import live_state  # noqa: E402
from scripts.elastic_local import ROOT, load_json, request, save_json  # noqa: E402
from scripts.kibana_local import kibana  # noqa: E402
from scripts.run_correlation import sha_json  # noqa: E402
from scripts.run_individual_detections import esql  # noqa: E402
from scripts.verify_technique_selection import require  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402

RESULT = "analysis/dashboard/dashboard-validation.json"
IMPORT_RESULT = "analysis/dashboard/import-validation.json"
VISUAL = "analysis/dashboard/visual-inspection.json"


def subset(expected, actual, path="dashboard"):
    """Kibana adds defaults; every explicitly authored property must survive readback."""
    if isinstance(expected, dict):
        require(isinstance(actual, dict), f"Object drift: {path}")
        for key, value in expected.items():
            require(key in actual, f"Missing live property: {path}.{key}")
            subset(value, actual[key], f"{path}.{key}")
    elif isinstance(expected, list):
        require(isinstance(actual, list) and len(actual) == len(expected), f"List drift: {path}")
        for n, (left, right) in enumerate(zip(expected, actual, strict=True)):
            subset(left, right, f"{path}[{n}]")
    else:
        require(expected == actual, f"Live property drift: {path}")


def check_layout(panels):
    require(len({p["id"] for p in panels}) == len(panels), "Duplicate panel ID")
    for n, panel in enumerate(panels):
        a = panel["grid"]
        require(
            a["x"] >= 0 and a["y"] >= 0 and a["w"] > 0 and a["h"] > 0 and a["x"] + a["w"] <= 48,
            "Panel outside grid",
        )
        for other in panels[n + 1 :]:
            b = other["grid"]
            overlap = (
                a["x"] < b["x"] + b["w"]
                and b["x"] < a["x"] + a["w"]
                and a["y"] < b["y"] + b["h"]
                and b["y"] < a["y"] + a["h"]
            )
            require(not overlap, f"Overlapping panels: {panel['id']} / {other['id']}")


def check_export(text, version):
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    objects = {(r["type"], r["id"]): r for r in rows if "type" in r}
    require(len(objects) == 3, "Export must contain dashboard, data view and UTC config")
    require(
        set(objects)
        == {("dashboard", DASHBOARD_ID), ("index-pattern", DATA_VIEW), ("config", version)},
        "Unexpected export objects",
    )
    require(
        rows[-1].get("exportedCount") == 3
        and rows[-1].get("missingRefCount") == 0
        and not rows[-1].get("missingReferences"),
        "Missing export references",
    )
    refs = []
    for obj in objects.values():
        for ref in obj.get("references", []):
            require((ref["type"], ref["id"]) in objects, "Unresolved saved-object reference")
            refs.append(ref)
    require(len(refs) >= 6, "Metrics must reference the exported data view")
    require(
        objects[("index-pattern", DATA_VIEW)]["attributes"]["title"] == PATTERN
        and objects[("index-pattern", DATA_VIEW)]["attributes"]["timeFieldName"] == "@timestamp",
        "Exported data-view drift",
    )
    require(
        objects[("config", version)]["attributes"]["dateFormat:tz"] == "UTC",
        "UTC config not exported",
    )
    require(
        objects[("config", version)]["attributes"]["discover:sampleSize"] == 1000,
        "Discover must load all 611 evidence records",
    )
    return {
        "objects": [{"type": t, "id": i} for t, i in sorted(objects)],
        "reference_count": len(refs),
        "missing_references": 0,
    }


def validate_panels(
    expected,
    documents,
    space=SPACE,
    api=kibana,
    client=request,
    dashboard_id=DASHBOARD_ID,
    view_id=DATA_VIEW,
):
    expected = copy.deepcopy(expected)
    for panel in expected["panels"]:
        source = panel["config"].get("data_source", {})
        if source.get("type") == "data_view_reference":
            source["ref_id"] = view_id
        if panel["type"] == "options_list_control":
            panel["config"]["data_view_id"] = view_id
        for tab in panel["config"].get("tabs", []):
            tab["data_source"]["ref_id"] = view_id
    live = api(f"/api/dashboards/{dashboard_id}", space=space)
    require(live["id"] == dashboard_id and live["data"]["title"] == TITLE, "Live dashboard missing")
    subset(expected, live["data"])
    check_layout(live["data"]["panels"])
    view = api(f"/api/data_views/data_view/{view_id}", space=space)["data_view"]
    require(
        view["title"] == PATTERN and view["timeFieldName"] == "@timestamp", "Live data-view drift"
    )
    require(
        view["fieldFormats"]["event.id"]["params"]["urlTemplate"] == source_event_url(),
        "Source event Discover link drift",
    )
    version = api("/api/status")["version"]["number"]
    config = api(f"/api/saved_objects/config/{version}", space=space)
    require(config["attributes"]["dateFormat:tz"] == "UTC", "Live space must display UTC")
    observed = {"metric_values": {}, "daily_totals": {}, "host_totals": {}, "query_results": {}}
    observed["detection_evidence"] = validate_evidence(live["data"], documents, client)
    for panel in live["data"]["panels"]:
        config = panel["config"]
        if panel["type"] != "vis":
            continue
        require(config["time_range"] == TIME_RANGE, "All panels require fixed historical time")
        if config["type"] == "metric":
            metric = config["metrics"][0]
            require(
                config["ignore_global_filters"] is True and "filter" in metric,
                "Cohort must be an aggregation filter; ignored global queries lose membership",
            )
            expression = metric["filter"]["expression"]
            aggregate = (
                "COUNT_DISTINCT(host.name)" if metric["operation"] == "unique_count" else "COUNT(*)"
            )
            query = (
                f"FROM {INDEX} | WHERE KQL({json.dumps(expression)})"
                f' AND @timestamp >= TO_DATETIME("{TIME_RANGE["from"]}")'
                f' AND @timestamp <= TO_DATETIME("{TIME_RANGE["to"]}") | STATS value = {aggregate}'
            )
            rows = esql(query, client)
            expected_value = RULE_COUNTS.get(panel["id"].removeprefix("metric-"), 3)
            require(rows == [{"value": expected_value}], f"Live metric mismatch: {panel['id']}")
            observed["metric_values"][panel["id"]] = rows[0]["value"]
            observed["query_results"][panel["id"]] = {"query": query, "rows": rows}
        else:
            for layer, rule in zip(config["layers"], RULE_COUNTS, strict=True):
                require(
                    layer["ignore_global_filters"] is True and layer["sampling"] == 1,
                    "Chart filtering/sampling drift",
                )
                rows = esql(layer["data_source"]["query"], client)
                require(
                    sum(r["memberships"] for r in rows) == RULE_COUNTS[rule], "Chart total mismatch"
                )
                wanted = Counter()
                by_host = panel["id"] == "activity-host"
                for doc in documents.values():
                    if doc.get("detection", {}).get("id") == rule:
                        wanted[doc["host"]["name"] if by_host else doc["@timestamp"][:10]] += 1
                actual = {
                    r["host.name"] if by_host else r["day"][:10]: r["memberships"] for r in rows
                }
                require(actual == dict(wanted), "Chart bucket/host membership mismatch")
                observed["host_totals" if by_host else "daily_totals"][rule] = actual
                observed["query_results"][panel["id"] + "/" + rule] = {
                    "query": layer["data_source"]["query"],
                    "rows": rows,
                }
    return {
        "space": space,
        "panel_count": len(live["data"]["panels"]),
        "panel_titles": [p["config"]["title"] for p in live["data"]["panels"]],
        "live_definition_sha256": sha_json(live["data"]),
        "timezone": "UTC",
        **observed,
    }


def validate_evidence(dashboard, documents, client=request):
    """Read every underlying row, including IDs, rather than aggregate View data output."""
    table = next(p for p in dashboard["panels"] if p["id"] == "detection-evidence")
    control = next(p for p in dashboard["panels"] if p["id"] == "detection-membership")
    tab = table["config"]["tabs"][0]
    require(
        table["type"] == "discover_session" and tab["view_mode"] == "documents",
        "Evidence must be a document table",
    )
    require(
        table["config"]["time_range"] == TIME_RANGE
        and tab["column_order"] == EVIDENCE_COLUMNS
        and tab["query"] == {"language": "kql", "expression": EVIDENCE_QUERY}
        and tab["sample_size"] >= sum(RULE_COUNTS.values()),
        "Evidence scope/columns drift",
    )
    require(
        control["config"]["field_name"] == "detection.id"
        and control["config"]["single_select"] is True,
        "Membership selector drift",
    )
    p6 = load_json(ROOT / "analysis/detections/detection-results.json")
    result = {}
    for rule, count in RULE_COUNTS.items():
        expression = tab["query"]["expression"] + f' AND detection.id: "{rule}"'
        query = (
            f"FROM {PATTERN} | WHERE KQL({json.dumps(expression)})"
            f' AND @timestamp >= TO_DATETIME("{TIME_RANGE["from"]}")'
            f' AND @timestamp <= TO_DATETIME("{TIME_RANGE["to"]}")'
            " | KEEP event.id, detection.id | SORT event.id | LIMIT 1000"
        )
        rows = esql(query, client)
        ids = [row["event.id"] for row in rows]
        expected_ids = sorted(
            d["event"]["id"] for d in documents.values() if d.get("detection", {}).get("id") == rule
        )
        require(
            len(rows) == count and len(set(ids)) == count and ids == expected_ids,
            f"Evidence row/ID mismatch: {rule}",
        )
        require(
            ids == sorted(p6["queries"][rule]["event_ids"])
            and all(row["detection.id"] == rule for row in rows),
            f"Evidence differs from validated individual detection membership: {rule}",
        )
        drilldown_rows = esql(detection_discover_query(rule), client)
        require(
            sorted(r["event.id"] for r in drilldown_rows) == ids
            and all(r["detection.id"] == rule for r in drilldown_rows),
            f"Discover drilldown membership mismatch: {rule}",
        )
        source = client(
            "/windows-apt-events-*/_search",
            {
                "size": 1000,
                "track_total_hits": True,
                "query": {"terms": {"event.id": ids}},
                "_source": ["event.id"],
            },
            "POST",
        )
        source_ids = sorted(hit["_source"]["event"]["id"] for hit in source["hits"]["hits"])
        require(
            source["hits"]["total"] == {"value": count, "relation": "eq"} and source_ids == ids,
            f"Source traceability mismatch: {rule}",
        )
        result[rule] = {
            "row_count": count,
            "query": query,
            "source_event_ids": ids,
            "phase6_membership_equal": True,
            "source_records_resolved": count,
            "discover_row_count": len(drilldown_rows),
        }
    return result


def import_check(exported, expected, documents, root=ROOT, api=kibana):
    space = "attack-correlator-check-" + uuid.uuid4().hex[:12]
    require(api(f"/api/spaces/space/{space}", missing=True) is None, "Import requires a new space")
    api(
        "/api/spaces/space",
        {
            "id": space,
            "name": "ATT&CK import validation",
            "initials": "IV",
            "description": "Disposable project saved-object import validation.",
            "disabledFeatures": [],
        },
        "POST",
    )
    # User objects must be absent. Kibana initializes a default config object on
    # the first space request; overwrite applies to that empty space's UTC config.
    require(
        api(f"/api/dashboards/{DASHBOARD_ID}", space=space, missing=True) is None,
        "Import dashboard already exists",
    )
    require(
        api(f"/api/data_views/data_view/{DATA_VIEW}", space=space, missing=True) is None,
        "Import data view already exists",
    )
    result = api(
        "/api/saved_objects/_import?overwrite=true", exported, "POST", space=space, multipart=True
    )
    save_json(
        root / IMPORT_RESULT, {"passed": False, "space": space, "saved_object_import": result}
    )
    require(
        result.get("success") is True
        and result.get("successCount") == 3
        and not result.get("errors"),
        "Clean-space saved-object import failed",
    )
    destinations = {r["type"]: r.get("destinationId", r["id"]) for r in result["successResults"]}
    dashboard_id, view_id = destinations["dashboard"], destinations["index-pattern"]
    panels = validate_panels(
        expected, documents, space=space, api=api, dashboard_id=dashboard_id, view_id=view_id
    )
    result = {
        "passed": True,
        "space": space,
        "clean_before_import": True,
        "dashboard_id": dashboard_id,
        "data_view_id": view_id,
        "saved_object_import": result,
        "live_panels": panels,
        "export_sha256": digest(root / EXPORT),
        "url": f"http://localhost:5601/s/{space}/app/dashboards#/view/{dashboard_id}",
    }
    save_json(root / IMPORT_RESULT, result)
    return result


def visual_evidence(root, exported_hash, import_space):
    path = root / VISUAL
    if not path.is_file():
        return {"passed": False, "status": "pending real browser inspection"}
    value = load_json(path)
    require(
        value.get("passed") is True
        and value["export_sha256"] == exported_hash
        and value["import_space"] == import_space,
        "Visual evidence is stale",
    )
    require(
        value["working_metric_values"] == [290, 172, 41, 108, 3, 3]
        and value["imported_metric_values"] == [290, 172, 41, 108, 3, 3],
        "Visual metric mismatch",
    )
    require(
        value["global_filter_invariance_verified"]
        and value["primary_order_verified"]
        and value["commands_and_ids_readable"]
        and value["no_panel_errors"],
        "Incomplete visual review",
    )
    require(
        value["evidence_membership_rows"] == RULE_COUNTS
        and value["source_discover_verified"]
        and value["detection_discover_verified"],
        "Incomplete evidence traceability review",
    )
    require(len(value["screenshots"]) >= 3, "Required real dashboard screenshots missing")
    for filename, expected_hash in value["screenshots"].items():
        require(
            filename.startswith("analysis/dashboard/screenshots/")
            and ".." not in Path(filename).parts,
            "Invalid screenshot path",
        )
        require(digest(root / filename) == expected_hash, "Screenshot hash drift")
    return value


def run(root=ROOT, reuse_import=False, require_visual=False):
    save_json(root / RESULT, {"passed": False, "status": "validation running"})
    documents, manifest = prepare(root)
    require(load_json(root / MANIFEST) == manifest, "Presentation manifest is stale; rebuild it")
    require(readback() == documents, "Live presentation documents differ from source")
    live_mapping = request(f"/{INDEX}/_mapping")[INDEX]["mappings"]
    require(live_mapping == mapping(), "Presentation mapping drift")
    no_unsupported_fields(live_mapping)
    resolved = request(f"/_resolve/index/{PATTERN}")
    require(
        [i["name"] for i in resolved["indices"]] == [INDEX] and not resolved["aliases"],
        "Data view includes an unexpected index",
    )
    expected = definition(documents, root)
    require(load_json(root / DEFINITION) == expected, "Dashboard definition is stale; rebuild it")
    observed = validate_panels(expected, documents)
    version = kibana("/api/status")["version"]["number"]
    exported = (root / EXPORT).read_text(encoding="utf-8")
    export_result = check_export(exported, version)
    export_hash = digest(root / EXPORT)
    if reuse_import:
        imported = load_json(root / IMPORT_RESULT)
        require(
            imported["passed"] and imported["export_sha256"] == export_hash,
            "Stale import validation; run a new import",
        )
        imported["live_panels"] = validate_panels(
            expected,
            documents,
            space=imported["space"],
            dashboard_id=imported["dashboard_id"],
            view_id=imported["data_view_id"],
        )
    else:
        imported = import_check(exported, expected, documents, root)
    visual = visual_evidence(root, export_hash, imported["space"])
    if require_visual:
        require(visual["passed"], "Visual inspection is required before completion")
    source_after = live_state(request)
    require(
        source_after
        == (manifest["source_state"]["counts"], manifest["source_state"]["mapping_sha256"]),
        "Source state changed",
    )
    result = {
        "passed": True,
        "all_completion_checks_passed": visual["passed"],
        "validated_at_utc": datetime.now(UTC).isoformat(),
        "kibana_version": version,
        "dashboard": TITLE,
        "dashboard_id": DASHBOARD_ID,
        "source_state": manifest["source_state"],
        "presentation_index": INDEX,
        "counts": validate_documents(documents),
        "source_event_ids_verified": manifest["source_event_ids_verified"],
        "documents_sha256": manifest["documents_sha256"],
        "live_panels": observed,
        "export": {"file": EXPORT, "sha256": export_hash, **export_result},
        "clean_space_import": {"space": imported["space"], "passed": True, "objects_imported": 3},
        "visual_inspection": visual,
        "implementation_sha256": {
            p: digest(root / p)
            for p in (
                "scripts/build_dashboard_data.py",
                "scripts/build_dashboard.py",
                "scripts/validate_dashboard.py",
                "scripts/kibana_local.py",
            )
        },
    }
    save_json(root / RESULT, result)
    (root / "analysis/dashboard/dashboard-report.md").write_text(
        report(result), encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {
                "passed": True,
                "all_completion_checks_passed": visual["passed"],
                "counts": result["counts"],
                "import_space": imported["space"],
            }
        )
    )
    return result


def report(result):
    return (
        "# Live dashboard validation\n\n"
        f"**{result['dashboard']}** · Kibana {result['kibana_version']} · UTC\n\n"
        f"Validated: {result['validated_at_utc']}. API/data/import checks: **passed**. "
        "Visual inspection: "
        f"**{'passed' if result['visual_inspection']['passed'] else 'pending'}**.\n\n"
        "| Analytical unit | Live result |\n|---|---:|\n"
        "| Detection event-within-rule memberships | 611 |\n"
        "| PowerShell / shell / service-create / service-config distinct events "
        "| 290 / 172 / 41 / 108 |\n"
        "| Broad / refined ordered pairs | 261 / 3 |\n"
        "| Refined participating events / hosts | 6 / 3 |\n"
        "| Ordered triples / scenario rows / primary rows | 3 / 9 / 3 |\n"
        "| Presentation documents | 881 |\n\n"
        "Every generated document equals its live indexed counterpart; "
        f"{result['source_event_ids_verified']} required source IDs were fetched and verified. "
        "Source totals remain 102,011 / 90,601 timed / 11,410 undated; "
        "the mapping hash is unchanged. Both chart series reconcile by exact day and host, "
        "not only grand total. "
        "All six metric aggregation filters were executed using their live KQL expressions.\n\n"
        "The 19 live panels retain a fixed **5 November–15 December 2024 UTC** scope. "
        "The native Detection Event Evidence table reproduces all four membership row sets "
        "(290/172/41/108), with exact individual detection ID equality and "
        "one original source record per ID. "
        "The primary DESKTOP-DS4FBF4 sequence retains exact source IDs, UTC nanoseconds, "
        "the GUID edge, source-only SCM image evidence and its **41,801,900 ns** span. "
        "Commands remain inert text; missing fields display as Unavailable.\n\n"
        "`kibana/dashboard.ndjson` was exported from live Kibana "
        "with the data view and UTC settings: "
        f"3 objects, 0 missing references. A clean space `{result['clean_space_import']['space']}` "
        "accepted all objects, resolved every panel and reproduced the exact live query results. "
        "This disposable validation space is retained for inspection.\n\n"
        "261 → 3 is candidate sequence volume reduction, "
        "**not measured false-positive reduction**. "
        "No independent malicious-intent or execution-outcome truth exists. "
        "Strict ancestry, source evidence and timing can miss alternate execution paths "
        "or incomplete telemetry. The SCM installation observation remains distinct "
        "from refined sc.exe create/config cohorts. "
        "This is a presentation layer, not a new detector.\n\n"
        "Reproduce: `python scripts/build_dashboard_data.py`, `python scripts/build_dashboard.py`, "
        "`python scripts/validate_dashboard.py`. After real browser inspection, use "
        "`python scripts/validate_dashboard.py --reuse-import-check --require-visual`. "
        "Detailed queries, buckets, source/mapping hashes and screenshot evidence "
        "are in `dashboard-validation.json`.\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reuse-import-check",
        action="store_true",
        help="Recheck the same live imported objects; export hash must match",
    )
    parser.add_argument(
        "--require-visual",
        action="store_true",
        help="Fail unless current real browser evidence exists",
    )
    arguments = parser.parse_args()
    run(reuse_import=arguments.reuse_import_check, require_visual=arguments.require_visual)
