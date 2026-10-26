"""Read-only technique selection exploratory telemetry queries; these are not detection rules."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, request, save_json  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402

PATTERN = "windows-apt-events-*"
FIELDS = [
    "@timestamp",
    "event.id",
    "event.code",
    "event.provider",
    "host.name",
    "agent",
    "user",
    "process",
    "file",
    "registry",
    "dll",
    "source",
    "destination",
    "dns",
    "windows_apt.provenance",
    "windows_apt.quality",
    "windows_apt.annotations.attack",
    "windows_apt.scenario.id",
    "windows_apt.scenario.name",
    "windows_apt.scenario.attribution_strength",
]


def term(field, value):
    return {"term": {field: value}}


def all_of(*queries):
    return {"bool": {"filter": list(queries)}}


def any_of(*queries):
    return {"bool": {"should": list(queries), "minimum_should_match": 1}}


def wildcard(field, value):
    return {"wildcard": {field: {"value": value, "case_insensitive": True}}}


def sysmon(*codes):
    return all_of(
        term("event.provider", "Microsoft-Windows-Sysmon"), {"terms": {"event.code": list(codes)}}
    )


def process(*names):
    return all_of(sysmon("1"), any_of(*(wildcard("process.name", n) for n in names)))


def probes():
    ps = process("powershell.exe", "pwsh.exe")
    cmd = process("cmd.exe")
    tasks = process("schtasks.exe")
    return {
        "powershell_execution": ps,
        "powershell_encoded_or_bypass": all_of(
            ps,
            any_of(
                wildcard("process.command_line", "*-enc*"),
                wildcard("process.command_line", "*bypass*"),
            ),
        ),
        "command_shell_execution": cmd,
        "schtasks_execution": tasks,
        "schtasks_create": all_of(tasks, wildcard("process.command_line", "*/create*")),
        "schtasks_change": all_of(tasks, wildcard("process.command_line", "*/change*")),
        "schtasks_run": all_of(tasks, wildcard("process.command_line", "*/run*")),
        "scheduled_task_files": all_of(sysmon("11"), wildcard("file.path", r"*System32*\Tasks\*")),
        "scheduled_task_registry": all_of(
            sysmon("12", "13", "14"), wildcard("registry.path", "*Schedule*TaskCache*")
        ),
        "scheduled_task_security": all_of(
            term("event.provider", "Microsoft-Windows-Security-Auditing"),
            {"terms": {"event.code": ["4698", "4702", "4699"]}},
        ),
        "task_scheduler_provider": term("event.provider", "Microsoft-Windows-TaskScheduler"),
        "service_installed": all_of(
            term("event.provider", "Service Control Manager"), term("event.code", "7045")
        ),
        "service_create_command": all_of(
            process("sc.exe"), wildcard("process.command_line", "* create *")
        ),
        "service_binpath_config": all_of(
            process("sc.exe"),
            wildcard("process.command_line", "* config *"),
            wildcard("process.command_line", "*binPath=*"),
        ),
        "service_launched_shell": all_of(
            process("cmd.exe"), wildcard("process.parent.name", "services.exe")
        ),
        "service_security_4697": all_of(
            term("event.provider", "Microsoft-Windows-Security-Auditing"),
            term("event.code", "4697"),
        ),
        "security_process_4688": all_of(
            term("event.provider", "Microsoft-Windows-Security-Auditing"),
            term("event.code", "4688"),
        ),
        "powershell_native_logging": {
            "terms": {
                "event.provider": [
                    "Microsoft-Windows-PowerShell",
                    "PowerShell",
                    "Windows PowerShell",
                ]
            }
        },
        "service_registry_imagepath": all_of(
            sysmon("13"), wildcard("registry.path", "*CurrentControlSet*Services*ImagePath")
        ),
        "file_deletion_sysmon": sysmon("23", "26"),
        "file_deletion_command": all_of(
            cmd,
            any_of(
                wildcard("process.command_line", "* del *"),
                wildcard("process.command_line", "* erase *"),
            ),
        ),
        "run_key_registry": all_of(
            sysmon("12", "13", "14"), wildcard("registry.path", "*CurrentVersion*Run*")
        ),
        "uac_ms_settings_registry": all_of(
            sysmon("12", "13", "14"), wildcard("registry.path", "*ms-settings*shell*open*command*")
        ),
        "uac_autoelevated_process": process("fodhelper.exe", "ComputerDefaults.exe"),
        "dll_load": sysmon("7"),
        "compiler_execution": process("csc.exe"),
        "winrm_child_process": all_of(
            sysmon("1"), wildcard("process.parent.name", "wsmprovhost.exe")
        ),
        "winrm_network": all_of(sysmon("3"), {"terms": {"destination.port": [5985, 5986]}}),
        "visual_basic_hosts": process("wscript.exe", "cscript.exe"),
    }


def query_probe(query, client=request):
    body = {
        "size": 5,
        "track_total_hits": True,
        "query": query,
        "_source": FIELDS,
        "sort": [{"event.id": "asc"}],
        "aggs": {
            "with_timestamp": {"filter": {"exists": {"field": "@timestamp"}}},
            "process_guid": {"filter": {"exists": {"field": "process.entity_id"}}},
            "parent_guid": {"filter": {"exists": {"field": "process.parent.entity_id"}}},
            "providers": {"terms": {"field": "event.provider", "size": 30}},
            "event_codes": {"terms": {"field": "event.code", "size": 30}},
        },
    }
    result = client(f"/{PATTERN}/_search", body, method="POST")
    if result.get("timed_out") or result["_shards"]["failed"]:
        raise ValueError("Incomplete exploratory search")
    if result["hits"]["total"]["relation"] != "eq":
        raise ValueError("Exploratory counts must be exact")
    count = result["hits"]["total"]["value"]
    timed = result["aggregations"]["with_timestamp"]["doc_count"]
    if not 0 <= timed <= count:
        raise ValueError("Inconsistent timestamp count")
    return {
        "request": body,
        "count": count,
        "with_timestamp": timed,
        "without_timestamp": count - timed,
        "usable_time_percent": round(100 * timed / count, 2) if count else None,
        "aggregations": result["aggregations"],
        "examples": result["hits"]["hits"],
    }


def fetch_events(query, client=request, fields=FIELDS):
    """Small projected readback with deterministic search_after; no index mutation."""
    body = {"size": 1000, "query": query, "_source": fields, "sort": [{"event.id": "asc"}]}
    events = []
    seen = set()
    while True:
        result = client(f"/{PATTERN}/_search", body, method="POST")
        if result.get("timed_out") or result["_shards"]["failed"]:
            raise ValueError("Incomplete projected event readback")
        hits = result["hits"]["hits"]
        if not hits:
            return events
        ids = [hit["_source"]["event"]["id"] for hit in hits]
        if len(ids) != len(set(ids)) or seen.intersection(ids):
            raise ValueError("Duplicate event IDs in projected readback")
        seen.update(ids)
        events.extend(hit["_source"] for hit in hits)
        body["search_after"] = hits[-1]["sort"]


def main():
    validation = json.loads((ROOT / "analysis/ingestion/ingestion-validation.json").read_text())
    totals = {
        "all": request(f"/{PATTERN}/_count")["count"],
        "timed": request(
            f"/{PATTERN}/_count", {"query": {"exists": {"field": "@timestamp"}}}, method="POST"
        )["count"],
    }
    if not validation["passed"] or totals != {"all": 102011, "timed": 90601}:
        raise ValueError("ingestion validation live state must pass before candidate exploration")
    results = {}
    for name, query in probes().items():
        results[name] = query_probe(query)
        print(name, results[name]["count"], results[name]["with_timestamp"], flush=True)
    save_json(ROOT / "analysis/selection/exploratory-queries.json", results)
    events = fetch_events(sysmon("1"))
    save_json(ROOT / "analysis/inspection/selection-process-events.json", events)
    save_json(
        ROOT / "analysis/inspection/selection-service-events.json",
        fetch_events(probes()["service_installed"], fields=FIELDS + ["windows_apt.original"]),
    )
    save_json(
        ROOT / "analysis/selection/live-state.json",
        {
            "accessed_at_utc": datetime.now(UTC).isoformat(),
            "index_pattern": PATTERN,
            "counts": totals | {"untimed": totals["all"] - totals["timed"]},
            "phase4_passed": validation["passed"],
            "phase4_validation_sha256": digest(
                ROOT / "analysis/ingestion/ingestion-validation.json"
            ),
            "phase3_manifest_sha256": digest(ROOT / "analysis/normalization-manifest.json"),
            "phase2_evidence_sha256": digest(ROOT / "analysis/attack_evidence.json"),
            "projected_process_count": len(events),
            "projected_process_sha256": digest(
                ROOT / "analysis/inspection/selection-process-events.json"
            ),
            "projected_service_sha256": digest(
                ROOT / "analysis/inspection/selection-service-events.json"
            ),
            "query_results_sha256": digest(ROOT / "analysis/selection/exploratory-queries.json"),
        },
    )
    print(f"Saved {len(events)} projected process records for exploratory ancestry review.")


if __name__ == "__main__":
    main()
