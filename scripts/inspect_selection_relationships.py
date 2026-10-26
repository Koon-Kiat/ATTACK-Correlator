"""Bounded exploratory process/object joins for technique selection; no alerts or rules are
installed.
"""

import re
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.elastic_local import ROOT, load_json, save_json  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402


def nanos(value):
    if not value:
        return None
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    if not match:
        raise ValueError("Correlation requires explicit UTC with at most nine fractional digits")
    delta = datetime.fromisoformat(match[1]).replace(tzinfo=UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or "").ljust(9, "0"))


def identity(event, parent=False):
    process = event.get("process", {})
    process = process.get("parent", {}) if parent else process
    host = event.get("host", {}).get("name")
    guid = process.get("entity_id")
    return (host.casefold(), guid.casefold()) if host and guid else None


def category(event):
    process = event.get("process", {})
    name = process.get("name", "").casefold()
    command = process.get("command_line", "")
    if name in {"powershell.exe", "pwsh.exe"}:
        return "T1059.001"
    if name == "cmd.exe":
        return "T1059.003"
    if name == "sc.exe" and (
        re.search(r"\screate\s", command, re.I)
        or (re.search(r"\sconfig\s", command, re.I) and "binpath=" in command.casefold())
    ):
        return "T1543.003"
    return None


def parent_pairs(events, window_seconds):
    if window_seconds < 0:
        raise ValueError("Correlation window cannot be negative")
    ids = [event["event"]["id"] for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate event IDs would inflate pair counts")
    lookup = defaultdict(list)
    for event in events:
        key = identity(event)
        if key and nanos(event.get("@timestamp")) is not None:
            lookup[key].append(event)
    pairs = []
    for child in events:
        child_time = nanos(child.get("@timestamp"))
        if child_time is None:
            continue
        for parent in lookup.get(identity(child, parent=True), []):
            if parent["event"]["id"] == child["event"]["id"]:
                continue
            gap = child_time - nanos(parent["@timestamp"])
            if 0 <= gap <= window_seconds * 10**9:
                pairs.append((parent, child, gap))
    return sorted(pairs, key=lambda pair: (pair[0]["event"]["id"], pair[1]["event"]["id"]))


def command_key(value):
    # Compare Windows case/backslash spelling only. Never HTML-decode or execute commands.
    return re.sub(r"\\+", r"\\", value).strip().casefold()


def compact(event):
    result = {key: value for key, value in event.items() if key != "windows_apt"}
    result["windows_apt"] = {
        key: value for key, value in event["windows_apt"].items() if key != "original"
    }
    original = event["windows_apt"].get("original", {})
    service = {
        key: value
        for key, value in original.items()
        if key.startswith("_source.data.win.eventdata.") and value.strip()
    }
    if service:
        result["windows_apt"]["original"] = service
    return result


def inspect(events, services):
    counts = {}
    examples = {}
    for window in (60, 300, 900):
        pairs = parent_pairs(events, window)
        grouped = defaultdict(list)
        for parent, child, gap in pairs:
            a, b = category(parent), category(child)
            if a and b and a != b:
                grouped[f"{a}->{b}"].append(
                    {
                        "event_ids": [parent["event"]["id"], child["event"]["id"]],
                        "host": parent["host"]["name"],
                        "gap_nanoseconds": gap,
                        "gap_seconds": gap / 10**9,
                        "join": (
                            "same host; parent.process.entity_id = child.process.parent.entity_id"
                        ),
                        "explicit_utc": True,
                        "events": [compact(parent), compact(child)],
                    }
                )
        counts[str(window)] = {key: len(value) for key, value in sorted(grouped.items())}
        if window == 300:
            examples = {key: value[:3] for key, value in sorted(grouped.items())}
    chains = []
    for shell, ps, gap in parent_pairs(events, 300):
        if category(shell) != "T1059.003" or category(ps) != "T1059.001":
            continue
        if shell["process"].get("parent", {}).get("name", "").casefold() != "services.exe":
            continue
        for service in services:
            service_time = nanos(service.get("@timestamp"))
            if service_time is None:
                continue
            if len({d["event"]["id"] for d in (service, shell, ps)}) != 3:
                continue
            if service["host"]["name"].casefold() != shell["host"]["name"].casefold():
                continue
            image = service["windows_apt"]["original"].get(
                "_source.data.win.eventdata.imagePath", ""
            )
            if not image or command_key(image) != command_key(shell["process"]["command_line"]):
                continue
            delta = nanos(shell["@timestamp"]) - service_time
            if not 0 <= delta <= 300 * 10**9:
                continue
            chains.append(
                {
                    "techniques": ["T1543.003", "T1059.003", "T1059.001"],
                    "events": [compact(service), compact(shell), compact(ps)],
                    "event_ids": [d["event"]["id"] for d in (service, shell, ps)],
                    "host": shell["host"]["name"],
                    "gaps_nanoseconds": [delta, gap],
                    "span_nanoseconds": delta + gap,
                    "joins": [
                        "same host and full service imagePath equals shell command_line "
                        "after Windows case/backslash comparison",
                        "same host and shell process.entity_id equals "
                        "PowerShell process.parent.entity_id",
                    ],
                    "explicit_utc": True,
                    "possible_benign_explanation": (
                        "Authorized service test or administrative automation; the command "
                        "requests creation of an art-marker file. No malicious intent, file "
                        "creation outcome or lasting persistence is proven by this chain."
                    ),
                }
            )
    return {
        "window_pair_counts": counts,
        "pair_examples": examples,
        "service_shell_powershell_chains": chains,
        "method": (
            "Distinct Sysmon process-creation documents, host plus GUID ancestry, explicit "
            "nanosecond time, inclusive windows. No labels or scenarios in joins. Chain "
            "object confirmation uses unindexed original imagePath only for review."
        ),
        "limitation": (
            "Observed relationships are exploratory evidence, not alerts, malicious "
            "causality, or independent ground truth."
        ),
    }


def main():
    state = load_json(ROOT / "analysis/selection/live-state.json")
    path = ROOT / "analysis/inspection/selection-process-events.json"
    if digest(path) != state["projected_process_sha256"]:
        raise ValueError("Projected process cache changed; rerun live candidate inspection")
    service_path = ROOT / "analysis/inspection/selection-service-events.json"
    if digest(service_path) != state["projected_service_sha256"]:
        raise ValueError("Projected service cache changed; rerun live candidate inspection")
    result = inspect(load_json(path), load_json(service_path))
    save_json(ROOT / "analysis/selection/correlation-feasibility.json", result)
    print(result["window_pair_counts"])
    print(
        "Service/shell/PowerShell object-and-GUID chains:",
        len(result["service_shell_powershell_chains"]),
    )


if __name__ == "__main__":
    main()
