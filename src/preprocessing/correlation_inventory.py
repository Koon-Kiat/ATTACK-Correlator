"""Explore timestamped relationships between distinct events; this is not a detection rule."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict

from src.preprocessing.event_inventory import brief, present
from src.preprocessing.windows_fields import P


def actor_guids(event: dict) -> set[str]:
    return {
        event["values"][field].strip().casefold()
        for field in [P + "processGuid", P + "sourceProcessGUID", P + "sourceProcessGuid"]
        if present(event["values"].get(field))
        and any(char in "123456789abcdefABCDEF" for char in event["values"][field])
    }


def relationships(events: list[dict], windows=(60, 300, 900)) -> list[dict]:
    maximum = max(windows)
    eligible = [
        event
        for event in events
        if event["time"] and event["host"] and any("." in ident for ident in event["labels"])
    ]
    aggregates = {}
    seen = set()

    def add(left, right, relation, context):
        if left["document_id"] == right["document_id"]:
            return
        gap = (right["time"] - left["time"]).total_seconds()
        if gap < 0 or gap > maximum:
            return
        for a in left["labels"]:
            for b in right["labels"]:
                if a == b or "." not in a or "." not in b:
                    continue
                pair = tuple(sorted([a, b]))
                key = (pair, relation, left["document_id"], right["document_id"])
                if key in seen:
                    continue
                seen.add(key)
                info = aggregates.setdefault(
                    pair,
                    {
                        "relations": {},
                        "hosts": Counter(),
                        "scenarios": Counter(),
                        "directions": Counter(),
                    },
                )
                stats = info["relations"].setdefault(
                    relation,
                    {
                        "gaps": [],
                        "exclusive_gaps": [],
                        "left_refs": set(),
                        "right_refs": set(),
                        "same_scenario_pairs": 0,
                        "same_stronger_scenario_pairs": 0,
                        "examples": [],
                        "exclusive_examples": [],
                    },
                )
                stats["gaps"].append(gap)
                exclusive = b not in left["labels"] and a not in right["labels"]
                if exclusive:
                    stats["exclusive_gaps"].append(gap)
                stats["left_refs"].add(left["document_id"])
                stats["right_refs"].add(right["document_id"])
                info["hosts"][left["host"]] += 1
                info["directions"][a + " -> " + b] += 1
                if left["scenario"] and left["scenario"] == right["scenario"]:
                    stats["same_scenario_pairs"] += 1
                    info["scenarios"][left["scenario"]] += 1
                    if left["strength"] in {"UNIQUE-MATCH", "NARROWED"} and right["strength"] in {
                        "UNIQUE-MATCH",
                        "NARROWED",
                    }:
                        stats["same_stronger_scenario_pairs"] += 1
                if len(stats["examples"]) < 3:
                    stats["examples"].append(
                        {
                            "key": context,
                            "gap_seconds": gap,
                            "left": brief(left),
                            "right": brief(right),
                        }
                    )
                if exclusive and len(stats["exclusive_examples"]) < 3:
                    stats["exclusive_examples"].append(
                        {
                            "key": context,
                            "gap_seconds": gap,
                            "left": brief(left),
                            "right": brief(right),
                        }
                    )

    groups = defaultdict(list)
    guid_index = defaultdict(list)
    for event in eligible:
        host = event["host"]
        for guid in actor_guids(event):
            groups[("same_actor_process_guid", host, guid)].append(event)
            guid_index[(host, guid)].append(event)
        for field in [P + "targetFilename", P + "imageLoaded"]:
            if field in event["values"]:
                groups[("shared_file_path", host, event["values"][field].casefold())].append(event)
        if P + "targetObject" in event["values"]:
            groups[
                ("shared_registry_object", host, event["values"][P + "targetObject"].casefold())
            ].append(event)
        endpoint = tuple(
            event["values"].get(P + part, "")
            for part in ["destinationIp", "destinationPort", "protocol"]
        )
        if all(present(value) for value in endpoint):
            groups[("shared_destination_endpoint", host, *endpoint)].append(event)
        if event["user"]:
            groups[("same_host_user", host, event["user"])].append(event)
            if event["scenario"]:
                groups[
                    ("same_derived_scenario_host_user", host, event["user"], event["scenario"])
                ].append(event)
    # For each context and current event, keep the nearest previous event per other label.
    # This bounds dense bursts and gives an explicit, reproducible exploratory counting unit.
    for key, members in sorted(groups.items()):
        latest = {}
        for event in sorted(
            members, key=lambda item: (item["time"], item["file"], item["row_index"])
        ):
            for previous in {value["document_id"]: value for value in latest.values()}.values():
                add(previous, event, key[0], list(key[1:]))
            for label in event["labels"]:
                if "." in label:
                    latest[label] = event
    for child in eligible:
        parent_guid = child["values"].get(P + "parentProcessGuid", "").strip().casefold()
        if parent_guid:
            for parent in guid_index.get((child["host"], parent_guid), []):
                add(parent, child, "parent_child_process_guid", [child["host"], parent_guid])
    output = []
    for pair, info in sorted(aggregates.items()):
        result = {
            "techniques": list(pair),
            "hosts": dict(sorted(info["hosts"].items())),
            "shared_derived_scenarios": dict(sorted(info["scenarios"].items())),
            "observed_label_order": dict(sorted(info["directions"].items())),
            "co_labelled_eligible_documents": sum(
                set(pair).issubset(event["labels"]) for event in eligible
            ),
            "relations": {},
        }
        for relation, stats in sorted(info["relations"].items()):
            gaps = stats["gaps"]
            result["relations"][relation] = {
                "nearest_event_pair_count": len(gaps),
                "pairs_by_maximum_window_seconds": {
                    str(window): sum(gap <= window for gap in gaps) for window in windows
                },
                "exclusive_label_pairs_by_maximum_window_seconds": {
                    str(window): sum(gap <= window for gap in stats["exclusive_gaps"])
                    for window in windows
                },
                "unique_earlier_documents": len(stats["left_refs"]),
                "unique_later_documents": len(stats["right_refs"]),
                "min_gap_seconds": min(gaps),
                "median_gap_seconds": statistics.median(gaps),
                "max_gap_seconds": max(gaps),
                "same_derived_scenario_pairs": stats["same_scenario_pairs"],
                "same_stronger_derived_scenario_pairs": stats["same_stronger_scenario_pairs"],
                "examples": stats["examples"],
                "exclusive_examples": stats["exclusive_examples"],
            }
        structural = sum(
            result["relations"]
            .get(relation, {})
            .get("pairs_by_maximum_window_seconds", {})
            .get("300", 0)
            for relation in ["same_actor_process_guid", "parent_child_process_guid"]
        )
        result["structural_pairs_within_300_seconds"] = structural
        result["exclusive_structural_pairs_within_300_seconds"] = sum(
            result["relations"]
            .get(relation, {})
            .get("exclusive_label_pairs_by_maximum_window_seconds", {})
            .get("300", 0)
            for relation in ["same_actor_process_guid", "parent_child_process_guid"]
        )
        result["limitations"] = [
            "Counts are exploratory event pairs, not alerts or confirmed malicious sequences.",
            "Same-event multi-labels are excluded; equal timestamps do not establish ordering.",
            "Scenario agreement is derived and dependent on technique labels.",
            "Exclusive-label pairs require A without B then B without A (or reverse); "
            "this separates label sets but does not validate either behaviour.",
            "Relations can overlap; do not add counts across relation types.",
            "Only aware Windows event timestamps and nonempty computer names are eligible.",
        ]
        output.append(result)
    return sorted(
        output, key=lambda item: (-item["structural_pairs_within_300_seconds"], item["techniques"])
    )
