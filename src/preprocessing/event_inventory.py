"""Read the inspected Windows-APT v4 release; count evidence without installing analytics."""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from src.preprocessing.inspect_dataset import read_records
from src.preprocessing.profile_values import canonical, extract_techniques, observed_time
from src.preprocessing.windows_fields import GROUPS, LABEL, NAMES, TACTICS, P, S


def present(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def json_list(value: str) -> list[str]:
    if not present(value):
        return []
    parsed = json.loads(value)
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError("Expected an observed JSON string array")
    return parsed


def rows(path: Path):
    index = 0
    for location, record, error in read_records(path, "utf-8-sig", ",", 64 * 1024**2):
        if error == "__header__":
            continue
        if error:
            raise ValueError(f"{path.name}:{location}: {error}; evidence analysis cannot skip rows")
        yield index, location, record
        index += 1


def payload_hash(record: dict) -> str:
    # Absent columns and empty CSV cells compare equivalently across unioned schemas.
    # Whitespace, strings, numeric spellings and all nonempty source values stay exact.
    return hashlib.sha256(
        canonical({key: value for key, value in record.items() if value != ""})
    ).hexdigest()


def count_values(values) -> dict:
    return dict(sorted(Counter(values).items()))


def brief(event: dict) -> dict:
    fields = [
        "_source.rule.description",
        "_source.agent.name",
        S + "computer",
        S + "eventID",
        S + "providerName",
        P + "image",
        P + "commandLine",
        P + "parentImage",
        P + "parentCommandLine",
        P + "imageLoaded",
        P + "targetFilename",
        P + "targetObject",
        P + "details",
        P + "sourceImage",
        P + "targetImage",
        P + "grantedAccess",
        P + "sourceIp",
        P + "destinationIp",
        "_source.syscheck.path",
        "_source.syscheck.event",
    ]
    return {
        "source_csv": event["file"],
        "row_index": event["row_index"],
        "csv_record_end_line": event["line"],
        "document_id": event["document_id"],
        "timestamp": event["time"].isoformat() if event["time"] else None,
        "event_labels": event["labels"],
        "scenario": event["scenario"],
        "attribution_strength": event["strength"],
        "fields": {
            field: {
                "value": event["values"][field][:400],
                "truncated": len(event["values"][field]) > 400,
            }
            for field in fields
            if present(event["values"].get(field))
        },
    }


def distribution(values: list[float]) -> dict:
    ordered = sorted(values)
    return {
        "count": len(values),
        "min_seconds": ordered[0] if values else None,
        "median_seconds": statistics.median(values) if values else None,
        "p95_seconds": ordered[int((len(values) - 1) * 0.95)] if values else None,
        "max_seconds": ordered[-1] if values else None,
    }


def load_release(raw: Path) -> tuple[dict, list[dict]]:
    manifests = list(raw.rglob("scenario_manifest.csv"))
    if len(manifests) != 1:
        raise ValueError("Expected exactly one active scenario_manifest.csv under dataset/raw")
    root = manifests[0].parent
    manifest = [row for _, _, row in rows(manifests[0])]
    validation = [row for _, _, row in rows(root / "validation_summary.csv")]
    mapping_path = root / "scenario_mapping_supplement/log_to_scenario_mapping.csv"
    mapping = [row for _, _, row in rows(mapping_path)]
    sources = sorted({row["Source_CSV"] for row in mapping})
    if "combined.csv" in sources:
        raise ValueError("This release's mapping references combined.csv; review the corpus policy")
    for source in sources:
        if Path(source).name != source or not (root / source).is_file():
            raise ValueError(f"Unresolved mapping source: {source!r}")
    by_key = {}
    duplicate_mapping_keys = 0
    for row in mapping:
        key = (row["Source_CSV"], int(row["Row_Index"]))
        if key in by_key:
            duplicate_mapping_keys += 1
        else:
            by_key[key] = row
    if duplicate_mapping_keys:
        raise ValueError("Duplicate mapping keys; cannot silently choose an attribution")
    scenarios = {row["Scenrario_ID"]: row for row in manifest}
    if len(scenarios) != len(manifest):
        raise ValueError("Duplicate manifest scenario keys")
    all_fields = set()
    field_counts = Counter()
    field_examples = {}
    events = []
    identities = defaultdict(set)
    fingerprints = Counter()
    combined_fingerprints = Counter()
    combined_stream = iter(rows(root / "combined.csv"))
    combined_identity_matches = 0
    combined_identity_mismatches = 0
    changed_fields = Counter()
    changed_field_examples = {}
    event_refs = set()
    join_checks = Counter()
    collector_deltas, serial_deltas = [], []
    serial_outliers = []
    full_log_shapes = Counter()
    source_types = defaultdict(Counter)
    source_counts = Counter()
    all_mentioned, assessment_mentions = Counter(), Counter()
    label_parse_problems = []
    key_fields = set(sum(GROUPS.values(), []))
    key_fields.update(
        [
            "_source.data.sca.type",
            P + "name",
            P + "destination",
            P + "type",
            P + "operation",
            P + "eventType",
        ]
    )
    for source in sources:
        for row_index, line, row in rows(root / source):
            source_counts[source] += 1
            all_fields.update(row)
            signature = payload_hash(row)
            fingerprints[signature] += 1
            document_id = row["_index"] + ":" + row["_id"]
            identities[document_id].add(signature)
            combined_item = next(combined_stream, None)
            combined_row = {}
            if combined_item is not None:
                combined_index, _, compared = combined_item
                combined_fingerprints[payload_hash(compared)] += 1
                if compared["_index"] + ":" + compared["_id"] == document_id:
                    combined_identity_matches += 1
                    combined_row = compared
                    for field in sorted(set(row) | set(compared)):
                        left, right = row.get(field, ""), compared.get(field, "")
                        if left != right:
                            changed_fields[field] += 1
                            changed_field_examples.setdefault(
                                field,
                                {
                                    "source_csv": source,
                                    "row_index": row_index,
                                    "combined_row_index": combined_index,
                                    "period_value": left[:240],
                                    "combined_value": right[:240],
                                    "truncated": len(left) > 240 or len(right) > 240,
                                },
                            )
                else:
                    combined_identity_mismatches += 1
            else:
                combined_identity_mismatches += 1
            mapping_key = (source, row_index)
            linked = by_key.get(mapping_key)
            event_refs.add(mapping_key)
            if linked is None:
                join_checks["unmatched_event"] += 1
                linked = {}
            else:
                join_checks["matched_event"] += 1
                for target, origin in [
                    ("Timestamp", "_source.@timestamp"),
                    ("Agent_Name", "_source.agent.name"),
                    ("MITRE_Technique", LABEL),
                ]:
                    if linked[target] != row.get(origin, ""):
                        join_checks[target + "_mismatch"] += 1
                if present(linked["Scenario_ID"]) and linked["Scenario_ID"] not in scenarios:
                    join_checks["unknown_scenario"] += 1
            for field, value in row.items():
                if present(value):
                    field_counts[field] += 1
                    field_examples.setdefault(
                        field,
                        {
                            "value": value[:240],
                            "truncated": len(value) > 240,
                            "source_csv": source,
                            "row_index": row_index,
                        },
                    )
            ids_in_row = set()
            for value in row.values():
                ids_in_row.update(extract_techniques(value))
            all_mentioned.update(ids_in_row)
            assessment_mentions.update(
                set().union(
                    *(
                        extract_techniques(row.get(field, ""))
                        for field in [
                            "_source.rule.mitre_techniques",
                            "_source.data.sca.check.compliance.mitre_techniques",
                        ]
                    )
                )
            )
            try:
                labels, names, tactics = (
                    json_list(row.get(field, "")) for field in [LABEL, NAMES, TACTICS]
                )
                if any(extract_techniques(label) != {label} for label in labels):
                    raise ValueError("Invalid technique token in event label array")
            except ValueError as error:
                label_parse_problems.append(
                    {"file": source, "row_index": row_index, "error": str(error)}
                )
                labels, names, tactics = [], [], []
            _, event_time = observed_time(row.get(S + "systemTime", ""))
            if event_time is not None and event_time.utcoffset() is None:
                event_time = None
            _, display_time = observed_time(row.get("_source.@timestamp", ""))
            if display_time is not None and event_time is not None:
                collector_deltas.append(
                    (display_time - event_time.replace(tzinfo=None)).total_seconds()
                )
            raw_message = row.get("_source.full_log", "")
            if present(raw_message):
                try:
                    original = json.loads(raw_message)
                    full_log_shapes[type(original).__name__] += 1
                    original_utc = original.get("win", {}).get("eventdata", {}).get("utcTime", "")
                    _, original_time = observed_time(original_utc)
                    serial = combined_row.get(P + "utcTime", "")
                    if original_time and present(serial):
                        try:
                            candidate = datetime(1899, 12, 30) + timedelta(days=float(serial))
                            delta = (candidate - original_time.replace(tzinfo=None)).total_seconds()
                            serial_deltas.append(delta)
                            if abs(delta) > 1:
                                serial_outliers.append(
                                    {
                                        "source_csv": source,
                                        "row_index": row_index,
                                        "combined_value": serial,
                                        "embedded_original_utcTime": original_utc,
                                        "difference_seconds": delta,
                                    }
                                )
                        except (ValueError, OverflowError):
                            pass
                except (ValueError, AttributeError):
                    full_log_shapes["plain_or_unparsed_text"] += 1
            values = {
                field: row[field] for field in key_fields if field in row and present(row[field])
            }
            event = {
                "file": source,
                "row_index": row_index,
                "line": line,
                "document_id": document_id,
                "signature": signature,
                "labels": sorted(set(labels)),
                "names": names,
                "tactics": tactics,
                "time": event_time,
                "display_time": display_time,
                "host": row.get(S + "computer", "").strip().casefold(),
                "agent": row.get("_source.agent.name", ""),
                "user": row.get(P + "user", "").strip(),
                "scenario": linked.get("Scenario_ID", ""),
                "strength": linked.get("Attribution_Strength", ""),
                "derived_label": linked.get("Derived_Label", ""),
                "values": values,
            }
            events.append(event)
            for field in [
                S + "providerName",
                S + "channel",
                "_source.decoder.name",
                "_source.location",
                "_source.input.type",
            ]:
                source_types[field][row.get(field, "").strip() or "(missing)"] += 1
    for _, _, extra_row in combined_stream:
        combined_fingerprints[payload_hash(extra_row)] += 1
        combined_identity_mismatches += 1
    overlap = sum((fingerprints & combined_fingerprints).values())
    exact_duplicate_rows = sum(count - 1 for count in fingerprints.values())
    # Coverage uses distinct source documents + distinct payloads.
    # Every exported row is still inventoried.
    unique_events = {}
    for event in events:
        unique_events.setdefault((event["document_id"], event["signature"]), event)
    selected = list(unique_events.values())
    manifest_counts = {
        row["Scenrario_ID"]: len(extract_techniques(row["Simulated Techniques"]))
        for row in manifest
    }
    validation_comparisons = []
    for row in validation:
        scenario = row["Scenrario_ID"]
        expected_count = int(row["Expected_techniques_count"])
        succeeded = float(row["Avg_techniques_succeeded_per_run"])
        reported_ratio = float(row["Avg_success_ratio"].rstrip("%"))
        validation_comparisons.append(
            {
                "scenario": scenario,
                "manifest_technique_count": manifest_counts.get(scenario),
                "declared_expected_count": expected_count,
                "average_succeeded": succeeded,
                "reported_success_percent": reported_ratio,
                "ratio_using_declared_count_percent": round(100 * succeeded / expected_count, 3)
                if expected_count
                else None,
            }
        )
    corpus = {
        "release_root_relative_to_raw": root.relative_to(raw).as_posix(),
        "corpus_policy": "Per-period exports referenced by mapping; combined.csv is compared "
        "separately",
        "count_unit": "Distinct (_index, _id, exact nonempty payload) source documents; not"
        " confirmed attacks",
        "exported_rows": len(events),
        "coverage_events": len(selected),
        "source_file_counts": dict(source_counts),
        "exact_duplicate_export_rows": exact_duplicate_rows,
        "duplicate_identity_rows": len(events) - len(identities),
        "conflicting_document_identities": sum(len(hashes) > 1 for hashes in identities.values()),
        "combined_export_rows": sum(combined_fingerprints.values()),
        "combined_positional_identity_matches": combined_identity_matches,
        "combined_positional_identity_mismatches": combined_identity_mismatches,
        "combined_field_difference_counts": dict(sorted(changed_fields.items())),
        "combined_field_difference_examples": dict(sorted(changed_field_examples.items())),
        "combined_exact_payload_overlap": overlap,
        "combined_only_payload_rows": sum((combined_fingerprints - fingerprints).values()),
        "period_only_payload_rows": sum((fingerprints - combined_fingerprints).values()),
        "fields": {
            field: {
                "nonempty_export_rows": field_counts[field],
                "empty_or_absent_export_rows": len(events) - field_counts[field],
                "example": field_examples.get(field),
            }
            for field in sorted(all_fields)
        },
        "log_sources": {
            field: dict(sorted(counts.items())) for field, counts in source_types.items()
        },
        "all_technique_text_mentions_in_event_rows": dict(sorted(all_mentioned.items())),
        "assessment_reference_rows": dict(sorted(assessment_mentions.items())),
        "label_parse_problems": label_parse_problems,
        "mapping": {
            "rows": len(mapping),
            "source_files": sources,
            "duplicate_join_keys": duplicate_mapping_keys,
            "join_checks": dict(join_checks),
            "orphan_mapping_keys": len(set(by_key) - event_refs),
            "strengths": count_values(row["Attribution_Strength"] for row in mapping),
            "derived_labels": count_values(row["Derived_Label"] for row in mapping),
            "scenario_assignments": count_values(
                row["Scenario_ID"] or "(unresolved)" for row in mapping
            ),
            "columns": list(mapping[0]) if mapping else [],
            "group_id_values": sorted(
                {row["MITRE_Group_ID"] for row in mapping if present(row["MITRE_Group_ID"])}
            ),
        },
        "manifest": manifest,
        "validation": validation,
        "validation_comparisons": validation_comparisons,
        "agents": {
            agent: {
                "events": sum(event["agent"] == agent for event in selected),
                "with_event_technique_labels": sum(
                    event["agent"] == agent and bool(event["labels"]) for event in selected
                ),
                "windows_event_timestamps": sum(
                    event["agent"] == agent and event["time"] is not None for event in selected
                ),
            }
            for agent in sorted({event["agent"] for event in selected})
        },
        "timestamp_quality": {
            "windows_utc_time_events": sum(event["time"] is not None for event in events),
            "display_time_events": sum(event["display_time"] is not None for event in events),
            "display_minus_windows_utc_wall_clock": distribution(collector_deltas),
            "excel_1899_12_30_hypothesis_vs_embedded_utcTime": distribution(serial_deltas),
            "serial_comparisons_within_one_second": sum(abs(x) <= 1 for x in serial_deltas),
            "serial_comparison_outliers": serial_outliers,
            "hypothesis_note": (
                "Diagnostic comparison only; no serial conversion or timezone policy "
                "applied to source data"
            ),
        },
        "full_log_value_shapes": dict(full_log_shapes),
    }
    return corpus, selected


def coverage(corpus: dict, events: list[dict]) -> dict:
    result = {}
    expected = defaultdict(list)
    for scenario in corpus["manifest"]:
        for ident in extract_techniques(scenario["Simulated Techniques"]):
            expected[ident].append(scenario["Scenrario_ID"])
    labelled = defaultdict(list)
    for event in events:
        for ident in event["labels"]:
            labelled[ident].append(event)
    for ident, matching in sorted(labelled.items()):
        field_counts = Counter(field for event in matching for field in event["values"])
        times = [event["time"] for event in matching if event["time"]]
        display = [event["display_time"] for event in matching if event["display_time"]]
        single_names = sorted(
            {
                event["names"][0]
                for event in matching
                if len(event["labels"]) == len(event["names"]) == 1
            }
        )
        scenarios = count_values(event["scenario"] or "(unresolved)" for event in matching)
        stronger_scenarios = count_values(
            event["scenario"]
            for event in matching
            if event["strength"] in {"UNIQUE-MATCH", "NARROWED"}
        )
        seen_contexts, examples = set(), []
        for event in matching:
            context = (
                event["values"].get("_source.rule.description"),
                event["values"].get(S + "eventID"),
            )
            if context not in seen_contexts and len(examples) < 5:
                seen_contexts.add(context)
                examples.append(brief(event))
        result[ident] = {
            "event_count": len(matching),
            "unambiguous_dataset_names": single_names,
            "co_labelled_names": sorted({name for event in matching for name in event["names"]}),
            "rule_descriptions": count_values(
                event["values"].get("_source.rule.description", "(missing)") for event in matching
            ),
            "files": count_values(event["file"] for event in matching),
            "manifest_expected_scenarios": sorted(expected[ident]),
            "derived_scenarios": scenarios,
            "stronger_derived_scenarios": stronger_scenarios,
            "agents": count_values(event["agent"] for event in matching),
            "computers": count_values(
                event["values"].get(S + "computer", "(missing)") for event in matching
            ),
            "users_by_source_field": {
                field: count_values(
                    event["values"][field] for event in matching if field in event["values"]
                )
                for field in GROUPS["user_authentication"]
                if field_counts[field]
            },
            "field_nonempty_events": dict(sorted(field_counts.items())),
            "behavioral_detail_events": sum(
                any(
                    field in event["values"]
                    for field in [
                        P + "commandLine",
                        P + "targetFilename",
                        P + "targetObject",
                        P + "sourceImage",
                        P + "destinationIp",
                        P + "imageLoaded",
                        P + "destination",
                        "_source.syscheck.path",
                    ]
                )
                for event in matching
            ),
            "tactic_co_labels": count_values(
                tactic for event in matching for tactic in event["tactics"]
            ),
            "provider_event_codes": count_values(
                event["values"].get(S + "providerName", "(missing)")
                + " / "
                + event["values"].get(S + "eventID", "(missing)")
                for event in matching
            ),
            "derived_labels": count_values(event["derived_label"] for event in matching),
            "attribution_strengths": count_values(event["strength"] for event in matching),
            "windows_event_time_utc": {
                "count": len(times),
                "min": min(times).isoformat() if times else None,
                "max": max(times).isoformat() if times else None,
            },
            "display_time_timezone_unassigned": {
                "count": len(display),
                "min": min(display).isoformat() if display else None,
                "max": max(display).isoformat() if display else None,
            },
            "examples": examples,
            "independent_benign_malicious_truth": (
                "Unavailable; derived labels and Wazuh tags are not independent binary truth"
            ),
        }
    return result
