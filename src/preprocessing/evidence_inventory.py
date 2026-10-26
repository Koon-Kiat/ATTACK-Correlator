"""Generate Phase 2 artifacts from raw v4 bytes; never modify or ingest source data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from src.preprocessing.correlation_inventory import relationships
from src.preprocessing.event_inventory import coverage, load_release
from src.preprocessing.inspect_dataset import engine_digest, inspect_dataset
from src.preprocessing.profile_values import (
    OTHER_ATTACK_PATTERN,
    extract_techniques,
    technique_kind,
)
from src.preprocessing.windows_fields import GROUPS


def fingerprint_files(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != ".gitkeep":
            if path.is_symlink():
                raise ValueError("Raw evidence may not be a symbolic link")
            with path.open("rb") as stream:
                result[path.relative_to(root).as_posix()] = hashlib.file_digest(
                    stream, "sha256"
                ).hexdigest()
    return result


def collect_mentions(raw: Path, schema: dict) -> dict:
    mentions = {}
    for file in schema["files"]:
        for field, info in file["fields"].items():
            for ident, count in info["attack_id_text_occurrences"].items():
                entry = mentions.setdefault(ident, {"kind": technique_kind(ident), "locations": []})
                entry["locations"].append(
                    {
                        "file": file["path"],
                        "field": field,
                        "text_occurrences": count,
                        "scope": "structured value mention; see event-label counts separately",
                    }
                )
    other_ids = {}
    for path in sorted(raw.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".md", ".py", ".ipynb"}:
            text = path.read_text(encoding="utf-8-sig")
            for ident in sorted(extract_techniques(text)):
                entry = mentions.setdefault(ident, {"kind": technique_kind(ident), "locations": []})
                entry["locations"].append(
                    {
                        "file": path.relative_to(raw).as_posix(),
                        "scope": "documentation/code/notebook mention only",
                    }
                )
            for ident in sorted(set(OTHER_ATTACK_PATTERN.findall(text))):
                other_ids.setdefault(ident, set()).add(path.relative_to(raw).as_posix())
    # Include other ATT&CK identifier families in structured values.
    # Do not present them as techniques.
    from src.preprocessing.inspect_dataset import read_records, strings

    for path in sorted(raw.rglob("*.csv")):
        for _, record, error in read_records(path, "utf-8-sig", ",", 64 * 1024**2):
            if error:
                continue
            for value in record.values():
                for text in strings(value):
                    for ident in OTHER_ATTACK_PATTERN.findall(text):
                        other_ids.setdefault(ident, set()).add(path.relative_to(raw).as_posix())
    return {
        "technique_identifiers": dict(sorted(mentions.items())),
        "other_identifier_families": {
            key: sorted(value) for key, value in sorted(other_ids.items())
        },
    }


def rate_candidates(coverage_data: dict, pairs: list) -> dict:
    ratings = {}
    for ident, info in coverage_data.items():
        if technique_kind(ident) != "sub-technique":
            continue
        count = info["event_count"]
        details = info["behavioral_detail_events"]
        structural = sum(
            pair["exclusive_structural_pairs_within_300_seconds"]
            for pair in pairs
            if ident in pair["techniques"]
        )
        candidates = [pair for pair in pairs if ident in pair["techniques"]]
        fraction = details / count
        quality = "Strong" if fraction >= 0.8 else "Moderate" if fraction >= 0.25 else "Weak"
        ratings[ident] = {
            "event_volume": "Strong" if count >= 1000 else "Moderate" if count >= 100 else "Weak",
            "observable_field_coverage": quality,
            "evidence_quality": "Moderate" if details else "Weak",
            "ground_truth": "Weak",
            "benign_comparison": "Weak",
            "siem_detection": "Strong"
            if count >= 100 and fraction >= 0.8
            else "Moderate"
            if details
            else "Weak",
            "correlation": "Strong" if structural >= 10 else "Moderate" if candidates else "Weak",
            "dashboard": "Strong" if count >= 100 and details else "Moderate" if count else "Weak",
            "explanation": (
                f"{count} labelled source documents; {details} have "
                "command/file/object/module/network detail; "
                f"{structural} exclusive-label structural pair observations within "
                "300 seconds across relation categories. Tags and derived scenarios "
                "are not independent truth; behavioural interpretation needs review."
            ),
        }
    return ratings


def write_json(path: Path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def generate(raw: Path, output: Path, reuse_schema: bool = False) -> dict:
    raw, output = raw.resolve(), output.resolve()
    if output.is_relative_to(raw) or raw.is_relative_to(output):
        raise ValueError("Output must be separate from the raw evidence tree")
    before = fingerprint_files(raw)
    if not before:
        raise ValueError("No raw dataset found; dataset-dependent work is pending")
    output.mkdir(parents=True, exist_ok=True)
    schema_path = output / "dataset_schema.json"
    if reuse_schema and schema_path.exists():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cached = {entry["path"]: entry["sha256"] for entry in schema.get("file_inventory", [])}
        if cached != before or schema.get("inspection_engine_sha256") != engine_digest():
            raise ValueError("Schema cache is stale; rerun without --reuse-schema")
    else:
        print("Inspecting all raw schemas and values...", flush=True)
        schema = inspect_dataset(raw)
        write_json(schema_path, schema)
    if schema["status"] != "inspected":
        raise ValueError(
            "Incomplete or malformed structured evidence; inspect dataset_schema.json first"
        )
    print("Checking source overlap, join keys, event labels and telemetry...", flush=True)
    corpus, events = load_release(raw)
    by_technique = coverage(corpus, events)
    print("Enumerating distinct-event correlation candidates...", flush=True)
    pairs = relationships(events)
    mentions = collect_mentions(raw, schema)
    result = {
        "phase": 2,
        "corpus": corpus,
        "coverage": by_technique,
        "mentions": mentions,
        "correlation_candidates": pairs,
        "candidate_ratings": rate_candidates(by_technique, pairs),
        "telemetry_groups": {
            group: [field for field in fields if field in corpus["fields"]]
            for group, fields in GROUPS.items()
        },
        "counting_notes": [
            "Event counts use one nonduplicated corpus; label sets can overlap across techniques.",
            "A Wazuh label is an annotation, not independent evidence of "
            "successful malicious execution.",
            "Manifest expectations, SCA references, code and documentation are "
            "not counted as event detections.",
            "Pairs involve distinct documents and known UTC Windows event times; "
            "no detection rule is created.",
            "Scenario fields are derived labels, not independent event-level "
            "benign/malicious ground truth.",
        ],
    }
    write_json(output / "attack_evidence.json", result)
    with (output / "attack_coverage.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "attack_id",
                "kind",
                "event_count",
                "dataset_names",
                "event_files",
                "manifest_expected_scenarios",
                "derived_scenarios",
                "stronger_derived_scenarios",
                "mention_files",
                "evidence_status",
            ],
        )
        writer.writeheader()
        for ident, mentions_info in mentions["technique_identifiers"].items():
            item = by_technique.get(ident, {})
            writer.writerow(
                {
                    "attack_id": ident,
                    "kind": technique_kind(ident),
                    "event_count": item.get("event_count", 0),
                    "dataset_names": json.dumps(item.get("unambiguous_dataset_names", [])),
                    "event_files": json.dumps(item.get("files", {}), sort_keys=True),
                    "manifest_expected_scenarios": json.dumps(
                        [
                            row["Scenrario_ID"]
                            for row in corpus["manifest"]
                            if ident in extract_techniques(row["Simulated Techniques"])
                        ]
                    ),
                    "derived_scenarios": json.dumps(
                        item.get("derived_scenarios", {}), sort_keys=True
                    ),
                    "stronger_derived_scenarios": json.dumps(
                        item.get("stronger_derived_scenarios", {}), sort_keys=True
                    ),
                    "mention_files": json.dumps(
                        sorted({loc["file"] for loc in mentions_info["locations"]})
                    ),
                    "evidence_status": "event_annotation_with_telemetry"
                    if item
                    else "reference_or_text_mention_only",
                }
            )
    from src.preprocessing.inventory_reports import render_reports

    render_reports(output, schema, result)
    if fingerprint_files(raw) != before:
        raise ValueError("Raw evidence changed during analysis; results must be regenerated")
    generated = [
        "dataset_schema.json",
        "attack_evidence.json",
        "attack_coverage.csv",
        "dataset_inventory.md",
        "attack_coverage.md",
        "ecs_mapping_candidates.md",
    ]
    code_root = Path(__file__).parent
    provenance = {
        "phase": 2,
        "raw_files_unchanged": True,
        "input_sha256": before,
        "generator_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(code_root.glob("*.py"))
        },
        "output_sha256": {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in generated
        },
    }
    write_json(output / "inventory-manifest.json", provenance)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("dataset/raw"))
    parser.add_argument("--output", type=Path, default=Path("analysis"))
    parser.add_argument(
        "--reuse-schema",
        action="store_true",
        help="Reuse only a byte- and code-verified schema cache",
    )
    args = parser.parse_args(argv)
    try:
        result = generate(args.input, args.output, args.reuse_schema)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"Phase 2 analysis failed: {error}\n")
    parents = sum(technique_kind(ident) == "parent-technique" for ident in result["coverage"])
    subtechniques = len(result["coverage"]) - parents
    print(
        f"Generated Phase 2 outputs: {parents} parent and {subtechniques} "
        "sub-technique event labels. No rules selected."
    )


if __name__ == "__main__":
    main()
