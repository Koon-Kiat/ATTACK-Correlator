"""Read-only, schema-agnostic CSV/JSON inventory. No normalization or labels inferred."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

from src.preprocessing.profile_values import TECHNIQUE_PATTERN, ValueProfile, canonical

SUPPORTED = {".csv", ".json", ".jsonl", ".ndjson", ".ipynb"}
ATTACK_ID = TECHNIQUE_PATTERN
HINTS = {
    "timestamp": r"timestamp|datetime|utc|(?:^|[ _./-])(?:time|date)(?:$|[ _./-])",
    "attack_label": r"mitre|attack|technique|tactic",
    "ground_truth": r"label|ground.?truth|malicious|benign|scenario|manifest|validation",
    "host": r"host|computer|agent",
    "process": r"process|command|image|parent|(?:^|[ _./-])pid(?:$|[ _./-])",
    "user": r"user|account|subject",
    "network": r"source|destination|src|dst|address|port|(?:^|[ _./-])ip(?:$|[ _./-])",
    "file": r"file|hash|targetobject|registry|creation|delet",
    "event_source": r"eventid|eventcode|provider|decoder|channel|location|input.type",
    "operating_system": r"os\.|operating|platform",
}


def reject_duplicate_keys(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key; object was not inspected")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {value}")


def parse_json(text: str):
    return json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)


def flatten(record: dict, prefix: str = "") -> dict:
    """Use JSON Pointer paths so nested keys cannot collide with literal dotted keys."""
    result = {}
    for key, value in record.items():
        path = prefix + "/" + key.replace("~", "~0").replace("/", "~1")
        if isinstance(value, dict) and value:
            result.update(flatten(value, path))
        else:
            result[path] = value
    return result


def read_records(path: Path, encoding: str, delimiter: str, max_json_bytes: int):
    """Yield (source location, record, error); never skip malformed records silently."""
    with path.open(encoding=encoding, errors="strict", newline="") as stream:
        if path.suffix.lower() == ".csv":
            # Large command lines are valid evidence; cap one field at 16 MiB.
            csv.field_size_limit(16 * 1024 * 1024)
            reader = csv.reader(stream, delimiter=delimiter, strict=True)
            headers = next(reader, None)
            if not headers or any(not name.strip() for name in headers):
                raise ValueError("CSV header missing or contains empty column names")
            if len(headers) != len(set(headers)):
                raise ValueError("Duplicate CSV column names; mapping would lose evidence")
            yield "header", {name: None for name in headers}, "__header__"
            for row in reader:
                if len(row) != len(headers):
                    yield (
                        reader.line_num,
                        None,
                        (f"CSV width {len(row)} differs from header width {len(headers)}"),
                    )
                else:
                    yield reader.line_num, dict(zip(headers, row, strict=True)), None
        elif path.suffix.lower() in {".ndjson", ".jsonl"}:
            for number, line in enumerate(stream, 1):
                try:
                    value = parse_json(line)
                    if not isinstance(value, dict):
                        raise ValueError("Record must be a JSON object")
                    yield number, value, None
                except (ValueError, RecursionError) as error:
                    yield number, None, str(error)
        else:
            if path.stat().st_size > max_json_bytes:
                raise ValueError("JSON document exceeds --max-json-mb; not read into memory")
            value = parse_json(stream.read())
            records = value if isinstance(value, list) else [value]
            for number, record in enumerate(records, 1):
                if not isinstance(record, dict):
                    yield number, None, "Record must be a JSON object"
                else:
                    yield number, record, None


def is_missing(value) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def timestamp_shape(value: str) -> str | None:
    """Probe ISO-formatted strings only; do not guess epoch units or timezone."""
    if not re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return "aware" if parsed.utcoffset() is not None else "naive"


def inspect_file(
    path: Path,
    root: Path,
    *,
    max_records: int = 0,
    encoding: str = "utf-8-sig",
    delimiter: str = ",",
    max_json_bytes: int = 64 * 1024 * 1024,
) -> dict:
    report = {
        "path": path.relative_to(root).as_posix(),
        "format": path.suffix.lower()[1:],
        "bytes": path.stat().st_size,
        "sha256": None,
        "records_examined": 0,
        "valid_records": 0,
        "malformed_records": 0,
        "scan_complete": True,
        "fields": {},
        "diagnostics": [],
        "diagnostics_omitted": 0,
    }
    profiles = {}
    batch = []
    row_signatures = {}
    duplicate_examples = []
    duplicate_count = 0

    def diagnostic(location, message):
        if len(report["diagnostics"]) < 20:
            report["diagnostics"].append({"location": location, "message": message})
        else:
            report["diagnostics_omitted"] += 1

    def add_fields(record):
        for field in record:
            profiles.setdefault(
                field,
                {
                    "present": 0,
                    "nonempty": 0,
                    "types": Counter(),
                    "pandas_inferences": set(),
                    "iso_timestamps": Counter(),
                    "attack_id_occurrences": Counter(),
                    "value_profile": ValueProfile(bool(re.search(HINTS["timestamp"], field, re.I))),
                },
            )

    def flush():
        if not batch:
            return
        # A bounded DataFrame provides type hints; source values are never coerced.
        frame = pd.DataFrame([row for _, row in batch], dtype=object)
        for field in frame.columns:
            values = [row[field] for _, row in batch if field in row]
            nonempty = [value for value in values if not is_missing(value)]
            info = profiles[field]
            for location, row in batch:
                if field in row and not is_missing(row[field]):
                    info["value_profile"].add(row[field], location)
            info["present"] += len(values)
            info["nonempty"] += len(nonempty)
            info["types"].update(type(value).__name__ for value in nonempty)
            if nonempty:
                info["pandas_inferences"].add(pd.api.types.infer_dtype(nonempty, skipna=False))
            for value in nonempty:
                for text in strings(value):
                    info["attack_id_occurrences"].update(ATTACK_ID.findall(text))
                if isinstance(value, str) and (shape := timestamp_shape(value)):
                    info["iso_timestamps"][shape] += 1
        batch.clear()

    try:
        with path.open("rb") as stream:
            report["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        for location, record, error in read_records(path, encoding, delimiter, max_json_bytes):
            if error == "__header__":
                add_fields(flatten(record))
                continue
            if max_records and report["records_examined"] >= max_records:
                report["scan_complete"] = False
                diagnostic(location, "Record limit reached; all counts are for the examined prefix")
                break
            report["records_examined"] += 1
            if error:
                report["malformed_records"] += 1
                diagnostic(location, error)
                continue
            report["valid_records"] += 1
            signature = hashlib.sha256(canonical(record)).digest()
            if signature in row_signatures:
                duplicate_count += 1
                if len(duplicate_examples) < 10:
                    duplicate_examples.append(
                        {
                            "first_location": row_signatures[signature],
                            "duplicate_location": location,
                        }
                    )
            else:
                row_signatures[signature] = location
            flat = flatten(record)
            add_fields(flat)
            batch.append((location, flat))
            if len(batch) >= 500:
                flush()
    except (OSError, UnicodeError, ValueError, csv.Error, RecursionError) as error:
        report["scan_complete"] = False
        diagnostic("file", str(error))
    flush()
    for field, info in sorted(profiles.items()):
        report["fields"][field] = {
            "present_records": info["present"],
            "absent_records": report["valid_records"] - info["present"],
            "empty_or_null_records": info["present"] - info["nonempty"],
            "observed_types": dict(sorted(info["types"].items())),
            "pandas_type_hints": sorted(info["pandas_inferences"]),
            "iso_timestamp_shapes": dict(sorted(info["iso_timestamps"].items())),
            "attack_id_text_occurrences": dict(sorted(info["attack_id_occurrences"].items())),
            **info["value_profile"].report(),
        }
    report["duplicate_records"] = duplicate_count
    report["duplicate_definition"] = "Repeated parsed records including all original fields"
    report["duplicate_examples"] = duplicate_examples
    report["empty_file"] = report["bytes"] == 0
    report["candidate_fields_by_name"] = {
        role: [field for field in report["fields"] if re.search(pattern, field, re.I)]
        for role, pattern in HINTS.items()
    }
    report["roles_without_name_candidates"] = [
        role for role, fields in report["candidate_fields_by_name"].items() if not fields
    ]
    return report


def inspect_dataset(root: Path, **options) -> dict:
    root = root.resolve()
    if root.exists() and not root.is_dir():
        raise ValueError("Input must be a directory")
    paths = sorted(root.rglob("*")) if root.exists() else []
    files = [p for p in paths if p.is_file() and p.name != ".gitkeep"]
    supported = [p for p in files if p.suffix.lower() in SUPPORTED and not p.is_symlink()]
    reports = [inspect_file(path, root, **options) for path in supported]
    issues = any(not item["scan_complete"] or item["malformed_records"] for item in reports)
    structured = {item["path"]: item for item in reports}
    inventory = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        entry = {
            "path": relative,
            "format": path.suffix.lower()[1:] or "extensionless",
            "bytes": path.stat().st_size,
            "empty": path.stat().st_size == 0,
            "sha256": None,
            "readable": True,
        }
        try:
            if relative in structured:
                entry["sha256"] = structured[relative]["sha256"]
                entry["parsed_records"] = structured[relative]["valid_records"]
            else:
                with path.open("rb") as stream:
                    entry["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError as error:
            entry["readable"], entry["error"] = False, str(error)
            issues = True
        inventory.append(entry)
    return {
        "report_version": 2,
        "inspection_engine_sha256": engine_digest(),
        "status": "pending_dataset" if not reports else "needs_review" if issues else "inspected",
        "scope": "Read-only file inventory; no ECS mapping, technique selection, or evaluation",
        "caveats": [
            "Field-name candidates are hints, not verified semantics or ground truth.",
            "ATT&CK-shaped strings do not prove that a sub-technique occurred.",
            "Counts are per file; overlapping combined and per-period exports may double-count.",
            "JSON arrays are records; a wrapper object is one record, not an assumed event array.",
            "Examples retain source locations and mark truncation at 240 characters.",
            "Distinct counts above 10000 are explicit lower bounds, not estimates.",
            "A notebook is inspected as one JSON document, not a telemetry event.",
            "Timestamp range calculations use microseconds; raw examples preserve"
            " original precision.",
            "Empty means JSON null or a whitespace-only string; NA/null strings are preserved.",
            "CSV quoting/encoding failures stop a file; fatal errors have unknown record counts.",
        ],
        "files": reports,
        "file_inventory": inventory,
        "uninspected_files": [p.relative_to(root).as_posix() for p in files if p not in supported],
        "next_step": "Review files, manifest, semantics, timezones and ground truth in Phase 2",
    }


def engine_digest() -> str:
    from src.preprocessing import profile_values

    return hashlib.sha256(
        Path(__file__).read_bytes() + Path(profile_values.__file__).read_bytes()
    ).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("dataset/raw"))
    parser.add_argument("--output", type=Path, default=Path("analysis/inspection/report.json"))
    parser.add_argument("--max-records", type=int, default=0, help="Per file; 0 means full scan")
    parser.add_argument("--encoding", default="utf-8-sig")
    parser.add_argument("--delimiter", default=",")
    parser.add_argument("--max-json-mb", type=int, default=64)
    args = parser.parse_args(argv)
    if args.max_records < 0 or args.max_json_mb < 1 or len(args.delimiter) != 1:
        parser.error(
            "Use a nonnegative record limit, positive JSON size and one-character delimiter"
        )
    if args.output.resolve().is_relative_to(args.input.resolve()):
        parser.error("Inspection reports must be outside the source directory")
    try:
        report = inspect_dataset(
            args.input,
            max_records=args.max_records,
            encoding=args.encoding,
            delimiter=args.delimiter,
            max_json_bytes=args.max_json_mb * 1024**2,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, LookupError) as error:
        parser.exit(1, f"Inspection failed: {error}\n")
    print(f"{report['status']}: {len(report['files'])} supported files; report: {args.output}")
    return {"inspected": 0, "needs_review": 1, "pending_dataset": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
