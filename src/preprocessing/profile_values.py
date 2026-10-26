"""Small, bounded value summaries used by read-only inspection."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime

TECHNIQUE_PATTERN = re.compile(r"(?<![A-Za-z0-9_.])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9_.])")
OTHER_ATTACK_PATTERN = re.compile(r"(?<![A-Za-z0-9_])(?:TA\d{4}|G\d{4}|S\d{4}|M\d{4})(?!\w)")
MONTHS = {
    name: number
    for number, name in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)
}


def extract_techniques(value: str) -> set[str]:
    return set(TECHNIQUE_PATTERN.findall(value))


def technique_kind(identifier: str) -> str:
    if re.fullmatch(r"T\d{4}\.\d{3}", identifier):
        return "sub-technique"
    if re.fullmatch(r"T\d{4}", identifier):
        return "parent-technique"
    raise ValueError(f"Not a technique identifier: {identifier}")


def observed_time(value: str) -> tuple[str, datetime | None]:
    """Parse explicit formats for inspection; never infer a timezone or epoch unit."""
    match = re.fullmatch(
        r"([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) @ (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", value
    )
    if match:
        month, day, year, hour, minute, second, fraction = match.groups()
        try:
            result = datetime(
                int(year),
                MONTHS[month],
                int(day),
                int(hour),
                int(minute),
                int(second),
                int(((fraction or "") + "000000")[:6]),
            )
            return "display_month_day_year_at_time_timezone_unspecified", result
        except (ValueError, KeyError):
            return "invalid_display_timestamp", None
    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", value):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.utcoffset() is not None:
                return "iso8601_with_offset", result.astimezone(UTC)
            return "iso8601_timezone_unspecified", result
        except ValueError:
            return "invalid_iso_timestamp", None
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value):
        return "numeric_time_candidate_units_unresolved", None
    if re.fullmatch(r"\d{1,2}:\d{2}(?:\.\d+)?", value):
        return "partial_clock_missing_date_and_hour", None
    if re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}(?: \d{1,2}:\d{2}(?::\d{2})?)?", value):
        return "slash_date_order_and_timezone_unresolved", None
    return "other", None


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class ValueProfile:
    """Exact small-domain distinct counts; explicit lower bounds beyond the memory cap."""

    def __init__(self, is_time: bool, distinct_limit: int = 10000):
        self.is_time = is_time
        self.distinct_limit = distinct_limit
        self.distinct = set()
        self.distinct_capped = False
        self.examples = []
        self.forms = Counter()
        self.time_formats = Counter()
        self.time_ranges = {}
        self.json_shapes = Counter()
        self.json_paths = Counter()
        self.json_paths_capped = False

    def add(self, value, location):
        encoded = canonical(value)
        signature = hashlib.sha256(encoded).digest()
        if signature not in self.distinct:
            if len(self.distinct) < self.distinct_limit:
                self.distinct.add(signature)
            else:
                self.distinct_capped = True
        if len(self.examples) < 3:
            displayed = value if isinstance(value, str) else encoded.decode()
            if not any(example["value"] == displayed[:240] for example in self.examples):
                self.examples.append(
                    {
                        "value": displayed[:240],
                        "truncated": len(displayed) > 240,
                        "source_location": location,
                    }
                )
        if not isinstance(value, str):
            return
        if re.fullmatch(r"[+-]?\d+", value):
            self.forms["integer_text"] += 1
        elif re.fullmatch(r"[+-]?(?:\d+\.\d*|\d*\.\d+)(?:[eE][+-]?\d+)?", value):
            self.forms["decimal_text"] += 1
        elif value in {"true", "false", "True", "False"}:
            self.forms["boolean_text"] += 1
        else:
            self.forms["other_text"] += 1
        form, parsed = observed_time(value)
        if parsed is not None or self.is_time:
            self.time_formats[form] += 1
        if parsed is not None:
            key = "aware_utc" if parsed.utcoffset() is not None else "naive_unassigned_timezone"
            text = parsed.isoformat()
            limits = self.time_ranges.setdefault(key, {"min": text, "max": text})
            limits["min"], limits["max"] = min(limits["min"], text), max(limits["max"], text)
        if value.lstrip().startswith(("{", "[")):
            try:
                nested = json.loads(value)
            except (ValueError, RecursionError):
                self.json_shapes["json_like_unparseable"] += 1
                return
            self.json_shapes[type(nested).__name__] += 1
            if isinstance(nested, dict):
                self._paths(nested)

    def _paths(self, value, prefix=""):
        for key, child in value.items():
            path = prefix + "/" + key.replace("~", "~0").replace("/", "~1")
            if isinstance(child, dict) and child:
                self._paths(child, path)
            elif path in self.json_paths or len(self.json_paths) < 500:
                self.json_paths[path] += 1
            else:
                self.json_paths_capped = True

    def report(self):
        return {
            "distinct_nonempty_values": len(self.distinct),
            "distinct_count_exact": not self.distinct_capped,
            "distinct_count_note": "lower bound"
            if self.distinct_capped
            else "complete examined scope",
            "examples": self.examples,
            "lexical_forms": dict(sorted(self.forms.items())),
            "timestamp_formats": dict(sorted(self.time_formats.items())),
            "timestamp_ranges": self.time_ranges,
            "embedded_json_shapes": dict(sorted(self.json_shapes.items())),
            "embedded_json_leaf_paths": dict(sorted(self.json_paths.items())),
            "embedded_json_path_limit_reached": self.json_paths_capped,
        }
