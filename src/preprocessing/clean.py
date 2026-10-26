"""Lossless CSV evidence capture and strict scalar validation for Phase 3."""

import csv
import ipaddress
import ntpath
import re
from datetime import UTC, datetime
from uuid import UUID


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def original_fields(row):
    """Empty CSV cells are elided; the source-schema sidecar restores them exactly."""
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in row.items()):
        raise ValueError("CSV evidence must contain string keys and values")
    return {k: v for k, v in row.items() if v != ""}


def restore_row(original, headers):
    if not set(original).issubset(headers):
        raise ValueError("Original fields are outside the source schema")
    return {key: original.get(key, "") for key in headers}


def csv_rows(path):
    """Recover width errors explicitly; fatal framing/encoding errors abort the run."""
    csv.field_size_limit(16 * 1024**2)
    with path.open(encoding="utf-8-sig", errors="strict", newline="") as stream:
        reader = csv.reader(stream, strict=True)
        headers = next(reader, [])
        if not headers or len(set(headers)) != len(headers) or any(not h.strip() for h in headers):
            raise ValueError(f"Invalid or duplicate CSV header in {path.name}")
        for index, values in enumerate(reader):
            row = dict(zip(headers, values, strict=False))
            error = None
            if len(values) != len(headers):
                error = f"CSV width {len(values)} differs from header width {len(headers)}"
            yield headers, index, reader.line_num, row, values, error


def integer(value, maximum):
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
        raise ValueError("Expected unsigned decimal or hexadecimal integer")
    number = int(value, 16 if value.lower().startswith("0x") else 10)
    if not 0 <= number <= maximum:
        raise ValueError("Integer outside allowed range")
    return number


def port(value):
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("Port must be a decimal integer")
    return integer(value, 65535)


def ip(value):
    if "%" in value:
        raise ValueError("Scoped IPv6 is not an Elasticsearch IP scalar")
    return str(ipaddress.ip_address(value))


def guid(value):
    if not re.fullmatch(r"\{[0-9A-Fa-f-]{36}\}|[0-9A-Fa-f-]{36}", value):
        raise ValueError("Expected a complete GUID")
    if UUID(value.strip("{}")).int == 0:
        raise ValueError("All-zero GUID is not a usable process identity")
    return value


def boolean(value):
    if value.lower() not in {"true", "false"}:
        raise ValueError("Expected true or false")
    return value.lower() == "true"


def safe_text(value):
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Control characters in identifier/path")
    return value


def windows_path(value, executable=False):
    """Validate without interpreting backslash escapes or expanding environment variables."""
    value = safe_text(value)
    for quote in ['"', '\\"']:
        if value.startswith(quote) and value.endswith(quote) and len(value) > 2 * len(quote):
            value = value[len(quote) : -len(quote)]
            break
    if executable and value.casefold() == "system":
        return None, value
    if not value or value != value.strip() or any(c in value for c in '<>"|?*'):
        raise ValueError("Malformed Windows path")
    drive, tail = ntpath.splitdrive(value)
    absolute = bool(re.fullmatch(r"[A-Za-z]:", drive) and tail.startswith("\\"))
    unc = drive.startswith("\\\\") and tail.startswith("\\")
    bare = "\\" not in value and "/" not in value and ":" not in value
    if not (absolute or unc or (executable and bare)) or ":" in tail:
        raise ValueError("Ambiguous path, device path or alternate stream")
    name = ntpath.basename(value)
    if not name or name in {".", ".."}:
        raise ValueError("Path has no filename")
    if executable and ntpath.splitext(name)[1].lower() not in {".exe", ".com", ".scr"}:
        raise ValueError("Not a defensible executable filename")
    return value, name


def utc_timestamp(value):
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", value
    )
    if not match:
        raise ValueError("Timestamp needs explicit offset and at most nine fractional digits")
    whole, fraction, offset = match.groups()
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:]) > 59):
        raise ValueError("Invalid timezone offset")
    parsed = datetime.fromisoformat(whole + offset.replace("Z", "+00:00")).astimezone(UTC)
    delta = parsed - datetime(1970, 1, 1, tzinfo=UTC)
    nanos = (delta.days * 86400 + delta.seconds) * 10**9 + int((fraction or "").ljust(9, "0"))
    if not 0 <= nanos <= 2**63 - 1:
        raise ValueError("Timestamp outside Elasticsearch date_nanos range")
    return parsed.strftime("%Y-%m-%dT%H:%M:%S") + ("." + fraction if fraction else "") + "Z"
