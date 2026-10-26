"""Extract a user-supplied ZIP without overwrites; verify every extracted byte by SHA-256."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


def digest(stream) -> str:
    return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(archive: Path, destination: Path, report_path: Path) -> dict:
    archive, destination, report_path = (
        archive.resolve(),
        destination.resolve(),
        report_path.resolve(),
    )
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Destination must be new or empty; original data will not be overwritten")
    if report_path.is_relative_to(destination) or report_path == archive:
        raise ValueError("Preparation report must be separate from original evidence")
    with archive.open("rb") as stream:
        archive_sha256 = digest(stream)
    manifest = []
    with ZipFile(archive) as bundle:
        entries = [entry for entry in bundle.infolist() if not entry.is_dir()]
        targets = set()
        # Validate the whole inventory before creating anything in the destination.
        for entry in entries:
            member = PurePosixPath(entry.filename)
            if (
                member.is_absolute()
                or ".." in member.parts
                or any(
                    ":" in part or "\\" in part or part.endswith((".", " "))
                    for part in member.parts
                )
                or stat.S_ISLNK(entry.external_attr >> 16)
            ):
                raise ValueError(f"Unsafe archive member: {entry.filename!r}")
            target = destination.joinpath(*member.parts).resolve()
            if not target.is_relative_to(destination) or str(target).casefold() in targets:
                raise ValueError("Archive paths escape the destination or collide")
            targets.add(str(target).casefold())
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.filename).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            with bundle.open(entry) as source, target.open("rb") as extracted:
                expected, actual = digest(source), digest(extracted)
            if actual != expected:
                raise ValueError(f"Extracted SHA-256 differs from archive: {entry.filename}")
            manifest.append(
                {
                    "path": entry.filename,
                    "bytes": entry.file_size,
                    "sha256": actual,
                    "archive_match": True,
                }
            )
    report = {
        "archive": archive.name,
        "archive_sha256": archive_sha256,
        "files": manifest,
        "all_extracted_bytes_verified": True,
        "note": "ZIP byte verification does not authenticate publisher or dataset version",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--destination", type=Path, default=Path("dataset/raw/windows-apt-2025-v4"))
    parser.add_argument("--report", type=Path, default=Path("analysis/inspection/preparation.json"))
    args = parser.parse_args()
    try:
        result = prepare(args.archive, args.destination, args.report)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Preparation failed: {error}\n")
    print(f"Extracted and verified {len(result['files'])} files. Report: {args.report}")
