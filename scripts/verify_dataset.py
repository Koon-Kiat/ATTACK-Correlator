"""Check a publisher checksum file without running publisher code or changing source bytes."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def verify(root: Path) -> dict:
    root = root.resolve()
    checksums = root / "checksums.sha256"
    entries = []
    for number, line in enumerate(checksums.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?(.+)", line.strip())
        if not match:
            raise ValueError(f"Malformed checksum entry on line {number}")
        expected, original_name = match.groups()
        # Original checksums may contain the publisher's absolute Windows paths.
        # Resolve only a unique basename inside the supplied dataset directory.
        name = original_name.replace("\\", "/").split("/")[-1]
        candidates = [path for path in root.rglob("*") if path.is_file() and path.name == name]
        if len(candidates) != 1 or candidates[0].is_symlink():
            raise ValueError(f"Checksum filename missing, ambiguous or symlink: {name}")
        with candidates[0].open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        entries.append(
            {
                "file": candidates[0].relative_to(root).as_posix(),
                "expected": expected.lower(),
                "actual": actual,
                "match": expected.lower() == actual,
            }
        )
    if not entries:
        raise ValueError("Checksum file contains no entries")
    verified = {entry["file"] for entry in entries}
    return {
        "checked": len(entries),
        "matched": sum(entry["match"] for entry in entries),
        "entries": entries,
        "not_covered": sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
            and path.relative_to(root).as_posix() not in verified
            and path != checksums
        ),
        "note": "Internal checksums detect byte changes; they do not authenticate the publisher",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument(
        "--output", type=Path, default=Path("analysis/inspection/publisher-checksums.json")
    )
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(args.root.resolve()):
        parser.error("Checksum report must be outside the source directory")
    try:
        result = verify(args.root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Verification failed: {error}\n")
    print(f"Publisher checksum matches: {result['matched']}/{result['checked']}")
    raise SystemExit(0 if result["matched"] == result["checked"] else 1)
