"""Package reviewed Git-index blobs; keep every generated artifact outside Git."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".local",
    ".test-tmp",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "reports",
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def forbidden(name):
    path = PurePosixPath(name)
    return (
        path.is_absolute()
        or ".." in path.parts
        or bool(set(path.parts) & EXCLUDED_PARTS)
        or "phase" in path.name.lower()
        or path.name.lower().startswith("ai-usage")
        or (path.name.startswith(".env") and path.name != ".env.example")
        or path.suffix.lower() in {".zip", ".pem", ".key", ".p12", ".pfx", ".pyc", ".log"}
        or (name.startswith(("dataset/raw/", "dataset/processed/")) and path.name != ".gitkeep")
    )


def package(output):
    """Fail on forbidden staged inputs and preserve hash-linked blob bytes exactly."""
    output = output.resolve()
    if not output.is_relative_to(ROOT / "reports"):
        raise ValueError("Output must stay inside the ignored reports directory")
    if git("ls-files", "reports").strip():
        raise ValueError("The reports directory must not be tracked")
    entries = []
    for entry in git("ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, encoded_name = entry.split(b"\t", 1)
        mode, blob, stage = metadata.decode().split()
        name = encoded_name.decode("utf-8")
        if stage != "0" or mode not in {"100644", "100755"} or forbidden(name):
            raise ValueError(f"Unexpected or forbidden staged archive input: {name}")
        entries.append((name, mode, blob))
    if not entries or not any(name == ".env.example" for name, _, _ in entries):
        raise ValueError("Reviewed project inputs and .env.example are required")
    # Compare actual local credential values without emitting them or copying .env.
    secrets = []
    env_path = ROOT / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            name, value = line.split("=", 1)
            if re.search(r"PASSWORD|KEY|TOKEN|SECRET", name, re.I):
                value = value.strip().strip("\"'")
                if len(value) >= 8 and value != "GENERATE_ME":
                    secrets.append(value.encode())
    output.parent.mkdir(parents=True, exist_ok=True)
    inventory = []
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name, mode, blob in sorted(entries):
            content = git("cat-file", "blob", blob)
            if any(secret in content for secret in secrets):
                raise ValueError(f"Local credential found in staged input: {name}")
            if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", content):
                raise ValueError(f"Private key material found in staged input: {name}")
            info = ZipInfo(name, date_time=(2026, 9, 15, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = int(mode, 8) << 16
            archive.writestr(info, content)
            inventory.append(
                {
                    "path": name,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "git_blob": blob,
                }
            )
    with ZipFile(output) as archive:
        if archive.testzip() is not None or len(archive.namelist()) != len(inventory):
            raise ValueError("Archive integrity check failed")
        for row in inventory:
            if hashlib.sha256(archive.read(row["path"])).hexdigest() != row["sha256"]:
                raise ValueError(f"Archive readback differs: {row['path']}")
    audit = {
        "archive": output.name,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "file_count": len(inventory),
        "zip_bytes": output.stat().st_size,
        "source": "Git index blobs, including reviewed uncommitted changes",
        "index_tree": git("write-tree").decode().strip(),
        "crc_and_complete_sha256_readback_passed": True,
        "forbidden_paths_absent": True,
        "local_credential_values_absent": True,
        "private_key_markers_absent": True,
        "phase_filenames_absent": True,
        "ai_usage_documents_absent": True,
        "git_history_absent": True,
        "files": inventory,
    }
    (output.parent / "archive-validation.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (output.parent / "archive-contents.txt").write_text(
        "\n".join(row["path"] for row in inventory) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({key: value for key, value in audit.items() if key != "files"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports/ATTACK-Correlator-code.zip")
    package(parser.parse_args().output)
