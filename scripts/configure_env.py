"""Generate local credentials once; never print or overwrite existing secrets."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def configure(root: Path = ROOT) -> bool:
    target = root / ".env"
    if target.exists():
        print("Existing .env retained. See .env.example for required settings.")
        return False
    lines = (root / ".env.example").read_text(encoding="utf-8").splitlines()
    content = (
        "\n".join(
            line.replace("GENERATE_ME", secrets.token_hex(32))
            if line.endswith("=GENERATE_ME")
            else line
            for line in lines
        )
        + "\n"
    )
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    print("Created ignored .env with random credentials. No secrets printed.")
    return True


if __name__ == "__main__":
    configure()
