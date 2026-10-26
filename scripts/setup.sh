#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--start" ) ]]; then
  echo "Usage: bash scripts/setup.sh [--start]" >&2
  exit 2
fi
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/configure_env.py
docker compose config --quiet
if [[ "${1:-}" == "--start" ]]; then
  docker compose up -d --wait --wait-timeout 360
fi
echo "Setup complete. See README.md for dataset inspection and current phase limits."
