#!/usr/bin/env bash
# Offline repository gate. It does not prove a vulnerability claim.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/check.py
python3 -m unittest discover -s tests -v
