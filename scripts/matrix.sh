#!/usr/bin/env bash
# G3 — version x arch matrix (pos / patched-negative / bias control).
#
#   scripts/matrix.sh --dry-run
#   scripts/matrix.sh --rows 8.4 --proof lab-matrix/out/p1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 poc/verify_matrix.py "$@"
