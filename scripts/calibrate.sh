#!/usr/bin/env bash
# G1 — per-build heap-geometry calibration sweep (lab-only).
#
#   scripts/calibrate.sh --self-test
#   scripts/calibrate.sh --target 127.0.0.1:18164 --arch aarch64 \
#       --proof lab-matrix/out/p1 --write
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m php2shell.calibrate "$@"
