#!/usr/bin/env bash
# G4 — build-to-build ELF diff for the matrix (host-side, no lab traffic).
#
#   scripts/diff_builds.sh --self-test
#   scripts/diff_builds.sh --old php:8.4.26-apache --new php:8.4.27-apache
#   scripts/diff_builds.sh --old php:8.4.26-apache --new php:8.4.27-apache \
#       --ghidriff --write-profile
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m php2shell.build_diff "$@"
