#!/usr/bin/env bash
# G5 — PHP gadget inventory over app trees (read-only, no lab traffic).
#
#   scripts/gadget_sweep.sh --self-test
#   scripts/gadget_sweep.sh                          # all known lab roots
#   scripts/gadget_sweep.sh lab-roundcube/roundcubemail-1.6.11 --label roundcube
#   scripts/gadget_sweep.sh lab-drupal --no-semgrep --out reports/gadgets
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m php2shell.gadget_sweep "$@"
