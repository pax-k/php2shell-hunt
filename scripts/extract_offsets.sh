#!/usr/bin/env bash
# G2 — extract per-build libphp offsets from stock docker images.
#
#   scripts/extract_offsets.sh php:8.4.26-apache php:8.4.27-apache
#   scripts/extract_offsets.sh --platform linux/amd64 php:8.4.26-apache
#   scripts/extract_offsets.sh --self-test
#
# Writes rows into profiles/offsets.json when --write is given (passed
# through). Offsets only; heap geometry is scripts/calibrate.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m php2shell.offsets "$@"
