#!/usr/bin/env bash
# Wrapper over the loopback-only scanner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scanner/check.py" "$@"
