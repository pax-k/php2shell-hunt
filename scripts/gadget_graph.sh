#!/usr/bin/env bash
# G6 — cross-class PHP gadget graph (PHP-Parser facts, read-only).
#
#   scripts/gadget_graph.sh --self-test
#   scripts/gadget_graph.sh lab-drupal --label drupal
#   composer install -d tools/gadget/php   # one-time facts dependency
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m php2shell.gadget_graph "$@"
