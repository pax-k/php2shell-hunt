#!/usr/bin/env bash
# Lab matrix helper. All targets bind to loopback.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/lab/docker-compose.yml"

usage() {
  cat <<'USAGE'
usage: scripts/lab_matrix.sh <list|defaults|up|down|status|logs>

  list      show the version/port matrix
  defaults  print stock php --ini and key php -i values
  up [svc]  start named services; default is the 8.4.26/8.4.27 pair
  down      stop and remove the lab
  status    show container state
  logs      follow logs
USAGE
}

case "${1:-list}" in
  list)
    cat <<'MATRIX'
version  port   expected
8.4.26   18091  vulnerable
8.4.27   18092  patched
8.5.11   18093  vulnerable
8.5.12   18094  patched
MATRIX
    ;;
  defaults)
    for version in 8.4.26 8.4.27; do
      echo "== php:$version-apache"
      docker run --rm "php:$version-apache" php --ini
      docker run --rm "php:$version-apache" php -r \
        'foreach (["session.upload_progress.enabled","session.upload_progress.cleanup","session.use_strict_mode","session.use_only_cookies","memory_limit","post_max_size","upload_max_filesize"] as $k) echo $k,"=",ini_get($k),"\n";'
    done
    ;;
  up)
    "$ROOT/lab/setup.sh"
    shift
    if [ "$#" -eq 0 ]; then
      set -- php-8.4.26 php-8.4.27
    fi
    docker compose -f "$COMPOSE" up -d "$@"
    ;;
  down)
    docker compose -f "$COMPOSE" down
    ;;
  status)
    docker compose -f "$COMPOSE" ps
    ;;
  logs)
    docker compose -f "$COMPOSE" logs -f --tail=100
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
