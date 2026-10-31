#!/usr/bin/env bash
set -euo pipefail
# Rebuild the lab-roundcube-redis lab from scratch.
# LAB-ONLY: images are php:8.4.27-apache + phpredis 6.3.0 and redis:7-alpine.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose build
docker compose up -d
docker exec php2shell-rc-redis-8427 php -m | grep -qx redis
echo "lab up: http://127.0.0.1:18320 (redis storage) / :18321 (php storage)"
echo "redis:  127.0.0.1:16379"
