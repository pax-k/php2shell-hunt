#!/bin/sh
# Install Joomla (CLI, non-interactive) into the running lab-joomla stack.
# Run AFTER `docker compose up -d` (db must be healthy). Lab-disposable.
set -eu
cd "$(dirname "$0")"

echo "[*] running Joomla CLI installer (this can take a minute) ..."
docker compose exec -T php php installation/joomla.php install \
    --no-interaction \
    --site-name="php2shell Joomla Lab" \
    --admin-user="Super User" \
    --admin-username=admin \
    --admin-password=adminpass123 \
    --admin-email=admin@example.com \
    --db-type=mysqli \
    --db-host=db \
    --db-user=joomla \
    --db-pass=joomlapass \
    --db-name=joomla \
    --db-prefix=jos_

echo "[*] removing installation/ directory"
docker compose exec -T php rm -rf installation

echo "[*] opening write dirs for the www-data runtime"
docker compose exec -T php sh -c \
    'chmod -R a+rwX /var/www/html 2>/dev/null || true; chown -R www-data:www-data /var/www/html 2>/dev/null || true'

echo "[+] Joomla installed"