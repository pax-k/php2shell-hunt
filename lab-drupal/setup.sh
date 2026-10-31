#!/bin/sh
# Build the lab-drupal webroot: Drupal 11.4.11 core (official release tarball,
# includes vendor/) plus the tracked 115560 consumer endpoints. The application
# tree is downloaded, not committed (see .gitignore); re-running is idempotent.
set -eu
cd "$(dirname "$0")"

DV=11.4.11
URL="https://ftp.drupal.org/files/projects/drupal-${DV}.tar.gz"

if [ ! -f html/vendor/autoload.php ]; then
    echo "[*] downloading Drupal ${DV} ..."
    rm -rf html
    mkdir -p html
    curl -fsSLo /tmp/drupal.tar.gz "$URL"
    tar -xzf /tmp/drupal.tar.gz -C html --strip-components=1
    rm -f /tmp/drupal.tar.gz
fi

# 115560 consumer, prime, seed, and measurement endpoints. They require only
# vendor/autoload.php; no database or Drupal bootstrap is needed for the lab.
cp endpoints/vd*.php html/

echo "[+] webroot ready: $(pwd)/html"
