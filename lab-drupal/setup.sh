#!/bin/sh
# LAB-ONLY setup. Downloads a pinned public application release and adds the
# tracked research endpoints. Existing application trees are preserved.
set -eu
cd "$(dirname "$0")"

if [ ! -e html ]; then
    lab_tmp=$(mktemp -d)
    trap 'rm -rf "$lab_tmp"' EXIT HUP INT TERM
    curl -fsSLo "$lab_tmp/release.tar.gz" 'https://ftp.drupal.org/files/projects/drupal-11.4.11.tar.gz'
    printf '%s  %s\n' 'f6935da6ddfb2b3bf5c79c5118018be91021f7d5e12901eed1a71de140708e13' "$lab_tmp/release.tar.gz" | shasum -a 256 -c -
    mkdir "$lab_tmp/html"
    tar -xzf "$lab_tmp/release.tar.gz" -C "$lab_tmp/html" --strip-components=1
    test -f "$lab_tmp/html/vendor/autoload.php"
    mv "$lab_tmp/html" html
fi

if [ ! -f html/vendor/autoload.php ]; then
    echo "Existing html/ is incomplete. Preserve or move it before setup." >&2
    exit 1
fi

cp endpoints/vd*.php html/
echo "[+] 11.4.11 lab webroot ready: $(pwd)/html"
