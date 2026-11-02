#!/bin/sh
# LAB-ONLY setup. Downloads a pinned public application release and adds the
# tracked research endpoints. Existing application trees are preserved.
set -eu
cd "$(dirname "$0")"

if [ ! -e html ]; then
    lab_tmp=$(mktemp -d)
    trap 'rm -rf "$lab_tmp"' EXIT HUP INT TERM
    curl -fsSLo "$lab_tmp/release.tar.gz" 'https://github.com/roundcube/roundcubemail/releases/download/1.6.11/roundcubemail-1.6.11-complete.tar.gz'
    printf '%s  %s\n' 'a230e432065555bfa27bea3fcf4ac672f2359ef28ad84f5945ea3ccf702e7466' "$lab_tmp/release.tar.gz" | shasum -a 256 -c -
    mkdir "$lab_tmp/html"
    tar -xzf "$lab_tmp/release.tar.gz" -C "$lab_tmp/html" --strip-components=1
    test -f "$lab_tmp/html/index.php"
    mv "$lab_tmp/html" html
fi

if [ ! -f html/index.php ]; then
    echo "Existing html/ is incomplete. Preserve or move it before setup." >&2
    exit 1
fi

mkdir -p html/plugins/vd115560
cp plugin/vd115560/vd115560.php html/plugins/vd115560/
cp config.inc.php html/config/config.inc.php
cp prime.php scan_prefix.php html/
echo "[+] 1.6.11 lab webroot ready: $(pwd)/html"
