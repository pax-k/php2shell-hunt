#!/bin/sh
# Build the lab-roundcube webroot: Roundcube 1.6.11 from the official release
# tarball plus the tracked lab config and plugin. The application tree is
# downloaded, not committed (see .gitignore); re-running is idempotent.
set -eu
cd "$(dirname "$0")"

RC=1.6.11
URL="https://github.com/roundcube/roundcubemail/releases/download/${RC}/roundcubemail-${RC}-complete.tar.gz"

if [ ! -f html/index.php ]; then
    echo "[*] downloading Roundcube ${RC} ..."
    rm -rf html
    mkdir -p html
    curl -fsSLo /tmp/roundcube.tar.gz "$URL"
    tar -xzf /tmp/roundcube.tar.gz -C html --strip-components=1
    rm -f /tmp/roundcube.tar.gz
fi

# Lab plugin: loaded before rcmail::session_init(); performs the runtime
# handler switch and defines the re-entry gadget classes.
mkdir -p html/plugins/vd115560
cp plugin/vd115560/vd115560.php html/plugins/vd115560/

# Lab-only config: session_storage='php' so the upload-progress file is the
# record Roundcube reads; the plugin supplies the missing switch.
cp config.inc.php html/config/config.inc.php

# Prime endpoint (writes the first progress record) and the measurement helper.
cp prime.php scan_prefix.php html/

echo "[+] webroot ready: $(pwd)/html"
