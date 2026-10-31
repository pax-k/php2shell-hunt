#!/bin/sh
# Build the lab-wp-zendmm webroot: the CVE-2026-10961x chain endpoints
# (canonical copies from ../lab-chain-a/webroot) + a real WordPress core install.
# WordPress files are NOT tracked in git (see .gitignore); re-running this
# script rebuilds the webroot from scratch.
set -eu
cd "$(dirname "$0")"

# start clean
rm -rf webroot
mkdir -p webroot/app webroot/api

# 1. chain endpoints (tracked, canonical source: ../lab-chain-a/webroot)
cp ../lab-chain-a/webroot/app/upload.php  webroot/app/
cp ../lab-chain-a/webroot/app/.user.ini   webroot/app/   # php_serialize handler dir
cp ../lab-chain-a/webroot/api/producer.php webroot/api/
cp ../lab-chain-a/webroot/api/endpoint.php webroot/api/
cp ../lab-chain-a/webroot/api/.user.ini   webroot/api/   # php handler dir (mismatch)
cp ../lab-chain-a/webroot/obj_probe.php   webroot/

# 2. WordPress core
if [ ! -e webroot/wp-settings.php ]; then
    echo "[*] downloading WordPress core ..."
    curl -fsSLo /tmp/php2shell-wp.tar.gz https://wordpress.org/latest.tar.gz
    tar -xzf /tmp/php2shell-wp.tar.gz -C webroot --strip-components=1
    rm -f /tmp/php2shell-wp.tar.gz
fi

# 3. lab config (disposable creds; DB service: db)
cp wp-config-lab.php webroot/wp-config.php

# 4. LAB-ONLY var_destroy UAF harness (mu-plugin: auto-loaded, no activation).
#    Models a plugin-level double-unserialize bug; see docs/VAR_DESTROY_UAF.md.
mkdir -p webroot/wp-content/mu-plugins
cp uaf-harness/uaf-harness.php webroot/wp-content/mu-plugins/

echo "[+] webroot ready ($(ls webroot | wc -l | tr -d ' ') top-level entries)"
