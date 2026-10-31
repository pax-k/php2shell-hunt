#!/bin/sh
# Build the lab-joomla webroot: Joomla 5.4.10 core + the CVE-2026-10961x
# chain endpoints (canonical copies from ../lab-chain-a/webroot) + a sysinfo.php
# banner the adaptive driver parses. Joomla core is NOT tracked in git
# (see .gitignore); re-running rebuilds webroot files but keeps the DB.
set -eu
cd "$(dirname "$0")"

JV=5.4.10

if [ ! -e webroot/installation ] && [ ! -e webroot/configuration.php ]; then
    rm -rf webroot
    mkdir -p webroot
    echo "[*] downloading Joomla ${JV} (Full Package) ..."
    curl -fsSLo /tmp/joomla.tar.gz \
        "https://github.com/joomla/joomla-cms/releases/download/${JV}/Joomla_${JV}-Stable-Full_Package.tar.gz"
    tar -xzf /tmp/joomla.tar.gz -C webroot
    rm -f /tmp/joomla.tar.gz
fi

# chain endpoints (tracked, canonical source: ../lab-chain-a/webroot)
mkdir -p webroot/app webroot/api
cp ../lab-chain-a/webroot/app/upload.php       webroot/app/
cp ../lab-chain-a/webroot/app/.user.ini        webroot/app/    # php_serialize handler dir
cp ../lab-chain-a/webroot/api/producer.php     webroot/api/
cp ../lab-chain-a/webroot/api/endpoint.php     webroot/api/
cp ../lab-chain-a/webroot/api/handler_probe.php webroot/api/
cp ../lab-chain-a/webroot/api/.user.ini        webroot/api/    # php handler dir (mismatch)
cp ../lab-chain-a/webroot/obj_probe.php        webroot/
cp ../lab-chain-a/webroot/lfi.php              webroot/

# sysinfo banner (fingerprint endpoint for the adaptive driver)
cat > webroot/sysinfo.php << 'EOF'
<?php
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
echo "memory_limit: " . ini_get('memory_limit') . "\n";
echo "OK\n";
EOF

echo "[+] webroot ready ($(ls webroot | wc -l | tr -d ' ') top-level entries)"