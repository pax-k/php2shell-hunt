#!/bin/sh
# CVE-2026-109619 mod_php chain (lab-asan-modphp): switch Apache's PHP
# module to the tracked system allocator so request-owned allocations are
# real malloc()s freed at shutdown — making cross-request stale-state
# dereferences visible to AddressSanitizer.
#
# NOTE: the tracked allocator still enforces memory_limit (its limit
# error reports "at file:0"), so the OOM producers remain available.
#
# Revert with restore-alloc.sh. The OOM-trigger POC
# (verify_cve_109618_oom.py) is calibrated for the default ZendMM mode
# and should be run after restoring.

set -e

CONTAINER=php-asan-modphp-lab

docker exec "$CONTAINER" sh -c '
if ! grep -q "^export USE_ZEND_ALLOC" /etc/apache2/envvars; then
    cat >> /etc/apache2/envvars <<EOF

# CVE-2026-109619 research: tracked system allocator (ASAN visibility)
export USE_ZEND_ALLOC=0
export USE_TRACKED_ALLOC=1
EOF
fi
grep USE_ZEND /etc/apache2/envvars
'

# Full restart so the master re-reads envvars (a graceful reload does
# not re-source it).
docker restart "$CONTAINER"
echo "waiting for apache..."
sleep 5
curl -s -m 10 http://127.0.0.1:18082/index.php || true
echo
echo "mode check (expect 'at file:0' tracked signature):"
curl -s -m 30 http://127.0.0.1:18082/oom_probe.php | grep -o "exhausted at [^ ]*" | head -1
