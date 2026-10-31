#!/bin/sh
# Restore the mod_php ASAN lab's default ZendMM allocator (required for
# the memory_limit-calibrated OOM trigger in verify_cve_109618_oom.py).

set -e

CONTAINER=php-asan-modphp-lab

docker exec "$CONTAINER" sh -c '
sed -i -e "/^export USE_ZEND_ALLOC/d" -e "/^export USE_TRACKED_ALLOC/d" -e "/tracked system allocator/d" -e "/CVE-2026-109619 research/d" /etc/apache2/envvars
grep USE_ZEND /etc/apache2/envvars || echo "(env vars removed)"
'
docker restart "$CONTAINER"
sleep 5
echo "mode check (expect a zend source location signature):"
curl -s -m 30 http://127.0.0.1:18082/oom_probe.php | grep -o "exhausted at [^ ]*" | head -1
