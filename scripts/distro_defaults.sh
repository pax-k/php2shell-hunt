#!/usr/bin/env bash
# G7 — verify the precondition layer under real "default install" postures.
#
# Two models:
#   :18170  official image with NO php.ini (compiled defaults, 128M)
#   :18171  Ubuntu 24.04 apt `libapache2-mod-php` (distro package)
#
# Checks: SAPI/version/memory_limit/upload_progress, and the lengthless
# `post_max_size` delivery. This proves trigger + delivery under packager
# defaults; it does NOT claim the core chain fires on those builds (that needs
# a per-build calibration row first — see scripts/calibrate.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT_DEFAULT=18170
PORT_UBUNTU=18171

echo "[*] starting distro-default models (builds the Ubuntu image once)"
( cd lab-matrix && docker compose --profile distro up -d --build \
    default-vuln default-patched ubuntu-modphp )

wait_up() {
  local port="$1" i
  for i in $(seq 1 60); do
    if curl -fsS -m 3 "http://127.0.0.1:${port}/probe.php" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "[!] :${port} did not come up" >&2
  return 1
}

fail=0
for port in "$PORT_DEFAULT" "$PORT_UBUNTU"; do
  wait_up "$port"
  echo
  echo "== :${port} profile"
  profile="$(python3 poc/verify_sapi_profile.py --target "http://127.0.0.1:${port}")"
  echo "$profile" | sed 's/^/    /'
  if ! grep -q "upload_progress.*True" <<<"$profile"; then
    echo "[!] :${port}: upload_progress is not On (core chain precondition)"
    fail=1
  fi

  echo
  echo "== :${port} lengthless post_max_size delivery"
  bypass="$(python3 poc/verify_postmax_bypass.py --mode apache \
      --host 127.0.0.1 --port "$port" 2>&1)"
  echo "$bypass" | grep -E '^\[(EVIDENCE|\*)\]|^    ' | sed 's/^/    /' || true
  if ! grep -q "LENGTHLESS BYPASS REPRODUCED" <<<"$bypass"; then
    echo "[!] :${port}: lengthless bypass not reproduced"
    fail=1
  fi
done

echo
if [ "$fail" -eq 0 ]; then
  echo "[EVIDENCE] distro-default preconditions reproduced on 2 models"
  exit 0
fi
echo "[!] distro-default precondition check failed"
exit 1
