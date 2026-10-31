"""Docker helper for resolving the instrumented rung-5b lab dynamically.

There is intentionally no static port -> container registry. The driver
discoers which (if any) FPM container serves a target and whether it is a
[UAFDBG]-instrumented build by triggering the calibration endpoint and
looking for the oracle print in the containers' fresh logs.
"""

import datetime
import shutil
import subprocess
import time

from . import probe


def docker_available():
    return shutil.which("docker") is not None


def _docker_ps_names():
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15,
        )
        return [n.strip() for n in r.stdout.splitlines() if n.strip()]
    except Exception:
        return []


def _docker_logs_since(name, since_ts):
    try:
        r = subprocess.run(
            ["docker", "logs", "--since", since_ts, name],
            capture_output=True, text=True, timeout=15,
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def discover_container(host, port, obj_probe_path="/obj_probe.php"):
    """Return the name of the [UAFDBG]-instrumented FPM container serving
    `host:port`, or None.

    Approach: trigger the calibration endpoint (obj_probe.php), then scan the
    fresh docker logs of every PHP-ish FPM container for the oracle print
    (`zsys=` / `[UAFDBG]`). Only the container that actually handled the
    trigger logs in the post-trigger window, so the result is tied to the
    target rather than to any port table.
    """
    if not docker_available():
        return None
    names = [
        n for n in _docker_ps_names()
        if "php" in n.lower() and "nginx" not in n.lower() and "db" not in n.lower()
    ]
    if not names:
        return None

    t0 = (datetime.datetime.now(datetime.timezone.utc)
          .replace(microsecond=0).isoformat().replace("+00:00", "Z"))
    try:
        probe.http_get(host, port, obj_probe_path, timeout=10, recv_timeout=6)
    except OSError:
        pass
    time.sleep(0.6)

    for name in names:
        blob = _docker_logs_since(name, t0)
        if "zsys=" in blob or "[UAFDBG]" in blob:
            return name
    return None