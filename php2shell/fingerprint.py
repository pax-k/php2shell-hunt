"""Target fingerprinting: app type, PHP version/SAPI/config, and live
precondition checks that feed the strategy decision table.

Produces a TargetProfile consumed by strategies.py and engine.py.
"""

from dataclasses import dataclass, field

from . import probe
from .apps import ADAPTERS

WORDPRESS_KEY = "wordpress"
JOOMLA_KEY = "joomla"
GENERIC_KEY = "generic"


@dataclass
class TargetProfile:
    host: str
    port: int
    app_key: str = "unknown"
    app_label: str = "unknown"
    adapter: object = None
    php_version: str = None
    sapi: str = None
    upload_progress: bool = None
    memory_limit: str = None
    # live-verified endpoint availability
    lfi_ok: bool = False
    gadget_ok: bool = False
    handler_mismatch: bool = False
    handlers: dict = field(default_factory=dict)
    obj_probe_ok: bool = False
    container: str = None
    findings: list = field(default_factory=list)

    def note(self, msg):
        self.findings.append(msg)


def _detect_app(host, port, adapter_hint):
    """Detect app type via HTTP markers. Returns (key, adapter)."""
    order = [adapter_hint] if adapter_hint else None
    if order:
        # explicit --app forces a specific adapter; still verify reachability
        return adapter_hint, ADAPTERS[adapter_hint]

    candidates = [WORDPRESS_KEY, JOOMLA_KEY, GENERIC_KEY]
    for key in candidates:
        a = ADAPTERS[key]
        resp = probe.http_get(host, port, a.detect_path, timeout=10, recv_timeout=8)
        b = probe.body(resp)
        if any(m.encode("latin-1") in b for m in a.markers):
            return key, a
    return "unknown", None


def _parse_lab_banner(b):
    """Parse the generic lab's /index.php banner:

        PHP <version>
        SAPI <name>
        upload_progress <0/1>
        OK
    """
    ver = sapi = up = mem = None
    for line in b.decode("latin-1", "replace").splitlines():
        line = line.strip()
        if line.startswith("PHP "):
            ver = line[4:].strip()
        elif line.startswith("SAPI "):
            sapi = line[4:].strip()
        elif line.startswith("upload_progress "):
            up = line[len("upload_progress "):].strip().lower() in ("1", "on", "true")
        elif line.startswith("memory_limit:"):
            mem = line.split(":", 1)[1].strip()
    return ver, sapi, up, mem


def fingerprint(host, port, app_hint=None, container_hint=None):
    p = TargetProfile(
        host=host, port=port,
        container=container_hint,
        app_key=(app_hint or "unknown"),
    )

    # App detection (explicit hint wins; otherwise probe by markers)
    detected, adapter = _detect_app(host, port, app_hint)
    p.app_key = detected
    p.adapter = adapter
    if adapter:
        p.app_label = adapter.label
        p.note(f"app detected: {adapter.label}")
    else:
        p.note("app not recognized (no known marker hit)")

    # PHP version / SAPI / upload_progress — via the adapter's fingerprint
    # endpoint (the generic lab banner, or a lab `sysinfo.php` for apps whose
    # index.php is a front controller); fall back to X-Powered-By.
    if adapter:
        resp = probe.http_get(host, port, adapter.fingerprint_path, timeout=10, recv_timeout=8)
        b = probe.body(resp)
        ver, sapi, up, mem = _parse_lab_banner(b)
        if not (ver or up is not None):
            # Minimal stock labs (e.g. lab-pure-modphp's `<?php echo "OK"; ?>`)
            # still expose the lab probe endpoint; use it as a fallback.
            resp = probe.http_get(host, port, "/probe.php", timeout=10, recv_timeout=8)
            ver, sapi, up, mem = _parse_lab_banner(probe.body(resp))
        if ver or up is not None:
            p.php_version, p.sapi, p.upload_progress, p.memory_limit = ver, sapi, up, mem
        else:
            xpb = probe.header_value(resp, "X-Powered-By")
            if xpb:
                p.php_version = xpb.replace("PHP/", "")
    else:
        resp = probe.http_get(host, port, "/", timeout=10, recv_timeout=8)
        xpb = probe.header_value(resp, "X-Powered-By")
        p.php_version = xpb.replace("PHP/", "") if xpb else None
        # Unknown app: the lab probe endpoint still carries SAPI/limits.
        resp = probe.http_get(host, port, "/probe.php", timeout=10, recv_timeout=8)
        ver, sapi, up, mem = _parse_lab_banner(probe.body(resp))
        p.php_version = p.php_version or ver
        p.sapi, p.upload_progress, p.memory_limit = sapi, up, mem
    p.note(
        f"php={p.php_version or '?'} sapi={p.sapi or '?'} "
        f"upload_progress={p.upload_progress} memory_limit={p.memory_limit or '?'}"
    )

    # Live precondition checks (only where an adapter layout is known)
    if adapter:
        # Chain A: LFI reachable?
        r = probe.http_get(host, port, adapter.lfi_path, timeout=10, recv_timeout=8)
        p.lfi_ok = " 200 " in probe.status(r) or " 404 " not in probe.status(r)
        p.note(f"lfi endpoint {adapter.lfi_path}: {'reachable' if p.lfi_ok else 'absent'}")

        # Chain C: gadget endpoint banner
        r = probe.http_get(host, port, adapter.read_path, timeout=10, recv_timeout=8)
        p.gadget_ok = adapter.gadget_banner.encode("latin-1") in probe.body(r)
        p.note(f"gadget endpoint {adapter.read_path}: {'present' if p.gadget_ok else 'absent'}")

        # Chain C: serialize_handler mismatch (php_serialize write vs php read)
        r = probe.http_get(host, port, adapter.handler_probe, timeout=10, recv_timeout=8)
        hb = probe.body(r).decode("latin-1", "replace")
        for line in hb.splitlines():
            if line.startswith("handler="):
                p.handlers[adapter.handler_probe] = line.split("=", 1)[1].strip()
        # the write dir (/app) is php_serialize by lab construction; if the
        # read dir (/api) reports `php` the mismatch precondition holds.
        read_handler = p.handlers.get(adapter.handler_probe)
        p.handler_mismatch = read_handler == "php"
        p.note(f"read-dir serialize_handler={read_handler} "
               f"(mismatch vs php_serialize write dir: {p.handler_mismatch})")

        # rung-5b: calibration endpoint reachable (the [UAFDBG] oracle is
        # confirmed dynamically at strategy-eval time via docker logs)
        r = probe.http_get(host, port, adapter.obj_probe, timeout=10, recv_timeout=8)
        p.obj_probe_ok = b"calib done" in probe.body(r)
        p.note(f"obj_probe {adapter.obj_probe}: {'present' if p.obj_probe_ok else 'absent'}")

    return p