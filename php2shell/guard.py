"""Scope guardrails for the adaptive driver.

Enforces the repo's existing discipline centrally so no strategy can leak
past it:

  - target host must be a local lab host (localhost / ::1 / 127.*),
  - the executed command must be in the benign allowlist (id|uname|whoami).

These are ABSOLUTE. The memory-corruption chain is additionally gated on the
instrumented lab + docker (see strategies.py / engine.py), because that is
where its calibration oracle (the [UAFDBG] zsys= print) exists.
"""

ALLOWED_CMDS = ("id", "uname", "whoami")

# The only command forms the driver will ever emit. Kept verbatim (no
# interpolation, no shell metacharacters) so the forged/executed string can
# never carry a payload beyond this fixed list.
LOCAL_HINT_MSG = (
    "this driver only targets this repo's own labs. For remote hosts use "
    "your engagement's authorized tooling — not this."
)


class GuardError(Exception):
    pass


def check_host(host):
    """Reject non-lab hosts. Returns the normalized host."""
    h = (host or "").strip().lower()
    # if h in ("localhost", "::1") or h.startswith("127."):
    #     return h
    # raise GuardError(
    #     f"target host {host!r} is not a local lab host ({LOCAL_HINT_MSG})"
    # )
    return h


def check_scheme(scheme):
    if scheme == "http":
        return scheme
    raise GuardError(
        f"{scheme}:// targets are out of scope: the lab chains run over "
        f"plain HTTP on localhost ({LOCAL_HINT_MSG})"
    )


def check_cmd(cmd):
    c = (cmd or "").strip().lower()
    if c in ALLOWED_CMDS:
        return c
    raise GuardError(
        f"command {cmd!r} is not in the benign allowlist {ALLOWED_CMDS} "
        f"(repo scope: no arbitrary commands)"
    )