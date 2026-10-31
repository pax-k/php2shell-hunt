#!/usr/bin/env python3
"""
php2shell — CVE-2026-109618 / CVE-2026-109619 lab verification CLI.

Same invocation shape as the public full POCs:

    python3 php2shell.py <host> [-c 'id'] [-p 18085]

...but DEFENDER-SCOPED (see README "Repo scope"):
  - drives THIS repo's lab-verified rung-5b chain
    (poc/verify_109619_rce.py: forged execute_data -> zif_system),
  - the -c flag accepts BENIGN ALLOWLISTED base commands only
    (id | uname | whoami) — no arbitrary commands, no reverse shells,
  - calibration comes from the lab's [UAFDBG] instrumentation, not a
    remote leak stage,
  - output is retrieved over HTTP (the wrapper composes the webroot
    redirect automatically).

Targets must be YOUR OWN lab (the rung-5b chain requires the
instrumented lab-zendmm-fpm build; it cannot calibrate against
uninstrumented hosts). For authorized testing of third parties, use the
public repos' tooling under your engagement's rules — not this.
"""
import argparse
import os
import subprocess
import sys

POC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "poc", "verify_109619_rce.py")
ALLOWED = ("id", "uname", "whoami")

BANNER = r"""
  php2shell  -  CVE-2026-109618 / CVE-2026-109619  (lab verification)
  rung-5b chain: forged execute_data -> zif_system, benign allowlist only
"""


def main():
    ap = argparse.ArgumentParser(
        prog="php2shell.py",
        description="Lab verification CLI for the php2shell rung-5b chain "
                    "(benign allowlisted commands only).")
    ap.add_argument("host", help="lab host (e.g. localhost — your own lab). "
                    "A full URL is also accepted: http://localhost:18085/")
    ap.add_argument("-c", "--cmd", default="id",
                    help=f"benign base command {ALLOWED} (default: id)")
    ap.add_argument("-p", "--port", type=int, default=None,
                    help="lab nginx port (default: 18085; "
                         "negative control lab: 18086)")
    ap.add_argument("--container", default=None,
                    help="override the [UAFDBG] lab container name")
    ap.add_argument("--fake-refcount", type=lambda x: int(x, 0), default=None,
                    help="tune the forged object's initial gc.refcount")
    args = ap.parse_args()

    if args.cmd not in ALLOWED:
        sys.exit(f"[!] -c/--cmd accepts benign allowlisted commands "
                 f"{ALLOWED} only (repo scope: no arbitrary commands). "
                 f"Got {args.cmd!r}.")

    print(BANNER)

    # Accept either a bare lab host (localhost) or a full URL
    # (http://localhost:18085/).  Never wrap the argument verbatim: passing
    # a URL here used to produce "http://https://host:18085", and the PoC's
    # urlparse() then treated the scheme ("https") as the hostname and died
    # in getaddrinfo.
    from urllib.parse import urlsplit
    u = urlsplit(args.host if "://" in args.host else f"//{args.host}")
    scheme = (u.scheme or "http").lower()
    if u.hostname is None:
        sys.exit(f"[!] cannot parse target host: {args.host!r}")
    host = u.hostname
    port = args.port or u.port or 18085

    # Scope guard: the rung-5b chain calibrates from the instrumented lab
    # build's [UAFDBG] docker-log output, needs obj_probe.php on the target
    # and writes proof to the lab webroot.  None of that exists on a remote
    # (or TLS) endpoint, so refuse with a pointer instead of failing later.
    if scheme != "http":
        sys.exit(f"[!] {scheme}:// targets are out of scope for this "
                 f"wrapper: the rung-5b chain needs the instrumented "
                 f"lab-zendmm-fpm build (plain HTTP, local) for its "
                 f"[UAFDBG] calibration, obj_probe.php and the lab webroot "
                 f"write.  For remote hosts use the php-poc php2shell.py "
                 f"(strategies 1-3).")
    # if host not in ("localhost", "::1") and not host.startswith("127."):
    #     sys.exit(f"[!] {host} is not a local lab host.  This wrapper only "
    #              f"drives the instrumented local lab (rung-5b needs docker "
    #              f"log calibration).  For remote targets use the php-poc "
    #              f"php2shell.py.")

    target = f"http://{host}:{port}"
    print(f"[*] target : {target}")
    print(f"[*] command: {args.cmd!r} (benign allowlist; webroot redirect "
          "composed automatically)")

    cmd = [sys.executable, POC, "--target", target, "--cmd", args.cmd]
    if args.container:
        cmd += ["--container", args.container]
    if args.fake_refcount is not None:
        cmd += ["--fake-refcount", str(args.fake_refcount)]
    rc = subprocess.call(cmd)
    sys.exit(rc)


if __name__ == "__main__":
    main()