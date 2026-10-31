#!/usr/bin/env python3
"""Triage an ASAN fuzz run for the disclosure campaign.

Inputs: the ASAN stderr/stdout log from fuzz/asan_run.php, and optionally the
corpus file (to recover the killing input). Emits:
  - the killing index (last "PROCESSING <i>" before the first ERROR)
  - the report class (READ vs WRITE vs other)
  - a dedup fingerprint (top 3 stack frames)
  - a verdict bucket: candidate-disclosure / corruption / dos

This does NOT decide reachability; that is the track's job (replay on the
stock target without the detector's own file reads).

Lab-only helper.
"""
import argparse
import re
import sys

ERR = re.compile(r"ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+)")
FRAME = re.compile(r"^\s+#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)")
PROC = re.compile(r"PROCESSING (\d+)")


def parse(text):
    procs = [int(m.group(1)) for m in PROC.finditer(text)]
    m = ERR.search(text)
    if not m:
        return None
    kind = m.group(1)
    frames = []
    for line in text[m.end():].splitlines():
        fm = FRAME.match(line)
        if fm:
            frames.append(fm.group(2))
        if len(frames) >= 4:
            break
    return {
        "killing_index": procs[-1] if procs else None,
        "asan_kind": kind,
        "frames": frames,
        "fingerprint": "|".join(frames[:3]) or kind,
    }


def bucket(kind):
    k = kind.lower()
    if "read" in k and ("overflow" in k or "use-after-free" in k or "out-of-bounds" in k):
        return "candidate-disclosure"
    if "uninitialized" in k:
        return "candidate-disclosure"
    if "write" in k or "double-free" in k or "use-after-free" in k:
        return "corruption"
    return "dos"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--corpus", default=None)
    args = ap.parse_args()
    text = open(args.log, "r", errors="replace").read()
    r = parse(text)
    if r is None:
        print("no ASAN report found")
        return 0
    r["verdict"] = bucket(r["asan_kind"])
    print(f"killing_index: {r['killing_index']}")
    print(f"asan_kind:     {r['asan_kind']}")
    print(f"verdict:       {r['verdict']}")
    print(f"fingerprint:   {r['fingerprint']}")
    if args.corpus and r["killing_index"] is not None:
        lines = open(args.corpus, "rb").read().splitlines()
        i = r["killing_index"]
        if 0 <= i < len(lines):
            print(f"input(b64):    {lines[i].decode('latin-1')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
