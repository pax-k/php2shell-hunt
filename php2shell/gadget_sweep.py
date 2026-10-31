"""PHP gadget sweep over the lab app trees.

Deterministic inventory first: ctags gives class/method ranges, ast-grep gives
magic methods and sink call sites, and a small ranker turns the overlap into
ranked candidates. Semgrep (taint/magic rules) runs only on the candidate
files, so a 14k-file Drupal tree stays cheap.

    scripts/gadget_sweep.sh --out reports/gadgets
    scripts/gadget_sweep.sh lab-roundcube/roundcubemail-1.6.11 --label roundcube

This is a candidate generator, not an oracle: a hit means "read this next".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "tools" / "gadget" / "sgconfig.yml"
SEMGREP_RULES = ROOT / "tools" / "gadget" / "semgrep.yml"
MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "bower_components",
             "__pycache__", ".idea", ".vscode"}
TEST_DIRS = {"test", "tests", "Tests", "__tests__"}

# Known lab app roots, used when no positional root is given.
LAB_ROOTS = {
    "drupal": "lab-drupal",
    "roundcube": "lab-roundcube/roundcubemail-1.6.11",
    "joomla": "lab-joomla/webroot",
    "wordpress": "lab-wp-zendmm/webroot",
    "115560": "lab-115560/webroot",
    "lab": "lab/webroot",
    "matrix": "lab-matrix/webroot",
}

MAGIC = {
    "__destruct", "__wakeup", "__unserialize", "__sleep", "__serialize",
    "__toString", "__call", "__callStatic", "__get", "__set", "__isset",
    "__unset", "__invoke", "__set_state", "__clone", "__debugInfo",
}
REENTRY_MAGIC = {"__destruct", "__wakeup", "__unserialize"}
CATEGORY = {
    "php-magic-method": "magic",
    "php-sink-terminal": "terminal",
    "php-sink-dispatch": "dispatch",
    "php-sink-file": "file",
    "php-sink-unserialize": "unserialize",
    "php-autoload-hook": "autoload",
}
WEIGHT = {"terminal": 45, "dispatch": 45, "unserialize": 35,
          "file": 30, "autoload": 5}
MARKER_RE = re.compile(r"phar://|session\.(?:serialize_handler|save_handler|"
                       r"upload_progress)")


def _tool(name: str) -> str | None:
    return shutil.which(name)


def _run(argv, timeout=600, check=False):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, check=check)


def discover(root: Path, include_tests: bool) -> list[Path]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and (include_tests or d not in TEST_DIRS)
        )
        for name in sorted(filenames):
            if not name.endswith(".php"):
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size <= MAX_BYTES:
                    files.append(path)
            except OSError:
                continue
    return files


def parse_ctags(root: Path, include_tests: bool) -> dict[str, list[dict]]:
    exe = _tool("ctags")
    if not exe:
        return {}
    argv = [exe, "-f", "-", "--languages=PHP", "--output-format=json",
            "--fields=+neK", "-R"]
    if not include_tests:
        argv += ["--exclude=tests", "--exclude=test", "--exclude=Tests"]
    proc = _run(argv + [str(root)])
    by_file: dict[str, list[dict]] = defaultdict(list)
    for line in proc.stdout.splitlines():
        try:
            tag = json.loads(line)
        except ValueError:
            continue
        if tag.get("_type") == "tag" and tag.get("path"):
            by_file[str((root / tag["path"]).resolve())].append(tag)
    return by_file


def _scan_braces(lines: list[str], start: int) -> int:
    """Line (1-based) of the closing brace for the block opening after start."""
    depth, opened = 0, False
    quote = None
    block = False
    heredoc = None
    for idx in range(start - 1, len(lines)):
        line = lines[idx]
        i = 0
        while i < len(line):
            ch, nxt = line[i], line[i + 1: i + 2]
            if heredoc:
                if line.strip() == heredoc:
                    heredoc = None
                break
            if block:
                if ch == "*" and nxt == "/":
                    block = False
                    i += 2
                    continue
                i += 1
                continue
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch in "'\"":
                quote = ch
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                block = True
                i += 2
                continue
            if ch == "#" and nxt != "[":
                break
            if line[i: i + 3] == "<<<":
                match = re.match(r"<<<['\"]?(\w+)", line[i:])
                if match:
                    heredoc = match.group(1)
                    break
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return idx + 1
            i += 1
    return len(lines) if opened else start


def intervals(tags: list[dict], lines: list[str]) -> list[dict]:
    out = []
    for tag in tags:
        if tag.get("kind") not in ("class", "function", "method"):
            continue
        start = int(tag.get("line", 0))
        if not start:
            continue
        out.append({
            "name": tag.get("name", ""),
            "kind": tag.get("kind"),
            "scope": tag.get("scope", ""),
            "start": start,
            "end": _scan_braces(lines, start),
        })
    return out


def ast_matches(root: Path, include_tests: bool) -> tuple[list[dict], dict]:
    exe = _tool("ast-grep")
    if not exe:
        return [], {"status": "unavailable", "hint": "install ast-grep"}
    argv = [exe, "scan", "-c", str(RULES), "--json=stream",
            "--no-ignore", "vcs", "--globs", "!**/.git/**", str(root)]
    if not include_tests:
        for glob in ("tests", "test", "Tests"):
            argv += ["--globs", f"!**/{glob}/**"]
    proc = _run(argv)
    matches = []
    for line in proc.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        rule = obj.get("ruleId", "")
        matches.append({
            "file": str(Path(obj["file"]).resolve()),
            "line": int(obj["range"]["start"]["line"]) + 1,
            "text": obj.get("text", "").strip()[:160],
            "rule": rule,
            "category": CATEGORY.get(rule, "other"),
        })
    status = {"status": "ok", "matches": len(matches)}
    if proc.returncode not in (0, 1):
        status["stderr_tail"] = proc.stderr[-1000:]
    return matches, status


def _sink_text(category: str) -> str:
    return {"terminal": "command execution", "dispatch": "dynamic call",
            "unserialize": "deserialization re-entry",
            "file": "file write/include", "autoload": "autoload probe"}.get(
        category, category)


def rank(root: Path, matches: list[dict],
         tags_by_file: dict[str, list[dict]]) -> tuple[list[dict], list[dict]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for item in matches:
        by_file[item["file"]].append(item)

    entries: dict[tuple, dict] = {}
    magic_methods = []
    for filename, hits in by_file.items():
        path = Path(filename)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        ivs = intervals(tags_by_file.get(filename, []), lines)
        methods = [i for i in ivs if i["kind"] in ("function", "method")]
        classes = [i for i in ivs if i["kind"] == "class"]
        for hit in hits:
            enclosing = [i for i in methods
                         if i["start"] <= hit["line"] <= i["end"]]
            enclosing.sort(key=lambda i: i["end"] - i["start"])
            method = enclosing[0] if enclosing else None
            owner = (method or {}).get("scope") or ""
            if not owner:
                in_class = [c for c in classes
                            if c["start"] <= hit["line"] <= c["end"]]
                owner = in_class[0]["name"] if in_class else ""
            name = method["name"] if method else "<file>"
            key = (filename, owner, name)
            entry = entries.setdefault(key, {
                "file": filename, "class": owner, "method": name,
                "line": (method or {}).get("start", hit["line"]),
                "magic": name in MAGIC, "categories": set(), "sinks": [],
            })
            if hit["category"] != "magic":
                entry["categories"].add(hit["category"])
                entry["sinks"].append({
                    "category": hit["category"], "line": hit["line"],
                    "text": hit["text"], "rule": hit["rule"],
                })
            if name in MAGIC:
                magic_methods.append({
                    "file": filename, "class": owner, "method": name,
                    "line": entry["line"],
                    "categories": sorted(entry["categories"]),
                })

    ranked = []
    for entry in entries.values():
        cats = entry["categories"]
        if not cats:
            continue
        score = max([WEIGHT.get(c, 0) for c in cats] or [0])
        kind = max(cats, key=lambda c: WEIGHT.get(c, 0))
        if entry["magic"] and entry["method"] in REENTRY_MAGIC:
            if "unserialize" in cats:
                score, kind = 100, "reentry"
            elif "terminal" in cats:
                score, kind = 90, "terminal"
        if entry["magic"] and "dispatch" in cats:
            score = max(score, 80)
        if entry["magic"] and "file" in cats:
            score = max(score, 60)
        if entry["magic"] and "autoload" in cats:
            score = max(score, 20)
        entry["score"] = score
        entry["kind"] = kind
        entry["categories"] = sorted(cats)
        entry["sinks"].sort(key=lambda s: (-WEIGHT.get(s["category"], 0),
                                           s["line"]))
        ranked.append(entry)
    ranked.sort(key=lambda e: (-e["score"], e["file"], e["line"],
                               e["class"], e["method"]))
    magic_methods.sort(key=lambda m: (m["file"], m["line"]))
    return ranked, magic_methods


def markers(root: Path) -> list[dict]:
    exe = _tool("rg")
    pattern = MARKER_RE.pattern
    if exe:
        proc = _run([exe, "-n", "--no-heading", "--with-filename",
                     "--no-ignore", "-g", "*.php", "-e", pattern, str(root)])
        lines = proc.stdout.splitlines()
        prefix = str(root)
        out = []
        for line in lines:
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            path, lineno, text = parts
            path = path[len(prefix):].lstrip("/") if path.startswith(prefix) \
                else path
            out.append({"file": path, "line": int(lineno),
                        "text": text.strip()[:200]})
        return out
    out = []
    for path in discover(root, include_tests=True):
        try:
            for n, line in enumerate(path.read_text(
                    encoding="utf-8", errors="replace").splitlines(), 1):
                if MARKER_RE.search(line):
                    out.append({"file": str(path.relative_to(root)),
                                "line": n, "text": line.strip()[:200]})
        except OSError:
            continue
    return out


def run_semgrep(files: list[Path]) -> dict:
    exe = _tool("semgrep")
    if not exe:
        return {"status": "unavailable", "hint": "install semgrep"}
    if not files:
        return {"status": "skipped", "reason": "no candidate files"}
    argv = [exe, "--config", str(SEMGREP_RULES), "--json", "--quiet",
            "--metrics=off", "--disable-version-check", "--timeout", "20",
            "--max-target-bytes", str(MAX_BYTES), "--jobs", "8",
            *[str(f) for f in files]]
    proc = _run(argv, timeout=900)
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return {"status": "error", "stderr_tail": proc.stderr[-1000:]}
    results = []
    for item in data.get("results", []):
        check = item.get("check_id", "").split(".")[-1]
        results.append({
            "rule": check,
            "file": _rel(item.get("path", "")),
            "line": item.get("start", {}).get("line"),
            "message": item.get("extra", {}).get("message", ""),
        })
    results.sort(key=lambda r: (r["file"], r["line"] or 0, r["rule"]))
    return {"status": "ok", "results": results,
            "errors": len(data.get("errors", []))}


def _rel(path: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return path


def _table(rows, headers) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join("" if v is None else str(v)
                                     for v in row) + " |")
    return "\n".join(out)


def sweep_root(root: Path, label: str, include_tests: bool,
               do_semgrep: bool, semgrep_max: int) -> dict:
    files = discover(root, include_tests)
    tags = parse_ctags(root, include_tests)
    matches, ast_status = ast_matches(root, include_tests)
    ranked, magic = rank(root, matches, tags)
    marks = markers(root)

    candidate_files = []
    for entry in ranked:
        path = Path(entry["file"])
        if path not in candidate_files:
            candidate_files.append(path)
        if len(candidate_files) >= semgrep_max:
            break
    semgrep = (run_semgrep(candidate_files) if do_semgrep
               else {"status": "disabled"})

    tools = {
        "ast-grep": ast_status,
        "ctags": {"status": "ok" if tags else "unavailable"},
        "semgrep": semgrep,
        "rg": {"status": "ok" if _tool("rg") else "unavailable"},
    }
    return {
        "schema": 1,
        "label": label,
        "root": _rel(str(root)),
        "php_files": len(files),
        "counts": {
            "magic_methods": len(magic),
            "candidates": len(ranked),
            "reentry": sum(1 for e in ranked if e["kind"] == "reentry"),
            "markers": len(marks),
        },
        "candidates": [{**e, "file": _rel(e["file"])} for e in ranked],
        "magic_methods": [{**m, "file": _rel(m["file"])} for m in magic],
        "markers": marks,
        "semgrep": semgrep,
        "tools": tools,
    }


def render(data: dict) -> str:
    c = data["counts"]
    lines = [
        f"# Gadget sweep: `{data['label']}`",
        "",
        f"Root `{data['root']}` — {data['php_files']} PHP files, "
        f"{c['magic_methods']} magic methods, {c['candidates']} candidates, "
        f"{c['reentry']} re-entry.",
        "",
        "Candidate generation only. A hit means *read this next*, not "
        "*exploitable*; dynamic reachability and the lab decide that.",
        "",
        "## Ranked candidates",
        "",
    ]
    rows = []
    for e in data["candidates"][:25]:
        rows.append([e["score"], e["kind"], e["class"] or "-", e["method"],
                     ", ".join(e["categories"]), f"{e['file']}:{e['line']}"])
    lines += [_table(rows, ["score", "kind", "class", "method", "sinks",
                            "where"]), ""]

    reentry = [e for e in data["candidates"] if e["kind"] == "reentry"]
    lines += ["## Re-entry candidates (magic -> unserialize)", ""]
    if reentry:
        lines += [_table(
            [[e["class"], e["method"], f"{e['file']}:{e['line']}",
              "; ".join(s["text"] for s in e["sinks"][:3])]
             for e in reentry],
            ["class", "method", "where", "evidence"]), ""]
    else:
        lines += ["None in this tree.", ""]

    lines += ["## Magic method inventory", ""]
    counts = Counter(m["method"] for m in data["magic_methods"])
    lines += [_table([[name, n] for name, n in counts.most_common()],
                     ["magic method", "count"]), ""]
    sample = data["magic_methods"][:20]
    if sample:
        lines += [_table([[m["class"] or "-", m["method"],
                           f"{m['file']}:{m['line']}"] for m in sample],
                         ["class", "method", "where"]), ""]

    lines += ["## Stream / session markers", ""]
    if data["markers"]:
        lines += [_table([[m["file"], m["line"], m["text"]]
                          for m in data["markers"][:40]],
                         ["file", "line", "text"]), ""]
    else:
        lines += ["None in this tree.", ""]

    sg = data["semgrep"]
    lines += ["## Semgrep (candidate files only)", ""]
    if sg.get("status") == "ok":
        if sg["results"]:
            lines += [_table([[r["rule"], r["file"], r["line"],
                               r["message"]] for r in sg["results"][:40]],
                             ["rule", "file", "line", "message"]), ""]
        else:
            lines += ["No findings.", ""]
    else:
        lines += [f"{sg.get('status')}"
                  + (f" — {sg['hint']}" if sg.get("hint") else ""), ""]

    lines += ["## Tools", ""]
    for name, status in data["tools"].items():
        detail = status.get("hint") or status.get("status")
        if name == "semgrep" and status.get("status") == "ok":
            detail = f"{len(status.get('results', []))} findings"
        if name == "ast-grep" and status.get("status") == "ok":
            detail = f"{status.get('matches', 0)} matches"
        lines.append(f"- **{name}**: {detail}")
    lines += [
        "",
        "## Reproduce",
        "",
        "```sh",
        f"scripts/gadget_sweep.sh {data['root']} --label {data['label']}",
        "```",
        "",
    ]
    return "\n".join(lines)


def self_test() -> bool:
    lines = ["<?php", "class A {", "  function f() {", "    if (1) { }",
             "  }", "}", "?>"]
    assert _scan_braces(lines, 2) == 6, _scan_braces(lines, 2)
    assert _scan_braces(lines, 3) == 5, _scan_braces(lines, 3)
    if not (_tool("ast-grep") and _tool("ctags")):
        print("[skip] ast-grep/ctags not installed; brace check only")
        return True
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "a.php").write_text(
            "<?php\nclass A {\n"
            "  function __destruct() { unserialize($this->x); }\n"
            "  function run() { system($_GET['c']); }\n}\n",
            encoding="utf-8")
        data = sweep_root(root, "selftest", False, False, 0)
    assert data["counts"]["reentry"] == 1, data["counts"]
    assert data["candidates"][0]["kind"] == "reentry", data["candidates"][0]
    md = render(data)
    assert "Re-entry candidates" in md and "unserialize" in md
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("roots", nargs="*", help="app roots (default: known labs)")
    ap.add_argument("--label", default=None, help="label (single root only)")
    ap.add_argument("--out", default=str(ROOT / "reports" / "gadgets"))
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--no-semgrep", action="store_true")
    ap.add_argument("--semgrep-max-files", type=int, default=40)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        print("[ok] gadget_sweep self-test (ranges, reentry rank, report)")
        return 0

    roots = [Path(r) for r in args.roots] if args.roots else [
        ROOT / p for p in LAB_ROOTS.values() if (ROOT / p).is_dir()
    ]
    if not roots:
        ap.error("no roots found; pass one or run from the repo root")
    if args.label and len(roots) != 1:
        ap.error("--label requires exactly one root")

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    reverse = {str((ROOT / v).resolve()): k for k, v in LAB_ROOTS.items()}
    failed = 0
    for root in roots:
        root = root.resolve()
        label = args.label or reverse.get(str(root)) or root.name
        try:
            data = sweep_root(root, label, args.include_tests,
                              not args.no_semgrep, args.semgrep_max_files)
        except Exception as exc:  # noqa: BLE001 - one bad tree must not stop all
            print(f"[error] {root}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            failed += 1
            continue
        json_path = outdir / f"{label}.json"
        md_path = outdir / f"{label}.md"
        json_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        md_path.write_text(render(data), encoding="utf-8")
        c = data["counts"]
        print(f"[ok] {label}: {data['php_files']} files, "
              f"{c['magic_methods']} magic, {c['candidates']} candidates, "
              f"{c['reentry']} reentry -> {_rel(str(md_path))}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
