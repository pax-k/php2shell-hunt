"""Cross-class PHP gadget graph from PHP-Parser facts.

`tools/gadget/php/facts.php` emits per-file classes, properties, methods and
calls. This module merges inheritance/traits/interfaces, resolves property
types to candidate classes, and searches from deserialization entry points
(`__destruct`, `__wakeup`, `__unserialize`) to sinks such as `unserialize()`.

It answers the question the same-method sweep cannot: the Drupal P5 chain
(`YamlCacheCollectorDiscovery::__destruct` -> CacheCollector -> MemoryBackend
-> `unserialize()`).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter, deque
from pathlib import Path

from . import gadget_sweep

ROOT = Path(__file__).resolve().parent.parent
FACTS = ROOT / "tools" / "gadget" / "php" / "facts.php"
VENDOR = ROOT / "tools" / "gadget" / "php" / "vendor" / "autoload.php"
ENTRY = ("__destruct", "__wakeup", "__unserialize")
SINKS = {
    "unserialize": "reentry", "igbinary_unserialize": "reentry",
    "yaml_parse": "reentry", "system": "terminal", "exec": "terminal",
    "shell_exec": "terminal", "passthru": "terminal", "popen": "terminal",
    "proc_open": "terminal", "pcntl_exec": "terminal", "eval": "terminal",
    "call_user_func": "dispatch", "call_user_func_array": "dispatch",
    "forward_static_call": "dispatch", "forward_static_call_array": "dispatch",
    "file_put_contents": "file", "fopen": "file", "fwrite": "file",
    "move_uploaded_file": "file", "copy": "file", "rename": "file",
    "unlink": "file", "include": "file", "include_once": "file",
    "require": "file", "require_once": "file",
}
WEIGHT = {"reentry": 100, "terminal": 90, "dispatch": 70, "file": 50}


def load_facts(text: str) -> tuple[dict, int]:
    classes: dict[str, dict] = {}
    errors = 0
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            errors += 1
            continue
        if record.get("error"):
            errors += 1
        for info in record.get("classes", []):
            if isinstance(info.get("properties"), list):
                info["properties"] = {}
            if isinstance(info.get("methods"), list):
                info["methods"] = {}
            classes[info["name"]] = info
    return classes, errors


def _merge_traits(classes: dict) -> None:
    def merge(name: str, seen: set[str]) -> None:
        info = classes.get(name)
        if not info:
            return
        for trait in info.get("traits", []):
            if trait in seen or trait not in classes:
                continue
            seen.add(trait)
            merge(trait, seen)
            tinfo = classes[trait]
            for method, detail in tinfo["methods"].items():
                info["methods"].setdefault(method, detail)
            for prop, detail in tinfo["properties"].items():
                info["properties"].setdefault(prop, detail)
    for name in classes:
        merge(name, {name})


class Graph:
    def __init__(self, classes: dict):
        _merge_traits(classes)
        self.classes = classes
        self._rm: dict[tuple, tuple | None] = {}
        self._children: dict[str, list[str]] = {}
        for name, info in classes.items():
            for parent in info.get("extends", []) + info.get("implements", []):
                self._children.setdefault(parent, []).append(name)
        self._desc: dict[str, list[str]] = {}

    def concrete(self, name: str) -> bool:
        info = self.classes.get(name)
        return bool(info and not info.get("interface") and not info.get("abstract"))

    def resolve_method(self, cls: str, method: str) -> tuple[str, str] | None:
        key = (cls, method)
        if key in self._rm:
            return self._rm[key]
        info = self.classes.get(cls)
        result = None
        if info:
            if method in info.get("methods", {}):
                result = (cls, method)
            else:
                for parent in info.get("extends", []):
                    result = self.resolve_method(parent, method)
                    if result:
                        break
        self._rm[key] = result
        return result

    def descendants(self, name: str) -> list[str]:
        if name in self._desc:
            return self._desc[name]
        out, stack = [], [name]
        while stack:
            for child in self._children.get(stack.pop(), []):
                if child not in out:
                    out.append(child)
                    stack.append(child)
        self._desc[name] = out
        return out

    def ancestors(self, name: str) -> list[str]:
        out, seen = [], {name}
        stack = [name]
        while stack:
            info = self.classes.get(stack.pop())
            for parent in (info or {}).get("extends", []):
                if parent not in seen:
                    seen.add(parent)
                    out.append(parent)
                    stack.append(parent)
        return out

    def candidates(self, type_name: str, method: str) -> list[str]:
        key = (type_name, method)
        cached = getattr(self, "_cand", {})
        if key in cached:
            return cached[key]
        out = []
        for name in [type_name] + self.descendants(type_name):
            if not self.concrete(name):
                continue
            resolved = self.resolve_method(name, method)
            if resolved and resolved[1] == method:
                out.append(name)
        out.sort(key=lambda n: (n != type_name, len(self.ancestors(n)), n))
        out = out[:64]
        self._cand = cached
        cached[key] = out
        return out

    def property_types(self, cls: str, prop: str) -> list[str]:
        for owner in [cls] + self.ancestors(cls):
            info = self.classes.get(owner, {})
            detail = info.get("properties", {}).get(prop)
            if not detail:
                continue
            out = []
            for type_name in detail.get("types", []):
                if type_name in ("self", "static"):
                    out.append(owner)
                elif type_name == "parent":
                    out.extend(info.get("extends", []))
                else:
                    out.append(type_name)
            return list(dict.fromkeys(out))
        return []

    def sinks(self, node: tuple) -> list[dict]:
        cls, method, defining = node
        info = self.classes.get(defining, {}).get("methods", {}).get(method, {})
        out = []
        for call in info.get("calls", []):
            kind = call.get("kind")
            name = (call.get("name") or "").lower()
            if kind == "function" and name in SINKS:
                out.append({"kind": SINKS[name], "name": name,
                            "line": call.get("line")})
            elif kind == "include":
                out.append({"kind": "file", "name": "include",
                            "line": call.get("line")})
            elif kind == "eval":
                out.append({"kind": "terminal", "name": "eval",
                            "line": call.get("line")})
        return out

    def successors(self, node: tuple) -> list[tuple[tuple, str]]:
        cls, method, defining = node
        info = self.classes.get(defining, {}).get("methods", {}).get(method, {})
        out: list[tuple[tuple, str]] = []
        for call in info.get("calls", []):
            kind = call.get("kind")
            name = call.get("name")
            targets = list(call.get("targets") or [])
            if kind == "method":
                if call.get("receiver_kind") == "this":
                    targets = [cls]
                elif call.get("receiver_kind") == "property" and not targets:
                    targets = self.property_types(cls, call.get("prop") or "")
                if not name:
                    r = self.resolve_method(cls, "__call")
                    if r:
                        out.append(((cls, "__call", r[0]), "dynamic -> __call"))
                    continue
                for target in targets:
                    cands = self.candidates(target, name)
                    if not cands:
                        r = self.resolve_method(target, "__call")
                        if r:
                            out.append(((target, "__call", r[0]),
                                        f"{name} -> __call"))
                    for cand in cands:
                        r = self.resolve_method(cand, name)
                        if r:
                            out.append(((cand, name, r[0]),
                                        f"method {name}"))
            elif kind == "static" and name:
                for target in targets:
                    for cand in self.candidates(target, name):
                        r = self.resolve_method(cand, name)
                        if r:
                            out.append(((cand, name, r[0]), f"static {name}"))
            elif kind == "string":
                for target in targets:
                    for cand in self.candidates(target, "__toString"):
                        r = self.resolve_method(cand, "__toString")
                        if r:
                            out.append(((cand, "__toString", r[0]),
                                        "string -> __toString"))
        return list(dict.fromkeys(out))


def node_dict(graph: Graph, node: tuple, edge: str | None = None) -> dict:
    cls, method, defining = node
    info = graph.classes.get(defining, {})
    detail = info.get("methods", {}).get(method, {})
    out = {
        "class": cls, "method": method, "file": info.get("file", ""),
        "line": detail.get("line", 0),
    }
    if defining != cls:
        out["defining"] = defining
    if edge:
        out["edge"] = edge
    return out


def find_paths(classes: dict, max_depth: int = 10, max_paths: int = 200,
               budget: int = 300000) -> dict:
    graph = Graph(classes)
    entries = []
    for cls in classes:
        if not graph.concrete(cls):
            continue
        for magic in ENTRY:
            resolved = graph.resolve_method(cls, magic)
            if resolved:
                entries.append((cls, magic, resolved[0]))
    entries = list(dict.fromkeys(entries))
    paths, visits = [], 0
    for entry in entries:
        # BFS: shortest chains first. A per-entry visited set is enough because
        # a node's sinks/successors do not depend on the prefix that reached it.
        queue = deque([(entry, [entry], {(entry[0], entry[1])}, [], 0)])
        entry_paths = 0
        while queue and visits < budget and entry_paths < 40 \
                and len(paths) < max_paths * 8:
            node, path, seen, edges, depth = queue.popleft()
            visits += 1
            sinks = graph.sinks(node)
            entry_paths += len(sinks)
            for sink in sinks:
                last = path[-1]
                sink_info = dict(sink)
                sink_info["file"] = graph.classes.get(last[2], {}).get("file", "")
                paths.append({
                    "entry": node_dict(graph, entry),
                    "sink": sink_info,
                    "depth": depth,
                    "score": WEIGHT[sink["kind"]] - depth * 3,
                    "path": [node_dict(graph, path[i],
                                       "entry" if i == 0 else edges[i - 1])
                             for i in range(len(path))],
                })
            if sinks or depth >= max_depth:
                continue
            for nxt, edge in graph.successors(node):
                key = (nxt[0], nxt[1])
                if key in seen:
                    continue
                queue.append((nxt, path + [nxt], seen | {key},
                              edges + [edge], depth + 1))
    paths.sort(key=lambda p: (-p["score"], p["depth"], p["entry"]["class"],
                              p["entry"]["method"], p["sink"]["name"]))
    dedup, seen_paths = [], set()
    for item in paths:
        key = (item["entry"]["class"], item["entry"]["method"],
               item["sink"]["kind"], item["sink"]["file"],
               item["sink"]["line"],
               tuple((n["class"], n["method"]) for n in item["path"]))
        if key in seen_paths:
            continue
        seen_paths.add(key)
        dedup.append(item)
        if len(dedup) >= max_paths:
            break
    return {
        "classes": len(classes),
        "methods": sum(len(c.get("methods", {})) for c in classes.values()),
        "entries": len(entries),
        "visits": visits,
        "paths": dedup,
        "sink_counts": dict(Counter(p["sink"]["kind"] for p in dedup)),
    }


def run_facts(root: Path, files: list[Path]) -> tuple[dict, int]:
    if not VENDOR.is_file():
        raise RuntimeError(
            "php-parser vendor missing: composer install -d tools/gadget/php")
    php = shutil.which("php")
    if not php:
        raise RuntimeError("php is not installed")
    proc = subprocess.run(
        [php, str(FACTS), "--root", str(root)],
        input="".join(f"{f}\n" for f in files),
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"facts.php failed: {proc.stderr[-1000:]}")
    return load_facts(proc.stdout)


def _chain(path: dict) -> str:
    names = [f"{n['class'].split(chr(92))[-1]}::{n['method']}"
             for n in path["path"]]
    return " -> ".join(names) + f" -> {path['sink']['name']}()"


def render(label: str, root: Path, result: dict) -> str:
    lines = [
        f"# Cross-class gadget graph: `{label}`",
        "",
        f"Root `{gadget_sweep._rel(str(root))}` — {result['classes']} classes, "
        f"{result['methods']} methods, {result['entries']} entries, "
        f"{result['visits']} visited nodes, {len(result['paths'])} paths.",
        "",
        "Typed property/interface expansion via PHP-Parser facts. This finds "
        "chains the same-method sweep cannot; it still does not prove "
        "reachability or attacker control.",
        "",
        "## Top paths",
        "",
    ]
    rows = [[p["score"], p["sink"]["kind"], p["depth"],
             f"`{_chain(p)}`",
             f"{p['sink']['file']}:{p['sink']['line']}"]
            for p in result["paths"][:30]]
    if rows:
        lines += ["| score | sink | depth | chain | sink at |",
                  "|---|---|---|---|---|"]
        lines += ["| " + " | ".join(str(v) for v in row) + " |" for row in rows]
    else:
        lines.append("No paths.")
    lines += ["", "## Reproduce", "", "```sh",
              f"scripts/gadget_graph.sh {gadget_sweep._rel(str(root))} "
              f"--label {label}", "```", ""]
    return "\n".join(lines)


def self_test() -> bool:
    classes = {
        "A": {
            "name": "A", "file": "a.php", "line": 1, "extends": [],
            "implements": [], "traits": [], "interface": False,
            "trait": False, "abstract": False,
            "properties": {"b": {"types": ["B"], "line": 2}},
            "methods": {"__destruct": {
                "name": "__destruct", "line": 3, "end": 5, "static": False,
                "abstract": False, "returns": [], "params": [],
                "calls": [{"kind": "method", "name": "run", "line": 4,
                           "targets": ["B"], "receiver_kind": "property",
                           "prop": "b"}],
                "strings": []}},
        },
        "B": {
            "name": "B", "file": "b.php", "line": 1, "extends": [],
            "implements": [], "traits": [], "interface": False,
            "trait": False, "abstract": False, "properties": {},
            "methods": {"run": {
                "name": "run", "line": 3, "end": 4, "static": False,
                "abstract": False, "returns": [], "params": [],
                "calls": [{"kind": "function", "name": "unserialize",
                           "line": 4}], "strings": []}},
        },
    }
    result = find_paths(classes, max_depth=5)
    assert result["paths"], result
    assert result["paths"][0]["sink"]["kind"] == "reentry", result["paths"][0]
    assert "unserialize" in render("selftest", Path("."), result)
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", nargs="?", default=None)
    ap.add_argument("--label", default="drupal")
    ap.add_argument("--out", default=str(ROOT / "reports" / "gadgets"))
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--top", type=int, default=200)
    ap.add_argument("--budget", type=int, default=300000)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        print("[ok] gadget_graph self-test (typed edge, reentry path, report)")
        return 0

    root = Path(args.root).resolve() if args.root else ROOT / "lab-drupal"
    if not root.is_dir():
        print(f"[error] not a directory: {root}", file=sys.stderr)
        return 2
    files = gadget_sweep.discover(root, args.include_tests)
    if args.limit:
        files = files[:args.limit]
    try:
        classes, errors = run_facts(root, files)
    except RuntimeError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    result = find_paths(classes, args.max_depth, args.top, args.budget)
    result["facts_errors"] = errors
    result["files"] = len(files)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / f"{args.label}-graph.json"
    md_path = outdir / f"{args.label}-graph.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    md_path.write_text(render(args.label, root, result), encoding="utf-8")
    print(f"[ok] {len(files)} files, {result['classes']} classes, "
          f"{result['entries']} entries, {len(result['paths'])} paths "
          f"({errors} fact errors) -> {gadget_sweep._rel(str(md_path))}")
    for item in result["paths"][:5]:
        print(f"     {item['sink']['kind']:8} {_chain(item)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
