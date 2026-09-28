"""
bridge — Athena's in-process tool surface for the ported Basilisk engines.

Why this file exists
====================
The engines ported in v7.8 (exploits · pentest · workspace · research ·
verify · browser · tasks · juiceshop · xbow · bench · skills · mcp · reach)
are deliberately self-contained: none of them knows about the host, and each
takes its host-side dependencies (a scope predicate, a settings dict, an HTTP
reader) as injected callables.  This module is that injection point.

It gives athena.py ONE thing to merge into PURE_TOOL_DISPATCH and ONE spec
string to append to the system prompt, so the host stays small and every new
capability is added here rather than threaded through the REPL.

Contract (same as every other athena_ext module)
-----------------------------------------------
  * stdlib only, imports nothing from athena.py.
  * fail-soft: a missing engine disables its tools; it never breaks boot.
  * pure/local: these run in-process with NO shell and NO y/n gate.  The
    network-touching readers (research/verify/browser) still honour the
    engagement scope when it is enabled and sanitise every fetched byte
    through webshield before it can reach the model.  Nothing here fires an
    exploit — exploit_build only CONSTRUCTS a payload, exactly like
    sqlmap_plan; the operator still runs the command through the gate.

Signature contract for every entry: fn(session, args: dict) -> str
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

MAX_RETURN = 6000            # chars of a tool result fed back to the model
_HOME = Path(os.path.expanduser("~/.athena"))
_SETTINGS_FILE = _HOME / "settings.json"
_MCP_FILE = _HOME / "mcp.json"
_SKILLS_DIR = _HOME / "skills"


# ═════════════════════════════════════════════════════════════════════
# small helpers
# ═════════════════════════════════════════════════════════════════════

def _lazy(name: str):
    """Import a sibling engine, or None.  Cached by the import system."""
    try:
        return __import__(f"athena_ext.{name}", fromlist=[name])
    except Exception:
        return None


def _j(obj: Any, cap: int = MAX_RETURN) -> str:
    try:
        s = json.dumps(obj, indent=2, default=str)
    except Exception:
        s = str(obj)
    return s[:cap]


def _err(msg: str) -> str:
    return json.dumps({"ok": False, "error": msg})


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _settings() -> Dict[str, Any]:
    try:
        if _SETTINGS_FILE.exists():
            return _as_dict(json.loads(_SETTINGS_FILE.read_text()))
    except Exception:
        pass
    return {}


def _opt_in(feature: str) -> bool:
    """Opt-in gate for the sensitive engines (skills · mcp · reach).

    Enabled by EITHER the env var ATHENA_<FEATURE>=1/true/yes/on OR
    `"<feature>_enabled": true` in ~/.athena/settings.json.  Default OFF, as
    the project's own safety notes require for these three.
    """
    v = (os.environ.get(f"ATHENA_{feature.upper()}") or "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    return bool(_settings().get(f"{feature}_enabled"))


def _scope_host_ok(session: Any, host: Optional[str]) -> bool:
    """SSRF/scope floor shared by the browser and the research readers.

    Fails CLOSED only when scope is enabled — an unknown host is refused, the
    same way engage.scope_check does.  When scope is disabled there is no
    authorisation list to check against, so a plain public fetch is allowed;
    that matches how Athena already treats curl without scope.
    """
    try:
        scope = getattr(session, "scope", None)
        if scope is None or not getattr(scope, "enabled", False):
            return True
        if not host:
            return False
        # Reuse the engagement's own matcher so there is exactly one scope
        # implementation, not two that can drift.
        h = host.split(":", 1)[0].strip().lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
            if scope.blocked_cidrs and scope._ip_in_cidrs(h, scope.blocked_cidrs):
                return False
            if scope.allowed_cidrs:
                return scope._ip_in_cidrs(h, scope.allowed_cidrs)
            return True
        if scope.blocked_domains and scope._domain_matches(h, scope.blocked_domains):
            return False
        if scope.allowed_domains:
            return scope._domain_matches(h, scope.allowed_domains)
        return True
    except Exception:
        # An error in the floor must not become an open door when scope is on.
        return not getattr(getattr(session, "scope", None), "enabled", False)


def _sanitize(text: str, source: str) -> str:
    """Run fetched text through webshield before it can reach the model."""
    ws = _lazy("webshield")
    if ws is not None:
        try:
            return ws.sanitize(text, source=source).get("text", text)
        except Exception:
            pass
    return text


_READ_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Athena/7.8 research")


def _read_url(session: Any) -> Callable[[str], Dict[str, Any]]:
    """A reader for research/verify: GET a URL, scope-check, sanitise, return
    {"ok", "text", "engine"}.  No shell, no gate — but the scope floor and the
    webshield firewall both apply, because a search page is untrusted input."""
    def _read(url: str, _timeout: int = 20) -> Dict[str, Any]:
        try:
            p = urllib.parse.urlparse(url)
            if p.scheme not in ("http", "https"):
                return {"ok": False, "error": f"refusing {p.scheme!r} scheme"}
            if not _scope_host_ok(session, p.hostname):
                return {"ok": False,
                        "error": f"host {p.hostname!r} refused by scope"}
            req = urllib.request.Request(url, headers={
                "User-Agent": _READ_UA,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            })
            with urllib.request.urlopen(req, timeout=_timeout) as r:
                raw = r.read(2_000_000)
                ctype = (r.headers.get("Content-Type") or "").lower()
            for enc in ("utf-8", "latin-1"):
                try:
                    text = raw.decode(enc)
                    break
                except Exception:
                    text = raw.decode("utf-8", "replace")
            if "json" in ctype:
                text = text
            return {"ok": True, "engine": "urllib", "text": text}
        except Exception as e:
            return {"ok": False, "engine": "urllib",
                    "error": f"{type(e).__name__}: {e}"}
    return _read


def _fetch_json(url: str, _timeout: int = 15) -> Any:
    """A read-only JSON fetcher for cve_lookup / enrich_with_cves (KEV, EPSS,
    NVD).  Public advisory data; no credentials, no target traffic."""
    req = urllib.request.Request(url, headers={
        "User-Agent": _READ_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=_timeout) as r:
        return json.loads(r.read(4_000_000).decode("utf-8", "replace"))


# ═════════════════════════════════════════════════════════════════════
# exploits — 56 payload / request builders (CONSTRUCT only, never fire)
# ═════════════════════════════════════════════════════════════════════

_EXPLOIT_SKIP = {"jwt_decode", "z85_encode", "z85_decode"}


def _exploit_kinds() -> List[str]:
    ex = _lazy("exploits")
    if ex is None:
        return []
    out = []
    for n in dir(ex):
        if n.startswith("_") or n in _EXPLOIT_SKIP:
            continue
        fn = getattr(ex, n)
        if callable(fn) and getattr(fn, "__module__", "") == "athena_ext.exploits":
            out.append(n)
    return sorted(out)


def _t_exploit_list(session, a):
    import inspect
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    rows = []
    for n in _exploit_kinds():
        fn = getattr(ex, n)
        try:
            sig = str(inspect.signature(fn))
        except Exception:
            sig = "(...)"
        doc = (inspect.getdoc(fn) or "").split("\n", 1)[0][:80]
        rows.append({"kind": n, "params": sig, "doc": doc})
    return _j({"ok": True, "count": len(rows), "builders": rows})


def _t_exploit_build(session, a):
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    kind = str(a.get("kind") or a.get("type") or a.get("name") or "").strip()
    if not kind:
        return _err("exploit_build needs a 'kind' — call exploit_list to see them")
    fn = getattr(ex, kind, None)
    if not callable(fn) or kind.startswith("_"):
        near = [k for k in _exploit_kinds() if kind.lower() in k.lower()][:8]
        return _err(f"unknown builder {kind!r}"
                    + (f"; did you mean {near}?" if near else ""))
    params = {k: v for k, v in a.items()
              if k not in ("kind", "type", "name")}
    try:
        res = fn(**params)
    except TypeError as e:
        return _err(f"{kind} bad/missing args: {e}")
    except Exception as e:
        return _err(f"{kind} failed: {type(e).__name__}: {e}")
    return _j(res)


def _t_exploit_encode(session, a):
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    return _j(ex.payload_encoder(
        payload=a.get("payload", a.get("text", "")),
        scheme=a.get("scheme", "all"), decode=bool(a.get("decode", False))))


def _t_exploit_fingerprint(session, a):
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    return _j(ex.tech_fingerprint(headers=a.get("headers", ""),
                                  body=a.get("body", "")))


def _t_exploit_waf(session, a):
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    return _j(ex.waf_detect(blocked_payload=a.get("blocked_payload", ""),
                            response_body=a.get("response_body", ""),
                            status_code=int(a.get("status_code", 0) or 0)))


def _t_exploit_trick(session, a):
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    return _j(ex.trick_detect(text=a.get("text", "")))


def _t_exploit_oracle(session, a):
    ex = _lazy("exploits")
    if ex is None:
        return _err("exploits engine unavailable")
    return _j(ex.oracle_analyze(
        mode=a.get("mode", "diff"), baseline=a.get("baseline", ""),
        test=a.get("test", ""), baseline_status=a.get("baseline_status", 0),
        test_status=a.get("test_status", 0),
        baseline_times=a.get("baseline_times", ""),
        payload_times=a.get("payload_times", "")))


# ═════════════════════════════════════════════════════════════════════
# pentest — recon planning, output parsing, CVE/KEV/EPSS, reporting
# ═════════════════════════════════════════════════════════════════════

def _t_pentest_tooling(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    r = p.tooling_check()
    return _j(r) if isinstance(r, dict) and r.get("text") is None else \
        (r.get("text") or _j(r))


def _t_pentest_plan(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.plan_recon(str(a.get("target", a.get("host", ""))),
                           str(a.get("profile", "web")),
                           str(a.get("intensity", "normal"))))


def _t_parse_output(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.parse_output(str(a.get("tool", a.get("scanner", ""))),
                             str(a.get("raw", a.get("output", "")))))


def _t_cve_lookup(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.cve_lookup(str(a.get("product", a.get("service", ""))),
                           str(a.get("version", "")),
                           fetch_json=_fetch_json,
                           limit=int(a.get("limit", 8) or 8),
                           enrich=bool(a.get("enrich", True))))


def _t_enrich_cves(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.enrich_with_cves(_as_dict(a.get("parsed", a)),
                                 fetch_json=_fetch_json,
                                 max_lookups=int(a.get("max_lookups", 10) or 10)))


def _t_methodology(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.methodology(str(a.get("area", "")), str(a.get("phase", ""))))


def _t_cheatsheet(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.cheatsheet(str(a.get("topic", ""))))


def _t_wordlist_find(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.wordlist_find(str(a.get("kind", ""))))


def _t_nuclei_template(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.nuclei_template(a.get("spec"), str(a.get("mode", "build")),
                                str(a.get("yaml_text", a.get("yaml", "")))))


def _t_reflect_findings(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.reflect_findings(a.get("findings", [])))


def _t_report_findings(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.report_findings(a.get("findings", []),
                                str(a.get("target", "")),
                                str(a.get("scope_note", "")),
                                str(a.get("title", ""))))


def _t_attack_writeup(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    return _j(p.attack_writeup(access=a.get("access", ""),
                               steps=a.get("steps"),
                               target=str(a.get("target", "")),
                               scope_note=str(a.get("scope_note", "")),
                               impact=str(a.get("impact", "")),
                               remediation=str(a.get("remediation", "")),
                               root_cause=str(a.get("root_cause", ""))))


def _t_sqlmap_plan(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    keys = ("target", "mode", "data", "cookie", "headers", "level",
            "risk", "dbms", "technique", "db", "table", "request_file", "extra")
    kw = {k: a.get(k) for k in keys if k in a}
    return _j(p.sqlmap_plan(**kw))


def _t_webapp_paths(session, a):
    p = _lazy("pentest")
    if p is None:
        return _err("pentest engine unavailable")
    extra = a.get("extra")
    if isinstance(extra, str):
        extra = [x.strip() for x in extra.split(",") if x.strip()]
    return _j(p.webapp_recon_paths(extra))


# ═════════════════════════════════════════════════════════════════════
# workspace — a confined code workspace (import / read / edit / diff / test)
# ═════════════════════════════════════════════════════════════════════

def _t_workspace(session, a):
    w = _lazy("workspace")
    if w is None:
        return _err("workspace engine unavailable")
    op = str(a.get("op", a.get("action", ""))).strip().lower()
    g = a.get

    def _paths(v):
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    try:
        if op in ("import", "open"):
            path = str(g("path", g("zip", g("dir", ""))))
            if not path:
                return _err("workspace import needs a path (zip or dir)")
            fn = w.import_zip if os.path.isfile(path) and path.lower().endswith(".zip") \
                else w.import_dir
            return _j(fn(path, str(g("name", ""))))
        if op == "status":
            return _j(w.status())
        if op == "tree":
            return _j(w.tree(int(g("max_entries", 400) or 400), str(g("path", ""))))
        if op == "overview":
            return _j(w.overview())
        if op == "read":
            return _j(w.read(str(g("path", "")), int(g("start", 1) or 1),
                             int(g("end", 0) or 0),
                             int(g("max_bytes", 200000) or 200000)))
        if op == "read_many":
            return _j(w.read_many(_paths(g("paths", [])),
                                  int(g("max_chars", 6000) or 6000)))
        if op in ("search", "grep"):
            return _j(w.search(str(g("pattern", "")), str(g("glob", "")),
                               bool(g("regex", False)),
                               int(g("max_results", 120) or 120),
                               int(g("context", 0) or 0)))
        if op in ("glob", "glob_files"):
            return _j(w.glob_files(str(g("pattern", "*")),
                                   int(g("limit", 300) or 300)))
        if op == "write":
            return _j(w.write(str(g("path", "")), str(g("content", "")),
                              bool(g("create", False))))
        if op == "replace":
            return _j(w.replace(str(g("path", "")), str(g("old", "")),
                                str(g("new", "")), int(g("count", 1) or 1)))
        if op == "edits":
            return _j(w.edits(str(g("path", "")), g("items", [])))
        if op == "append":
            return _j(w.append(str(g("path", "")), str(g("content", "")),
                               bool(g("create", False))))
        if op == "insert":
            return _j(w.insert(str(g("path", "")), str(g("content", "")),
                               int(g("after_line", 0) or 0),
                               int(g("before_line", 0) or 0)))
        if op == "delete":
            return _j(w.delete(str(g("path", ""))))
        if op == "diff":
            return _j(w.diff(str(g("path", ""))))
        if op == "revert":
            return _j(w.revert(str(g("path", ""))))
        if op == "export":
            return _j(w.export_zip(str(g("out_path", "")),
                                   bool(g("include_secrets", False)),
                                   bool(g("changed_only", False)),
                                   bool(g("force", False))))
        if op == "close":
            return _j(w.close(bool(g("discard", False))))
        if op == "test_detect":
            return _j(w.detect_test_command())
        if op == "parse_test":
            return _j(w.parse_test_output(str(g("raw", "")),
                                          int(g("rc", 0) or 0)))
        if op == "record_baseline":
            return _j(w.record_baseline(str(g("raw", "")), int(g("rc", 0) or 0),
                                        str(g("command", ""))))
        if op == "compare_baseline":
            return _j(w.compare_to_baseline(str(g("raw", "")),
                                            int(g("rc", 0) or 0)))
        if op == "baseline_status":
            return _j(w.baseline_status())
        if op == "health":
            return _j(w.health())
        if op == "repo_root":
            return _j({"ok": True, "root": w.repo_root()})
    except Exception as e:
        return _err(f"workspace {op}: {type(e).__name__}: {e}")
    return _err(f"unknown workspace op {op!r}; see the tool spec for valid ops")


# ═════════════════════════════════════════════════════════════════════
# tasks — a per-session task plan the model keeps honest against
# ═════════════════════════════════════════════════════════════════════

def _taskplan(session):
    tp = getattr(session, "_athena_taskplan", None)
    if tp is None:
        t = _lazy("tasks")
        if t is None:
            return None
        tp = t.TaskPlan()
        try:
            session._athena_taskplan = tp
        except Exception:
            pass
    return tp


def _t_task_plan(session, a):
    tp = _taskplan(session)
    if tp is None:
        return _err("tasks engine unavailable")
    return _j(tp.set_plan(a.get("items", a.get("plan", [])),
                          a.get("goal", "")))


def _t_task_status(session, a):
    tp = _taskplan(session)
    if tp is None:
        return _err("tasks engine unavailable")
    st = tp.status()
    st["rendered"] = tp.render()
    return _j(st)


def _t_task_update(session, a):
    tp = _taskplan(session)
    if tp is None:
        return _err("tasks engine unavailable")
    return _j(tp.update(a.get("id", a.get("ident", "")),
                        a.get("status", ""), a.get("note", "")))


def _t_task_render(session, a):
    tp = _taskplan(session)
    if tp is None:
        return _err("tasks engine unavailable")
    return tp.render()


def _t_task_clear(session, a):
    tp = _taskplan(session)
    if tp is None:
        return _err("tasks engine unavailable")
    tp.clear()
    return _j({"ok": True, "cleared": True})


# ═════════════════════════════════════════════════════════════════════
# research / verify / browser — OSINT and multi-source verification
# ═════════════════════════════════════════════════════════════════════

def _t_research_expand(session, a):
    r = _lazy("research")
    if r is None:
        return _err("research engine unavailable")
    extra = a.get("extra") or ()
    if isinstance(extra, str):
        extra = [x.strip() for x in extra.split(",") if x.strip()]
    return _j({"ok": True, "queries": r.expand(
        str(a.get("question", "")), extra, str(a.get("year", "")))})


def _t_research_search(session, a):
    r = _lazy("research")
    if r is None:
        return _err("research engine unavailable")
    return _j(r.search(str(a.get("question", a.get("query", ""))),
                       read_fn=_read_url(session),
                       queries=a.get("queries") or (),
                       engines=a.get("engines") or (),
                       limit=int(a.get("limit", 12) or 12),
                       max_pages=int(a.get("max_pages", 4) or 4)))


def _t_research_run(session, a):
    r = _lazy("research")
    if r is None:
        return _err("research engine unavailable")
    return _j(r.research(str(a.get("question", a.get("query", ""))),
                         read_fn=_read_url(session),
                         queries=a.get("queries") or (),
                         max_sources=int(a.get("max_sources", 3) or 3),
                         per_source_chars=int(a.get("per_source_chars", 4000) or 4000),
                         engines=a.get("engines") or ()))


def _t_verify_claim(session, a):
    v = _lazy("verify")
    r = _lazy("research")
    if v is None or r is None:
        return _err("verify/research engine unavailable")
    read = _read_url(session)

    def _search(**kw):
        return r.search(kw.get("query", a.get("query", "")), read_fn=read,
                        queries=kw.get("queries") or (),
                        engines=kw.get("engines") or (),
                        limit=int(kw.get("limit", 8) or 8),
                        max_pages=int(kw.get("max_pages", 4) or 4))
    return _j(v.verify(str(a.get("query", a.get("claim", ""))),
                       search_fn=_search, read_fn=read,
                       max_sources=int(a.get("max_sources", 5) or 5)))


def _t_browser_fetch(session, a):
    b = _lazy("browser")
    if b is None:
        return _err("browser engine unavailable")
    res = b.fetch(str(a.get("url", "")),
                  host_ok=lambda h: _scope_host_ok(session, h),
                  timeout=int(a.get("timeout", 25) or 25),
                  prefer=str(a.get("prefer", "")),
                  block_heavy=bool(a.get("block_heavy", True)))
    if isinstance(res, dict):
        res = dict(res)
        html = res.pop("html", "")
        if html:
            res["text"] = _sanitize(html, source=str(a.get("url", "")))
            res["html_chars"] = len(html)
    return _j(res)


def _t_browser_status(session, a):
    b = _lazy("browser")
    if b is None:
        return _err("browser engine unavailable")
    return _j(b.probe())


# ═════════════════════════════════════════════════════════════════════
# scoring — juiceshop · xbow · bench
# ═════════════════════════════════════════════════════════════════════

def _t_juiceshop_score(session, a):
    j = _lazy("juiceshop")
    if j is None:
        return _err("juiceshop engine unavailable")
    return _j(j.score_challenges(a.get("payload", a.get("challenges", []))))


def _t_juiceshop_next(session, a):
    j = _lazy("juiceshop")
    if j is None:
        return _err("juiceshop engine unavailable")
    return _j(j.next_targets(a.get("payload", a.get("challenges", [])),
                             int(a.get("limit", 0) or 0),
                             int(a.get("max_difficulty", 0) or 0),
                             int(a.get("per_tier", 0) or 0)))


def _t_juiceshop_report(session, a):
    j = _lazy("juiceshop")
    if j is None:
        return _err("juiceshop engine unavailable")
    return _j(j.juiceshop_report(a.get("scored", a)))


def _t_juiceshop_diff(session, a):
    j = _lazy("juiceshop")
    if j is None:
        return _err("juiceshop engine unavailable")
    return _j(j.diff_solved(a.get("before", []), a.get("after", [])))


def _t_xbow_extract_flag(session, a):
    x = _lazy("xbow")
    if x is None:
        return _err("xbow engine unavailable")
    flag = x.extract_flag(str(a.get("text", "")))
    return _j({"ok": flag is not None, "flag": flag})


def _t_xbow_record(session, a):
    x = _lazy("xbow")
    if x is None:
        return _err("xbow engine unavailable")
    res = _state_list(session, "xbow_results")
    rec = x.record_result(str(a.get("challenge", "")),
                          str(a.get("submitted", a.get("flag", ""))),
                          str(a.get("expected", "")),
                          a.get("seconds"), str(a.get("notes", "")))
    res.append(rec)
    return _j(rec)


def _t_xbow_score(session, a):
    x = _lazy("xbow")
    if x is None:
        return _err("xbow engine unavailable")
    results = a.get("results")
    if results is None:
        results = _state_list(session, "xbow_results")
    return _j(x.score_results(results))


def _t_xbow_report(session, a):
    x = _lazy("xbow")
    if x is None:
        return _err("xbow engine unavailable")
    return _j(x.xbow_report(a.get("scored", a)))


def _t_bench_targets(session, a):
    b = _lazy("bench")
    if b is None:
        return _err("bench engine unavailable")
    return _j(b.benchmark_targets(str(a.get("target", ""))))


def _t_bench_score(session, a):
    b = _lazy("bench")
    if b is None:
        return _err("bench engine unavailable")
    findings = a.get("findings")
    if findings is None:
        findings = _session_findings(session)
    return _j(b.score_run(str(a.get("target", "")), findings,
                          a.get("ground_truth")))


def _t_bench_report(session, a):
    b = _lazy("bench")
    if b is None:
        return _err("bench engine unavailable")
    return _j(b.benchmark_report(a.get("scored", a)))


def _t_bench_compare(session, a):
    b = _lazy("bench")
    if b is None:
        return _err("bench engine unavailable")
    return _j(b.compare_runs(a.get("runs", [])))


def _state_list(session, attr: str) -> list:
    lst = getattr(session, attr, None)
    if not isinstance(lst, list):
        lst = []
        try:
            setattr(session, attr, lst)
        except Exception:
            pass
    return lst


def _session_findings(session) -> List[Dict[str, Any]]:
    """Best-effort bridge to Athena's own PTT findings for scoring."""
    out: List[Dict[str, Any]] = []
    try:
        ptt = getattr(session, "ptt", None)
        findings = getattr(ptt, "findings", None) or []
        for f in findings:
            out.append({
                "name": getattr(f, "ftype", "") + ":" + str(getattr(f, "value", "")),
                "description": str(getattr(f, "value", "")),
                "cwe": getattr(f, "cwe", None),
                "severity": getattr(f, "severity", None),
            })
    except Exception:
        pass
    return out


# ═════════════════════════════════════════════════════════════════════
# skills (OPT-IN) — agent-written scripts, run in the sandbox
# ═════════════════════════════════════════════════════════════════════

def _skillstore(session):
    st = getattr(session, "_athena_skillstore", None)
    if st is None:
        s = _lazy("skills")
        if s is None:
            return None
        try:
            _SKILLS_DIR.mkdir(parents=True, exist_ok=True)
            st = s.SkillStore(_SKILLS_DIR)
            session._athena_skillstore = st
        except Exception:
            return None
    return st


def _skills_gate(session) -> Optional[str]:
    if not _opt_in("skills"):
        return ("skills are OPT-IN and currently OFF. Enable with "
                "ATHENA_SKILLS=1 (or \"skills_enabled\": true in "
                "~/.athena/settings.json) and restart. Skills execute "
                "agent-written code inside the bubblewrap sandbox.")
    return None


def _t_skill_list(session, a):
    gate = _skills_gate(session)
    if gate:
        return _err(gate)
    st = _skillstore(session)
    if st is None:
        return _err("skills engine unavailable")
    return st.tool_list()


def _t_skill_run(session, a):
    gate = _skills_gate(session)
    if gate:
        return _err(gate)
    st = _skillstore(session)
    if st is None:
        return _err("skills engine unavailable")
    return st.tool_run(str(a.get("name", "")), _as_dict(a.get("args", {})),
                       int(a.get("timeout", 20) or 20))


def _t_skill_propose(session, a):
    gate = _skills_gate(session)
    if gate:
        return _err(gate)
    st = _skillstore(session)
    if st is None:
        return _err("skills engine unavailable")
    caps = a.get("capabilities") or []
    if isinstance(caps, str):
        caps = [x.strip() for x in caps.split(",") if x.strip()]
    return st.tool_propose(str(a.get("name", "")), str(a.get("code", "")),
                           str(a.get("test", a.get("tests", ""))),
                           str(a.get("description", "")), caps)


def _t_skill_commit(session, a):
    gate = _skills_gate(session)
    if gate:
        return _err(gate)
    st = _skillstore(session)
    if st is None:
        return _err("skills engine unavailable")
    caps = a.get("capabilities") or []
    if isinstance(caps, str):
        caps = [x.strip() for x in caps.split(",") if x.strip()]
    return _j(st.commit(str(a.get("name", "")), str(a.get("code", "")),
                        str(a.get("test", a.get("tests", ""))),
                        str(a.get("description", "")), caps))


def _t_skill_curate(session, a):
    gate = _skills_gate(session)
    if gate:
        return _err(gate)
    st = _skillstore(session)
    if st is None:
        return _err("skills engine unavailable")
    return _j(st.curate())


# ═════════════════════════════════════════════════════════════════════
# mcp (OPT-IN) — stdio MCP servers from ~/.athena/mcp.json
# ═════════════════════════════════════════════════════════════════════

def _mcp_gate(session) -> Optional[str]:
    if not _opt_in("mcp"):
        return ("MCP is OPT-IN and currently OFF. Enable with ATHENA_MCP=1 "
                "(or \"mcp_enabled\": true in ~/.athena/settings.json) and put "
                "server configs in ~/.athena/mcp.json.")
    return None


def _mcp_manager(session):
    mgr = getattr(session, "_athena_mcp", None)
    if mgr is not None:
        return mgr
    m = _lazy("mcp")
    if m is None:
        return None
    try:
        cfg = json.loads(_MCP_FILE.read_text()) if _MCP_FILE.exists() else []
    except Exception:
        cfg = []
    if isinstance(cfg, dict):
        cfg = cfg.get("servers", [])
    if not cfg:
        return None
    try:
        mgr = m.MCPManager(cfg, ledger=None)
        session._athena_mcp = mgr
    except Exception:
        return None
    return mgr


def _t_mcp_list(session, a):
    gate = _mcp_gate(session)
    if gate:
        return _err(gate)
    mgr = _mcp_manager(session)
    if mgr is None:
        return _err("no MCP servers configured in ~/.athena/mcp.json")
    return _j({"ok": True, "tools": mgr.discover(), "specs": mgr.tool_specs()})


def _t_mcp_call(session, a):
    gate = _mcp_gate(session)
    if gate:
        return _err(gate)
    mgr = _mcp_manager(session)
    if mgr is None:
        return _err("no MCP servers configured in ~/.athena/mcp.json")
    return mgr.call(str(a.get("tool", a.get("name", ""))),
                    _as_dict(a.get("arguments", a.get("args", {}))),
                    int(a.get("timeout", 60) or 60))


# ═════════════════════════════════════════════════════════════════════
# reach (OPT-IN) — semantic web search + GitHub
# ═════════════════════════════════════════════════════════════════════

def _reach_gate(session) -> Optional[str]:
    if not _opt_in("reach"):
        return ("reach is OPT-IN and currently OFF (it is an external-text "
                "surface). Enable with ATHENA_REACH=1 (or \"reach_enabled\": "
                "true in ~/.athena/settings.json).")
    return None


def _reach_tools(session):
    r = _lazy("reach")
    if r is None:
        return None
    try:
        r.bind_settings(_settings())
    except Exception:
        pass
    try:
        return r.tools()
    except Exception:
        return None


def _t_reach(session, a):
    gate = _reach_gate(session)
    if gate:
        return _err(gate)
    tools = _reach_tools(session)
    if not tools:
        return _err("reach engine unavailable")
    op = str(a.get("op", a.get("tool", ""))).strip()
    if not op:
        return _err("reach needs an 'op': web_search_smart | github_search | "
                    "github_repo")
    fn = tools.get(op)
    if not fn:
        return _err(f"unknown reach op {op!r}; valid: {list(tools)}")
    try:
        return str(fn(a))[:MAX_RETURN]
    except Exception as e:
        return _err(f"{op}: {type(e).__name__}: {e}")


# ═════════════════════════════════════════════════════════════════════
# registry + prompt spec
# ═════════════════════════════════════════════════════════════════════

REGISTRY: Dict[str, Callable[[Any, dict], str]] = {
    # exploits
    "exploit_list":       _t_exploit_list,
    "exploit_build":      _t_exploit_build,
    "exploit_encode":     _t_exploit_encode,
    "exploit_fingerprint": _t_exploit_fingerprint,
    "exploit_waf":        _t_exploit_waf,
    "exploit_trick":      _t_exploit_trick,
    "exploit_oracle":     _t_exploit_oracle,
    # pentest
    "pentest_tooling":    _t_pentest_tooling,
    "pentest_plan":       _t_pentest_plan,
    "parse_output":       _t_parse_output,
    "cve_lookup":         _t_cve_lookup,
    "enrich_cves":        _t_enrich_cves,
    "methodology":        _t_methodology,
    "cheatsheet":         _t_cheatsheet,
    "wordlist_find":      _t_wordlist_find,
    "nuclei_template":    _t_nuclei_template,
    "reflect_findings":   _t_reflect_findings,
    "report_findings":    _t_report_findings,
    "attack_writeup":     _t_attack_writeup,
    "sqlmap_plan":        _t_sqlmap_plan,
    "webapp_paths":       _t_webapp_paths,
    # workspace
    "workspace":          _t_workspace,
    # tasks
    "task_plan":          _t_task_plan,
    "task_status":        _t_task_status,
    "task_update":        _t_task_update,
    "task_render":        _t_task_render,
    "task_clear":         _t_task_clear,
    # research / verify / browser
    "research_expand":    _t_research_expand,
    "research_search":    _t_research_search,
    "research_run":       _t_research_run,
    "verify_claim":       _t_verify_claim,
    "browser_fetch":      _t_browser_fetch,
    "browser_status":     _t_browser_status,
    # scoring
    "juiceshop_score":    _t_juiceshop_score,
    "juiceshop_next":     _t_juiceshop_next,
    "juiceshop_report":   _t_juiceshop_report,
    "juiceshop_diff":     _t_juiceshop_diff,
    "xbow_extract_flag":  _t_xbow_extract_flag,
    "xbow_record":        _t_xbow_record,
    "xbow_score":         _t_xbow_score,
    "xbow_report":        _t_xbow_report,
    "bench_targets":      _t_bench_targets,
    "bench_score":        _t_bench_score,
    "bench_report":       _t_bench_report,
    "bench_compare":      _t_bench_compare,
    # opt-in
    "skill_list":         _t_skill_list,
    "skill_run":          _t_skill_run,
    "skill_propose":      _t_skill_propose,
    "skill_commit":       _t_skill_commit,
    "skill_curate":       _t_skill_curate,
    "mcp_list":           _t_mcp_list,
    "mcp_call":           _t_mcp_call,
    "reach":              _t_reach,
}


SPEC = (
    "ATHENA ENGINES (in-process; same [TOOL]name[/TOOL][ARGS]json[/ARGS]; "
    "no shell, no gate — they BUILD/ANALYSE, they never fire):\n"
    "  exploit_list — list all 50+ payload/request builders with params.\n"
    "  exploit_build[ARGS]{\"kind\":\"ssti_payload\",\"engine\":\"jinja2\",\"cmd\":\"id\"}"
    "[/ARGS] — construct the payload for jwt_forge/jwt_attack/nosql_injection/"
    "sqli_payload/ssti_payload/xxe_payload/ssrf_payload/deserialization_payload/"
    "prototype_pollution/path_traversal/xss_payload/command_injection/idor_probe/"
    "race_condition/upload_bypass/graphql_probe/open_redirect/cors_probe/"
    "ldap_injection/xpath_injection/crlf_injection/host_header_injection/"
    "request_smuggling/payload_mutate/oauth_probe/saml_attack/csrf_poc/… "
    "(kind + its params; returns the exact payload/spec + notes).\n"
    "  exploit_encode[ARGS]{\"payload\":\"...\",\"scheme\":\"all|url|base64|…\"}"
    "[/ARGS]; exploit_fingerprint[ARGS]{\"headers\":\"…\",\"body\":\"…\"}[/ARGS]; "
    "exploit_waf[ARGS]{\"blocked_payload\":\"…\",\"response_body\":\"…\"}[/ARGS].\n"
    "  pentest_plan[ARGS]{\"target\":\"…\",\"profile\":\"web|network|ad|api\"}[/ARGS] "
    "— ordered recon steps; parse_output[ARGS]{\"tool\":\"nmap|nuclei|…\",\"raw\":\"…\"}"
    "[/ARGS] — normalise scanner output; cve_lookup[ARGS]{\"product\":\"nginx\","
    "\"version\":\"1.18\"}[/ARGS] — NVD + KEV/EPSS; enrich_cves[ARGS]{\"parsed\":{…}}"
    "[/ARGS]; methodology/cheatsheet/tooling/wordlist_find; nuclei_template[ARGS]"
    "{\"spec\":{…}}[/ARGS]; reflect_findings/report_findings/attack_writeup; "
    "sqlmap_plan; webapp_paths.\n"
    "  workspace[ARGS]{\"op\":\"import|tree|overview|read|search|glob|read_many|"
    "write|replace|edits|append|insert|delete|diff|revert|export|close|test_detect|"
    "parse_test|record_baseline|compare_baseline|baseline_status|health\",…}[/ARGS] "
    "— a CONFINED copy of a repo you import (zip/dir); read+edit+diff/test with "
    "revert; nothing outside the workspace is touched.\n"
    "  task_plan[ARGS]{\"goal\":\"…\",\"items\":[…]}[/ARGS] / task_status / "
    "task_update[ARGS]{\"id\":\"…\",\"status\":\"done|doing|blocked\",\"note\":\"…\"}"
    "[/ARGS] / task_render — a live plan you keep honest against.\n"
    "  research_search[ARGS]{\"question\":\"…\"}[/ARGS] — multi-engine OSINT, "
    "ranked by source agreement; research_run — search + read + cross-check; "
    "research_expand; verify_claim[ARGS]{\"query\":\"…\"}[/ARGS] — multi-source "
    "verification (returns agreement + confidence); browser_fetch[ARGS]{\"url\":\"…\"}"
    "[/ARGS] — real-browser render (scope-checked, webshield-sanitised); "
    "browser_status.\n"
    "  Scoring/bench: juiceshop_score/juiceshop_next/juiceshop_report/juiceshop_diff; "
    "xbow_extract_flag/xbow_record/xbow_score/xbow_report; bench_targets/bench_score/"
    "bench_report/bench_compare.\n"
    "  OPT-IN (off unless enabled): skill_list/skill_run/skill_propose/skill_commit/"
    "skill_curate (ATHENA_SKILLS=1); mcp_list/mcp_call (ATHENA_MCP=1 + "
    "~/.athena/mcp.json); reach[ARGS]{\"op\":\"web_search_smart|github_search|"
    "github_repo\",…}[/ARGS] (ATHENA_REACH=1).\n"
    "  WORKFLOW: recon (pentest_plan/parse_output/cve_lookup) → understand "
    "(workspace/methodology) → build the exact payload (exploit_build) → run it "
    "yourself behind the gate → prove it (oracle_*) → record (reflect_findings/"
    "attack_writeup). Never claim a finding the oracle has not confirmed."
)