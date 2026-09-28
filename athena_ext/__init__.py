# athena_ext — Athena's "smart" in-process subsystems.
#
# Each module here is self-contained (stdlib-only) and imported lazily by
# athena.py so a missing/broken module degrades gracefully instead of
# killing the agent at startup.  The whole directory is the single source of
# the engine surface: `athena_ext/bridge.py` exposes every engine below as an
# in-process *pure tool* ([TOOL]name[/TOOL][ARGS]json[/ARGS]) that builds,
# analyses and verifies — it never fires an attack; the operator still drives
# each command through the y/n gate.
#
# Core (always on)
#   settings   shared control panel  (~/.athena/settings.json; CLI + GUI)
#   providers  multi-provider registry + LIVE /models discovery + chain build
#   bridge     pure-tool wrappers + REGISTRY/SPEC for every engine below
#   memory     persistent cross-session recall (SQLite)
#   oracle     out-of-band canary + verified-exploitation ledger
#   zdayfind   variant-analysis source scanner (Project-Zero style SAST)
#   codescan   SAST / SCA / secrets tool orchestration + result parsers
#   headroom   tool-output / context compression (token savings)
#   foresight  destructive-op risk assessment + undo hints
#   sandbox    bubblewrap isolation primitive + capability report
#   webshield  untrusted-web sanitiser (leash-on content handling)
#   engage     engagement scope / RoE bookkeeping
#   unblock    stuck-state recovery playbooks
#   recall     cross-session recall helpers
#
# Ported engines (in-process pure tools)
#   exploits   payload/request builders (JWT, SSTI, XXE, SSRF, SQLi, …)
#   pentest    recon plans, scanner-output parsing, CVE/KEV/EPSS enrichment
#   workspace  confined repo import → read/search/edit/diff/revert/test
#   verify     multi-source fact verification with confidence
#   research   multi-engine OSINT ranked by source agreement
#   tasks      live task plan you keep honest against
#   browser    real-browser rendering (scope-gated)
#   juiceshop  OWASP Juice Shop scoring harness
#   xbow       XBOW-style challenge scoring
#   bench      objective run scoring
#
# Opt-in (OFF by default; enable via ATHENA_SKILLS/MCP/REACH=1 or
# `<feature>_enabled: true` in ~/.athena/settings.json)
#   skills     agent-written scripts in the bubblewrap sandbox
#   mcp        stdio MCP server integration
#   reach      semantic web/GitHub search surface

__all__ = [
    "settings", "providers", "bridge",
    "memory", "oracle", "zdayfind", "codescan",
    "headroom", "foresight", "sandbox", "webshield", "engage", "unblock",
    "recall",
    "exploits", "pentest", "workspace", "verify", "research", "tasks",
    "browser", "juiceshop", "xbow", "bench",
    "skills", "mcp", "reach",
]

__version__ = "7.8.0"
