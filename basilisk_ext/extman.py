"""
extman — the one seam between Basilisk and the sidecar.

Holds the injected primitives (settings, model-completion callable, optional
embedder), owns the long-lived stores (memory, skills), and exposes the four
hook functions the host calls.  Every public function is null-safe: if the
sidecar was never init()'d, or the relevant setting is off, it returns the
input unchanged / an empty result, so a broken or absent sidecar can never
take Basilisk down.
"""

from __future__ import annotations

import os
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import memory as _memory
from . import skills as _skills
from . import foresight as _foresight
from . import mcp as _mcp


class _State:
    """Module-level singleton.  Cheap to reason about; one operator, one app."""
    def __init__(self) -> None:
        self.ready: bool = False
        self.settings: Dict[str, Any] = {}
        self.data_dir: Path = Path.home() / ".local" / "share" / "basilisk"
        self.ext_dir: Path = self.data_dir / "ext"
        self.complete_fn: Optional[Callable[[str, str], str]] = None
        self.embed_fn: Optional[Callable[[List[str]], List[List[float]]]] = None
        self.mem: Optional[_memory.MemoryStore] = None
        self.skl: Optional[_skills.SkillStore] = None
        self.mcp: Optional[_mcp.MCPManager] = None
        self.ledger: Any = None

    def on(self, key: str, default: bool = False) -> bool:
        return bool(self.settings.get(key, default))


S = _State()


def _as_int(v: Any, default: int) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _as_float(v: Any, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _mem_text(a: Dict[str, Any]) -> str:
    """Build the memory text from whatever field the model used.  Models
    reach for {value}, {content}, {fact} or a {key,value} pair as often as
    {text}; accepting all of them stops valid memories being dropped as
    'empty'."""
    for k in ("text", "value", "content", "fact", "memory", "note", "info"):
        v = a.get(k)
        if v:
            key = a.get("key") or a.get("name")
            # a key + value pair becomes "key: value" for context
            if key and k != "text":
                return f"{key}: {v}".strip()
            return str(v).strip()
    key = a.get("key") or a.get("name")
    return str(key).strip() if key else ""


def _log(msg: str) -> None:
    try:
        S.ext_dir.mkdir(parents=True, exist_ok=True)
        with open(S.ext_dir / "ext.log", "a", encoding="utf-8") as f:
            f.write(msg.rstrip() + "\n")
    except Exception:
        pass


# ── boot ────────────────────────────────────────────────────────────────

def init(settings: Dict[str, Any],
         data_dir: str = "~/.local/share/basilisk",
         complete_fn: Optional[Callable[[str, str], str]] = None,
         embed_fn: Optional[Callable[[List[str]], List[List[float]]]] = None,
         ledger: Any = None
         ) -> None:
    """Call once at host startup, after settings load and the router exists.

    complete_fn(system, user) -> str   : a SHORT synchronous completion using
        whatever backend the host already routes to.  Used for memory
        consolidation and the optional foresight model pass.  May raise / time
        out; callers tolerate it.  If None, the sidecar runs in heuristic-only
        mode (no model calls) and still works.
    embed_fn(texts) -> list[vector]    : optional.  If provided, memory recall
        uses cosine similarity; if None, recall falls back to keyword+recency.
    """
    try:
        S.settings = settings or {}
        S.data_dir = Path(os.path.expanduser(data_dir))
        S.ext_dir = S.data_dir / "ext"
        S.ext_dir.mkdir(parents=True, exist_ok=True)
        S.complete_fn = complete_fn
        S.embed_fn = embed_fn
        S.mem = _memory.MemoryStore(S.ext_dir / "memory.db", embed_fn=embed_fn)
        S.skl = _skills.SkillStore(S.ext_dir / "skills")
        S.ledger = ledger
        # MCP: only spin up if explicitly enabled AND servers are configured.
        # Discovery launches subprocesses, so it's wrapped — a broken server
        # config can never block sidecar init.
        S.mcp = None
        if S.on("mcp_enabled"):
            servers = S.settings.get("mcp_servers") or []
            if servers:
                try:
                    S.mcp = _mcp.MCPManager(servers, ledger=ledger)
                    disc = S.mcp.discover()
                    _log("[mcp] discovered: " +
                         ", ".join(f"{k}={len(v)}" for k, v in disc.items()))
                except Exception:
                    _log("[mcp] discovery FAILED\n" + traceback.format_exc())
                    S.mcp = None
        S.ready = True
        _log(f"[init] ready dir={S.ext_dir} model={'yes' if complete_fn else 'no'} "
             f"embed={'yes' if embed_fn else 'no'}")
    except Exception:
        S.ready = False
        _log("[init] FAILED\n" + traceback.format_exc())


def set_mcp_enabled(on: bool) -> Dict[str, Any]:
    """Start or stop MCP at runtime, from the Settings toggle.  Brings the
    manager up (discover servers) or down (stop subprocesses) to match.  The
    caller persists the 'mcp_enabled' flag; this just makes reality match it.
    Returns a status dict for the UI."""
    if not S.ready:
        return {"ok": False, "error": "extensions not initialised"}
    try:
        if on:
            servers = S.settings.get("mcp_servers") or []
            if not servers:
                return {"ok": False,
                        "error": "no MCP servers configured — add one first"}
            if S.mcp:
                try:
                    S.mcp.shutdown()
                except Exception:
                    pass
            S.mcp = _mcp.MCPManager(servers, ledger=S.ledger)
            disc = S.mcp.discover()
            n = S.mcp.tool_count()
            _log(f"[mcp] started: {n} tools from " +
                 ", ".join(f"{k}={len(v)}" for k, v in disc.items()))
            return {"ok": True, "enabled": True, "tools": n,
                    "servers": list(disc.keys())}
        if S.mcp:
            try:
                S.mcp.shutdown()
            except Exception:
                pass
        S.mcp = None
        _log("[mcp] stopped")
        return {"ok": True, "enabled": False, "tools": 0}
    except Exception as e:
        _log("[mcp] set_mcp_enabled FAILED\n" + traceback.format_exc())
        S.mcp = None
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def mcp_status() -> Dict[str, Any]:
    """Current MCP state for the Settings UI."""
    running = bool(S.mcp)
    servers = S.settings.get("mcp_servers") or []
    return {"running": running,
            "configured_servers": len(servers),
            "tools": (S.mcp.tool_count() if running else 0)}


def system_prompt_block() -> str:
    """Static text to append to the system prompt when the sidecar is live.

    Documents the new tools so the model knows they exist.  Empty if the
    sidecar is off — so a stock Basilisk prompt is unchanged.  Host appends this
    via the persona custom-addendum seam (no edit to basilisk_persona.py needed).
    """
    if not S.ready:
        return ""
    parts: List[str] = []
    if S.on("memory_enabled"):
        parts.append(_memory.PROMPT_BLOCK)
    if S.on("skills_enabled"):
        parts.append(S.skl.prompt_block())
    if S.on("foresight_enabled"):
        parts.append(_foresight.PROMPT_BLOCK)
    if S.on("mcp_enabled") and S.mcp:
        specs = S.mcp.tool_specs()
        if specs:
            lines = ["── EXTERNAL TOOLS (MCP) ──",
                     "Extra tools from connected MCP servers are available, "
                     "namespaced mcp__<server>__<tool>. Call them like any "
                     "tool. Their arguments are safety-screened and every call "
                     "is logged. Use `mcp_tools` to list them. Available now:"]
            for s in specs[:40]:
                d = (s.get("description") or "").strip().splitlines()
                lines.append(f"  <tool name=\"{s['name']}\">{{...}}</tool>  // "
                             f"{d[0] if d else ''}")
            parts.append("\n".join(lines))
    return ("\n\n".join(p for p in parts if p)).strip()


# ── hook 1: recall injection (before stream_chat) ─────────────────────────

def inject_memory(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Given the assembled message list, return it with a compact recall
    block spliced in right after the system message.  Relevance-scoped:
    pulls the top-k memories matching the latest user turn, never the whole
    store, so the token window does not grow with history."""
    if not (S.ready and S.on("memory_enabled") and S.mem):
        return messages
    try:
        query = _latest_user_text(messages)
        if not query:
            return messages
        k = int(S.settings.get("memory_recall_k", 6))
        hits = S.mem.recall(query, k=k)
        block = S.mem.format_block(hits)
        if not block:
            return messages
        recall_msg = {"role": "system", "content": block}
        if messages and messages[0].get("role") == "system":
            return [messages[0], recall_msg, *messages[1:]]
        return [recall_msg, *messages]
    except Exception:
        _log("[inject_memory] " + traceback.format_exc())
        return messages


# ── hook 2: turn recorder (after a turn settles) ──────────────────────────

def record_turn(user_text: str, assistant_text: str) -> None:
    """Fire-and-forget after each completed turn.  Heuristic capture is
    instant and synchronous; model-based consolidation (if enabled and a
    completer exists) is debounced and done on a background thread so it
    never sits on the UI path."""
    if not (S.ready and S.on("memory_enabled") and S.mem):
        return
    try:
        S.mem.observe_turn(user_text or "", assistant_text or "",
                           complete_fn=S.complete_fn,
                           consolidate=S.on("memory_consolidate"))
    except Exception:
        _log("[record_turn] " + traceback.format_exc())


def backfill_memory(limit: int = 64) -> int:
    """Embed a bounded batch of memories that have no vector yet, so semantic
    recall can see everything stored before embeddings were enabled.  Returns
    the count embedded (0 when nothing's left or the store/embedder is absent).
    The host loops this on a background thread until it returns 0."""
    if not (S.ready and S.mem):
        return 0
    try:
        return S.mem.backfill_embeddings(limit)
    except Exception:
        _log("[backfill_memory] " + traceback.format_exc())
        return 0


# ── hook 3: extra tools (merged into the dispatch dict) ───────────────────

def extra_tools(host: Any) -> Dict[str, Callable[[Dict[str, Any]], str]]:
    """Return {tool_name: fn(args) -> result_str} to merge into the host
    dispatch table.

    Each fn just RETURNS its result string.  The host runs it on a background
    thread and marshals the string back onto its UI loop (exactly how its own
    tools work).  This matters for skill_run, which launches a sandbox
    subprocess that can take many seconds: returning a value lets the host keep
    it off the GTK main thread instead of freezing the app until it finishes.
    """
    if not S.ready:
        return {}

    out: Dict[str, Callable[[Dict[str, Any]], str]] = {}

    if S.on("memory_enabled") and S.mem:
        out["memory_recall"] = lambda a: S.mem.tool_recall(
            a.get("query", a.get("text", a.get("q", a.get("value", "")))),
            _as_int(a.get("k", 8), 8))
        out["memory_remember"] = lambda a: S.mem.tool_remember(
            _mem_text(a), a.get("kind", "fact"),
            _as_float(a.get("salience", 0.5), 0.5))
        out["memory_forget"] = lambda a: S.mem.tool_forget(
            a.get("query", a.get("id", a.get("text", a.get("value", "")))))

    if S.on("skills_enabled") and S.skl:
        # skill_write is registered by the HOST (basilisk.py), not here, so its
        # save can go through Basilisk's own confirm dialog before the sidecar
        # validates + sandbox-tests + persists via commit_skill().
        out["skill_list"] = lambda a: S.skl.tool_list()
        out["skill_run"] = lambda a: S.skl.tool_run(
            a.get("name", ""), a.get("args", {}),
            timeout=_as_int(a.get("timeout", 20), 20))

    if S.on("mcp_enabled") and S.mcp:
        # Each discovered MCP tool becomes a namespaced dispatch entry
        # (mcp__<server>__<tool>).  The manager safety-screens arguments and
        # logs to the evidence ledger before the call leaves the process.
        def _mk(tool_name):
            return lambda a: S.mcp.call(tool_name, a if isinstance(a, dict) else {})
        for spec in S.mcp.tool_specs():
            out[spec["name"]] = _mk(spec["name"])
        # A lister so the operator/model can see what's wired up.
        out["mcp_tools"] = lambda a: _mcp_tools_listing()

    return out


def _mcp_tools_listing() -> str:
    """Human/model-readable summary of the wired MCP servers and their tools."""
    if not (S.ready and S.mcp):
        return "MCP is not enabled or no servers are configured."
    specs = S.mcp.tool_specs()
    if not specs:
        return "MCP is enabled but no tools were discovered from the servers."
    lines = [f"{len(specs)} MCP tool(s) available:"]
    for s in specs:
        desc = (s.get("description") or "").strip().splitlines()
        lines.append(f"  {s['name']} — {desc[0] if desc else ''}")
    return "\n".join(lines)


def commit_skill(name: str, code: str, test: str, description: str,
                 capabilities: List[str]) -> Dict[str, Any]:
    """Called by the host when the operator clicks Apply on a skill card.
    The click is the approval.  Validate -> sandbox-test -> persist."""
    if not (S.ready and S.skl):
        return {"ok": False, "error": "sidecar not ready"}
    return S.skl.commit(name, code, test, description, capabilities)


# ── hook 4: foresight (before an action executes) ─────────────────────────

def foresight(command: str, kind: str = "shell") -> Dict[str, Any]:
    """Predict the consequences of an action before it runs and return a
    verdict the host can act on:

        {"verdict": "allow" | "caution" | "block",
         "reversibility": "reversible" | "hard" | "irreversible",
         "blast_radius": "process" | "user" | "system" | "network",
         "reasons": [str, ...],
         "undo": str | None}

    Deterministic rules run always (free, instant).  A model pass runs only
    if foresight_model is on AND a completer exists, and only refines a
    non-block verdict — it can escalate to caution/block but the hard rules
    cannot be talked down by it.  If the sidecar is off, returns an allow so
    the host gate behaves exactly as today.
    """
    if not S.ready or not S.on("foresight_enabled"):
        return {"verdict": "allow", "reasons": []}
    try:
        return _foresight.assess(
            command, kind,
            complete_fn=(S.complete_fn if S.on("foresight_model") else None))
    except Exception:
        _log("[foresight] " + traceback.format_exc())
        return {"verdict": "allow", "reasons": ["foresight error; fell open"]}


# ── helpers ───────────────────────────────────────────────────────────────

def _latest_user_text(messages: List[Dict[str, str]]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            c = m.get("content", "")
            # ignore tool-result envelopes; recall on real user intent
            if "<tool_result>" in c:
                continue
            return c
    return ""
