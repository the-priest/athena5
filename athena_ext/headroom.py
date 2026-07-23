"""
headroom — context compression for Basilisk.

What this does, in one line: before a turn's messages go to the model, the
big `<tool_result>` dumps (nmap, recon, journal tails, web reads, JSON
blobs) get crushed — keeping every line that matters (errors, open ports,
CVEs, the head and tail) and collapsing the noise.  Same answers, a
fraction of the tokens, so a long session doesn't drain the API balance and
more of the real signal fits in context.

Two engines, picked automatically:

  1. The real `headroom-ai` package (https://pypi.org/project/headroom-ai/)
     if it's installed — a Rust+ML pipeline that compresses 60-95%.  Used
     as the per-block compressor when present.
  2. A built-in, stdlib-only fallback that does the high-value structural
     compression (collapse repeated/near-identical lines, strip ANSI,
     middle-truncate while preserving "signal" lines, sample huge JSON
     arrays).  This is what runs on the phone, on a fresh box, anywhere the
     wheel won't install.  No dependency, never fails to import.

Design contract (see basilisk_ext/__init__.py): this module imports NOTHING
from basilisk.py / basilisk_core.py / basilisk_persona.py.  It takes the message list
and the settings dict and hands back a compressed message list.  Delete the
package and Basilisk behaves exactly as before.

Protocol safety — this is load-bearing:
  * The system prompt (role="system") is NEVER touched.  It carries the
    tool contract; compressing it would break tool-calling.
  * The operator's actual typed messages are NEVER touched.  Only messages
    that are tool-result envelopes — `<tool_result>...</tool_result>`,
    emitted as role="user" by the host — are candidates.
  * The most-recent N tool results are left full (freshest, most likely to
    be acted on this turn).  Only older, already-read dumps get crushed.
  * If anything throws, the originals pass through unchanged.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── tunables (all overridable from settings) ──────────────────────────
_DEFAULT_MIN_CHARS = 1200      # don't bother compressing a block under this
_DEFAULT_KEEP_RECENT = 2       # leave the last N tool_result blocks full
_DEFAULT_TARGET_RATIO = 0.35   # aim to keep ~this fraction (fallback engine)
_HEAD_LINES = 12               # lines kept from the top when truncating
_TAIL_LINES = 8                # lines kept from the bottom when truncating
_JSON_SAMPLE = 8               # array elements kept head+tail when sampling

_TOOL_RE = re.compile(r"<tool_result>\n?(.*?)\n?</tool_result>",
                      re.DOTALL)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_WS_RUN_RE = re.compile(r"[ \t]{3,}")

# Lines matching this ALWAYS survive truncation — the findings, not the
# noise.  Tuned for an offensive-security operator's tool output.
_SIGNAL_RE = re.compile(
    r"\b("
    r"error|errno|warn|warning|fail|failed|failure|fatal|critical|crit|"
    r"denied|refused|unauthor|forbidden|exception|traceback|panic|"
    r"open|filtered|vuln|vulnerable|cve-\d|cwe-\d|exploit|payload|"
    r"root|admin|password|passwd|secret|token|api[_-]?key|private key|"
    r"port\s+\d+|\d+/tcp|\d+/udp|"                    # ports (a finding)
    r"http[s]?://|status[:= ]+\d{3}|\[\d{3}\]"        # urls / http status
    # NB: a bare IPv4 is deliberately NOT signal — host-enumeration lines
    # ("scan report for 10.0.0.5") are the noise we want to drop.  An IP
    # only matters here when it sits next to a port/keyword, which the
    # branches above already catch.
    r")\b",
    re.IGNORECASE)


# ═════════════════════════════════════════════════════════════════════
# real-package probe (cached) — used as the per-block compressor when present
# ═════════════════════════════════════════════════════════════════════

_PKG_STATE: Dict[str, Any] = {"checked": False, "fn": None, "name": "fallback"}


def _real_compress(text: str, target_ratio: float) -> Optional[str]:
    """Compress one text block with the real headroom-ai package, if it's
    importable.  Returns the compressed text, or None to signal 'use the
    fallback' (package absent, or it declined / inflated)."""
    if not _PKG_STATE["checked"]:
        _PKG_STATE["checked"] = True
        try:
            from headroom import compress as _hc  # type: ignore
            _PKG_STATE["fn"] = _hc
            _PKG_STATE["name"] = "headroom-ai"
        except Exception:
            _PKG_STATE["fn"] = None
            _PKG_STATE["name"] = "fallback"
    fn = _PKG_STATE["fn"]
    if fn is None:
        return None
    try:
        # Feed the block as a single tool-style user message and let the
        # package's pipeline compress it.  protect_recent=0 so it actually
        # crushes this lone block; compress_user_messages=True because we've
        # deliberately wrapped a tool dump as a user message here.
        msgs = [{"role": "user", "content": text}]
        res = fn(msgs, compress_user_messages=True, protect_recent=0,
                 target_ratio=target_ratio)
        out = ""
        for m in getattr(res, "messages", []) or []:
            c = m.get("content", "")
            if isinstance(c, str):
                out = c
            elif isinstance(c, list):
                out = "\n".join(
                    p.get("text", "") for p in c
                    if isinstance(p, dict) and p.get("type") == "text")
        out = out.strip()
        # Only accept a real win; otherwise fall back to our structural pass.
        if out and len(out) < len(text) * 0.95:
            return out
        return None
    except Exception:
        return None


def engine_name() -> str:
    """Which compressor is active — 'headroom-ai' or 'fallback'.  Triggers
    the one-time import probe."""
    _real_compress("", 0.5)
    return _PKG_STATE["name"]


# ═════════════════════════════════════════════════════════════════════
# built-in stdlib compressor — the always-available fallback
# ═════════════════════════════════════════════════════════════════════

def _normalize_key(line: str) -> str:
    """A loose key for 'these lines are basically the same': drop ANSI, then
    mask numbers/hex so `Nmap scan report for 10.0.0.5` and `... 10.0.0.6`
    collapse into one repeated shape."""
    s = _ANSI_RE.sub("", line)
    s = re.sub(r"0x[0-9a-fA-F]+", "0xN", s)
    s = re.sub(r"\d+", "N", s)
    return s.strip()


def _collapse_runs(lines: List[str]) -> List[str]:
    """Collapse consecutive identical-or-near-identical lines into one line
    plus a count.  This alone kills most of the bulk in scan / log output."""
    out: List[str] = []
    i = 0
    n = len(lines)
    while i < n:
        key = _normalize_key(lines[i])
        j = i + 1
        while j < n and _normalize_key(lines[j]) == key and key:
            j += 1
        run = j - i
        if run >= 4:
            out.append(lines[i])
            out.append(f"        … ({run - 1} more similar lines collapsed)")
        else:
            out.extend(lines[i:j])
        i = j
    return out


def _sample_json(text: str) -> Optional[str]:
    """If the block is JSON with large arrays, keep head+tail of each big
    array and note how many were dropped.  Returns None if it isn't JSON or
    sampling wouldn't help."""
    t = text.strip()
    if not (t.startswith("{") or t.startswith("[")):
        return None
    try:
        data = json.loads(t)
    except Exception:
        return None

    dropped = {"n": 0}

    def walk(obj: Any) -> Any:
        if isinstance(obj, list):
            if len(obj) > _JSON_SAMPLE * 2 + 2:
                head = [walk(x) for x in obj[:_JSON_SAMPLE]]
                tail = [walk(x) for x in obj[-_JSON_SAMPLE:]]
                cut = len(obj) - _JSON_SAMPLE * 2
                dropped["n"] += cut
                return head + [f"... <{cut} more items omitted>"] + tail
            return [walk(x) for x in obj]
        if isinstance(obj, dict):
            return {k: walk(v) for k, v in obj.items()}
        return obj

    sampled = walk(data)
    if dropped["n"] == 0:
        return None
    try:
        return json.dumps(sampled, indent=2, default=str)
    except Exception:
        return None


def _crush(text: str, target_ratio: float) -> str:
    """The structural fallback compressor.  Lossy on noise, lossless on
    signal lines."""
    if not text:
        return text

    # JSON path — sampling huge arrays beats line tricks for structured data.
    js = _sample_json(text)
    if js is not None and len(js) < len(text):
        return js

    text = _ANSI_RE.sub("", text)
    text = _WS_RUN_RE.sub("  ", text)
    lines = text.split("\n")
    lines = _collapse_runs(lines)

    budget = max(_HEAD_LINES + _TAIL_LINES + 4,
                 int(len(lines) * max(0.05, min(target_ratio, 1.0))))
    if len(lines) <= budget:
        return "\n".join(lines)

    head = lines[:_HEAD_LINES]
    tail = lines[-_TAIL_LINES:]
    middle = lines[_HEAD_LINES:-_TAIL_LINES]

    # Always keep the signal lines from the middle, up to the remaining
    # budget; they're the findings.
    room = max(0, budget - _HEAD_LINES - _TAIL_LINES)
    kept_signal = [ln for ln in middle if _SIGNAL_RE.search(ln)]
    omitted = len(middle) - min(len(kept_signal), room)
    kept_signal = kept_signal[:room]

    parts = list(head)
    if kept_signal:
        parts.append(f"        ┄┄ {omitted} noise lines omitted; "
                     f"{len(kept_signal)} signal lines kept ┄┄")
        parts.extend(kept_signal)
    else:
        parts.append(f"        ┄┄ {len(middle)} lines omitted ┄┄")
    parts.extend(tail)
    return "\n".join(parts)


def _compress_block(text: str, target_ratio: float) -> str:
    """Compress one tool-result body: try the real package, else the
    built-in crusher.  Whichever yields the smaller result wins."""
    best = text
    real = _real_compress(text, target_ratio)
    if real is not None and len(real) < len(best):
        best = real
    fb = _crush(text, target_ratio)
    if len(fb) < len(best):
        best = fb
    return best


# ═════════════════════════════════════════════════════════════════════
# public entry point — called from BackendRouter.stream_chat
# ═════════════════════════════════════════════════════════════════════

def compress_messages(
    messages: List[Dict[str, Any]],
    settings: Optional[Dict[str, Any]] = None,
    log: Optional[Callable[[str], None]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return (compressed_messages, stats).  Never raises — on any error it
    returns the originals with an empty stats dict.

    Only `<tool_result>` envelopes carried as role="user" are touched, and
    the most-recent `headroom_keep_recent` of them are left full.  System
    prompt and real user messages pass through verbatim."""
    stats: Dict[str, Any] = {
        "enabled": False, "engine": _PKG_STATE.get("name", "fallback"),
        "blocks": 0, "before": 0, "after": 0, "saved": 0, "pct": 0.0,
    }
    s = settings or {}
    if not s.get("headroom_enabled", True):
        return messages, stats
    if not isinstance(messages, list) or not messages:
        return messages, stats

    try:
        min_chars = int(s.get("headroom_min_chars", _DEFAULT_MIN_CHARS))
    except (TypeError, ValueError):
        min_chars = _DEFAULT_MIN_CHARS
    try:
        keep_recent = int(s.get("headroom_keep_recent", _DEFAULT_KEEP_RECENT))
    except (TypeError, ValueError):
        keep_recent = _DEFAULT_KEEP_RECENT
    try:
        target = float(s.get("headroom_target_ratio", _DEFAULT_TARGET_RATIO))
    except (TypeError, ValueError):
        target = _DEFAULT_TARGET_RATIO

    # Index of every tool-result message, so we can spare the most recent.
    tr_positions = [
        i for i, m in enumerate(messages)
        if m.get("role") == "user"
        and isinstance(m.get("content"), str)
        and "<tool_result>" in m["content"]
    ]
    spare = set(tr_positions[-keep_recent:]) if keep_recent > 0 else set()

    engine = engine_name()
    stats["engine"] = engine

    out: List[Dict[str, Any]] = []
    before_total = 0
    after_total = 0
    blocks = 0

    for i, m in enumerate(messages):
        content = m.get("content")
        if i in spare or i not in tr_positions or not isinstance(content, str):
            out.append(m)
            continue

        def _sub(mo: "re.Match[str]") -> str:
            nonlocal before_total, after_total, blocks
            body = mo.group(1)
            if len(body) < min_chars:
                return mo.group(0)
            comp = _compress_block(body, target)
            if len(comp) >= len(body):
                return mo.group(0)
            before_total += len(body)
            after_total += len(comp)
            blocks += 1
            note = (f"\n[headroom: {len(body)}→{len(comp)} chars via {engine}]")
            return f"<tool_result>\n{comp}{note}\n</tool_result>"

        new_content = _TOOL_RE.sub(_sub, content)
        nm = dict(m)
        nm["content"] = new_content
        out.append(nm)

    if blocks:
        saved = before_total - after_total
        pct = (saved / before_total * 100.0) if before_total else 0.0
        stats.update({
            "enabled": True, "blocks": blocks,
            "before": before_total, "after": after_total,
            "saved": saved, "pct": round(pct, 1),
        })
        if log:
            try:
                log(f"headroom: {blocks} block(s) "
                    f"{before_total}→{after_total} chars "
                    f"(-{pct:.0f}%) via {engine}")
            except Exception:
                pass
    return out, stats
