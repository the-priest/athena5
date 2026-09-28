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
import sys
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
# The host writes `[tool: web_read]` as the first line inside the envelope.
_SOURCE_RE = re.compile(r"^\s*\[tool:\s*([A-Za-z_][\w.-]*)\s*\]\s*$", re.M)

# Readers whose entire value is verbatim content — never compress these.
_DEFAULT_SKIP_TOOLS = ("web_read", "web_search", "read_file",
                       "workspace_read", "cve_lookup")


def _source_tool(body: str) -> str:
    """The tool named by the `[tool: …]` line, or '' when untagged.

    Only the first 400 chars are searched: the marker is written as the first
    line, and scanning a whole 200KB dump for it on every frame is a cost with
    no upside.
    """
    m = _SOURCE_RE.search(body[:400])
    return (m.group(1) or "").strip().lower() if m else ""
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

# An opaque placeholder standing in for text that lives somewhere else —
# headroom-ai's cache-compress reference `<<ccr:5eb8f2bbc609,string,6.6KB>>`
# and anything shaped like it.  Text containing one of these is a receipt, not
# content: the model cannot dereference it, so accepting it is data loss.
_REFERENCE_RE = re.compile(r"<<\s*[A-Za-z][\w.-]{1,20}\s*:[^>]{4,200}>>")

# ── PROSE vs MACHINE OUTPUT ──────────────────────────────────────────
# Everything above assumes the block is machine output: noise is repetitive,
# signal is rare and keyword-shaped, and the middle is expendable.  For a page
# of PROSE that assumption inverts — every line is signal, no line repeats, and
# _SIGNAL_RE matches almost nothing.  Applied to a fetched web page it kept the
# lines containing "http://" and "fail", dropped 114 lines of the actual answer
# as "noise", and produced something that READS complete while missing the
# point of the document.  That last part is what made it expensive: the model
# could not tell it had been given a gutted page, so it re-fetched the same URL
# over and over hunting for content that was deleted before delivery.
#
# So the compressor needs a notion it did not have: "this is not the kind of
# text I know how to shred safely."
_STRUCTURED_HINT_RE = re.compile(
    r"\d+/(?:tcp|udp)"                     # port lines
    r"|^\s*[\w.\-\[\]]+\s*[:=]\s"          # key: value / key=value
    r"|^\s*[\[{\]}]"                       # JSON / bracketed structure
    r"|^\s*[|+\-]{2,}"                     # table rules
    r"|\S\s{3,}\S"                         # column alignment
    r"|^\s*(?:[/~]|[A-Za-z]:\\)\S*\s*$"    # a bare path
    r"|^\s*\$\s"                           # shell prompt echo
    , re.MULTILINE)

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z'’-]+")
_PROSE_SAMPLE_LINES = 300   # enough evidence; see _looks_like_prose


def _looks_like_prose(lines: List[str]) -> bool:
    """True when the block reads as natural language rather than tool output.

    Judged on SHAPE, not on which tool produced it, so it protects every
    prose-bearing result — a fetched page, a CVE description, a README pulled
    in by read_file, a markdown doc out of the workspace — including the ones
    nobody remembered to tag.

    Conservative by construction: it must be clearly prose to qualify, because
    a false positive here only costs tokens, while a false negative costs the
    operator the answer he was looking for.
    """
    body = [ln.strip() for ln in lines if ln.strip()]
    if len(body) < 4:
        return False
    # SAMPLE, don't scan.  This runs on every candidate block, and the blocks
    # that matter most for cost are the huge ones — a 200k-line journal tail
    # does not need 200k regex searches to be recognised as not-prose.
    #
    # THREE CONTIGUOUS WINDOWS, not a stride.  A stride was the obvious way and
    # it is wrong here: documents are periodic (heading, paragraph, blank,
    # heading…), so `body[::stride]` can land on the same phase every time and
    # sample only headings — which read as not-prose and lost the protection
    # for exactly the long documents that need it most.  Contiguous windows
    # preserve local structure, and taking one from the start, middle and end
    # still refuses to judge a log by its prose preamble.
    if len(body) > _PROSE_SAMPLE_LINES:
        w = _PROSE_SAMPLE_LINES // 3
        mid = len(body) // 2
        body = (body[:w]
                + body[mid - w // 2: mid + (w - w // 2)]
                + body[-w:])
    sentences = 0
    structured = 0
    for ln in body:
        if _STRUCTURED_HINT_RE.search(ln):
            structured += 1
            continue
        words = _WORD_RE.findall(ln)
        # A prose line: several real words, mostly lowercase (not a banner or
        # a column header), and long enough to be a sentence fragment.
        if len(words) >= 6 and sum(1 for w in words if w[0].islower()) >= 3:
            sentences += 1
    n = len(body)
    return (structured / n) < 0.25 and (sentences / n) >= 0.55


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
            import headroom as _pkg  # type: ignore
            # ── NAME COLLISION GUARD ──
            # This module is ALSO called headroom (basilisk_ext/headroom.py), and
            # the third-party package it wants is `headroom` too.  Whenever
            # basilisk_ext/ ends up on sys.path — tests/test_basilisk.py,
            # test_core.py and test_webshield.py all put it there — this import
            # resolves to THIS FILE and the module silently probes itself.
            #
            # It has never mis-fired at runtime (basilisk_ext is imported as a
            # package, so the absolute import reaches the real one), but it did
            # something worse: it means the tests can NEVER exercise the
            # headroom-ai engine, because in a test process the name always
            # resolves to us.  That is precisely why the cache-reference bug
            # shipped — the only engine the suite could see was the fallback.
            #
            # Identity check, not a name check.
            if getattr(_pkg, "__name__", "") == __name__ or _pkg is sys.modules.get(__name__):
                raise ImportError("resolved to basilisk_ext's own headroom module")
            _hc = getattr(_pkg, "compress", None)
            if not callable(_hc):
                raise ImportError("headroom package has no callable compress()")
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
        parts: List[str] = []
        for m in getattr(res, "messages", []) or []:
            c = m.get("content", "")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                for p in c:
                    if not isinstance(p, dict):
                        continue
                    if p.get("type") == "text":
                        parts.append(p.get("text", ""))
                    else:
                        # A non-text content part is data we cannot render back
                        # into the prompt — a cache handle, an image ref, an
                        # unknown future type.  Silently dropping it (what this
                        # loop used to do) turns "compressed" into "deleted"
                        # with no marker anywhere.  Refuse the whole result and
                        # let the structural compressor have it.
                        return None
        # ACCUMULATE, don't overwrite.  This was `out = c` per message, so a
        # package returning more than one message kept only the last.
        out = "\n".join(p for p in parts if p).strip()
        if not out:
            return None
        # ── VALIDATE, DON'T JUST MEASURE LENGTH ──
        # The old acceptance test was `len(out) < len(text) * 0.95` and nothing
        # else.  "Is it shorter?" is the one question a cache REFERENCE always
        # answers best: headroom-ai handed back
        #     {"ok":true,"status":200,"text":"<<ccr:5eb8f2bbc609,string,6.6KB>>"}
        # for an 8KB page — 67 chars, a 99.2% "win", and completely unreadable.
        # It sailed through the check, and the model was left holding a hash
        # where the page used to be with no way to tell that had happened.
        #
        # A compressor that returns a POINTER has not compressed anything; it
        # has moved the data somewhere this process cannot reach.  Length is
        # the wrong question — READABILITY is the question.
        if _REFERENCE_RE.search(out):
            return None
        # Defence in depth for a reference shape nobody has seen yet: no real
        # summary of a substantial block is 2% of it.  Set far below any
        # plausible summary ratio so it catches pointers and nothing else.
        if len(text) > 800 and len(out) < max(120, len(text) * 0.02):
            return None
        # Only accept a real win; otherwise fall back to our structural pass.
        if len(out) < len(text) * 0.95:
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


_PROSE_MIN_KEEP = 0.60      # a document keeps at least this fraction
# Below this, a document is passed through WHOLE.  ~12KB is roughly 3k tokens —
# an ordinary article, reference page or README — and cutting one of those is a
# few hundred tokens saved against a real chance of deleting the sentence the
# operator asked about.  The saving that actually matters comes from scan and
# log dumps, which are hundreds of KB and are not prose.
_PROSE_FLOOR_CHARS = 12000


def _crush_prose(lines: List[str], target_ratio: float) -> str:
    """Compress a document without shredding it.

    Two rules, both learned from the web_read failure:

      1. CONTIGUOUS.  Keep a run from the top and a run from the bottom and
         drop the middle in one piece.  Never cherry-pick lines by keyword —
         scattered surviving sentences reassemble into something that reads
         like a whole document and is not one, which is worse than an obvious
         hole because nothing downstream can detect it.

      2. LOUD.  The gap marker says, in words, that content was REMOVED and
         that the block is incomplete.  The model's correct response to a
         truncated document is to fetch the rest or say it could not read it;
         it can only do that if it knows.

    Retention floor is high on purpose.  Prose is what the operator asked a
    question about; shaving tokens off the answer is a false economy when the
    alternative is the model re-fetching the same page three times.
    """
    body = "\n".join(lines)
    if len(body) <= _PROSE_FLOOR_CHARS:
        return body
    keep = max(_PROSE_MIN_KEEP, min(max(target_ratio, 0.0), 1.0))
    if keep >= 1.0:
        return body
    n = len(lines)
    room = int(n * keep)
    if room >= n:
        return body
    head_n = max(1, int(room * 0.75))       # front-weighted: documents lead
    tail_n = max(1, room - head_n)          # with the substance
    if head_n + tail_n >= n:
        return body
    dropped = n - head_n - tail_n
    dropped_chars = len("\n".join(lines[head_n:n - tail_n]))
    marker = (f"        ┄┄ [INCOMPLETE] {dropped} lines "
              f"({dropped_chars} chars) of this document were REMOVED to save "
              f"context. This is not the whole page — if the part you need is "
              f"missing, say so or fetch it again rather than assuming it is "
              f"absent from the source. ┄┄")
    return "\n".join(lines[:head_n] + [marker] + lines[n - tail_n:])


def _crush(text: str, target_ratio: float,
           prose: Optional[bool] = None) -> str:
    """The structural fallback compressor.  Lossy on noise, lossless on
    signal lines.

    `prose` lets the caller pass a verdict it has already computed — the shape
    test is the most expensive thing in this module, and _compress_block needs
    the same answer to set its floor.  Left as None it works it out itself, so
    calling _crush directly still behaves.
    """
    if not text:
        return text

    # JSON path — sampling huge arrays beats line tricks for structured data.
    js = _sample_json(text)
    if js is not None and len(js) < len(text):
        return js

    text = _ANSI_RE.sub("", text)
    text = _WS_RUN_RE.sub("  ", text)
    lines = text.split("\n")

    # ── PROSE PATH ──
    # Checked BEFORE _collapse_runs, which masks numbers to spot near-identical
    # lines: on scan output that is exactly right, on a document it can merge
    # two genuinely different sentences that differ only by a figure — and a
    # figure is usually the answer ("within six months", "104 weeks").
    if prose if prose is not None else _looks_like_prose(lines):
        return _crush_prose(lines, target_ratio)

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


def _json_carries_prose(text: str) -> bool:
    """True for a JSON envelope with a big natural-language string inside it.

    This is the shape web_read actually returns — `{"ok":true,"status":200,
    "text":"<the whole page>"}` — and it defeats a line-based prose test
    completely, because JSON escapes the newlines: a 7KB article arrives as
    ONE line and reads to any line-shape heuristic as structured data.
    """
    t = text.strip()
    if not (t.startswith("{") or t.startswith("[")):
        return False
    try:
        data = json.loads(t)
    except Exception:
        return False

    def walk(o: Any, depth: int = 0) -> bool:
        if depth > 6:
            return False
        if isinstance(o, str):
            if len(o) < 800:
                return False
            return _looks_like_prose(o.split("\n"))
        if isinstance(o, dict):
            return any(walk(v, depth + 1) for v in o.values())
        if isinstance(o, list):
            return any(walk(v, depth + 1) for v in o[:50])
        return False

    return walk(data)


def _compress_block(text: str, target_ratio: float) -> str:
    """Compress one tool-result body: try the real package, else the
    built-in crusher.  Whichever yields the smaller result wins —
    subject to a floor when the block is a document.

    ── WHY THE FLOOR IS HERE AND NOT IN ONE ENGINE ──
    "Don't shred prose" is a fact about the CONTENT, not about which
    compressor happens to be installed.  Putting the rule in _crush alone
    protected the fallback path and left the headroom-ai path — the one that
    was actually running on the operator's box — free to summarise a legal
    reference page down to 4.5% of itself.  A summary that loses "within six
    months" and "104 weeks" has kept the topic and thrown away the answer,
    and nothing downstream can tell that happened.
    """
    # Computed ONCE and handed to _crush.  It used to be evaluated here and
    # again inside _crush, which doubled the cost of the most expensive check
    # in the module on every block.
    line_prose = _looks_like_prose(text.split("\n"))
    protected = line_prose or _json_carries_prose(text)
    floor = int(len(text) * _PROSE_MIN_KEEP) if protected else 0

    best = text
    real = _real_compress(text, target_ratio)
    if real is not None and len(real) < len(best) and len(real) >= floor:
        best = real
    fb = _crush(text, target_ratio, prose=line_prose)
    if len(fb) < len(best) and len(fb) >= floor:
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

    # Tools whose output must never be compressed, by name.  Default covers the
    # readers whose whole value is verbatim content: compressing a page you
    # fetched in order to READ it is self-defeating, and the operator pays for
    # the fetch either way.
    raw_skip = s.get("headroom_skip_tools", _DEFAULT_SKIP_TOOLS)
    if isinstance(raw_skip, str):
        raw_skip = [p for p in re.split(r"[,\s]+", raw_skip) if p]
    try:
        skip_tools = {str(t).strip().lower() for t in (raw_skip or []) if t}
    except TypeError:
        skip_tools = set(_DEFAULT_SKIP_TOOLS)

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
            # The host tags each envelope with the tool that produced it (see
            # _feed_tool_result).  An explicit source beats inferring one from
            # content, and it makes the exclusion list something the operator
            # can change in settings instead of something only a code edit can.
            src = _source_tool(body)
            if src and src in skip_tools:
                return mo.group(0)
            comp = _compress_block(body, target)
            if len(comp) >= len(body):
                return mo.group(0)
            before_total += len(body)
            after_total += len(comp)
            blocks += 1
            note = (f"\n[headroom: {len(body)}→{len(comp)} chars via {engine}]")
            return f"<tool_result>\n{comp}{note}\n</tool_result>"

        # `(.*?)` scans to end-of-string from every opener before failing, so
        # an unclosed <tool_result> makes this quadratic — 718ms on a
        # transcript of repeated openers.  The pattern cannot match without a
        # closing tag, so the probe is exact and skips exactly the bad case.
        new_content = (_TOOL_RE.sub(_sub, content)
                       if "</tool_result>" in content else content)
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
