"""
memory — persistent, relevance-scoped recall for Basilisk.

The "Honcho concept" without the service or the GPU.  Design goals, in order:

  1. Recall by RELEVANCE, inject a handful, never the whole store.  That is
     the answer to "don't bloat the token window": history can grow forever,
     but each turn only ever sees top-k (default 6) memories scored against
     the current message.
  2. Run on a phone.  Default scorer is keyword (FTS5 if present, LIKE if
     not) + recency + salience — zero model compute, instant.  Embeddings are
     OPTIONAL: if the host injects an embed_fn, recall upgrades to cosine.
  3. No hidden side-channel.  One SQLite file at a path the operator owns,
     a settings toggle, and a memory_forget tool.  Nothing leaves the box
     except the same API calls Basilisk already makes.

Storage model (one table, deliberately boring):

    memories(id, ts, kind, text, salience, source, embedding)
      kind     : fact | preference | event | fix | skill_note
      salience : 0..1, how strongly to favour it in recall
      source   : 'heuristic' | 'model' | 'tool' | 'manual'
      embedding: packed float32 blob, or NULL in keyword mode
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


PROMPT_BLOCK = (
    "MEMORY: you have persistent recall across sessions.  Relevant past "
    "facts are injected automatically each turn under a 'Recalled memory' "
    "header — treat them as things you already know, do not announce that "
    "you 'remembered'.  To store something durable the operator tells you to "
    "keep, call memory_remember.  To look something up explicitly, call "
    "memory_recall.  To drop something, call memory_forget.  Store facts and "
    "preferences, not transient chatter."
)

# Cheap heuristic triggers for always-on capture (no model call).
_REMEMBER_RE = re.compile(
    r"\b(remember that|remember this|note that|keep in mind|for future|"
    r"don'?t forget|make a note|my name is|i'?m called|call me|i go by|"
    r"i prefer|i use|i'?m using|i work|i'?m working on|i run|i own|i have a|"
    r"i always|i never|i hate|i like|i love|my \w+ is|our \w+ is)\b",
    re.IGNORECASE)


def _pack(vec: List[float]) -> bytes:
    return struct.pack(f"{len(vec)}f", *vec)


def _unpack(blob: bytes) -> List[float]:
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


_STOPWORDS = {
    "the", "and", "for", "are", "was", "you", "your", "his", "her", "its",
    "our", "their", "with", "that", "this", "from", "into", "what", "when",
    "where", "why", "how", "did", "does", "has", "have", "had", "out", "any",
    "all", "can", "should", "would", "could", "about", "they", "them",
}


def _tokens(s: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9_]{3,}", (s or "").lower())
            if t not in _STOPWORDS]


# Security-domain synonym groups.  Keyword recall (no embeddings) otherwise
# misses obvious paraphrases — "SQL injection" wouldn't find a memory stored as
# "SQLi", because they share no token.  Each group below is treated as
# interchangeable: if a query (or a stored memory) contains any member, the
# search is expanded to include the others.  This is the cheap, offline,
# deterministic stand-in for semantic search.  Bidirectional and multi-word
# aware.  Keep entries to genuine equivalences so recall doesn't get noisy.
_SYNONYM_GROUPS = [
    {"sqli", "sql injection"},
    {"xss", "cross site scripting", "cross-site scripting"},
    {"rce", "remote code execution"},
    {"lfi", "local file inclusion"},
    {"rfi", "remote file inclusion"},
    {"ssrf", "server side request forgery", "server-side request forgery"},
    {"csrf", "cross site request forgery", "cross-site request forgery"},
    {"idor", "insecure direct object reference"},
    {"xxe", "xml external entity"},
    {"ssti", "server side template injection", "server-side template injection"},
    {"privesc", "priv esc", "privilege escalation"},
    {"recon", "reconnaissance"},
    {"creds", "credentials", "credential"},
    {"enum", "enumeration"},
    {"vuln", "vulnerability", "vulnerabilities", "vulns"},
    {"auth", "authentication"},
    {"authz", "authorization"},
    {"mitm", "man in the middle", "man-in-the-middle"},
    {"c2", "command and control"},
    {"waf", "web application firewall"},
    {"dos", "denial of service"},
    {"ad", "active directory"},
    {"2fa", "mfa", "two factor", "two-factor", "multi factor", "multi-factor"},
    {"info", "information"},
    {"subdomain", "subdomains", "sub-domain"},
    {"directory", "directories", "dir"},
]

# Precompute: lowercased query substrings to look for, each mapped to the extra
# tokens it should inject.
_SYNONYM_TRIGGERS = []  # list of (trigger_str, is_phrase, extra_tokens_frozenset)
for _grp in _SYNONYM_GROUPS:
    _extra = set()
    for _m in _grp:
        _extra.update(_tokens(_m))
    for _m in _grp:
        _SYNONYM_TRIGGERS.append((_m, " " in _m, frozenset(_extra)))


def _expand_query_tokens(query: str, qtoks: List[str]) -> List[str]:
    """qtoks plus any synonym-group tokens triggered by the query.  Phrase
    members ('sql injection') are matched against the raw query string; single
    words are matched against the token list."""
    low = (query or "").lower()
    qset = set(qtoks)
    extra: set = set()
    for trigger, is_phrase, extra_tokens in _SYNONYM_TRIGGERS:
        hit = (trigger in low) if is_phrase else (trigger in qset)
        if hit:
            extra.update(extra_tokens)
    if not extra:
        return list(qtoks)
    # preserve order: originals first, then new tokens
    return list(dict.fromkeys(list(qtoks) + sorted(extra)))


def _prefix_match(q: str, h: str) -> bool:
    """Two tokens count as the same word if they share a >=4-char prefix.
    Cheap stemming so 'command'/'commands', 'scan'/'scanning', 'fix'/'fixed'
    all match without a real stemmer or FTS tokenizer config."""
    n = min(len(q), len(h))
    if n < 4:
        return q == h
    p = min(n, 5)
    return q[:p] == h[:p]


def _overlap(qtokens: List[str], text: str) -> float:
    htoks = set(_tokens(text))
    if not qtokens:
        return 0.0
    hits = sum(1 for q in qtokens if any(_prefix_match(q, h) for h in htoks))
    return hits / len(qtokens)


class MemoryStore:
    def __init__(self, db_path: Path,
                 embed_fn: Optional[Callable[[List[str]], List[List[float]]]] = None):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.embed_fn = embed_fn
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        # One connection is shared across the UI thread (recall injection), the
        # post-turn recorder thread (writes), and the tool dispatch (writes).
        # A single sqlite connection is NOT safe for concurrent use, so every
        # access below is serialised through this reentrant lock; remember()
        # calling _is_duplicate() re-enters from the same thread, hence RLock.
        # WAL + a busy timeout further smooth contention (incl. the separate
        # worker process) instead of failing a write with "database is locked"
        # — which previously dropped memories silently.
        self._lock = threading.RLock()
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute("PRAGMA busy_timeout=5000")
        except sqlite3.OperationalError:
            pass
        self._fts = False
        self._turns_since_consolidate = 0
        self._init_schema()

    # ── schema ────────────────────────────────────────────────────────
    def _init_schema(self) -> None:
      with self._lock:
        c = self._db
        c.execute("""
            CREATE TABLE IF NOT EXISTS memories(
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        REAL NOT NULL,
                kind      TEXT NOT NULL DEFAULT 'fact',
                text      TEXT NOT NULL,
                salience  REAL NOT NULL DEFAULT 0.5,
                source    TEXT NOT NULL DEFAULT 'heuristic',
                embedding BLOB
            )""")
        # FTS5 is the fast path for keyword recall but is not guaranteed to be
        # compiled into the stock NetHunter python sqlite.  Probe once; fall
        # back to LIKE scanning if the module is missing.
        try:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS mem_fts "
                      "USING fts5(text, content='memories', content_rowid='id')")
            c.execute("""
                CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON memories BEGIN
                  INSERT INTO mem_fts(rowid, text) VALUES (new.id, new.text);
                END""")
            c.execute("""
                CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON memories BEGIN
                  INSERT INTO mem_fts(mem_fts, rowid, text)
                  VALUES('delete', old.id, old.text);
                END""")
            self._fts = True
            # Repopulate the external-content index from the content table.  On
            # a fresh DB this is a no-op; on a DB whose rows predate the FTS
            # table (an upgrade) or drifted, it makes keyword recall see them
            # again instead of silently missing them.  Isolated so a rebuild
            # hiccup never disables an otherwise-working FTS path.
            try:
                c.execute("INSERT INTO mem_fts(mem_fts) VALUES('rebuild')")
            except sqlite3.OperationalError:
                pass
        except sqlite3.OperationalError:
            self._fts = False
        c.commit()

    # ── write ─────────────────────────────────────────────────────────
    def remember(self, text: str, kind: str = "fact",
                 salience: float = 0.5, source: str = "manual") -> Optional[int]:
      with self._lock:
        text = (text or "").strip()
        if len(text) < 4:
            return None
        if self._is_duplicate(text):
            return None
        emb = None
        if self.embed_fn:
            try:
                v = self.embed_fn([text])[0]
                emb = _pack(v)
            except Exception:
                emb = None
        cur = self._db.execute(
            "INSERT INTO memories(ts, kind, text, salience, source, embedding) "
            "VALUES(?,?,?,?,?,?)",
            (time.time(), kind, text, max(0.0, min(1.0, salience)), source, emb))
        self._db.commit()
        return cur.lastrowid

    def _is_duplicate(self, text: str) -> bool:
      with self._lock:
        norm = re.sub(r"\s+", " ", text.lower()).strip()
        for row in self._db.execute("SELECT text FROM memories "
                                    "ORDER BY id DESC LIMIT 200"):
            if re.sub(r"\s+", " ", row["text"].lower()).strip() == norm:
                return True
        return False

    # ── turn observation (always-on heuristic + optional model) ────────
    def observe_turn(self, user_text: str, assistant_text: str,
                     complete_fn: Optional[Callable[[str, str], str]] = None,
                     consolidate: bool = False) -> None:
        # 1. instant heuristic capture from the USER turn only (the model's
        #    own words are not facts about the operator).
        if _REMEMBER_RE.search(user_text):
            # Keep the whole statement (collapsed to one line, capped), not
            # just the first physical line — the durable fact is often on a
            # later line of a multi-line message.
            line = re.sub(r"\s+", " ", user_text).strip()[:400]
            self.remember(line, kind="preference", salience=0.7,
                          source="heuristic")
        # 2. debounced model consolidation, only if asked and a completer is
        #    available.  Caller runs this on a background thread.
        if not (consolidate and complete_fn):
            return
        self._turns_since_consolidate += 1
        every = 4
        if self._turns_since_consolidate < every:
            return
        self._turns_since_consolidate = 0
        try:
            self._model_consolidate(user_text, assistant_text, complete_fn)
        except Exception:
            pass

    def _model_consolidate(self, user_text: str, assistant_text: str,
                           complete_fn: Callable[[str, str], str]) -> None:
        sys = ("Extract DURABLE facts or preferences about the operator or "
               "their systems from this exchange — things worth recalling "
               "weeks later. Output JSONL, one object per line: "
               '{"kind":"fact|preference|fix","text":"...","salience":0..1}. '
               "No prose. No markdown. Empty output if nothing durable.")
        usr = f"USER:\n{user_text[:1500]}\n\nASSISTANT:\n{assistant_text[:1500]}"
        raw = (complete_fn(sys, usr) or "").strip()
        for line in raw.splitlines():
            line = line.strip().strip("`")
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.remember(str(obj.get("text", "")),
                          kind=str(obj.get("kind", "fact")),
                          salience=float(obj.get("salience", 0.5)),
                          source="model")

    # ── recall ────────────────────────────────────────────────────────
    def recall(self, query: str, k: int = 6) -> List[sqlite3.Row]:
        """Hybrid recall.  The keyword channel (FTS/overlap) ALWAYS runs; when
        an embedder is wired, the semantic (cosine) channel is folded in on top.
        A memory surfaces if it hits EITHER channel — so turning embeddings on
        can only ADD recall, never hide a memory keyword would have found (e.g.
        one stored before embeddings were enabled, with no vector yet).  If the
        embedder is offline or errors, this turn is simply keyword-only."""
        query = (query or "").strip()
        if not query:
            return []
        qv = None
        if self.embed_fn:
            try:
                qv = self.embed_fn([query])[0]
            except Exception:
                qv = None
        return self._recall_hybrid(query, qv, k)

    def _keyword_rows(self, qtoks: List[str], k: int) -> List[sqlite3.Row]:
        """Keyword candidate rows — FTS prefix match, else a bounded overlap
        scan.  Caller holds self._lock."""
        rows: List[sqlite3.Row] = []
        if self._fts and qtoks:
            # Prefix-wildcard each token so 'commands' finds 'command' etc.
            terms = " OR ".join((t[:6] + "*") for t in qtoks[:16])
            try:
                rows = list(self._db.execute(
                    "SELECT m.* FROM mem_fts f JOIN memories m ON m.id=f.rowid "
                    "WHERE mem_fts MATCH ? ORDER BY rank LIMIT ?",
                    (terms, k * 4)))
            except sqlite3.OperationalError:
                rows = []
        if not rows:
            for row in self._db.execute("SELECT * FROM memories "
                                        "ORDER BY id DESC LIMIT 500"):
                if _overlap(qtoks, row["text"]) > 0:
                    rows.append(row)
        return rows

    # Semantic gating.  Sentence embeddings are anisotropic — even unrelated
    # text sits at a moderate baseline cosine — so a fixed floor alone lets
    # noise through.  A memory only counts as a semantic hit if its cosine
    # clears BOTH an absolute floor AND the query's own typical (median)
    # similarity by a margin: a query truly about nothing stored produces a
    # flat distribution with no standout, so nothing passes.
    # Semantic gating.  Sentence embeddings are anisotropic — even unrelated
    # text sits at a moderate baseline cosine — so a fixed floor alone lets
    # noise through.  A memory counts as a semantic hit only if its cosine
    # clears an absolute floor AND stands out above the query's TYPICAL
    # UNRELATED similarity (a low percentile of the distribution, not the
    # median: the median breaks when only a couple of memories exist because
    # the match itself becomes the midpoint).  A query about nothing stored
    # yields a flat distribution with no standout, so nothing passes.
    _SEM_MIN = 0.45
    _SEM_MARGIN = 0.10

    def _recall_hybrid(self, query: str, qv: Optional[List[float]],
                       k: int) -> List[sqlite3.Row]:
      with self._lock:
        now = time.time()
        qtoks = _expand_query_tokens(query, _tokens(query))
        # 1. keyword channel — always contributes its matches.
        kw_rows: Dict[int, sqlite3.Row] = {
            r["id"]: r for r in self._keyword_rows(qtoks, k)}
        # 2. semantic channel — cosine over embedded rows, relatively gated.
        sem_score: Dict[int, float] = {}
        sem_rows: Dict[int, sqlite3.Row] = {}
        if qv is not None:
            emb = []
            for r in self._db.execute(
                    "SELECT * FROM memories WHERE embedding IS NOT NULL"):
                emb.append((_cosine(qv, _unpack(r["embedding"])), r))
            if emb:
                sims = sorted(s for s, _ in emb)
                if len(sims) >= 3:
                    # ~33rd percentile = a typical UNRELATED similarity; a real
                    # match must beat it by a margin.  Stays correct for small
                    # stores (for n=2 this is the lower/unrelated one).
                    baseline = sims[len(sims) // 3]
                    gate = max(self._SEM_MIN, baseline + self._SEM_MARGIN)
                else:
                    # too few to estimate a baseline — absolute floor only.
                    gate = self._SEM_MIN
                for s, r in emb:
                    if s >= gate:
                        sem_score[r["id"]] = s
                        sem_rows[r["id"]] = r
        cand: Dict[int, sqlite3.Row] = dict(kw_rows)
        cand.update(sem_rows)
        scored: List[Tuple[float, sqlite3.Row]] = []
        for cid, r in cand.items():
            kw = _overlap(qtoks, r["text"])
            rel = max(kw, sem_score.get(cid, 0.0))   # hit on EITHER channel
            if rel <= 0.0:
                continue
            score = (0.6 * rel + 0.25 * r["salience"]
                     + 0.15 * self._recency(r["ts"], now))
            scored.append((score, r))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [r for _, r in scored[:k]]

    def backfill_embeddings(self, limit: int = 64) -> int:
        """Embed stored memories that have no vector yet (everything from before
        semantic recall was enabled) so the semantic channel can see them.
        Bounded per call — the host loops it on a background thread.  embed_fn
        is called OUTSIDE the DB lock (it's a network call).  Returns how many
        rows were embedded; 0 when nothing's left or no embedder is wired."""
        if not self.embed_fn:
            return 0
        with self._lock:
            rows = list(self._db.execute(
                "SELECT id, text FROM memories WHERE embedding IS NULL "
                "ORDER BY id DESC LIMIT ?", (max(1, limit),)))
        if not rows:
            return 0
        try:
            vecs = self.embed_fn([r["text"] for r in rows])
        except Exception:
            return 0
        if len(vecs) != len(rows):
            return 0
        n = 0
        with self._lock:
            for r, v in zip(rows, vecs):
                try:
                    self._db.execute(
                        "UPDATE memories SET embedding=? WHERE id=?",
                        (_pack(v), r["id"]))
                    n += 1
                except Exception:
                    pass
            self._db.commit()
        return n

    @staticmethod
    def _recency(ts: float, now: float) -> float:
        # 30-day half-life, clamped 0..1
        age_days = max(0.0, (now - ts) / 86400.0)
        return 0.5 ** (age_days / 30.0)

    # ── formatting + forget ────────────────────────────────────────────
    def format_block(self, rows: List[sqlite3.Row]) -> str:
        if not rows:
            return ""
        lines = ["Recalled memory (relevant to this turn — already known, "
                 "do not say you 'remembered'):"]
        for r in rows:
            lines.append(f"  - [{r['kind']}] {r['text']}")
        return "\n".join(lines)

    def forget(self, query_or_id: str) -> int:
      with self._lock:
        q = (query_or_id or "").strip()
        if not q:
            return 0
        if q.isdigit():
            cur = self._db.execute("DELETE FROM memories WHERE id=?", (int(q),))
            self._db.commit()
            return cur.rowcount
        kws = [w.lower() for w in re.findall(r"[A-Za-z0-9_]{3,}", q)]
        if not kws:
            return 0
        ids = []
        for row in self._db.execute("SELECT id, text FROM memories"):
            hay = row["text"].lower()
            if all(w in hay for w in kws):
                ids.append(row["id"])
        for i in ids:
            self._db.execute("DELETE FROM memories WHERE id=?", (i,))
        self._db.commit()
        return len(ids)

    # ── tool surface (string in, string out — host feeds it back) ──────
    def tool_recall(self, query: str, k: int = 8) -> str:
        rows = self.recall(query, k=k)
        if not rows:
            return "no relevant memories."
        return json.dumps([{"id": r["id"], "kind": r["kind"],
                            "text": r["text"], "salience": r["salience"]}
                           for r in rows], indent=2)

    def tool_remember(self, text: str, kind: str, salience: float) -> str:
        rid = self.remember(text, kind=kind, salience=salience, source="tool")
        if rid is None:
            return "not stored (empty or duplicate)."
        return f"stored memory #{rid} [{kind}]."

    def tool_forget(self, query_or_id: str) -> str:
        n = self.forget(query_or_id)
        return f"forgot {n} memor{'y' if n == 1 else 'ies'}."

    def stats(self) -> Dict[str, Any]:
      with self._lock:
        row = self._db.execute("SELECT COUNT(*) n, MAX(ts) last "
                               "FROM memories").fetchone()
        return {"count": row["n"], "last_ts": row["last"],
                "fts": self._fts, "vector": bool(self.embed_fn)}
