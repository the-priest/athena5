"""
basilisk_ext.tasks — the TASK LEDGER.

WHY THIS EXISTS
===============
Two complaints, one missing mechanism:

    "it still sometimes stops when it's supposed to keep working"
    "it still doesn't stop when it's supposed to and sends two answers"

Both are the same gap wearing two faces. Nothing in the app ever knew WHAT
the model set out to do, so "is this turn finished?" could only ever be
answered by reading the model's prose — and a prose reader is always one
phrasing away from being wrong in BOTH directions at once:

  * "I've fixed two of the five files" reads like a conclusion, so the turn
    ended with three files untouched.  (Stopped too early.)
  * A complete, finished answer reads like it might continue, so it got
    nudged and the model answered the same question again.  (Two answers.)

The fix is the one this codebase has reached for every time a prose reader
failed: replace the reading with STATE THE APP OWNS.  The model declares its
plan up front; every item has a status; and the turn-ending decision becomes
arithmetic over that ledger instead of a guess about English.

  open items  -> the turn MAY NOT end (bounded — see the host's push cap)
  no open items -> the turn MUST end, and the host stops pushing entirely,
                   which is what makes a second answer structurally
                   impossible rather than merely discouraged.

DESIGN RULES (each one is load-bearing)
=======================================
  * `blocked` and `dropped` CLOSE an item.  A ledger where the only exit is
    `done` is an infinite loop with extra steps: a model that genuinely
    cannot proceed must be able to say so and stop.  Both demand a reason,
    so "blocked" cannot become a silent escape hatch.
  * Re-opening a closed item is allowed but COUNTED.  A model that flips an
    item done/open/done is looping, and `churn` is how the host sees it
    without reading a word of prose.
  * A plan is per REQUEST, not per chat.  The host resets it when the
    operator speaks.  Carrying it across requests would let yesterday's
    unfinished item hold today's answer hostage.
  * Pure stdlib, no host imports, no GTK, no I/O.  Same contract as every
    other module in this package.
  * TOTAL: every entry point returns a dict and never raises.  A ledger that
    raises takes the turn down with it, and it exists to END turns cleanly.

Every error string here is written as a PROMPT, because that is what it is:
the model reads it and acts on it.  "unknown id" teaches nothing; "unknown
id 'x' — the plan has: 1, 2, 3" is a correction it can follow.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

__all__ = [
    "TaskPlan", "OPEN_STATES", "CLOSED_STATES", "VALID_STATES",
    "normalise_status", "MAX_ITEMS", "MAX_TITLE",
]

# ── the state model ──────────────────────────────────────────────────
# OPEN means the turn still has work to do. CLOSED means it does not.
# `doing` is open on purpose: a model that marks everything `doing` and
# stops has not finished, and the gate should say so.
OPEN_STATES = frozenset({"open", "doing"})
CLOSED_STATES = frozenset({"done", "blocked", "dropped"})
VALID_STATES = OPEN_STATES | CLOSED_STATES

# A reason is MANDATORY for these two, because they are the ways out of the
# loop. Without that rule "blocked" is just "done" for a model in a hurry.
NEEDS_REASON = frozenset({"blocked", "dropped"})

MAX_ITEMS = 40          # a plan longer than this is not a plan, it is a diary
MAX_TITLE = 200
MAX_NOTE = 600

# Synonyms the model actually emits. Mapping them is the difference between
# a working call and a refusal the model has to guess its way out of.
_STATUS_ALIASES = {
    "todo": "open", "to-do": "open", "pending": "open", "not started": "open",
    "not_started": "open", "queued": "open", "waiting": "open", "new": "open",
    "in progress": "doing", "in_progress": "doing", "inprogress": "doing",
    "active": "doing", "started": "doing", "working": "doing",
    "wip": "doing", "current": "doing", "running": "doing",
    "complete": "done", "completed": "done", "finished": "done",
    "fixed": "done", "ok": "done", "passed": "done", "closed": "done",
    "stuck": "blocked", "failed": "blocked", "cannot": "blocked",
    "impossible": "blocked", "needs_operator": "blocked",
    "skip": "dropped", "skipped": "dropped", "cancelled": "dropped",
    "canceled": "dropped", "n/a": "dropped", "obsolete": "dropped",
    "unnecessary": "dropped", "not needed": "dropped",
}


def normalise_status(s: Any) -> str:
    """Map whatever the model wrote onto a real state, or "" if unmappable.

    Total: any input type, no exceptions."""
    try:
        t = str(s or "").strip().lower().replace("-", " ")
        t = re.sub(r"\s+", " ", t)
    except Exception:
        return ""
    if not t:
        return ""
    if t in VALID_STATES:
        return t
    if t in _STATUS_ALIASES:
        return _STATUS_ALIASES[t]
    t2 = t.replace(" ", "_")
    if t2 in VALID_STATES:
        return t2
    return _STATUS_ALIASES.get(t2, "")


def _clean(s: Any, cap: int) -> str:
    try:
        t = re.sub(r"\s+", " ", str(s or "")).strip()
    except Exception:
        return ""
    return t[:cap]


class TaskPlan:
    """The ledger for ONE operator request.

    Not thread-safe by design: every caller is the GTK main loop, and a lock
    here would be a lie about where the concurrency is.
    """

    def __init__(self) -> None:
        self._items: List[Dict[str, Any]] = []
        self.created_at: float = 0.0
        self.churn: int = 0          # closed items that were re-opened
        self.updates: int = 0        # every accepted status write
        self.goal: str = ""

    # ── construction ─────────────────────────────────────────────────
    def clear(self) -> None:
        self._items = []
        self.created_at = 0.0
        self.churn = 0
        self.updates = 0
        self.goal = ""

    def set_plan(self, items: Any, goal: Any = "") -> Dict[str, Any]:
        """Replace the plan. Accepts a list of strings or of dicts.

        REPLACE, not merge: a model re-planning mid-job is telling you the
        old plan was wrong, and silently keeping its items would leave the
        gate holding the turn open on work nobody intends to do.  The one
        thing carried across is the STATUS of an item whose title is
        unchanged — otherwise every re-plan would resurrect finished work
        and the job could never converge.
        """
        try:
            if isinstance(items, (str, bytes)):
                # One string per line is what a model reaches for when it
                # has not read the spec. Accept it rather than refuse it.
                raw = [ln for ln in str(items).splitlines() if ln.strip()]
            elif isinstance(items, dict):
                raw = [items]
            else:
                raw = list(items or [])
        except Exception:
            return {"ok": False, "error": (
                "plan items must be a list of short strings, e.g. "
                '{"items": ["read the failing test", "fix the parser", '
                '"run the suite"]}')}
        if not raw:
            return {"ok": False, "error": (
                "a plan needs at least one item. Pass the concrete steps you "
                "are about to take, e.g. "
                '{"items": ["read src/auth.py", "fix the token refresh", '
                '"run the tests"]}')}
        if len(raw) > MAX_ITEMS:
            return {"ok": False, "error": (
                f"{len(raw)} items is too many — cap is {MAX_ITEMS}. A plan is "
                f"the handful of steps that get this job done, not every "
                f"sub-step. Group them.")}

        # Keep the status of titles that survive the re-plan.
        prior = {}
        for it in self._items:
            prior[_norm_title(it["title"])] = (it["status"], it.get("note", ""))

        out: List[Dict[str, Any]] = []
        seen = set()
        for it in raw:
            if isinstance(it, dict):
                title = _clean(it.get("title") or it.get("task")
                               or it.get("name") or it.get("step")
                               or it.get("text") or it.get("item"), MAX_TITLE)
                st = normalise_status(it.get("status")) or "open"
                note = _clean(it.get("note") or it.get("detail")
                              or it.get("reason"), MAX_NOTE)
            else:
                title = _clean(it, MAX_TITLE)
                st = "open"
                note = ""
            # Numbered pastes ("1. read the file") keep their number in the
            # title otherwise, which then appears twice on screen.
            title = re.sub(r"^\s*(?:\d+[.)]|[-*•])\s+", "", title)
            if not title:
                continue
            key = _norm_title(title)
            if key in seen:
                continue                    # a duplicate step is one step
            seen.add(key)
            if key in prior:
                st, note = prior[key][0], prior[key][1] or note
            out.append({"id": str(len(out) + 1), "title": title,
                        "status": st, "note": note, "ts": time.time()})
        if not out:
            return {"ok": False, "error": (
                "none of those items had any text in them. Each item is a "
                "short concrete step.")}
        self._items = out
        self.created_at = time.time()
        self.churn = 0
        self.updates = 0
        self.goal = _clean(goal, MAX_TITLE)
        return self.status(_intro=True)

    # ── mutation ─────────────────────────────────────────────────────
    def update(self, ident: Any, status: Any, note: Any = "") -> Dict[str, Any]:
        """Move one item to a new state."""
        if not self._items:
            return {"ok": False, "error": (
                "there is no plan yet — call plan_set first with the steps "
                "you are about to take, then mark them off as you go.")}
        st = normalise_status(status)
        if not st:
            return {"ok": False, "error": (
                f"unknown status {str(status)[:40]!r}. Use one of: "
                f"open, doing, done, blocked, dropped.")}
        it = self._find(ident)
        if it is None:
            return {"ok": False, "error": (
                f"no plan item matches {str(ident)[:60]!r}. The plan has: "
                + "; ".join(f"{i['id']}={i['title'][:40]}"
                            for i in self._items))}
        note_s = _clean(note, MAX_NOTE)
        if st in NEEDS_REASON and not note_s:
            return {"ok": False, "error": (
                f"marking an item {st!r} requires a reason — pass `note` "
                f"saying exactly what stopped you (the error, the missing "
                f"file, the decision you need). {st!r} without a reason is "
                f"indistinguishable from giving up quietly.")}
        was = it["status"]
        if was in CLOSED_STATES and st in OPEN_STATES:
            self.churn += 1
        it["status"] = st
        if note_s:
            it["note"] = note_s
        it["ts"] = time.time()
        self.updates += 1
        return self.status(_changed=it["id"])

    def _find(self, ident: Any) -> Optional[Dict[str, Any]]:
        """By id, then by exact title, then by unique substring.

        The substring pass is not sloppiness: the model refers to its own
        steps by name far more naturally than by number, and refusing that
        just burns a round-trip. It is UNIQUE-match only, so it can never
        silently tick off the wrong item."""
        key = _clean(ident, MAX_TITLE)
        if not key:
            return None
        for it in self._items:
            if it["id"] == key:
                return it
        k = _norm_title(key)
        if not k:
            return None
        for it in self._items:
            if _norm_title(it["title"]) == k:
                return it
        hits = [it for it in self._items if k in _norm_title(it["title"])]
        if len(hits) == 1:
            return hits[0]
        hits = [it for it in self._items if _norm_title(it["title"]) in k]
        if len(hits) == 1:
            return hits[0]
        return None

    # ── reading ──────────────────────────────────────────────────────
    @property
    def items(self) -> List[Dict[str, Any]]:
        return [dict(i) for i in self._items]

    def __bool__(self) -> bool:
        return bool(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def open_items(self) -> List[Dict[str, Any]]:
        return [dict(i) for i in self._items if i["status"] in OPEN_STATES]

    def is_complete(self) -> bool:
        """True when a plan EXISTS and nothing in it is still open.

        An empty ledger is NOT complete — it is absent, which is a different
        thing and must not be read as permission to stop."""
        return bool(self._items) and not any(
            i["status"] in OPEN_STATES for i in self._items)

    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in VALID_STATES}
        for i in self._items:
            c[i["status"]] = c.get(i["status"], 0) + 1
        return c

    def status(self, _intro: bool = False,
               _changed: str = "") -> Dict[str, Any]:
        c = self.counts()
        op = self.open_items()
        out: Dict[str, Any] = {
            "ok": True,
            "goal": self.goal,
            "items": self.items,
            "counts": c,
            "open": len(op),
            "complete": self.is_complete(),
            "churn": self.churn,
        }
        if _changed:
            out["changed"] = _changed
        if op:
            out["next"] = op[0]["title"]
            out["still_open"] = [i["title"] for i in op]
            out["reminder"] = (
                "%d item(s) still open. Do the next one now — emit the tool "
                "call, do not describe it. The turn will not end while "
                "anything is open." % len(op))
        elif self._items:
            out["reminder"] = (
                "Every item is closed. Give the operator ONE final report now "
                "— what you did, what you ran, what the result was — and STOP. "
                "Do not restate anything already on screen, and do not start "
                "new work that was not asked for.")
        if _intro:
            out["reminder"] = (
                "Plan recorded. Work it top to bottom: mark an item `doing` "
                "when you start it and `done` the moment it is verified. Call "
                "the tool for the first step NOW — the plan is not the work.")
        return out

    def render(self, width: int = 0) -> str:
        """A compact plain-text checklist, for the terminal log and prompts."""
        if not self._items:
            return ""
        mark = {"open": "[ ]", "doing": "[~]", "done": "[x]",
                "blocked": "[!]", "dropped": "[-]"}
        lines = []
        for i in self._items:
            t = i["title"]
            if width and len(t) > width:
                t = t[:max(4, width - 1)] + "…"
            row = f"{mark.get(i['status'], '[ ]')} {t}"
            if i["status"] in NEEDS_REASON and i.get("note"):
                row += f"  — {i['note'][:80]}"
            lines.append(row)
        return "\n".join(lines)

    def summary_line(self) -> str:
        if not self._items:
            return ""
        c = self.counts()
        bits = [f"{c['done']}/{len(self._items)} done"]
        if c["doing"]:
            bits.append(f"{c['doing']} in progress")
        if c["blocked"]:
            bits.append(f"{c['blocked']} blocked")
        if c["dropped"]:
            bits.append(f"{c['dropped']} dropped")
        return ", ".join(bits)


def _norm_title(t: Any) -> str:
    try:
        return re.sub(r"[^a-z0-9 ]+", "", str(t or "").lower()).strip()
    except Exception:
        return ""
