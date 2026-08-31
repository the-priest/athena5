"""
recall — what has already been done this mission, and whether we are going
round in circles.

WHY THIS EXISTS
===============
Athena repeated itself.  Not "twice in a row" repeating, which the old
loop-breaker in athena.py already caught, but the harder kind: re-running
something it had already run three or four steps earlier, with other actions in
between.

That is not a model quirk, it is an information problem, and it was created by
the host:

  * The model's only record of its own actions was the transcript.
  * `_build_history_for_model` keeps just HISTORY_KEEP_FULL_TOOL_RESULTS (2)
    tool results at full length and cuts everything older to a 600-char head.
  * `headroom.compress_messages` then compresses what survives that.
  * And the mission-continue directive re-anchors every turn on the ORIGINAL
    objective — "take the very NEXT concrete action toward: <objective>".

So several steps in, the strongest thing in the model's context is the original
objective, and its evidence of having already tried something is a truncated
stub.  A model in that position re-runs the obvious first move.  It is behaving
correctly on the information it was given.

The fix is to give it the information.  This module keeps ONE LINE per action —
the action, and a digest of what came back — outside the transcript, so it is
never trimmed and never compressed.  Forty actions cost a few hundred tokens,
which is far less than one re-run of a scan.

The deterministic guard (`should_block`) is the backstop for when the model
ignores the list anyway.

DESIGN CONTRACT
===============
Same as the rest of basilisk_ext: this module imports NOTHING from athena.py,
basilisk_core.py or basilisk_persona.py.  It is pure data + string handling and
is unit-testable on its own.  If it fails to import, the host degrades to the
old behaviour rather than breaking.
"""

from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Optional


# One line per action.  Deliberately small: this block is re-sent on EVERY turn,
# so its size is multiplied by the number of steps in a run.
MAX_ENTRIES = 60           # ring buffer; older actions fall off the bottom
DIGEST_ENTRIES = 40        # how many of those are rendered into the prompt
OUTCOME_CHARS = 110        # per-entry outcome digest
ACTION_CHARS = 150         # per-entry action text

_WS = re.compile(r"\s+")
# Lines that say nothing about what happened.
_NOISE = re.compile(
    r"^\s*(\$|#|\.{3}|-{3,}|={3,}|\*{3,})?\s*$")

# ── "did this run actually TELL us anything?" ────────────────────────
# The guard's premise is "you already did this, so doing it again teaches you
# nothing".  That premise fails when the result never reached the model: a page
# fetched twice and compressed to a stub both times was, from the model's side,
# never read at all — and the guard then locked it out of the one source that
# had the answer.  Counting a destroyed result as a completed run turns a
# delivery failure into a permanent dead end.
#
# DELIBERATELY NARROW: this matches evidence that the result was damaged IN
# TRANSIT, not evidence that the tool FAILED.  A command that errors three
# times is exactly what the guard should stop — re-running it is unproductive
# in precisely the way the guard exists to catch.  The report suggested also
# releasing on "shorter than ~500 chars", which is not adopted: plenty of
# legitimate results are short, and that rule would quietly disable the guard.
_DAMAGED_IN_TRANSIT = re.compile(
    r"\[headroom:\s*\d+"                    # headroom compression note
    r"|\[INCOMPLETE"                        # prose/history truncation marker
    r"|earlier tool output trimmed"         # history trim note
    r"|<<\s*[A-Za-z][\w.-]{1,20}\s*:[^>]{4,200}>>",   # unhydrated cache ref
    re.IGNORECASE)

# How many extra attempts a repeatedly-damaged action gets before the guard
# closes anyway.  Without a ceiling, "the result was unusable" becomes an
# infinite retry licence — trading a dead end for a loop, which is worse.
UNUSABLE_GRACE = 2


def outcome_is_usable(text: str) -> bool:
    """False ONLY when a result was destroyed before the model could read it.

    An EMPTY result is usable.  That looks wrong at first and is not: plenty of
    commands legitimately say nothing when they succeed (`mkdir`, `chmod`, a
    grep with no match), and "it ran and produced no output" is a real answer
    that does not get truer by running it again.  Treating empty as "never
    delivered" would hand every silent command an extra pair of free retries
    and quietly loosen the guard everywhere — which is what it did to
    tests/test_recall.py's limit cases the first time this was written.
    """
    return not _DAMAGED_IN_TRANSIT.search(text or "")


def normalise(action: str) -> str:
    """Canonical form used to decide whether two actions are 'the same'.

    Deliberately conservative — whitespace and a trailing separator only.  It is
    tempting to normalise harder (sort flags, drop output redirection, ignore
    `-v`) but every such rule creates a way for two genuinely different commands
    to collide, and a false 'you already did this' is worse than a missed one:
    it stops real work with a confident wrong reason.
    """
    a = _WS.sub(" ", (action or "").strip())
    return a.rstrip("; ").strip()


def digest_outcome(text: str, limit: int = OUTCOME_CHARS) -> str:
    """Squash a tool result into one short line.

    Keeps the FIRST informative line, and appends the rc when the result carries
    one, because "ran and failed" versus "ran and worked" is the single most
    useful bit for deciding whether to try something else.
    """
    t = (text or "").strip()
    if not t:
        return "(no output)"
    rc = None
    m = re.search(r"\(rc=(-?\d+)\)", t[:400])
    if m:
        rc = m.group(1)
    lines = [ln.strip() for ln in t.splitlines()]
    body = ""
    for ln in lines:
        if _NOISE.match(ln):
            continue
        if ln.startswith("$ ") or re.fullmatch(r"\(rc=-?\d+\)", ln):
            continue
        body = ln
        break
    if not body:
        body = lines[0] if lines else "(no output)"
    if len(body) > limit:
        body = body[:limit - 1] + "…"
    if rc is not None:
        return f"rc={rc} · {body}"
    return body


class ActionLog:
    """A per-mission list of actions taken, with repeat + cycle detection.

    Thread-safe: tool results arrive from worker threads, and the prompt build
    reads the same structure on the main loop.
    """

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self._lock = threading.RLock()
        self._max = max(4, int(max_entries))
        self._entries: List[Dict[str, Any]] = []
        self._counts: Dict[str, int] = {}
        # Runs that actually delivered a readable result. The guard counts
        # THESE, not raw attempts — see outcome_is_usable.
        self._useful: Dict[str, int] = {}
        self._step = 0

    # ── lifecycle ────────────────────────────────────────────────────
    def reset(self) -> None:
        """New objective — the previous mission's actions are no longer 'what
        we already tried'."""
        with self._lock:
            self._entries = []
            self._counts = {}
            self._useful = {}
            self._step = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ── writing ──────────────────────────────────────────────────────
    def record(self, action: str, outcome: str = "") -> Dict[str, Any]:
        """Log one completed action.  Returns the entry that was stored."""
        key = normalise(action)
        if not key:
            return {}
        usable = outcome_is_usable(outcome)
        with self._lock:
            self._step += 1
            self._counts[key] = self._counts.get(key, 0) + 1
            if usable:
                self._useful[key] = self._useful.get(key, 0) + 1
            entry = {
                "step": self._step,
                "action": action.strip()[:ACTION_CHARS],
                "key": key,
                "outcome": digest_outcome(outcome),
                "times": self._counts[key],
                "usable": usable,
            }
            self._entries.append(entry)
            if len(self._entries) > self._max:
                # Drop the oldest, but keep its count — the whole point is that
                # "I did this ages ago" stays true after the line scrolls off.
                self._entries = self._entries[-self._max:]
            return dict(entry)

    # ── reading ──────────────────────────────────────────────────────
    def times_run(self, action: str) -> int:
        with self._lock:
            return self._counts.get(normalise(action), 0)

    def times_delivered(self, action: str) -> int:
        """Runs that returned something the model could actually read."""
        with self._lock:
            return self._useful.get(normalise(action), 0)

    def previous(self, action: str) -> Optional[Dict[str, Any]]:
        """The most recent stored entry for this action, if it is still in the
        ring buffer."""
        key = normalise(action)
        with self._lock:
            for e in reversed(self._entries):
                if e["key"] == key:
                    return dict(e)
        return None

    def should_block(self, action: str, limit: int = 2) -> bool:
        """True once this action has ALREADY been executed `limit` times.

        `limit` is the number of executions permitted, so the default of 2
        allows two and refuses the third.  Two is deliberate: re-running a check
        after changing something is how verification works — `systemctl status
        x`, then `systemctl start x`, then `systemctl status x` again is correct
        behaviour and must not be blocked.  A THIRD identical execution is not
        verification; by then either it already worked or it never will, and
        either way the result is not being read.

        Read the name literally — "block after this many runs".  An earlier
        draft had the docstring promising the third would be refused while the
        arithmetic permitted a fourth, which is the kind of off-by-one that
        makes a guard look present and do nothing.

        A run whose result was destroyed in transit (compressed to a stub,
        trimmed away, returned as an unhydrated cache reference) does NOT
        count towards the limit: from the model's side that action never
        produced anything, and refusing the retry strands it — it cannot get
        the data and cannot ask again.  That is a delivery failure being
        reported as a reasoning failure.

        A ceiling still applies (UNUSABLE_GRACE extra attempts), because
        "the result was unusable" must not become an unlimited retry licence.
        """
        if limit <= 0:
            return False
        if self.times_delivered(action) >= limit:
            return True
        return self.times_run(action) >= limit + UNUSABLE_GRACE

    def cycle(self, max_len: int = 4, reps: int = 2) -> Optional[List[str]]:
        """Detect a repeating cycle at the tail: A A A, A B A B, A B C A B C…

        The host's existing loop-breaker only catches N IDENTICAL CONSECUTIVE
        commands, so the commonest real stall — alternating between two actions
        forever — was invisible to it.

        The evidence threshold is calibrated by cycle length, because the two
        cases are not equally suspicious.  A SINGLE action repeated twice is
        weak evidence: re-polling a service that is still starting looks exactly
        like that and is correct.  So a one-action cycle needs three in a row
        (matching the existing loop-breaker's threshold), while an alternating
        or longer cycle needs only two full turns of it — nothing legitimate
        goes A-B-A-B.  Getting this wrong in the lax direction costs a nag on
        every normal turn, and a warning that cries wolf is one he learns to
        scroll past.
        """
        with self._lock:
            keys = [e["key"] for e in self._entries]
        for n in range(1, max_len + 1):
            need_reps = 3 if n == 1 else reps
            need = n * need_reps
            if len(keys) < need:
                continue
            tail = keys[-need:]
            first = tail[:n]
            if all(tail[i * n:(i + 1) * n] == first for i in range(need_reps)):
                return list(first)
        return None

    def digest(self, limit: int = DIGEST_ENTRIES) -> str:
        """The block injected into the model's context every turn.

        Format is deliberately dull and scannable.  It is not prose the model
        has to interpret; it is a checklist it can diff its intended next action
        against.
        """
        with self._lock:
            entries = list(self._entries)
        if not entries:
            return ""
        shown = entries[-limit:]
        omitted = len(entries) - len(shown)
        lines = []
        if omitted > 0:
            lines.append(f"  (…{omitted} earlier action(s) not shown)")
        for e in shown:
            rep = f"  [x{e['times']}]" if e["times"] > 1 else ""
            lines.append(f"  {e['step']:>3}. {e['action']}{rep}\n"
                         f"       -> {e['outcome']}")
        return "\n".join(lines)

    def prompt_block(self, limit: int = DIGEST_ENTRIES) -> str:
        """digest() wrapped in the instruction that makes it actionable."""
        d = self.digest(limit)
        if not d:
            return ""
        cyc = self.cycle()
        out = ["[ALREADY DONE THIS RUN — read this before choosing your next "
               "action. This list is complete and is NOT trimmed, even where "
               "the transcript above has been shortened to save context.",
               d,
               "Do NOT repeat any action above unless something has changed "
               "since that lists its result, and say what changed. If the next "
               "thing you were about to do is on this list, pick a different "
               "one."]
        if cyc:
            out.insert(1, "!! YOU ARE IN A LOOP: the last few actions repeat "
                          "the cycle " + " -> ".join(c[:80] for c in cyc)
                          + ". Break out of it. Do not take any of those "
                            "actions again — either verify the real state a "
                            "different way, or conclude with what you have.")
        out.append("]")
        return "\n".join(out)
