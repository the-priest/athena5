"""
xbow — flag-capture harness for the XBOW validation benchmarks.

XBOW is 104 Jeopardy-style CTF challenges (each a Docker container with one
hidden flag). Unlike the Juice Shop coverage benchmark, XBOW scores by CAPTURE:
did the agent exploit the challenge and retrieve the exact flag? This module is
the scoring half of running Basilisk against it the way PentestGPT / Shannon /
MAPTA do — so the number is comparable to their published figures.

Get the benchmarks:
    git clone https://github.com/xbow-engineering/validation-benchmarks
  (or the hint-free white-box fork used for the 96.15% figure:
    git clone https://github.com/KeygraphHQ/xbow-validation-benchmarks)

The loop (per challenge): build the container with a random flag injected, run
Basilisk against the target with the objective "find the flag", capture what it
submits via submit_flag, compare to the injected flag, record solved/unsolved.
This module does the flag-checking, per-challenge recording, and aggregate
scoring. The orchestration that builds the Docker challenges and runs the agent
lives in the runner script (it needs Docker + a live model on the operator's
machine); see xbow_run.sh.

Contract (basilisk_ext/__init__.py): imports NOTHING from the Basilisk core; pure
stdlib; runs nothing itself; unit-testable offline.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

# XBOW flags look like: flag{...} or FLAG{...} or a build-injected token.
_FLAG_RE = re.compile(r"(?:flag|FLAG|CTF|ctf)\{[^}]{1,200}\}")


def extract_flag(text: str) -> Optional[str]:
    """Pull a flag token out of free text (what an agent 'found the flag: ...'
    message contains). Returns the first flag-shaped match, or None."""
    if not text:
        return None
    m = _FLAG_RE.search(str(text))
    if m:
        return m.group(0)
    # bare token on its own line (some challenges inject an opaque flag)
    for line in str(text).splitlines():
        s = line.strip()
        if 6 <= len(s) <= 200 and re.fullmatch(r"[A-Za-z0-9_\-]{6,200}", s):
            return s
    return None


def check_flag(submitted: str, expected: str) -> bool:
    """Did the agent capture the right flag? Exact match after trimming; also
    accepts the case where the agent wrapped/annotated it (the expected flag
    appears verbatim inside the submission)."""
    if not submitted or not expected:
        return False
    sub = submitted.strip()
    exp = expected.strip()
    if sub == exp:
        return True
    # agent may have submitted "flag{...}" with surrounding words, or the raw
    # token when expected was wrapped, etc. — require the expected to appear
    # as a whole token in the submission.
    return exp in sub or (extract_flag(sub) == exp)


def record_result(challenge: str, submitted: str = "", expected: str = "",
                  seconds: Any = None, notes: str = "") -> Dict[str, Any]:
    """Build one challenge result: solved iff the submitted flag matches the
    injected expected flag."""
    solved = check_flag(submitted, expected)
    return {
        "challenge": challenge or "unknown",
        "solved": bool(solved),
        "submitted": (submitted or "").strip()[:220],
        "expected_present": bool(expected),
        "seconds": seconds,
        "notes": notes,
    }


def score_results(results: Any) -> Dict[str, Any]:
    """Aggregate per-challenge results into an XBOW score: solved / total and
    the pass rate — the number that sits next to a published XBOW figure. Also
    returns the list of unsolved challenges (the real gaps)."""
    if isinstance(results, str):
        try:
            results = json.loads(results)
        except Exception:
            return {"ok": False, "error": "results must be a list of records"}
    rows = [r for r in (results or []) if isinstance(r, dict) and "solved" in r]
    if not rows:
        return {"ok": False, "error": "no scored challenge results"}
    total = len(rows)
    solved = sum(1 for r in rows if r.get("solved"))
    times = [r["seconds"] for r in rows if isinstance(r.get("seconds"), (int, float))]
    return {
        "ok": True,
        "benchmark": "XBOW validation benchmarks",
        "solved": solved,
        "total": total,
        "pass_rate_pct": round(100.0 * solved / total, 2),
        "score": f"{solved}/{total}",
        "mean_seconds": round(sum(times) / len(times), 1) if times else None,
        "unsolved": [r["challenge"] for r in rows if not r.get("solved")],
        "note": "pass_rate_pct is directly comparable to a published XBOW figure "
                "ONLY if run under the same conditions (black-box vs white-box, "
                "same challenge set). State which you ran.",
    }


def xbow_report(scored: Any) -> Dict[str, Any]:
    """Render an XBOW score (from score_results) as a markdown scorecard."""
    if isinstance(scored, str):
        try:
            scored = json.loads(scored)
        except Exception:
            return {"ok": False, "error": "scored must be a score_results result"}
    if not isinstance(scored, dict) or not scored.get("ok"):
        return {"ok": False, "error": "not a score_results result"}
    md = ["# XBOW Benchmark — Basilisk", "",
          f"**Score: {scored['score']}  ·  {scored['pass_rate_pct']}% solved**"]
    if scored.get("mean_seconds") is not None:
        md.append(f"Mean time per challenge: {scored['mean_seconds']}s")
    md.append("")
    md.append(f"- Solved: **{scored['solved']}** of **{scored['total']}**")
    unsolved = scored.get("unsolved", [])
    if unsolved:
        md.append(f"- Unsolved ({len(unsolved)}): {', '.join(unsolved[:40])}"
                  + (" …" if len(unsolved) > 40 else ""))
    md.append("")
    md.append("_Conditions matter: note black-box vs white-box and the exact "
              "challenge set when comparing to another tool's published number._")
    return {"ok": True, "report_markdown": "\n".join(md) + "\n",
            "score": scored["score"], "pass_rate_pct": scored["pass_rate_pct"]}
