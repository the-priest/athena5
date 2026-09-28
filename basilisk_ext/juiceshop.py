"""
juiceshop — the HARD Juice Shop benchmark: score by the challenge scoreboard.

The 14-classes coverage run proves methodology but is inflated by recall. This
is the real test the whole security community uses: OWASP Juice Shop ships ~100+
individual hacking challenges rated 1-6 stars, and the app tracks which ones
you've ACTUALLY solved (it only flips a challenge to solved when the exploit
genuinely works — you can't recall your way past it). Human CTF players, tools,
and write-ups all report their numbers against this scoreboard, so it's
apples-to-apples.

How it works: Juice Shop exposes every challenge and its solved-state at
GET /api/Challenges. Basilisk hacks the app as normal, then this scorer reads
the live scoreboard and reports solved/total broken down by difficulty — a
number you can put next to a human's or another tool's.

Caveat baked into the report: Docker DISABLES the dangerous challenges by
default (they come back as 'unavailable'). For the full set, run the target with
NODE_ENV=unsafe. The scorer counts only challenges that are actually available,
and says which mode it saw, so the number is honest either way.

Contract (basilisk_ext/__init__.py): the SCORING here imports nothing from the core
and is pure/testable; the live GET lives in the tool wrapper.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List


def _challenges_list(payload: Any) -> List[Dict[str, Any]]:
    """Normalise the /api/Challenges response (which wraps rows in {"data":[…]})
    or a bare list into a list of challenge dicts."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            return []
    if isinstance(payload, dict):
        rows = payload.get("data")
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
        return []
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    return []


def score_challenges(payload: Any) -> Dict[str, Any]:
    """Score a Juice Shop /api/Challenges response by the scoreboard.

    Counts solved vs available, broken down by difficulty (1-6 stars). A
    challenge marked unavailable (dangerous ones disabled under Docker safe
    mode) is excluded from the denominator so the percentage is honest. Returns
    the objective number: solved / available, overall and per difficulty.
    """
    rows = _challenges_list(payload)
    if not rows:
        return {"ok": False,
                "error": "no challenges found. Is Juice Shop running, and did "
                         "you hit /api/Challenges on it?"}

    by_diff: Dict[int, Dict[str, int]] = {}
    total = solved = available = unavailable = 0
    solved_names: List[str] = []
    hardest_solved = 0
    for c in rows:
        total += 1
        try:
            diff = int(c.get("difficulty", 0) or 0)
        except (TypeError, ValueError):
            diff = 0
        # 'disabledEnv' non-empty (or an explicit unavailable flag) => disabled
        is_unavailable = bool(c.get("disabledEnv")) or \
            c.get("available") is False
        d = by_diff.setdefault(diff, {"solved": 0, "available": 0})
        if is_unavailable:
            unavailable += 1
            continue
        available += 1
        d["available"] += 1
        if c.get("solved"):
            solved += 1
            d["solved"] += 1
            solved_names.append(c.get("name", "?"))
            hardest_solved = max(hardest_solved, diff)

    breakdown = []
    for diff in sorted(by_diff):
        d = by_diff[diff]
        if d["available"] == 0:
            continue
        breakdown.append({
            "difficulty": diff,
            "stars": "*" * diff,
            "solved": d["solved"],
            "available": d["available"],
            "pct": round(100.0 * d["solved"] / d["available"], 1),
        })

    return {
        "ok": True,
        "benchmark": "OWASP Juice Shop — challenge scoreboard",
        "solved": solved,
        "total": total,
        "available": available,
        "unavailable": unavailable,
        "pct": round(100.0 * solved / available, 1) if available else 0.0,
        "pct_of_total": round(100.0 * solved / total, 1) if total else 0.0,
        "hardest_solved_stars": hardest_solved,
        "by_difficulty": breakdown,
        "solved_names": solved_names,
        "safe_mode": unavailable > 0,
        "note": (f"{total} challenges total; {unavailable} DISABLED by Docker "
                 f"safe mode (unsolvable), leaving {available} available. Score "
                 f"is solved/available. The UI shows {total} (all challenges); "
                 f"the difference is the disabled set. To unlock all {total}, run "
                 f"the target with NODE_ENV=unsafe."
                 if unavailable > 0 else
                 f"All {total} challenges available (full set, NODE_ENV=unsafe)."),
    }


def juiceshop_report(scored: Any) -> Dict[str, Any]:
    """Render the scoreboard score (from score_challenges) as a markdown
    scorecard with the per-difficulty breakdown — comparison-ready."""
    if isinstance(scored, str):
        try:
            scored = json.loads(scored)
        except Exception:
            return {"ok": False, "error": "scored must be a score_challenges result"}
    if not isinstance(scored, dict) or not scored.get("ok"):
        return {"ok": False, "error": "not a score_challenges result"}
    md = ["# Juice Shop Scoreboard — Basilisk", "",
          f"**Solved: {scored['solved']} / {scored['available']} available  "
          f"({scored['pct']}%)**  ·  hardest solved: "
          f"{'*' * scored['hardest_solved_stars'] or '-'}"]
    if scored.get("unavailable"):
        md.append(f"_{scored['total']} challenges total on the board; "
                  f"{scored['unavailable']} disabled by Docker safe mode "
                  f"(unsolvable) — scored against the {scored['available']} "
                  f"available._")
    md.append("")
    md.append("| Difficulty | Solved | Available | % |")
    md.append("|---|---:|---:|---:|")
    for r in scored.get("by_difficulty", []):
        md.append(f"| {r['stars']} ({r['difficulty']}) | {r['solved']} | "
                  f"{r['available']} | {r['pct']}% |")
    md.append("")
    if scored.get("safe_mode"):
        md.append(f"> {scored['unavailable']} challenges disabled by Docker safe "
                  f"mode — run with `NODE_ENV=unsafe` for the full set.")
    md.append("")
    md.append("_Scored from the live scoreboard: each challenge counts only when "
              "the app confirmed the exploit actually worked. Comparable to human "
              "and tool numbers on the same version._")
    return {"ok": True, "report_markdown": "\n".join(md) + "\n",
            "solved": scored["solved"], "pct": scored["pct"]}


# ═════════════════════════════════════════════════════════════════════
# CLOSED-LOOP HARNESS — the feedback signal that was missing.
#
# Solving used to be fire-and-forget: attack, then score once at the end,
# with no way for the agent to tell whether an attempt worked, which to
# retry, or what's still red.  These two pure functions supply that signal.
# The agent works the board -> score -> next_targets (what's left + how) ->
# attempt through the normal builder+scope+gate flow -> diff_solved (did it
# land?) -> repeat.  Read-only planning; no autonomous firing.
# ═════════════════════════════════════════════════════════════════════

# Map a challenge's category/name to the Basilisk capability that solves its
# class.  Keys are matched as case-insensitive substrings against the
# challenge category first, then its name.  This is what turns "23 still red"
# into "here's the tool for each."
_TECHNIQUE_HINTS = [
    ("nosql",              "nosql_injection — Mongo operator injection ($ne/$where/$regex; pick the mode for bypass/manipulation/dos/exfil)"),
    ("xxe",                "xxe_payload — DTD external-entity (file_read) or billion-laughs (dos), POST as XML to the upload sink"),
    ("captcha",            "captcha_solve — read /rest/captcha and submit the computed answer (auto-read; defeats the anti-automation gate)"),
    ("anti automation",    "captcha_solve + scripted repetition through the run loop (rate-limit / captcha bypass)"),
    ("unsigned jwt",       "jwt_forge mode=none — alg:none + empty signature"),
    ("jwt",                "jwt_forge — mode=none (alg:none) or mode=hs256 (RS256->HS256 confusion; fetch /encryptionkeys/jwt.pub first)"),
    ("coupon",             "coupon_forge — z85(campaign+discount); read the campaign code from main*.js first"),
    ("cryptographic",      "jwt_forge / coupon_forge / hashcat — depends on the primitive; inspect what token or code is checked"),
    ("injection",          "sqlmap_plan for SQLi; nosql_injection for Mongo. Confirm the DBMS from an error first"),
    ("xss",                "browser tool — drive a real JS-executing page; for stored/DOM inject via the review/search sink and confirm execution"),
    ("broken access",      "run/browser — IDOR: change the id/role in the request; hit admin-only endpoints directly with a forged/elevated token"),
    ("broken authentication", "sqlmap_plan (login SQLi) / jwt_forge / reset_password_plan (security-question reset for demo accounts)"),
    ("improper input",     "run — send the malformed/over-long/edge value the validator misses"),
    ("security misconfiguration", "run/web_read — hit exposed config (/rest/admin/application-configuration), CORS, directory listing (/ftp/)"),
    ("sensitive data",     "web_read/run — pull exposed files (/ftp/), leaked keys, backup files; grep responses for secrets"),
    ("vulnerable components", "run — enumerate versions (package.json, response headers), map to a known CVE, prove the specific issue"),
    ("forgery",            "run — craft the request the server trusts (CSRF token reuse / forged review/feedback with another user's id)"),
    ("miscellaneous",      "recon-driven — read the challenge hint; often an exposed path, easter egg, or metadata leak"),
]


def _hint_for(cat: str, name: str) -> str:
    hay_cat = (cat or "").lower()
    hay_name = (name or "").lower()
    for key, hint in _TECHNIQUE_HINTS:
        if key in hay_cat or key in hay_name:
            return hint
    return "recon-first — read the challenge hint, enumerate the relevant endpoint, then pick the class tool"


# Challenges whose suggested approach names one of these has a DIRECT Basilisk
# builder — so it's the fastest to fall and sorts first within its star tier.
_TOOLED = ("nosql_injection", "jwt_forge", "xxe_payload", "captcha_solve",
           "coupon_forge", "sqlmap_plan", "reset_password", "webapp_recon")


def _has_tool(approach: str) -> int:
    """0 if Basilisk has a direct builder for this class (rank first), else 1."""
    a = (approach or "").lower()
    return 0 if any(t in a for t in _TOOLED) else 1


def next_targets(payload: Any, limit: int = 0,
                 max_difficulty: int = 0, per_tier: int = 0) -> Dict[str, Any]:
    """From a live /api/Challenges response, return the still-UNSOLVED,
    available challenges ordered easiest-first, each annotated with the
    Basilisk capability that solves its class.  This is the 'what's still red
    and how do I hit it' signal that drives the loop.

    limit          — cap the list (0 = all).
    max_difficulty — only challenges up to this star rating (0 = all); useful
                     to clear a tier before moving up.
    per_tier       — focused subset: return up to this many UNSOLVED challenges
                     from EACH star level (1-6). per_tier=5 gives the 5-per-tier,
                     ~30-challenge board. Within a tier the picks are ordered by
                     Basilisk's tooling advantage (challenges it has a direct
                     builder for come first), so the subset is the set most
                     likely to fall fast.
    Pure: reads the payload the wrapper fetched; sends nothing.
    """
    rows = _challenges_list(payload)
    if not rows:
        return {"ok": False, "error": "no challenges found — is Juice Shop up "
                "and did you hit /api/Challenges?"}
    todo: List[Dict[str, Any]] = []
    for c in rows:
        if c.get("solved"):
            continue
        if bool(c.get("disabledEnv")) or c.get("available") is False:
            continue  # disabled by safe mode — unsolvable, don't suggest it
        try:
            diff = int(c.get("difficulty", 0) or 0)
        except (TypeError, ValueError):
            diff = 0
        if max_difficulty and diff > max_difficulty:
            continue
        name = c.get("name", "?")
        cat = c.get("category", "")
        # Pull the version-matched brief straight from the LIVE instance so the
        # model knows exactly what THIS build's challenge asks — no stale/baked
        # list. description + hint ship in /api/Challenges (unless the operator
        # disabled hints); key is the stable id used in the source.
        entry = {"name": name, "difficulty": diff, "stars": "*" * diff,
                 "category": cat, "approach": _hint_for(cat, name)}
        desc = (c.get("description") or "").strip()
        if desc:
            # strip Juice Shop's HTML tags for a clean one-liner
            entry["objective"] = re.sub(r"<[^>]+>", "", desc)[:300]
        hint = (c.get("hint") or "").strip()
        if hint:
            entry["hint"] = re.sub(r"<[^>]+>", "", hint)[:300]
        if c.get("hintUrl"):
            entry["hint_url"] = c.get("hintUrl")
        if c.get("key"):
            entry["key"] = c.get("key")   # stable id — grep the source for it
        todo.append(entry)

    subset = False
    if per_tier and per_tier > 0:
        # Focused subset: up to per_tier from EACH star level, ordered within a
        # tier by tooling advantage so the picks are the fastest to fall.
        by_diff: Dict[int, List[Dict[str, Any]]] = {}
        for r in todo:
            by_diff.setdefault(r["difficulty"], []).append(r)
        picked: List[Dict[str, Any]] = []
        for d in sorted(by_diff):
            tier = sorted(by_diff[d], key=lambda r: (_has_tool(r["approach"]),
                                                     r["category"], r["name"]))
            picked.extend(tier[:per_tier])
        todo = picked
        subset = True

    # easiest-first, tooled-first within a tier
    todo.sort(key=lambda r: (r["difficulty"], _has_tool(r["approach"]),
                             r["category"], r["name"]))
    if limit and limit > 0:
        todo = todo[:limit]
    by_star: Dict[int, int] = {}
    for r in todo:
        by_star[r["difficulty"]] = by_star.get(r["difficulty"], 0) + 1
    note = ("Ordered easiest-first, and within each tier the challenges Basilisk "
            "has a direct builder for come first. Work top-down, re-score after "
            "each solve, and use diff_solved to confirm a hit before moving on.")
    if subset:
        note = (f"FOCUSED SUBSET — up to {per_tier} unsolved per star level "
                f"({len(todo)} total), the fastest-to-fall first. " + note)
    return {"ok": True, "remaining": len(todo),
            "remaining_by_star": {("*" * k): v for k, v in sorted(by_star.items())},
            "subset": subset,
            "targets": todo,
            "note": note}


def diff_solved(before: Any, after: Any) -> Dict[str, Any]:
    """Diff two /api/Challenges snapshots.  Returns which challenges went from
    unsolved to solved (your last attempt landed), and any that regressed.
    This is how the loop CONFIRMS an exploit worked instead of guessing.
    Pure."""
    def _solved_set(payload: Any) -> set:
        return {c.get("name", "?") for c in _challenges_list(payload)
                if c.get("solved")}
    b = _solved_set(before)
    a = _solved_set(after)
    newly = sorted(a - b)
    regressed = sorted(b - a)
    return {"ok": True, "newly_solved": newly, "newly_solved_count": len(newly),
            "regressed": regressed, "total_solved_now": len(a),
            "note": ("solved this round: " + ", ".join(newly)) if newly
                    else "no new solves since the last snapshot — retry with a "
                         "variation or move to the next target"}
