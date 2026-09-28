"""
bench — reproducible benchmark scoring for Basilisk.

"It beats the best" is a claim until it's a number.  This module is how you get
the number: run Basilisk's workflow against a known-vulnerable practice target you
control (OWASP Juice Shop, DVWA, …), then score what it found against that
target's KNOWN vulnerability set — the ground truth.  Out comes precision,
recall, F1, and per-category coverage: an objective, reproducible scorecard you
can put next to any other tool's, or track across your own versions.

Why this is the right lever.  You can't out-benchmark the field on vibes.  A
scorecard tells you exactly what Basilisk missed (false negatives to fix) and what
it over-reported (false positives to tighten) on a target where the right answer
is already known — so effort goes to real gaps, not imagined ones.

What's here:
  • A GROUND-TRUTH catalog for standard practice targets — the known vuln classes
    each one contains, so you know what a perfect score looks like.
  • score_run() — match a run's findings against the ground truth and compute
    TP / FP / FN, precision, recall, F1, and category coverage.  The matching is
    generous but honest: a finding counts for a ground-truth vuln if the CWE
    matches, or the vuln class matches, or the name clearly refers to it.
  • benchmark_report() — a clean markdown scorecard.
  • compare_runs() — put several scored runs side by side (Basilisk vs another tool,
    or version N vs N+1).

Contract (basilisk_ext/__init__.py): imports NOTHING from the Basilisk core; pure
stdlib; runs nothing itself (it scores results you already produced); trivially
unit-testable offline.  Ground-truth data is the public, well-known vuln makeup
of these deliberately-vulnerable training apps.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

# ── canonical vulnerability classes, and the maps onto them ──
# One label per class so a finding and a ground-truth item can be compared even
# when they use different words.
_CWE_CLASS = {
    "89": "sqli", "79": "xss", "78": "rce", "94": "rce", "1336": "ssti",
    "22": "path-traversal", "98": "path-traversal", "434": "file-upload",
    "352": "csrf", "601": "open-redirect", "918": "ssrf", "611": "xxe",
    "502": "deserialization", "327": "crypto", "326": "crypto", "916": "crypto",
    "287": "auth", "306": "auth", "521": "auth", "330": "auth", "384": "auth",
    "639": "access-control", "284": "access-control", "285": "access-control",
    "863": "access-control", "862": "access-control", "566": "access-control",
    "798": "secrets", "200": "info-exposure", "532": "info-exposure",
    "16": "misconfig", "1035": "vuln-component", "937": "vuln-component",
    "1104": "vuln-component", "77": "rce", "90": "ldap-injection",
    "943": "nosql-injection",
}

# keyword → class (lowercased substring match on a finding's name/title/category)
_KW_CLASS = [
    (("sql injection", "sqli", "sql-i"), "sqli"),
    (("nosql", "no-sql"), "nosql-injection"),
    (("cross-site scripting", "xss"), "xss"),
    (("command injection", "os command", "rce", "remote code", "code injection",
      "command inject"), "rce"),
    (("server-side template", "ssti", "template injection"), "ssti"),
    (("path traversal", "directory traversal", "lfi", "file inclusion",
      "local file", "remote file inclusion", "rfi"), "path-traversal"),
    (("file upload", "unrestricted upload", "arbitrary file upload"), "file-upload"),
    (("csrf", "cross-site request"), "csrf"),
    (("open redirect", "unvalidated redirect", "url redirect"), "open-redirect"),
    (("ssrf", "server-side request"), "ssrf"),
    (("xxe", "xml external"), "xxe"),
    (("deserial", "insecure deserialization"), "deserialization"),
    (("weak crypto", "weak hash", "md5", "sha1", "insecure cipher", "ecb",
      "weak cipher", "broken crypto"), "crypto"),
    (("broken authentication", "weak password", "default credential",
      "default creds", "brute force", "brute-force", "forged jwt", "jwt",
      "session fixation", "weak session"), "auth"),
    (("broken access", "idor", "insecure direct object", "bola", "bfla",
      "privilege escal", "role escalation", "vertical privilege",
      "horizontal privilege", "mass assignment", "mass-assignment",
      "broken object level", "broken function level", "object level authorization",
      "object-level authorization", "function level authorization",
      "function-level authorization", "authorization bypass",
      "authorisation bypass", "missing authorization", "missing function level"),
     "access-control"),
    (("business logic", "business-logic", "logic flaw", "coupon", "referral",
      "negative quantity", "quantity overflow", "price manipulation",
      "workflow bypass", "insufficient workflow"), "business-logic"),
    (("hardcoded", "hard-coded", "secret", "api key", "api-key", "credential leak",
      "exposed key", "leaked"), "secrets"),
    (("sensitive data exposure", "excessive data exposure", "data exposure",
      "information disclosure", "info leak", "information exposure",
      "enumeration", "user enumeration", "backup file", "access log"),
     "info-exposure"),
    (("misconfig", "security misconfiguration", "cors", "verbose error",
      "error handling", "csp bypass", "clickjack", "security header",
      "rate limit", "rate-limit", "no rate limiting", "missing rate"), "misconfig"),
    (("vulnerable component", "outdated", "known vulnerab", "vulnerable library",
      "vulnerable dependency", "retire", "components with known"), "vuln-component"),
    (("ldap injection",), "ldap-injection"),
]


def _classify(text: str, cwe: Any = None) -> Optional[str]:
    """Map a finding/ground-truth item to a canonical class via CWE first, then
    keywords."""
    if cwe:
        m = re.search(r"(\d+)", str(cwe))
        if m and m.group(1) in _CWE_CLASS:
            return _CWE_CLASS[m.group(1)]
    t = (text or "").lower()
    for keys, cls in _KW_CLASS:
        if any(k in t for k in keys):
            return cls
    return None


# ═════════════════════════════════════════════════════════════════════
# GROUND TRUTH — the known vuln makeup of standard practice targets.
# {id, name, cls} per expected vulnerability class.
# ═════════════════════════════════════════════════════════════════════

def _gt(id_: str, name: str, cls: str) -> Dict[str, str]:
    return {"id": id_, "name": name, "cls": cls}


_GROUND_TRUTH: Dict[str, Dict[str, Any]] = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "url_hint": "http://localhost:3000",
        "vulns": [
            _gt("js-sqli", "SQL Injection (login bypass / union)", "sqli"),
            _gt("js-xss-dom", "DOM XSS", "xss"),
            _gt("js-xss-stored", "Persisted (stored) XSS", "xss"),
            _gt("js-bac-basket", "Broken Access Control (view another basket)", "access-control"),
            _gt("js-bac-admin", "Broken Access Control (admin section)", "access-control"),
            _gt("js-auth-jwt", "Broken Authentication (forged JWT / weak secret)", "auth"),
            _gt("js-auth-pw", "Weak password / credential stuffing", "auth"),
            _gt("js-expose", "Sensitive Data Exposure (backup / access logs)", "info-exposure"),
            _gt("js-ssrf", "Server-Side Request Forgery", "ssrf"),
            _gt("js-xxe", "XML External Entity", "xxe"),
            _gt("js-redirect", "Unvalidated redirect", "open-redirect"),
            _gt("js-deserialize", "Insecure deserialization", "deserialization"),
            _gt("js-components", "Vulnerable/outdated components", "vuln-component"),
            _gt("js-misconfig", "Security misconfiguration (CORS / errors)", "misconfig"),
            _gt("js-secrets", "Exposed secrets / hardcoded keys", "secrets"),
        ],
    },
    "dvwa": {
        "name": "Damn Vulnerable Web Application",
        "url_hint": "http://localhost/dvwa",
        "vulns": [
            _gt("dv-brute", "Brute Force", "auth"),
            _gt("dv-cmdi", "Command Injection", "rce"),
            _gt("dv-csrf", "CSRF", "csrf"),
            _gt("dv-lfi", "File Inclusion (LFI/RFI)", "path-traversal"),
            _gt("dv-upload", "File Upload", "file-upload"),
            _gt("dv-sqli", "SQL Injection", "sqli"),
            _gt("dv-sqli-blind", "SQL Injection (Blind)", "sqli"),
            _gt("dv-session", "Weak Session IDs", "auth"),
            _gt("dv-xss-dom", "XSS (DOM)", "xss"),
            _gt("dv-xss-reflected", "XSS (Reflected)", "xss"),
            _gt("dv-xss-stored", "XSS (Stored)", "xss"),
            _gt("dv-csp", "CSP Bypass", "misconfig"),
            _gt("dv-authbypass", "Authorisation Bypass", "access-control"),
        ],
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "url_hint": "http://localhost:8080/WebGoat",
        "vulns": [
            _gt("wg-sqli", "SQL Injection", "sqli"),
            _gt("wg-xss", "Cross-Site Scripting", "xss"),
            _gt("wg-access", "Broken Access Control / IDOR", "access-control"),
            _gt("wg-auth", "Authentication flaws (JWT, password reset)", "auth"),
            _gt("wg-pathtraversal", "Path Traversal", "path-traversal"),
            _gt("wg-deserialize", "Insecure Deserialization", "deserialization"),
            _gt("wg-xxe", "XXE", "xxe"),
            _gt("wg-ssrf", "SSRF", "ssrf"),
            _gt("wg-crypto", "Weak/absent cryptography", "crypto"),
            _gt("wg-components", "Vulnerable Components", "vuln-component"),
        ],
    },
    # Escape's "Duck Store" — a deliberately-vulnerable REST API used as an
    # API-security scanner benchmark. The planted flaws are API-first
    # (BOLA/BFLA/mass-assignment/SSRF/business-logic), not the web-app classes
    # Juice Shop leans on.
    #
    # NOTE ON NAMING (integrity): the tool-visible `name`s below are CLASS-LEVEL
    # only — the same generality as the juice-shop entries — so calling
    # benchmark_targets('duck-store') hands out a scorecard target ("there is an
    # SSRF class here"), NOT a step-by-step exploit map. This is a GRADING answer
    # key, used by benchmark_score AFTER a run to compute coverage; it is never
    # injected into an engagement. The concrete sinks (for the operator building
    # or grading a run, not for the agent) are kept in this comment:
    #   • BOLA/IDOR ....... GET /orders/{order_id} and GET /users/{user_uuid}
    #                       ship with NO security requirement in the schema.
    #   • BFLA ............ /admin/* reachable without the admin role.
    #   • Mass assignment . PUT /users/me/profile accepts `role` -> user->admin.
    #   • SSRF ............ GET /uploads/fetch-url?url= , POST /uploads/import-from-url
    #   • SQLi ............ /products/filter/by-color `sort` (ORDER BY), search `q`
    #   • Stored XSS ...... review/testimonial `content`, product-desc link preview
    #   • Broken auth ..... /totp/verify code oracle, temp-token 2FA exchange
    #   • File upload ..... /uploads/product|avatar|general accept arbitrary bytes
    #   • Data exposure ... user enumeration via /users/, admin stats, account_credit
    #   • Misconfig ....... /orders/{id}, /orders/referrer, /orders/coupons* unauth;
    #                       no rate limiting on any endpoint.
    #   • Business logic .. non-public coupons leaked + 100%-off coupon usable,
    #                       referral-credit farming on register, negative /
    #                       overflow cart quantity, sub-cent product price.
    # Class list matches the 22-finding assessment in
    # benchmarks/duck-store-assessment-2026-07-17.txt (findings dedup to classes).
    "duck-store": {
        "name": "Escape Duck Store (vulnerable API benchmark)",
        "url_hint": "http://localhost:8080",
        "vulns": [
            _gt("ds-bola", "Broken Object Level Authorization (IDOR)", "access-control"),
            _gt("ds-bfla", "Broken Function Level Authorization (admin routes)", "access-control"),
            _gt("ds-massassign", "Mass assignment / privilege escalation", "access-control"),
            _gt("ds-ssrf", "Server-Side Request Forgery", "ssrf"),
            _gt("ds-sqli", "SQL Injection (sort / search)", "sqli"),
            _gt("ds-xss", "Stored Cross-Site Scripting", "xss"),
            _gt("ds-auth", "Broken Authentication (2FA / token handling)", "auth"),
            _gt("ds-upload", "Unrestricted file upload", "file-upload"),
            _gt("ds-expose", "Excessive data exposure / enumeration", "info-exposure"),
            _gt("ds-misconfig", "Security misconfiguration (unauth routes / no rate limit)", "misconfig"),
            _gt("ds-logic", "Business-logic flaws (coupon / referral / quantity / price)", "business-logic"),
        ],
    },
}


def benchmark_targets(target: str = "") -> Dict[str, Any]:
    """List the known-vulnerable practice targets with a ground-truth vuln set
    (or one target's full expected set if `target` is given).  Use this to see
    what a perfect score looks like before you score a run."""
    t = (target or "").strip().lower()
    if t:
        gt = _GROUND_TRUTH.get(t)
        if not gt:
            return {"ok": False, "error": f"unknown target '{target}'. Known: "
                                          + ", ".join(sorted(_GROUND_TRUTH))}
        return {"ok": True, "target": t, "name": gt["name"],
                "url_hint": gt.get("url_hint"),
                "expected_vulns": gt["vulns"],
                "expected_count": len(gt["vulns"]),
                "classes": sorted({v["cls"] for v in gt["vulns"]})}
    out = []
    for key, gt in _GROUND_TRUTH.items():
        out.append({"target": key, "name": gt["name"],
                    "expected_count": len(gt["vulns"]),
                    "classes": sorted({v["cls"] for v in gt["vulns"]})})
    return {"ok": True, "targets": out,
            "note": "Score a run with benchmark_score(target, findings). Only "
                    "benchmark against practice targets you're running locally."}


# ═════════════════════════════════════════════════════════════════════
# SCORING — findings vs ground truth.
# ═════════════════════════════════════════════════════════════════════

# The set of valid canonical classes, so an explicit class on a finding can be
# trusted rather than re-derived from its text.
_KNOWN_CLASSES = set(_CWE_CLASS.values()) | {cls for _, cls in _KW_CLASS}


def _finding_class(f: Dict[str, Any]) -> Optional[str]:
    # trust an explicit, valid class the finding already carries
    for k in ("cls", "class"):
        v = str(f.get(k, "")).strip().lower()
        if v in _KNOWN_CLASSES:
            return v
    text = " ".join(str(f.get(k, "")) for k in
                    ("title", "name", "category", "rule", "template",
                     "description"))
    return _classify(text, f.get("cwe") or f.get("cve"))


def _coerce_findings(findings: Any) -> List[Dict[str, Any]]:
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            return []
    if isinstance(findings, dict):
        if isinstance(findings.get("findings"), list):
            findings = findings["findings"]
        else:
            findings = [findings]
    return [f for f in (findings or []) if isinstance(f, dict)]


def score_run(target: str = "", findings: Any = None,
              ground_truth: Any = None, tool: str = "basilisk") -> Dict[str, Any]:
    """Score a run's findings against a target's known vulnerabilities.

    `target` selects a built-in ground truth (juice-shop | dvwa | webgoat), or
    pass your own `ground_truth` as a list of {name/cls[, cwe]}.  `findings` is
    the run's findings (triage/report output, or a bare list).  Returns
    TP / FP / FN, precision, recall, F1, and per-class coverage — the objective
    scorecard.  A finding counts for a ground-truth vuln when their class
    matches (via CWE or vuln-class keywords).
    """
    items = _coerce_findings(findings)
    # resolve ground truth
    gt_list: List[Dict[str, Any]] = []
    tname = (target or "").strip().lower()
    if ground_truth:
        raw = ground_truth
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = []
        for g in (raw or []):
            if isinstance(g, dict):
                cls = g.get("cls") or _classify(
                    g.get("name", "") + " " + g.get("category", ""), g.get("cwe"))
                gt_list.append({"id": g.get("id") or g.get("name", "gt"),
                                "name": g.get("name", ""), "cls": cls})
        gt_name = target or "custom"
    elif tname in _GROUND_TRUTH:
        gt_list = [dict(v) for v in _GROUND_TRUTH[tname]["vulns"]]
        gt_name = _GROUND_TRUTH[tname]["name"]
    else:
        return {"ok": False, "error": f"no ground truth: pass a known target "
                                      f"({', '.join(sorted(_GROUND_TRUTH))}) or a "
                                      f"ground_truth list."}
    if not gt_list:
        return {"ok": False, "error": "ground truth is empty"}

    # classify findings
    found_classes: Dict[str, int] = {}
    unclassified = 0
    for f in items:
        c = _finding_class(f)
        if c:
            found_classes[c] = found_classes.get(c, 0) + 1
        else:
            unclassified += 1

    gt_classes = {}
    for g in gt_list:
        if g["cls"]:
            gt_classes.setdefault(g["cls"], []).append(g)

    # match: a ground-truth class is HIT if at least one finding shares its class
    hits, misses = [], []
    for cls, gts in gt_classes.items():
        if found_classes.get(cls):
            hits.append(cls)
        else:
            misses.append(cls)

    # TP counted per ground-truth CLASS covered (dedup: many findings of one
    # class still prove that one class); FN = classes with no finding.
    tp = len(hits)
    fn = len(misses)
    # FP = finding classes that aren't in the ground truth at all + unclassified
    extra_classes = [c for c in found_classes if c not in gt_classes]
    fp = len(extra_classes) + unclassified

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    coverage = []
    for cls in sorted(gt_classes):
        names = [g["name"] for g in gt_classes[cls]]
        coverage.append({"class": cls, "found": cls in hits,
                         "ground_truth_items": names,
                         "finding_hits": found_classes.get(cls, 0)})

    return {
        "ok": True,
        "tool": tool,
        "target": gt_name,
        "score": {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "coverage_pct": round(100.0 * tp / len(gt_classes), 1) if gt_classes else 0.0,
        },
        "counts": {"true_positive_classes": tp, "false_negative_classes": fn,
                   "false_positive_classes": fp, "findings_scored": len(items),
                   "unclassified_findings": unclassified},
        "found_classes": sorted(hits),
        "missed_classes": sorted(misses),
        "extra_classes": sorted(extra_classes),
        "coverage": coverage,
        "note": "coverage_pct = ground-truth vuln classes with at least one "
                "matching finding. Missed classes are the real gaps to close; "
                "extra/unclassified are possible false positives to check.",
    }


def benchmark_report(scored: Any) -> Dict[str, Any]:
    """Render a scored run (the dict from score_run) as a clean markdown
    scorecard — comparison-ready numbers, what was covered, what was missed."""
    if isinstance(scored, str):
        try:
            scored = json.loads(scored)
        except Exception:
            return {"ok": False, "error": "scored must be a score_run result"}
    if not isinstance(scored, dict) or not scored.get("score"):
        return {"ok": False, "error": "not a score_run result"}
    s = scored["score"]
    c = scored["counts"]
    md = [f"# Benchmark — {scored.get('tool','kali')} vs {scored.get('target','target')}", ""]
    md.append(f"**Coverage:** {s['coverage_pct']}%  ·  "
              f"**Precision:** {s['precision']}  ·  "
              f"**Recall:** {s['recall']}  ·  **F1:** {s['f1']}")
    md.append("")
    md.append(f"- Vuln classes found: **{c['true_positive_classes']}** · "
              f"missed: **{c['false_negative_classes']}** · "
              f"possible false positives: **{c['false_positive_classes']}**")
    md.append(f"- Findings scored: {c['findings_scored']} "
              f"({c['unclassified_findings']} unclassified)")
    md.append("")
    md.append("| Vuln class | Found? | Ground-truth items |")
    md.append("|---|:---:|---|")
    for row in scored.get("coverage", []):
        mark = "✅" if row["found"] else "❌"
        items = "; ".join(row["ground_truth_items"])[:80]
        md.append(f"| {row['class']} | {mark} | {items} |")
    md.append("")
    if scored.get("missed_classes"):
        md.append(f"**Gaps to close:** {', '.join(scored['missed_classes'])}")
    if scored.get("extra_classes"):
        md.append(f"**Check for false positives:** {', '.join(scored['extra_classes'])}")
    return {"ok": True, "report_markdown": "\n".join(md) + "\n",
            "coverage_pct": s["coverage_pct"], "f1": s["f1"]}


def compare_runs(runs: Any) -> Dict[str, Any]:
    """Put several scored runs side by side (Basilisk vs another tool, or version N
    vs N+1).  `runs` is a list of score_run results.  Returns a ranked table by
    F1, so 'beats the best' becomes a sortable column instead of an assertion."""
    if isinstance(runs, str):
        try:
            runs = json.loads(runs)
        except Exception:
            return {"ok": False, "error": "runs must be a list of score_run results"}
    rows = []
    for r in (runs or []):
        if isinstance(r, dict) and r.get("score"):
            rows.append({
                "tool": r.get("tool", "?"),
                "target": r.get("target", "?"),
                "coverage_pct": r["score"]["coverage_pct"],
                "precision": r["score"]["precision"],
                "recall": r["score"]["recall"],
                "f1": r["score"]["f1"],
                "missed": r.get("missed_classes", []),
            })
    if not rows:
        return {"ok": False, "error": "no scored runs to compare"}
    rows.sort(key=lambda x: (x["f1"], x["coverage_pct"]), reverse=True)
    md = ["# Benchmark comparison", "",
          "| Tool | Target | Coverage | Precision | Recall | F1 |",
          "|---|---|---:|---:|---:|---:|"]
    for x in rows:
        md.append(f"| {x['tool']} | {x['target']} | {x['coverage_pct']}% | "
                  f"{x['precision']} | {x['recall']} | **{x['f1']}** |")
    return {"ok": True, "ranked": rows, "winner": rows[0]["tool"],
            "report_markdown": "\n".join(md) + "\n"}
