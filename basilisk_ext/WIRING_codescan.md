# Wiring `codescan` into Basilisk

`basilisk_ext/codescan.py` is self-contained (imports nothing from core, stdlib
only, 35/35 offline tests pass). To expose its five capabilities as
model-callable tools, add the blocks below. Same pattern as the pentest tools —
nothing here changes existing behaviour, it only adds five tools.

Five tools: `code_tooling_check`, `code_scan_plan`, `parse_scan`,
`triage_findings`, `remediation_hint`. All are pure-local, no-network,
no-execution — so they go in the *batchable* set alongside `tooling_check`.

---

## 1) `basilisk_core.py` — add five wrappers

Paste next to `tool_tooling_check` (after the pentest wrappers, ~line 4045):

```python
def tool_code_tooling_check() -> Dict[str, Any]:
    """Inventory the code-security scanners installed on this box (SAST / SCA /
    secrets / IaC / container / web-DAST), with install lines for the gaps.
    Read-only — runs nothing but `which`."""
    try:
        from basilisk_ext import codescan as _cs
    except Exception as e:
        return {"ok": False, "error": f"codescan module unavailable: {e}"}
    try:
        return _cs.code_tooling_check()
    except Exception as e:
        return {"ok": False, "error": f"code_tooling_check failed: {e}"}


def tool_code_scan_plan(path: str = ".", kind: str = "auto",
                        intensity: str = "normal") -> Dict[str, Any]:
    """Build an ordered, PROPOSED scan plan for a code path/app (kind = auto |
    python | node | go | deps | secrets | iac | container | web). Auto-detects
    languages/lockfiles/IaC and sets JSON-output flags so results feed
    parse_scan. Runs NOTHING — every step goes through the approve gate."""
    try:
        from basilisk_ext import codescan as _cs
    except Exception as e:
        return {"ok": False, "error": f"codescan module unavailable: {e}"}
    try:
        return _cs.scan_plan((path or ".").strip(),
                             (kind or "auto").strip().lower(),
                             (intensity or "normal").strip().lower())
    except Exception as e:
        return {"ok": False, "error": f"code_scan_plan failed: {e}"}


def tool_parse_scan(tool: str, raw: str) -> Dict[str, Any]:
    """Normalise raw scanner JSON (semgrep, bandit, gitleaks, trufflehog,
    osv-scanner, trivy, pip-audit, npm audit, retire.js, nuclei) into one
    unified finding schema. Read-only text parsing."""
    try:
        from basilisk_ext import codescan as _cs
    except Exception as e:
        return {"ok": False, "error": f"codescan module unavailable: {e}"}
    try:
        return _cs.parse_scan((tool or "").strip().lower(), raw or "")
    except Exception as e:
        return {"ok": False, "error": f"parse_scan failed: {e}"}


def tool_triage_findings(findings: Any) -> Dict[str, Any]:
    """Merge findings from any number of scanners: dedup across tools (same
    CVE+package or file:line:rule collapse to one, recording which scanners
    agreed), one severity scale (highest wins), sort worst-first, and flag the
    low-confidence / needs-manual-confirmation ones. Pure offline heuristics."""
    try:
        from basilisk_ext import codescan as _cs
    except Exception as e:
        return {"ok": False, "error": f"codescan module unavailable: {e}"}
    try:
        return _cs.triage(findings)
    except Exception as e:
        return {"ok": False, "error": f"triage_findings failed: {e}"}


def tool_remediation_hint(finding: Any) -> Dict[str, Any]:
    """Short, standard, NON-EXPLOIT remediation pointer for a normalised
    finding: fixed-version upgrade (SCA), else the CWE-class fix, else a
    generic pointer. Reference knowledge only."""
    try:
        from basilisk_ext import codescan as _cs
    except Exception as e:
        return {"ok": False, "error": f"codescan module unavailable: {e}"}
    try:
        return _cs.remediation_hint(finding)
    except Exception as e:
        return {"ok": False, "error": f"remediation_hint failed: {e}"}
```

---

## 2) `basilisk.py` — import the wrappers (~line 48)

Extend the existing import from `basilisk_core`:

```python
    tool_nuclei_template, tool_reflect_findings,
    tool_code_tooling_check, tool_code_scan_plan, tool_parse_scan,
    tool_triage_findings, tool_remediation_hint,
```

## 3) `basilisk.py` — progress labels (~line 4512, in the label dict)

```python
        "code_tooling_check": "checking code scanners",
        "code_scan_plan":     "planning the code scan",
        "parse_scan":         "parsing scanner output",
        "triage_findings":    "triaging findings",
        "remediation_hint":   "looking up the fix",
```

## 4) `basilisk.py` — batchable resolver (Site A, ~line 4962)

These are pure-local (no network, no execution), so add them to the batchable
`if n == …` block next to `tooling_check`:

```python
        if n == "code_tooling_check":
            return lambda: tool_code_tooling_check()
        if n == "code_scan_plan":
            return lambda: tool_code_scan_plan(
                a.get("path", a.get("dir", a.get("target", "."))),
                a.get("kind", a.get("type", "auto")),
                a.get("intensity", a.get("depth", "normal")))
        if n == "parse_scan":
            return lambda: tool_parse_scan(
                a.get("tool", a.get("scanner", a.get("name", ""))),
                a.get("raw", a.get("output", a.get("json", a.get("text", "")))))
        if n == "triage_findings":
            return lambda: tool_triage_findings(
                a.get("findings", a.get("items", [])))
        if n == "remediation_hint":
            return lambda: tool_remediation_hint(
                a.get("finding", a.get("item", a)))
```

## 5) `basilisk.py` — main dispatch dict (Site B, ~line 5326)

Add next to the `"tooling_check": …` entry:

```python
            "code_tooling_check": lambda a: self._tool_simple(
                lambda: tool_code_tooling_check()),
            "code_scan_plan":     lambda a: self._tool_simple(
                lambda: tool_code_scan_plan(
                    a.get("path", a.get("dir", a.get("target", "."))),
                    a.get("kind", a.get("type", "auto")),
                    a.get("intensity", a.get("depth", "normal")))),
            "parse_scan":         lambda a: self._tool_simple(
                lambda: tool_parse_scan(
                    a.get("tool", a.get("scanner", a.get("name", ""))),
                    a.get("raw", a.get("output", a.get("json", a.get("text", "")))))),
            "triage_findings":    lambda a: self._tool_simple(
                lambda: tool_triage_findings(
                    a.get("findings", a.get("items", [])))),
            "remediation_hint":   lambda a: self._tool_simple(
                lambda: tool_remediation_hint(
                    a.get("finding", a.get("item", a)))),
```

---

## 6) `basilisk_persona.py` — tell the model the tools exist

**(a)** Add a catalog block. Paste after the `nuclei_template` line in the
PENTEST SUPPORT section (~line 383):

```
  ── (1f) CODE & DEPENDENCY AUDIT — find vulns in source, not just live hosts ──
  The static/dependency counterpart to the recon workflow. Safe on his OWN
  code: SAST reads source, SCA reads lockfiles, secrets scans code+history.
  Nothing here attacks anything or writes exploits — it drives standard
  installed scanners, then structures and triages what they find. The DAST
  scanners it can plan (nuclei/nikto) are authorised-targets-only, same gate.

  <tool name="code_tooling_check">{}</tool>  // which code scanners are installed (SAST/SCA/secrets/IaC/container/DAST) + install lines for gaps
  <tool name="code_scan_plan">{"path": ".", "kind": "auto"}</tool>  // ordered PROPOSED scan commands (auto-detects python/node/go/lockfiles/IaC); kind: auto|python|node|go|deps|secrets|iac|container|web
  <tool name="parse_scan">{"tool": "semgrep", "raw": "<scanner JSON you captured>"}</tool>  // normalise semgrep|bandit|gitleaks|trufflehog|osv-scanner|trivy|pip-audit|npm|retire|nuclei JSON → one finding schema
  <tool name="triage_findings">{"findings": [ … normalised findings … ]}</tool>  // dedup across scanners (2 tools agreeing = sturdier), one severity scale, sort, flag the ones needing manual confirmation
  <tool name="remediation_hint">{"finding": { … one normalised finding … }}</tool>  // standard non-exploit fix pointer (upgrade to fixed version / CWE-class fix)

  // Code-audit workflow: code_tooling_check → code_scan_plan (propose each
  // scan, approve, run) → parse_scan each tool's JSON → triage_findings to
  // merge+dedup → reflect_findings → report_findings. For dependency findings,
  // enrich_with_cves adds KEV/EPSS ranking (each carries its CVE). Only scan
  // code he owns or is authorised to assess.
```

**(b)** Add the five names to the two roster lists (the comma-lists at
~line 538 and ~line 641) so the summaries stay accurate, e.g.:

```
    …, tooling_check, pentest_plan, code_tooling_check, code_scan_plan,
    parse_scan, triage_findings, remediation_hint, …
```

---

## After wiring — smoke test

```bash
python3 -c "from basilisk_ext import codescan as c; print(c.code_tooling_check()['summary'])"
```

Then in-app: ask Basilisk to `code_scan_plan` on a repo path, approve the
`semgrep`/`osv-scanner` steps it proposes, paste their JSON back for
`parse_scan`, and `triage_findings` to merge. Every scan still runs through the
approve gate and lands in the evidence ledger like any other command.
