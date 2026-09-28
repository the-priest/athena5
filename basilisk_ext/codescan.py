"""
codescan — code & dependency vulnerability assessment for Basilisk.

The companion to pentest.py, aimed at the *other half* of the job: finding
vulnerabilities in source, dependencies, secrets and IaC rather than in a live
network target.  Same design contract as the rest of basilisk_ext — it imports
NOTHING from the Basilisk core, is pure stdlib, runs nothing itself, and writes no
exploit code.  It orchestrates standard, installed, battle-tested scanners
(the same engines the expensive commercial suites are built around), turns
their noisy output into one clean finding schema, and triages across them so
the real signal survives.

Five capabilities, all read-only or propose-only:

  1. code_tooling_check() — which code-security scanners are actually installed
     on THIS box, grouped (SAST / SCA / secrets / IaC / container / web-DAST),
     with the exact install line for the gaps.  The code-audit analogue of
     pentest.tooling_check().

  2. scan_plan()          — a correct, ORDERED scan plan for a path or app:
     the right scanners for what's there (auto-detects Python / JS / Go / IaC
     / lockfiles), in a sensible order, with JSON-output flags already set so
     the results feed straight into parse_scan().  It returns the plan; it
     does NOT run it.  Every command is still PROPOSED through the operator's
     approve-before-run gate, one at a time.

  3. parse_scan()         — normalise raw scanner JSON (semgrep, bandit,
     gitleaks, trufflehog, osv-scanner, trivy, pip-audit, npm audit, retire.js,
     nuclei) into one unified finding schema, so ten tools speak one language.

  4. triage()             — dedup across scanners (two tools flagging the same
     file:line, or the same CVE on the same package, collapse to one), map
     every tool's idiosyncratic severity onto one scale, sort by real risk,
     and flag the low-confidence / needs-manual-confirmation ones.  The bridge
     between raw scanner noise and a report you can defend.

  5. remediation_hint()   — for a normalised finding, a short, standard,
     non-exploit remediation pointer (upgrade to the fixed version, the CWE
     class fix, the config change).  Reference knowledge, not attack code.

Nothing here attacks anything, and nothing here writes exploits or payloads:
the scanners already contain their (defensive, published) detection logic; this
module drives them, structures the result, and reasons about it.  Scope and
authorisation stay the operator's to set; a scan of code you weren't authorised
to assess is on you, not the tool.  CVE/KEV/EPSS enrichment already lives in
pentest.enrich_with_cves — a triaged SCA finding carries its CVE id so that
chain still works.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

# ── one severity scale, and the map from every scanner's dialect onto it ──
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
             "unknown": 5, "": 5, None: 5}

# Each scanner labels severity its own way.  Normalise to our five levels.
_SEV_ALIAS = {
    # generic
    "critical": "critical", "crit": "critical",
    "high": "high", "error": "high", "severe": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "minor": "low",
    "info": "info", "informational": "info", "note": "info", "unknown": "info",
    # numeric CVSS buckets some tools emit as strings
}


def _norm_sev(s: Any) -> str:
    v = str(s or "").strip().lower()
    if v in _SEV_ALIAS:
        return _SEV_ALIAS[v]
    # a bare CVSS number → bucket it
    try:
        f = float(v)
        if f >= 9.0:
            return "critical"
        if f >= 7.0:
            return "high"
        if f >= 4.0:
            return "medium"
        if f > 0:
            return "low"
    except (ValueError, TypeError):
        pass
    return "info"


# ═════════════════════════════════════════════════════════════════════
# TOOLING — the modern code-security stack, grouped, with install lines.
# {tool: {grp, use, apt/pipx/go/npm}}.  Install hints prefer the packaged
# route, then pipx / go install / npm -g.
# ═════════════════════════════════════════════════════════════════════

_CODE_TOOLS: Dict[str, Dict[str, str]] = {
    # ── SAST (source static analysis) ──
    "semgrep":     {"grp": "sast", "use": "multi-language static analysis (thousands of rules)",
                    "pipx": "semgrep"},
    "bandit":      {"grp": "sast", "use": "Python security linter",
                    "pipx": "bandit"},
    "gosec":       {"grp": "sast", "use": "Go security checker",
                    "go": "github.com/securego/gosec/v2/cmd/gosec@latest"},
    "brakeman":    {"grp": "sast", "use": "Ruby on Rails static analysis",
                    "apt": "brakeman"},
    # ── SCA (dependency / lockfile CVEs) ──
    "osv-scanner": {"grp": "sca", "use": "lockfile → OSV vuln database (Google)",
                    "go": "github.com/google/osv-scanner/cmd/osv-scanner@latest"},
    "trivy":       {"grp": "sca", "use": "deps + containers + IaC vuln scanner",
                    "apt": "trivy"},
    "pip-audit":   {"grp": "sca", "use": "Python dependency CVEs (PyPI advisory DB)",
                    "pipx": "pip-audit"},
    "npm":         {"grp": "sca", "use": "Node dependency CVEs (`npm audit`)",
                    "apt": "npm"},
    "retire":      {"grp": "sca", "use": "known-vulnerable JS libraries (retire.js)",
                    "npm": "retire"},
    # ── secrets (leaked creds / keys in code & history) ──
    "gitleaks":    {"grp": "secrets", "use": "secrets in code and git history",
                    "apt": "gitleaks"},
    "trufflehog":  {"grp": "secrets", "use": "secrets with live-verification",
                    "go": "github.com/trufflesecurity/trufflehog/v3@latest"},
    # ── IaC / config ──
    "checkov":     {"grp": "iac", "use": "Terraform/CloudFormation/K8s misconfig",
                    "pipx": "checkov"},
    "kics":        {"grp": "iac", "use": "IaC misconfiguration (multi-format)",
                    "apt": "kics"},
    # ── container image ──
    "grype":       {"grp": "container", "use": "container image / filesystem CVEs",
                    "go": "github.com/anchore/grype@latest"},
    # ── web DAST (dynamic — needs a running, authorised target) ──
    "nuclei":      {"grp": "dast", "use": "templated web vuln scanning (authorised targets)",
                    "apt": "nuclei"},
    "nikto":       {"grp": "dast", "use": "web server misconfig scanner",
                    "apt": "nikto"},
    "sqlmap":      {"grp": "dast", "use": "SQL-injection detection (authorised targets)",
                    "apt": "sqlmap"},
    "dalfox":      {"grp": "dast", "use": "XSS detection (authorised targets)",
                    "apt": "dalfox"},
}

_GROUP_ORDER = ["sast", "sca", "secrets", "iac", "container", "dast"]
_GROUP_LABEL = {
    "sast": "SAST (source static analysis)",
    "sca": "SCA (dependency CVEs)",
    "secrets": "secrets",
    "iac": "IaC / config",
    "container": "container image",
    "dast": "web DAST (running target)",
}

# Some tools are invoked under a different binary name than the key above.
_BIN_ALIAS = {"pip-audit": ["pip-audit", "pip_audit"], "npm": ["npm"],
              "retire": ["retire"], "osv-scanner": ["osv-scanner", "osv_scanner"]}


def _install_hint(meta: Dict[str, str]) -> str:
    # Distro-aware when running inside Basilisk; apt fallback if core isn't
    # importable (standalone test use).
    try:
        from basilisk_core import translate_install_meta as _tim
        h = _tim(meta)
        if h:
            return h
    except Exception:
        pass
    if meta.get("apt"):
        return f"sudo apt install -y {meta['apt']}"
    if meta.get("pipx"):
        return f"pipx install {meta['pipx']}"
    if meta.get("go"):
        return f"go install -v {meta['go']}"
    if meta.get("npm"):
        return f"npm install -g {meta['npm']}"
    return ""


def _which(tool: str) -> Optional[str]:
    for c in _BIN_ALIAS.get(tool, [tool]):
        p = shutil.which(c)
        if p:
            return p
    return None


def code_tooling_check() -> Dict[str, Any]:
    """Inventory the code-security scanners installed on this box, grouped by
    role (SAST / SCA / secrets / IaC / container / web-DAST), with the install
    line for the gaps.  Read-only — runs nothing but `which`."""
    present: Dict[str, str] = {}
    missing: Dict[str, str] = {}
    for tool, meta in _CODE_TOOLS.items():
        path = _which(tool)
        if path:
            present[tool] = path
        else:
            missing[tool] = _install_hint(meta)

    groups: Dict[str, Dict[str, List[str]]] = {}
    for tool, meta in _CODE_TOOLS.items():
        g = meta["grp"]
        groups.setdefault(g, {"present": [], "missing": []})
        groups[g]["present" if tool in present else "missing"].append(tool)

    grp_lines = []
    for g in _GROUP_ORDER:
        if g not in groups:
            continue
        have = groups[g]["present"]
        gap = groups[g]["missing"]
        grp_lines.append({
            "group": g,
            "label": _GROUP_LABEL.get(g, g),
            "present": have,
            "missing": gap,
            "covered": bool(have),
        })

    install_gaps = [f"{t}: {hint}" for t, hint in missing.items() if hint]
    uncovered = [gl["label"] for gl in grp_lines if not gl["covered"]]

    return {
        "ok": True,
        "summary": f"{len(present)}/{len(_CODE_TOOLS)} code-security tools present"
                   + (f"; no coverage for: {', '.join(uncovered)}" if uncovered else
                      "; every category covered"),
        "present": present,
        "missing": missing,
        "groups": grp_lines,
        "install_gaps": install_gaps,
        "note": "SAST reads source, SCA reads lockfiles, secrets scans code+history — "
                "all safe on your own code. DAST tools (nuclei/nikto/sqlmap/dalfox) hit a "
                "RUNNING target and are authorised-targets-only.",
    }


# ═════════════════════════════════════════════════════════════════════
# SCAN PLAN — ordered, PROPOSED scan commands for a path/app.  Runs nothing.
# ═════════════════════════════════════════════════════════════════════

# lockfile / manifest → ecosystem, used both to detect languages and to know
# which SCA tool applies.
_LOCKFILES = {
    "requirements.txt": "python", "poetry.lock": "python", "Pipfile.lock": "python",
    "package-lock.json": "node", "yarn.lock": "node", "pnpm-lock.yaml": "node",
    "go.sum": "go", "go.mod": "go",
    "Gemfile.lock": "ruby", "Cargo.lock": "rust", "composer.lock": "php",
}
_SRC_EXT = {".py": "python", ".js": "node", ".ts": "node", ".jsx": "node",
            ".tsx": "node", ".go": "go", ".rb": "ruby", ".php": "php",
            ".java": "java", ".rs": "rust", ".c": "c", ".cpp": "c"}
_IAC_HINTS = {".tf": "terraform", ".yaml": "k8s?", ".yml": "k8s?",
              "Dockerfile": "docker"}


def _detect(path: str) -> Dict[str, Any]:
    """Lightweight, read-only walk (depth-limited) to see what's in the tree:
    languages present, lockfiles present, IaC present.  Never follows into the
    usual noise dirs."""
    langs: Dict[str, int] = {}
    locks: Dict[str, str] = {}
    iac: Dict[str, int] = {}
    skip = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist",
            "build", "vendor", ".mypy_cache", ".tox"}
    root = path if os.path.isdir(path) else os.path.dirname(path) or "."
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        # depth limit: don't descend forever on huge trees
        depth = dirpath[len(root):].count(os.sep)
        if depth > 6:
            dirnames[:] = []
            continue
        for fn in filenames:
            seen += 1
            if seen > 20000:
                break
            if fn in _LOCKFILES:
                locks[fn] = _LOCKFILES[fn]
                langs[_LOCKFILES[fn]] = langs.get(_LOCKFILES[fn], 0) + 1
            if fn == "Dockerfile" or fn.startswith("Dockerfile"):
                iac["docker"] = iac.get("docker", 0) + 1
            _, ext = os.path.splitext(fn)
            if ext in _SRC_EXT:
                langs[_SRC_EXT[ext]] = langs.get(_SRC_EXT[ext], 0) + 1
            if ext == ".tf":
                iac["terraform"] = iac.get("terraform", 0) + 1
    return {"root": root, "languages": langs, "lockfiles": locks, "iac": iac}


def _cmd(cmd: str, why: str, risk: str, tool: str, needs: str = "") -> Dict[str, str]:
    d = {"cmd": cmd, "why": why, "risk": risk, "tool": tool}
    if needs:
        d["needs"] = needs
    return d


def scan_plan(path: str = ".", kind: str = "auto",
              intensity: str = "normal") -> Dict[str, Any]:
    """Build an ordered, PROPOSED scan plan for a code path or app.

    `kind` = auto | python | node | go | deps | secrets | iac | container | web.
    `auto` inspects the tree and picks what applies.  `intensity` tunes depth
    (light | normal | deep).  Every step is a proposed command with JSON-output
    flags already set so parse_scan() can consume it; NOTHING is executed here.
    A step whose tool isn't installed is marked so.
    """
    kind = (kind or "auto").strip().lower()
    intensity = (intensity or "normal").strip().lower()
    p = (path or ".").strip() or "."
    det = _detect(p) if kind in ("auto", "python", "node", "go") else {
        "root": p, "languages": {}, "lockfiles": {}, "iac": {}}
    root = det["root"]

    def have(tool: str) -> bool:
        return _which(tool) is not None

    def add(steps: List[Dict[str, str]], tool: str, cmd: str, why: str, risk: str):
        needs = "" if have(tool) else _install_hint(_CODE_TOOLS.get(tool, {}))
        steps.append(_cmd(cmd, why, risk, tool, needs))

    steps: List[Dict[str, str]] = []
    langs = det["languages"]

    # `intensity` now actually tunes the scan (it was previously a no-op: every
    # level mapped to "" and the value was never read).  It changes how deep the
    # SAST pass goes and whether the slow live-secret verifier runs:
    #   light  → fast curated semgrep ruleset (p/ci), skip trufflehog's network
    #            verification — a quick first-look pass
    #   normal → semgrep `auto` ruleset, full tool set (default)
    #   deep   → auto + the security-audit ruleset, and drop semgrep's file-size
    #            cap so large/minified files are scanned too
    if intensity not in ("light", "normal", "deep"):
        intensity = "normal"
    _semgrep_cfg = {
        "light":  "--config p/ci",
        "normal": "--config auto",
        "deep":   "--config auto --config p/security-audit",
    }[intensity]
    _semgrep_extra = " --max-target-bytes 0" if intensity == "deep" else ""

    want_sast = kind in ("auto", "python", "node", "go")
    want_sca = kind in ("auto", "python", "node", "go", "deps")
    want_secrets = kind in ("auto", "secrets")
    want_iac = kind in ("auto", "iac") or bool(det["iac"])
    want_container = kind == "container"
    want_web = kind == "web"

    # ── secrets first: cheap, and you want to know before you share anything ──
    if want_secrets:
        add(steps, "gitleaks",
            f"gitleaks detect --source {root} --report-format json "
            f"--report-path gitleaks.json --no-banner",
            "leaked secrets/keys in code and git history", "safe")
        if intensity != "light":
            add(steps, "trufflehog",
                f"trufflehog filesystem {root} --json > trufflehog.json",
                "secrets with live-verification (Verified flag)", "safe")

    # ── SAST: language-aware ──
    if want_sast:
        if kind == "auto" or "python" in langs or kind == "python":
            add(steps, "semgrep",
                f"semgrep {_semgrep_cfg} --json{_semgrep_extra} "
                f"--output semgrep.json {root}",
                f"multi-language static analysis ({intensity} ruleset)", "safe")
            if "python" in langs or kind == "python":
                add(steps, "bandit",
                    f"bandit -r {root} -f json -o bandit.json",
                    "Python-specific security linting", "safe")
        if "go" in langs or kind == "go":
            add(steps, "gosec",
                f"gosec -fmt=json -out=gosec.json {root}/...",
                "Go static security analysis", "safe")

    # ── SCA: only the ecosystems actually present ──
    if want_sca:
        add(steps, "osv-scanner",
            f"osv-scanner --format json --recursive {root} > osv.json",
            "lockfile dependencies → OSV vuln database", "safe")
        if "python" in langs or kind in ("python", "deps"):
            add(steps, "pip-audit",
                "pip-audit --format json --output pip-audit.json",
                "Python deps → PyPI advisory DB (run in the project venv)", "safe")
        if "node" in langs or kind in ("node", "deps"):
            add(steps, "npm",
                "npm audit --json > npm-audit.json",
                "Node deps → npm advisory DB (run where package-lock.json is)", "safe")

    # ── IaC / config ──
    if want_iac:
        add(steps, "checkov",
            f"checkov -d {root} -o json > checkov.json",
            "IaC misconfiguration (Terraform/K8s/CFN)", "safe")

    # ── container image (explicit) ──
    if want_container:
        add(steps, "trivy",
            "trivy image --format json --output trivy.json <IMAGE:TAG>",
            "container image CVEs — replace <IMAGE:TAG>", "safe")
        add(steps, "grype",
            "grype <IMAGE:TAG> -o json > grype.json",
            "second-opinion image CVE scan", "safe")

    # ── web DAST (running, authorised target) ──
    if want_web:
        add(steps, "nuclei",
            "nuclei -u <URL> -jsonl -o nuclei.jsonl",
            "templated web vuln scan — AUTHORISED target only", "active")
        add(steps, "nikto",
            "nikto -h <URL> -Format json -output nikto.json",
            "web server misconfig — AUTHORISED target only", "active")

    installed = [s for s in steps if not s.get("needs")]
    gaps = sorted({s["tool"] for s in steps if s.get("needs")})

    return {
        "ok": True,
        "path": root,
        "kind": kind,
        "intensity": intensity,
        "detected": {"languages": langs, "lockfiles": det["lockfiles"],
                     "iac": det["iac"]},
        "summary": (f"{len(steps)} scan step(s) for "
                    f"{', '.join(langs) or 'this path'}"
                    + (f"; {len(gaps)} tool(s) not installed: {', '.join(gaps)}"
                       if gaps else "; all planned tools present")),
        "steps": steps,
        "runnable_now": len(installed),
        "missing_tools": gaps,
        "note": "Each step is PROPOSED — Basilisk runs none of them; they go through the "
                "approve-before-run gate one at a time. SAST/SCA/secrets steps are safe on "
                "your own code. 'active' steps touch a running target and are "
                "authorised-targets-only. Feed each tool's JSON to parse_scan, then triage.",
    }


# ═════════════════════════════════════════════════════════════════════
# PARSE — normalise raw scanner JSON into ONE finding schema.
# unified finding: {tool, severity, title, file, line, rule, cwe, package,
#                   version, fixed, cve, confidence, description, fix, refs}
# ═════════════════════════════════════════════════════════════════════

def _f(tool: str, **kw) -> Dict[str, Any]:
    """Build a unified finding with all keys present (None where unknown)."""
    base = {"tool": tool, "severity": "info", "title": "", "file": None,
            "line": None, "rule": None, "cwe": None, "package": None,
            "version": None, "fixed": None, "cve": None, "confidence": None,
            "description": "", "fix": None, "refs": []}
    base.update(kw)
    base["severity"] = _norm_sev(base["severity"])
    return base


def _loads(raw: str) -> Any:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        # tolerate JSONL (one object per line) — return a list
        rows = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                continue
        return rows or None


def _cwe_str(v: Any) -> Optional[str]:
    """Normalise a CWE from the many shapes tools emit → 'CWE-89'."""
    if v is None:
        return None
    if isinstance(v, dict):
        v = v.get("id") or v.get("cwe") or v.get("CWE")
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    s = str(v)
    m = re.search(r"(\d+)", s)
    return f"CWE-{m.group(1)}" if m else None


def _first_cve(*vals: Any) -> Optional[str]:
    for val in vals:
        for item in (val if isinstance(val, list) else [val]):
            m = re.search(r"CVE-\d{4}-\d{3,7}", str(item or ""), re.IGNORECASE)
            if m:
                return m.group(0).upper()
    return None


def _parse_semgrep(data: Any) -> List[Dict[str, Any]]:
    out = []
    results = data.get("results", []) if isinstance(data, dict) else []
    for r in results:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        out.append(_f(
            "semgrep",
            severity=extra.get("severity", "info"),
            title=(extra.get("message") or r.get("check_id") or "").split("\n")[0][:200],
            file=r.get("path"),
            line=(r.get("start", {}) or {}).get("line"),
            rule=r.get("check_id"),
            cwe=_cwe_str(meta.get("cwe")),
            cve=_first_cve(meta.get("cve"), meta.get("references")),
            description=(extra.get("message") or "").strip(),
            fix=extra.get("fix"),
            refs=[u for u in (meta.get("references") or []) if isinstance(u, str)][:5],
        ))
    return out


def _parse_bandit(data: Any) -> List[Dict[str, Any]]:
    out = []
    results = data.get("results", []) if isinstance(data, dict) else []
    for r in results:
        out.append(_f(
            "bandit",
            severity=r.get("issue_severity", "info"),
            title=(r.get("issue_text") or r.get("test_name") or "")[:200],
            file=r.get("filename"),
            line=r.get("line_number"),
            rule=r.get("test_id"),
            cwe=_cwe_str(r.get("issue_cwe")),
            confidence=str(r.get("issue_confidence") or "").lower() or None,
            description=(r.get("issue_text") or "").strip(),
            refs=[r["more_info"]] if r.get("more_info") else [],
        ))
    return out


def _parse_gitleaks(data: Any) -> List[Dict[str, Any]]:
    out = []
    rows = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
    for r in rows:
        out.append(_f(
            "gitleaks",
            severity="high",  # a live secret is high by default
            title=(r.get("Description") or r.get("RuleID") or "secret")[:200],
            file=r.get("File"),
            line=r.get("StartLine"),
            rule=r.get("RuleID"),
            confidence="medium",  # gitleaks doesn't verify — needs a look
            description=f"Potential secret ({r.get('RuleID','?')}) in "
                        f"{r.get('File','?')}. Commit {str(r.get('Commit',''))[:12]}.",
            fix="Rotate the exposed credential and purge it from history.",
        ))
    return out


def _parse_trufflehog(data: Any) -> List[Dict[str, Any]]:
    out = []
    rows = data if isinstance(data, list) else [data]
    for r in rows:
        if not isinstance(r, dict):
            continue
        verified = bool(r.get("Verified"))
        src = (((r.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem")
               or {})
        out.append(_f(
            "trufflehog",
            severity="critical" if verified else "high",
            title=f"{r.get('DetectorName','secret')} "
                  f"({'VERIFIED live' if verified else 'unverified'})",
            file=src.get("file"),
            line=src.get("line"),
            rule=r.get("DetectorName"),
            confidence="high" if verified else "low",
            description=f"{r.get('DetectorName','?')} secret"
                        + (" — verified as a working credential." if verified
                           else " — not verified; confirm before reporting."),
            fix="Rotate the credential; verified secrets are actively usable.",
        ))
    return out


def _parse_osv(data: Any) -> List[Dict[str, Any]]:
    out = []
    results = data.get("results", []) if isinstance(data, dict) else []
    for res in results:
        src = (res.get("source", {}) or {}).get("path")
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package", {}) or {}
            name, ver = p.get("name"), p.get("version")
            for v in pkg.get("vulnerabilities", []) or []:
                sev = "info"
                for s in v.get("severity", []) or []:
                    sev = _norm_sev(s.get("score"))
                ds = (v.get("database_specific", {}) or {}).get("severity")
                if ds:
                    sev = _norm_sev(ds)
                fixed = None
                for aff in v.get("affected", []) or []:
                    for rng in aff.get("ranges", []) or []:
                        for ev in rng.get("events", []) or []:
                            if ev.get("fixed"):
                                fixed = ev["fixed"]
                out.append(_f(
                    "osv-scanner",
                    severity=sev,
                    title=(v.get("summary") or v.get("id") or "")[:200],
                    file=src,
                    rule=v.get("id"),
                    package=name, version=ver, fixed=fixed,
                    cve=_first_cve(v.get("id"), v.get("aliases")),
                    description=(v.get("summary") or v.get("details") or "")[:500],
                    fix=(f"Upgrade {name} to {fixed} or later." if fixed and name
                         else "Upgrade to a fixed release."),
                    refs=[r.get("url") for r in (v.get("references") or [])
                          if isinstance(r, dict) and r.get("url")][:5],
                ))
    return out


def _parse_trivy(data: Any) -> List[Dict[str, Any]]:
    out = []
    results = data.get("Results", []) if isinstance(data, dict) else []
    for res in results:
        target = res.get("Target")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(_f(
                "trivy",
                severity=v.get("Severity", "info"),
                title=(v.get("Title") or v.get("VulnerabilityID") or "")[:200],
                file=target,
                rule=v.get("VulnerabilityID"),
                package=v.get("PkgName"),
                version=v.get("InstalledVersion"),
                fixed=v.get("FixedVersion"),
                cve=_first_cve(v.get("VulnerabilityID")),
                description=(v.get("Description") or "")[:500],
                fix=(f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}."
                     if v.get("FixedVersion") else "No fixed version published yet."),
                refs=[v.get("PrimaryURL")] if v.get("PrimaryURL") else [],
            ))
    return out


def _parse_pip_audit(data: Any) -> List[Dict[str, Any]]:
    out = []
    # newer: {"dependencies":[{name,version,vulns:[...]}]}; older: [ {...} ]
    deps = data.get("dependencies") if isinstance(data, dict) else data
    for d in deps or []:
        if not isinstance(d, dict):
            continue
        name, ver = d.get("name"), d.get("version")
        for v in d.get("vulns", []) or []:
            fixes = v.get("fix_versions") or []
            out.append(_f(
                "pip-audit",
                severity="high" if not fixes else "medium",
                title=(v.get("id") or "python dependency vuln")[:200],
                package=name, version=ver,
                fixed=fixes[0] if fixes else None,
                rule=v.get("id"),
                cve=_first_cve(v.get("id"), v.get("aliases")),
                description=(v.get("description") or "")[:500],
                fix=(f"Upgrade {name} to {fixes[0]}." if fixes and name
                     else "No fixed version listed."),
            ))
    return out


def _parse_npm_audit(data: Any) -> List[Dict[str, Any]]:
    out = []
    if not isinstance(data, dict):
        return out
    vulns = data.get("vulnerabilities", {}) or {}
    for name, info in vulns.items():
        if not isinstance(info, dict):
            continue
        via = info.get("via", [])
        cve = None
        title = name
        for x in (via if isinstance(via, list) else [via]):
            if isinstance(x, dict):
                cve = _first_cve(x.get("url"), x.get("name")) or cve
                title = x.get("title") or title
        fix = info.get("fixAvailable")
        fix_s = None
        if isinstance(fix, dict):
            fix_s = f"{fix.get('name')}@{fix.get('version')}"
        elif fix is True:
            fix_s = "run `npm audit fix`"
        out.append(_f(
            "npm",
            severity=info.get("severity", "info"),
            title=str(title)[:200],
            package=name,
            rule=None,
            cve=cve,
            fixed=fix_s,
            description=f"Vulnerable range {info.get('range','?')} for {name}.",
            fix=fix_s or "No automatic fix available.",
        ))
    return out


def _parse_retire(data: Any) -> List[Dict[str, Any]]:
    out = []
    rows = data.get("data", []) if isinstance(data, dict) else data
    for entry in rows or []:
        if not isinstance(entry, dict):
            continue
        fpath = entry.get("file")
        for res in entry.get("results", []) or []:
            comp, ver = res.get("component"), res.get("version")
            for v in res.get("vulnerabilities", []) or []:
                ident = v.get("identifiers", {}) or {}
                out.append(_f(
                    "retire",
                    severity=v.get("severity", "medium"),
                    title=(ident.get("summary") or f"vulnerable {comp}")[:200],
                    file=fpath,
                    package=comp, version=ver,
                    cve=_first_cve(ident.get("CVE")),
                    description=(ident.get("summary") or "")[:500],
                    fix=f"Upgrade {comp} past {ver}." if comp else "Upgrade the library.",
                    refs=[u for u in (v.get("info") or []) if isinstance(u, str)][:5],
                ))
    return out


def _parse_nuclei(data: Any) -> List[Dict[str, Any]]:
    out = []
    rows = data if isinstance(data, list) else [data]
    for o in rows:
        if not isinstance(o, dict):
            continue
        info = o.get("info", {}) or {}
        out.append(_f(
            "nuclei",
            severity=info.get("severity", "info"),
            title=(info.get("name") or o.get("template-id") or "")[:200],
            file=o.get("host") or o.get("matched-at"),
            rule=o.get("template-id") or o.get("templateID"),
            cve=_first_cve((info.get("classification", {}) or {}).get("cve-id"),
                           o.get("template-id")),
            description=(info.get("description") or "").strip()[:500],
        ))
    return out


_PARSERS = {
    "semgrep": _parse_semgrep, "bandit": _parse_bandit,
    "gitleaks": _parse_gitleaks, "trufflehog": _parse_trufflehog,
    "osv-scanner": _parse_osv, "osv": _parse_osv,
    "trivy": _parse_trivy, "grype": _parse_trivy,  # grype JSON differs; trivy is the common case
    "pip-audit": _parse_pip_audit, "pip_audit": _parse_pip_audit,
    "npm": _parse_npm_audit, "npm-audit": _parse_npm_audit,
    "retire": _parse_retire, "retirejs": _parse_retire,
    "nuclei": _parse_nuclei,
}


def parse_scan(tool: str, raw: str) -> Dict[str, Any]:
    """Normalise one scanner's raw JSON into the unified finding schema.

    Supported: semgrep, bandit, gitleaks, trufflehog, osv-scanner, trivy,
    pip-audit, npm (audit), retire(.js), nuclei.  Returns
    {ok, tool, summary, findings}.  Forgiving: JSONL is accepted, and an
    unparseable blob returns ok:false rather than raising.
    """
    t = (tool or "").strip().lower()
    parser = _PARSERS.get(t)
    if not parser:
        return {"ok": False, "tool": t,
                "error": f"no parser for '{tool}'. Supported: "
                         + ", ".join(sorted(set(_PARSERS)))}
    data = _loads(raw)
    if data is None:
        return {"ok": False, "tool": t, "error": "empty or unparseable JSON"}
    try:
        findings = parser(data)
    except Exception as e:
        return {"ok": False, "tool": t, "error": f"parse failed: {e}"}
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    roll = " · ".join(f"{k}:{counts[k]}" for k in
                      ("critical", "high", "medium", "low", "info")
                      if counts.get(k))
    return {"ok": True, "tool": t,
            "summary": f"{len(findings)} finding(s)" + (f" ({roll})" if roll else ""),
            "findings": findings}


# ═════════════════════════════════════════════════════════════════════
# TRIAGE — dedup across scanners, one severity scale, sort, confidence flags.
# ═════════════════════════════════════════════════════════════════════

def _dedup_key(f: Dict[str, Any]) -> Tuple:
    """Two findings are 'the same issue' if either:
      • same CVE on the same package (SCA overlap across osv/trivy/pip/npm), or
      • same file:line:rule (SAST/secrets overlap).
    """
    cve = (f.get("cve") or "").upper()
    pkg = (f.get("package") or "").lower()
    if cve and pkg:
        return ("cve", cve, pkg)
    if cve:
        return ("cve", cve, "")
    fpath = (f.get("file") or "").lower()
    line = f.get("line")
    rule = (f.get("rule") or "").lower()
    if fpath and rule:
        return ("loc", fpath, line, rule)
    # fall back to title so at least identical titles collapse
    return ("title", (f.get("title") or "").lower(), pkg)


def _coerce(findings: Any) -> List[Dict[str, Any]]:
    if isinstance(findings, str):
        d = _loads(findings)
        findings = d if d is not None else []
    if isinstance(findings, dict):
        findings = findings.get("findings", [findings])
    allowed = set(_f("x").keys()) - {"tool"}
    out = []
    for f in findings or []:
        if isinstance(f, dict):
            g = _f(f.get("tool", "?"),
                   **{k: v for k, v in f.items() if k in allowed})
            out.append(g)
    return out


def triage(findings: Any) -> Dict[str, Any]:
    """Merge findings from any number of scanners into one clean, deduplicated,
    severity-sorted list.

    - Cross-tool dedup: the same CVE+package, or the same file:line:rule,
      collapses to a single finding that records which scanners saw it (a
      finding two tools agree on is more trustworthy).
    - One severity scale: every tool's dialect is normalised; on a merge the
      HIGHEST severity wins.
    - Confidence: unverified secrets and evidence-thin findings are flagged
      "needs manual confirmation" so nothing weak reaches a report unchecked.

    Pure, offline heuristics — no model call, runs nothing.  Feed the result
    to pentest.report_findings, or pentest.enrich_with_cves for KEV/EPSS.
    """
    items = _coerce(findings)
    if not items:
        return {"ok": False, "error": "no findings to triage"}

    merged: Dict[Tuple, Dict[str, Any]] = {}
    for f in items:
        k = _dedup_key(f)
        if k in merged:
            m = merged[k]
            # highest severity wins
            if _SEV_RANK.get(f["severity"], 5) < _SEV_RANK.get(m["severity"], 5):
                m["severity"] = f["severity"]
            tset = set(m.get("tools", []))
            tset.add(f["tool"])
            m["tools"] = sorted(tset)
            m["corroborations"] = len(tset)
            # fill any gaps from the duplicate
            for key in ("cwe", "cve", "fixed", "fix", "line", "file"):
                if not m.get(key) and f.get(key):
                    m[key] = f[key]
            m["refs"] = list(dict.fromkeys((m.get("refs") or []) + (f.get("refs") or [])))[:6]
        else:
            g = dict(f)
            g["tools"] = [f["tool"]]
            g["corroborations"] = 1
            merged[k] = g

    out = list(merged.values())

    # confidence / manual-confirm flags
    for f in out:
        flags: List[str] = []
        conf = f.get("confidence")
        if f["tool"] in ("gitleaks",) and conf != "high":
            flags.append("secret unverified — confirm it's live before reporting")
        if f["tool"] == "trufflehog" and conf == "low":
            flags.append("secret not verified by the detector")
        if not f.get("file") and not f.get("package"):
            flags.append("no file or package located — thin, confirm manually")
        if f["severity"] in ("critical", "high") and f.get("corroborations", 1) == 1 \
                and f["tool"] in ("semgrep",) and not f.get("cwe") and not f.get("cve"):
            flags.append("single-tool high with no CWE/CVE — sanity-check for false positive")
        f["review_flags"] = flags
        f["needs_review"] = bool(flags)

    out.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 5),
                            -f.get("corroborations", 1),
                            f.get("file") or "",
                            f.get("line") or 0))

    counts: Dict[str, int] = {}
    for f in out:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    roll = " · ".join(f"{k}: {counts[k]}" for k in
                      ("critical", "high", "medium", "low", "info")
                      if counts.get(k))
    corroborated = sum(1 for f in out if f.get("corroborations", 1) > 1)
    needs_review = sum(1 for f in out if f.get("needs_review"))

    return {
        "ok": True,
        "summary": (f"{len(out)} unique finding(s) from {len(items)} raw "
                    f"({len(items) - len(out)} merged); {corroborated} "
                    f"corroborated by 2+ tools; {needs_review} need review. "
                    f"Severity — {roll or 'n/a'}."),
        "counts": counts,
        "total_raw": len(items),
        "total_unique": len(out),
        "corroborated": corroborated,
        "needs_review": needs_review,
        "findings": out,
        "note": "Highest severity wins on a merge; a finding two scanners agree on is "
                "sturdier. Clear review_flags before report_findings. Findings carry "
                "cve/package so enrich_with_cves can add KEV/EPSS ranking.",
    }


# ═════════════════════════════════════════════════════════════════════
# REMEDIATION — short, standard, NON-EXPLOIT fix pointers by CWE class.
# ═════════════════════════════════════════════════════════════════════

_CWE_FIX = {
    "CWE-89": "Parameterise queries / use an ORM; never build SQL by string "
              "concatenation. Validate and least-privilege the DB account.",
    "CWE-79": "Context-aware output encoding; a strict CSP; treat all input as "
              "untrusted. Use the framework's auto-escaping, don't disable it.",
    "CWE-78": "Avoid shell invocation; pass argv arrays, not a shell string. "
              "Allowlist arguments; never interpolate user input into a command.",
    "CWE-22": "Canonicalise and confine paths to an allowed base dir; reject '..'. "
              "Use safe path-join APIs, not string concatenation.",
    "CWE-502": "Don't deserialise untrusted data with pickle/yaml.load/etc. Use a "
               "data-only format (JSON) and validate the schema.",
    "CWE-798": "Remove hard-coded credentials; load from env/secret manager. Rotate "
               "anything that was committed.",
    "CWE-327": "Use a vetted modern algorithm (AES-GCM, SHA-256+); drop MD5/SHA1/DES "
               "and ECB mode.",
    "CWE-352": "Enforce anti-CSRF tokens and SameSite cookies on state-changing "
               "requests.",
    "CWE-918": "Allowlist outbound hosts; block internal/link-local ranges; don't let "
               "user input choose the request target.",
}


def remediation_hint(finding: Any) -> Dict[str, Any]:
    """A short, standard remediation pointer for a normalised finding.

    Prefers an explicit fixed-version upgrade (SCA), else the CWE-class fix,
    else a generic pointer.  Reference knowledge only — it describes the fix,
    it does not write exploit or attack code."""
    if isinstance(finding, str):
        d = _loads(finding)
        finding = d if isinstance(d, dict) else {"title": finding}
    if not isinstance(finding, dict):
        return {"ok": False, "error": "finding must be an object"}

    pkg = finding.get("package")
    fixed = finding.get("fixed")
    cwe = _cwe_str(finding.get("cwe"))
    parts: List[str] = []

    if pkg and fixed and "npm audit" not in str(fixed):
        parts.append(f"Upgrade {pkg} to {fixed} or later.")
    elif finding.get("fix"):
        parts.append(str(finding["fix"]))

    if cwe and cwe in _CWE_FIX:
        parts.append(_CWE_FIX[cwe])

    if not parts:
        parts.append("Confirm the finding, then apply the vendor/framework-"
                     "recommended fix and re-scan to verify it's resolved.")

    return {
        "ok": True,
        "cwe": cwe,
        "package": pkg,
        "fixed_version": fixed,
        "remediation": " ".join(parts),
        "verify": "Re-run the same scanner after the fix; the finding should "
                  "disappear. Keep the before/after in the evidence ledger.",
    }
