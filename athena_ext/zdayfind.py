"""
zdayfind — variant analysis: find the NEXT bug that looks like the LAST one.

Most zero-days are not novel classes; they are a known dangerous PATTERN
appearing somewhere new. Project-Zero-style "variant analysis" turns a single
past bug into a query and sweeps the codebase for lookalikes. zdayfind does
exactly that, offline and stdlib-only: it carries a library of sink/source
patterns — each one distilled from a class that has repeatedly produced real
CVEs / zero-days — and flags every place a codebase reaches that sink with
what looks like attacker-influenced input.

It is a LEAD GENERATOR, not a prover. A hit means "a human (or Basilisk's
exploit builders) should look here"; the verified-exploitation loop is what
turns a lead into a confirmed finding. Precision is tuned to surface the
dangerous shapes without drowning you — but expect to triage.

Two modes:
  * scan   — run the whole signature library over a file, a snippet, or a tree.
  * variant— give it ONE bad line/snippet and it extracts the sink and finds
             structurally-similar occurrences elsewhere (the pure PZ workflow).

Design notes: line-oriented regex (fast, gives line numbers for free),
language inferred from extension, vendored/build dirs skipped, output ranked
by severity then confidence. No third-party deps so it runs inside the
stdlib-only test harness and on a phone.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── language inference ──────────────────────────────────────────────
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js",
    ".php": "php", ".php5": "php", ".phtml": "php",
    ".java": "java", ".kt": "java",
    ".rb": "ruby", ".erb": "ruby",
    ".go": "go",
    ".cs": "dotnet", ".vbhtml": "dotnet", ".cshtml": "dotnet",
    ".c": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".h": "c", ".hpp": "c",
    ".html": "web", ".htm": "web", ".vue": "web", ".svelte": "web",
}
_SKIP_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "vendor", "venv", ".venv", "env",
    "dist", "build", "__pycache__", ".next", ".nuxt", "bower_components",
    "site-packages", "third_party", "target", "bin", "obj", ".tox", "coverage",
}
_MAX_BYTES = 1_500_000       # skip files bigger than this (minified/data)
_MAX_LINE = 600              # skip absurdly long lines (minified bundles)


def _lang_of(filename: str) -> str:
    return _EXT_LANG.get(Path(filename).suffix.lower(), "any")


# A signature:
#   id, name, cwe, severity(critical|high|medium|low), langs(set|"any"),
#   rx (compiled), why (one-line rationale naming the class),
#   fix (one-line remediation). `langs="any"` matches every language.
def _sig(id, name, cwe, sev, langs, pattern, why, fix, flags=0):
    return {
        "id": id, "name": name, "cwe": cwe, "severity": sev,
        "langs": langs if langs == "any" else set(langs),
        "rx": re.compile(pattern, re.I | flags),
        "why": why, "fix": fix,
    }


# Ordered rough-worst-first. Each entry is a class that has produced real
# zero-days; the pattern is the shape that class takes in source.
_SIGNATURES: List[Dict[str, Any]] = [
    # ---- remote code execution family ----
    _sig("py-yaml-load", "Unsafe YAML load -> RCE", "CWE-502", "critical", ("python",),
         r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(yaml\.)?SafeLoader)",
         "yaml.load without SafeLoader instantiates arbitrary Python objects (the PyYAML RCE class).",
         "use yaml.safe_load(), or pass Loader=SafeLoader."),
    _sig("py-pickle", "Untrusted pickle/marshal load -> RCE", "CWE-502", "critical", ("python",),
         r"\b(pickle|_pickle|cPickle|dill|marshal)\.(loads?|load)\s*\(",
         "pickle.loads on attacker data runs __reduce__ = code execution.",
         "never unpickle untrusted input; use json or a signed format."),
    _sig("php-unserialize", "unserialize() on user input -> object injection", "CWE-502", "critical", ("php",),
         r"\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
         "PHP unserialize() on request data triggers POP-chain object injection.",
         "use json_decode(); if you must, unserialize with allowed_classes:false."),
    _sig("java-ois", "Java ObjectInputStream on network data -> RCE", "CWE-502", "critical", ("java",),
         r"\bnew\s+ObjectInputStream\s*\(",
         "Java native deserialization + a gadget on the classpath = ysoserial RCE.",
         "avoid native serialization; use JSON, or a hardened ObjectInputFilter."),
    _sig("rb-marshal", "Ruby Marshal/YAML.load -> RCE", "CWE-502", "critical", ("ruby",),
         r"\b(Marshal\.load|YAML\.(load|unsafe_load))\s*\(",
         "Marshal.load / YAML.load build arbitrary Ruby objects from input.",
         "use JSON.parse or YAML.safe_load."),
    _sig("dotnet-deser", ".NET insecure deserializer -> RCE", "CWE-502", "critical", ("dotnet",),
         r"\b(BinaryFormatter|LosFormatter|NetDataContractSerializer|ObjectStateFormatter|SoapFormatter)\b",
         "BinaryFormatter/LosFormatter etc. are the .NET/ViewState deserialization RCE class.",
         "BinaryFormatter is obsolete/removed; use System.Text.Json with known types."),
    _sig("eval-input", "eval()/Function() on dynamic input -> code injection", "CWE-95", "critical", "any",
         r"\b(eval|Function|execScript|vm\.runInThisContext|vm\.runInNewContext)\s*\(",
         "eval/Function on anything reachable from input is direct code injection.",
         "never eval dynamic input; parse it, or use a safe interpreter/allow-list."),
    _sig("py-exec", "exec()/compile() on dynamic input", "CWE-95", "high", ("python",),
         r"\b(exec|compile)\s*\(",
         "exec()/compile() on request-derived strings runs arbitrary Python.",
         "avoid exec; use getattr/dispatch tables over an allow-list."),
    _sig("os-shell", "Shell exec with concatenation -> command injection", "CWE-78", "critical", "any",
         r"(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output)[^)]*shell\s*=\s*True|child_process\.(exec|execSync)|Runtime\.getRuntime\(\)\.exec|shell_exec|passthru|proc_open)",
         "building a shell command from input is the OS-command-injection class.",
         "pass an argv array (no shell), or strictly allow-list arguments."),
    _sig("backtick-exec", "Backtick shell execution", "CWE-78", "high", ("ruby", "php"),
         r"`[^`]*(#\{|\$_(GET|POST|REQUEST)|\$[A-Za-z_])[^`]*`",
         "backtick command execution with interpolation is OS command injection (Ruby/PHP).",
         "use a non-shell exec API with an argument array; never interpolate input."),
    _sig("ssti-render", "Template built from input -> SSTI -> RCE", "CWE-1336", "critical", "any",
         r"(render_template_string\s*\(|Template\s*\([^)]*\)\s*\.render\s*\(|new\s+Template\(|\$twig->createTemplate\(|env\.from_string\()",
         "compiling a template from user input is server-side template injection.",
         "render static templates and pass data as variables, never concatenate input into the template."),
    _sig("py-inputfmt-sql", "String-built SQL -> SQL injection", "CWE-89", "high", "any",
         r"(execute|executemany|query|cursor\.execute|db\.query|createQuery|rawQuery|prepare|mysql_query|pg_query)\s*\(.*\b(SELECT|INSERT|UPDATE|DELETE|UNION)\b.*(\+|\|\||\.format\s*\(|f[\"']|\$\{|#\{|[\"']\s*%\s*[\(a-zA-Z_])",
         "a query assembled by concatenation / f-string / % / format is SQL injection (parameterised %s placeholders are fine).",
         "use parameterised queries / prepared statements only."),
    # ---- SSRF / traversal / file ----
    _sig("ssrf-fetch", "Outbound request to a user-supplied URL -> SSRF", "CWE-918", "high", "any",
         r"(requests\.(get|post|put|head)|urllib\.request\.urlopen|urlopen|http\.get|axios\.(get|post)|fetch|HttpClient|file_get_contents|curl_exec|Net::HTTP|OpenURI)\s*\([^)]*(req\.|request\.|params|query|input|\$_(GET|POST|REQUEST)|user|url)",
         "fetching a URL taken from input reaches internal services / cloud metadata (SSRF).",
         "allow-list the host/scheme, resolve+re-check the IP, block link-local & metadata."),
    _sig("path-traversal", "File path built from input -> path traversal", "CWE-22", "high", "any",
         r"(open|read_file|readFile|readFileSync|send_file|sendFile|File\(|fopen|include|require|createReadStream)\s*\([^)]*(\+|\.\.|join\([^)]*req|params|input|\$_(GET|POST|REQUEST)|filename|path\s*[=,])",
         "joining request input into a filesystem path without normalising is traversal / LFI.",
         "resolve the real path and assert it stays under an allow-listed root."),
    _sig("xxe-parser", "XML parser with external entities enabled -> XXE", "CWE-611", "high", "any",
         r"(etree\.(parse|fromstring)|xml\.dom\.minidom\.parse|DocumentBuilderFactory|SAXParser|XMLReader|simplexml_load_|new\s+DOMDocument|libxml_)",
         "an XML parser left at defaults resolves external entities = XXE (file read / SSRF / OOB).",
         "disable DOCTYPE/external entities (defusedxml, disallow-doctype-decl, LIBXML_NOENT off)."),
    # ---- auth / crypto / secrets ----
    _sig("jwt-noverify", "JWT decoded without verifying signature", "CWE-347", "high", "any",
         r"(jwt\.decode\s*\([^)]*verify\s*[=:]\s*(False|false)|algorithms\s*[:=]\s*\[?\s*[\"']?none|verify_signature\s*[:=]\s*(False|false)|decode\s*\([^)]*complete\s*:\s*false)",
         "decoding a JWT without signature verification (or allowing alg=none) forges identity.",
         "always verify with a pinned algorithm and a secret/public key."),
    _sig("weak-crypto", "Weak/broken crypto primitive", "CWE-327", "medium", "any",
         r"\b(MD5|SHA1|DES|RC4|ECB|createHash\(['\"]md5|hashlib\.md5|hashlib\.sha1|Cipher\.getInstance\(['\"]DES)\b",
         "MD5/SHA1/DES/ECB for auth or confidentiality is broken (collisions / no diffusion).",
         "use bcrypt/argon2 for passwords, AES-GCM for data, SHA-256+ for integrity."),
    _sig("weak-random", "Non-cryptographic RNG for a security value", "CWE-338", "medium", "any",
         r"(Math\.random\s*\(\)|random\.(random|randint|choice|randrange)\s*\(|mt_rand\s*\(|rand\s*\(\))",
         "predictable RNG used for a token/OTP/session/nonce is guessable (weak-randomness class).",
         "use secrets (py) / crypto.randomBytes (node) / SecureRandom (java) / random_bytes (php)."),
    _sig("hardcoded-secret", "Hardcoded secret / key in source", "CWE-798", "high", "any",
         r"(AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|(api[_-]?key|secret|passwd|password|token|client[_-]?secret)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"'])",
         "a credential committed to source is the hardcoded-secret class (rotate immediately).",
         "load secrets from env/secret manager; purge from history and rotate the key."),
    # ---- injection into responses / clients ----
    _sig("xss-sink", "Unescaped input into HTML sink -> XSS", "CWE-79", "high", "any",
         r"(dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|\|\s*safe\b|mark_safe\s*\(|v-html|\.html\s*\(|render\s*\([^)]*\|\s*raw)",
         "writing input into an HTML sink without escaping is cross-site scripting.",
         "escape on output / use textContent / keep autoescaping on; sanitise rich HTML."),
    _sig("proto-pollution", "Recursive merge without __proto__ guard -> prototype pollution", "CWE-1321", "high", ("js",),
         r"(_\.merge|_\.mergeWith|_\.defaultsDeep|Object\.assign\([^)]*req\.|extend\(true|deepmerge|deepAssign|setWith)\s*\(",
         "deep-merging attacker JSON into an object pollutes Object.prototype (RCE/authz-bypass gadget).",
         "guard against __proto__/constructor/prototype keys, or use Object.create(null) / a Map."),
    _sig("mass-assign", "Whole request body bound to a model -> mass assignment", "CWE-915", "high", "any",
         r"(Object\.assign\s*\(\s*\w+\s*,\s*req\.body|\.update\(\s*req\.body|new\s+\w+\(\s*req\.body|\*\*request\.(json|data|form)|update_attributes\s*\(\s*params|\.save\(\s*\*\*)",
         "binding the raw body/params to a model lets a caller set fields like is_admin/role (mass assignment).",
         "bind an explicit allow-list of fields; never trust the whole body."),
    _sig("nosql-inject", "Request object passed straight into a NoSQL query", "CWE-943", "high", ("js", "python"),
         r"(\.find|\.findOne|\.update|\.remove|\.deleteOne)\s*\(\s*(req\.(body|query|params)|request\.(json|args))",
         "passing a request object into a Mongo/NoSQL query enables operator injection ($ne/$gt/$where).",
         "cast/validate types; reject keys beginning with $ ; use a schema."),
    _sig("open-redirect", "Redirect target taken from input -> open redirect", "CWE-601", "medium", "any",
         r"(redirect|sendRedirect|Location:\s*|res\.redirect|header\(\s*[\"']Location)\s*\(?[^)\n]*(req\.|request\.|params|query|\$_(GET|POST|REQUEST)|returnUrl|next|url)",
         "redirecting to a user-supplied URL is open redirect (phishing / token leak / SSRF pivot).",
         "redirect only to a relative path or an allow-listed host."),
    _sig("cors-star-cred", "Reflected/`*` CORS with credentials", "CWE-942", "medium", "any",
         r"(Access-Control-Allow-Origin[\"'\s:,]+\*|setHeader\([\"']Access-Control-Allow-Origin[\"'],\s*(req|origin)|Allow-Credentials[\"'\s:,]+true)",
         "reflecting Origin (or *) together with credentials lets any site read authenticated responses.",
         "echo only allow-listed origins; never combine * with credentials."),
    _sig("redos", "Regex with nested quantifiers -> ReDoS", "CWE-1333", "medium", "any",
         r"(\([^)]*[+*]\)[+*]|\(\.\*\)[+*]|\([^|)]+\|[^|)]+\)[+*]\+)",
         "catastrophic backtracking (e.g. (a+)+, (.*)* ) lets one request hang a worker (ReDoS).",
         "rewrite without nested/overlapping quantifiers, or use a linear-time engine (re2)."),
    _sig("ssrf-redirect-follow", "Verbose debug / stack-trace exposure", "CWE-489", "low", "any",
         r"(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG|console\.trace|printStackTrace|display_errors\s*[:=]\s*On)",
         "debug mode / stack traces in production leak internals and can enable RCE consoles.",
         "disable debug and verbose errors in production."),
    _sig("cmd-format-str", "User-controlled format string", "CWE-134", "medium", ("c", "python", "java"),
         r"(printf|sprintf|fprintf|String\.format|\.format)\s*\(\s*(req\.|request\.|params|input|user|argv)",
         "an attacker-controlled format string leaks/overwrites memory or crashes (format-string class).",
         "use a constant format string; pass user data as an argument."),
    _sig("ldap-concat", "LDAP filter built by concatenation", "CWE-90", "high", "any",
         r"(search|Search|ldap_search|InitialDirContext|search_s)\s*\([^)]*(\(\s*&|\(\s*\|)?[^)]*(\+|\.format|f[\"']|\$\{|\$_(GET|POST|REQUEST))",
         "concatenating input into an LDAP filter is LDAP injection (auth bypass / data exfil).",
         "escape RFC-4515 metacharacters, or use a parameterised filter API."),
    _sig("xslt-transform", "XSLT transform from untrusted stylesheet/input", "CWE-91", "high", "any",
         r"(XSLTProcessor|\.transformToFragment|TransformerFactory|xsltproc|processStylesheet|importStylesheet)\s*\(",
         "an attacker-influenced XSLT stylesheet can read files / execute (XSLT injection).",
         "disable extension functions & external access; never transform an untrusted stylesheet."),
    _sig("template-autoescape-off", "Autoescaping disabled", "CWE-79", "medium", "any",
         r"(autoescape\s*[:=]\s*(False|false|off)|\{%\s*autoescape\s+false|Markup\(|HtmlString\(|new\s+SafeString)",
         "turning autoescape off (or wrapping input as 'safe') reintroduces XSS everywhere downstream.",
         "keep autoescaping on; sanitise specific rich-text with a vetted allow-list sanitiser."),
]


def _iter_matches(code: str, lang: str, focus: Optional[set]) -> List[Dict[str, Any]]:
    lines = code.splitlines()
    out: List[Dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        if len(line) > _MAX_LINE:
            continue
        for sig in _SIGNATURES:
            if focus and sig["id"] not in focus and sig["name"].lower() not in focus:
                continue
            if sig["langs"] != "any" and lang != "any" and lang not in sig["langs"]:
                continue
            m = sig["rx"].search(line)
            if not m:
                continue
            # confidence: an input-ish token near the sink raises it
            snippet = line.strip()[:200]
            conf = "high" if re.search(
                r"(req\.|request\.|params|query|input|user|\$_(GET|POST|REQUEST|COOKIE)|argv|body)",
                line, re.I) else "review"
            out.append({
                "line": i, "snippet": snippet, "id": sig["id"],
                "class": sig["name"], "cwe": sig["cwe"], "severity": sig["severity"],
                "confidence": conf, "why": sig["why"], "fix": sig["fix"],
            })
    return out


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _rank(f: Dict[str, Any]) -> Tuple[int, int]:
    return (_SEV_RANK.get(f["severity"], 9), 0 if f["confidence"] == "high" else 1)


def scan_code(code: str, filename: str = "snippet", focus: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run the signature library over a single source string."""
    lang = _lang_of(filename)
    foc = set(x.strip().lower() for x in focus) if focus else None
    hits = _iter_matches(code or "", lang, foc)
    for h in hits:
        h["file"] = filename
    hits.sort(key=_rank)
    return {
        "ok": True, "mode": "scan", "file": filename, "lang": lang,
        "findings": hits, "count": len(hits),
        "by_severity": _tally(hits),
        "note": ("Leads, not proof — variant analysis flags the dangerous shape. "
                 "Confirm each with the exploit builders / verified-exploitation loop."),
    }


def _tally(hits: List[Dict[str, Any]]) -> Dict[str, int]:
    t: Dict[str, int] = {}
    for h in hits:
        t[h["severity"]] = t.get(h["severity"], 0) + 1
    return t


def scan_tree(path: str = ".", focus: Optional[List[str]] = None,
              max_files: int = 4000) -> Dict[str, Any]:
    """Walk a directory and scan every source file (vendored/build dirs skipped)."""
    root = Path(path).expanduser()
    if not root.exists():
        return {"ok": False, "error": f"path not found: {path}"}
    foc = set(x.strip().lower() for x in focus) if focus else None
    findings: List[Dict[str, Any]] = []
    scanned = 0
    skipped = 0
    if root.is_file():
        files = [root]
    else:
        files = []
        for p in root.rglob("*"):
            if p.is_dir():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() not in _EXT_LANG:
                continue
            files.append(p)
    for p in files[:max_files]:
        try:
            if p.stat().st_size > _MAX_BYTES:
                skipped += 1
                continue
            code = p.read_text(errors="ignore")
        except Exception:
            skipped += 1
            continue
        lang = _lang_of(p.name)
        for h in _iter_matches(code, lang, foc):
            h["file"] = str(p)
            findings.append(h)
        scanned += 1
    findings.sort(key=_rank)
    return {
        "ok": True, "mode": "scan-tree", "root": str(root),
        "files_scanned": scanned, "files_skipped": skipped,
        "count": len(findings), "by_severity": _tally(findings),
        "top": findings[:60],
        "note": ("Ranked worst-first; showing up to 60. Each hit is a lead for "
                 "manual review or an exploit-builder run, not a confirmed bug."),
    }


# ── variant mode: one bad line -> find its siblings ─────────────────
_SINK_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_\.]{2,}")


def _extract_sinks(snippet: str) -> List[str]:
    # pull the call-ish tokens (foo.bar( ) that characterise the sink
    toks = []
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_\.]{2,})\s*\(", snippet):
        t = m.group(1)
        if t.split(".")[-1].lower() not in ("if", "for", "while", "return", "function"):
            toks.append(t)
    if not toks:
        toks = _SINK_TOKEN.findall(snippet)[:3]
    # keep the most specific (longest) couple
    toks = sorted(set(toks), key=len, reverse=True)[:3]
    return toks


def find_variants(like: str, path: str = ".", max_files: int = 4000) -> Dict[str, Any]:
    """Project-Zero workflow: give ONE known-bad line/snippet and sweep the tree
    for structurally-similar sinks (the same dangerous call reachable elsewhere)."""
    sinks = _extract_sinks(like or "")
    if not sinks:
        return {"ok": False, "error": "could not extract a sink from the snippet; "
                                      "pass a line that contains the dangerous call."}
    root = Path(path).expanduser()
    if not root.exists():
        return {"ok": False, "error": f"path not found: {path}"}
    rx = re.compile("|".join(re.escape(s) for s in sinks))
    hits: List[Dict[str, Any]] = []
    files = ([root] if root.is_file()
             else [p for p in root.rglob("*")
                   if p.is_file()
                   and p.suffix.lower() in _EXT_LANG
                   and not any(part in _SKIP_DIRS for part in p.parts)])
    for p in files[:max_files]:
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            for i, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
                if len(line) <= _MAX_LINE and rx.search(line):
                    tainted = bool(re.search(
                        r"(req\.|request\.|params|query|input|user|\$_(GET|POST|REQUEST)|body)",
                        line, re.I))
                    hits.append({"file": str(p), "line": i,
                                 "snippet": line.strip()[:200],
                                 "reachable_from_input": tainted})
        except Exception:
            continue
    # input-reachable first
    hits.sort(key=lambda h: 0 if h["reachable_from_input"] else 1)
    return {
        "ok": True, "mode": "variant", "sinks": sinks, "root": str(root),
        "count": len(hits), "matches": hits[:80],
        "note": ("Occurrences of the same sink. Ones marked reachable_from_input "
                 "are the strongest variant candidates — the original bug, elsewhere."),
    }


def zday_scan(path: str = "", code: str = "", like: str = "",
              focus: str = "", filename: str = "snippet") -> Dict[str, Any]:
    """Tool entry. Variant-analysis source scanner for novel/zero-day-class bugs.

    - {"like": "<one bad line>", "path": "<dir>"}  -> find siblings of that sink.
    - {"code": "<source>", "filename": "x.py"}     -> scan a snippet.
    - {"path": "<file-or-dir>"}                     -> scan a file or whole tree.
    - optional {"focus": "sqli,xss,ssti"}           -> only those signature ids/classes.

    Leads only; confirm with the exploit builders. Authorised code only.
    """
    foc = [x for x in re.split(r"[,\s]+", focus) if x] if focus else None
    if like.strip():
        return find_variants(like, path or ".")
    if code.strip():
        return scan_code(code, filename or "snippet", foc)
    if path.strip():
        return scan_tree(path, foc)
    return {"ok": False,
            "error": "give one of: like (a bad snippet to find variants of), "
                     "code (source to scan), or path (file/dir to scan)."}


def signature_catalog() -> Dict[str, Any]:
    """List every variant-analysis signature and the bug class it hunts."""
    return {"ok": True, "count": len(_SIGNATURES),
            "signatures": [{"id": s["id"], "class": s["name"], "cwe": s["cwe"],
                            "severity": s["severity"], "why": s["why"]}
                           for s in _SIGNATURES]}
