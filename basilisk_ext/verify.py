"""
verify — multi-source verification for Basilisk.

The job: when the operator asks for a fact about the current world — or
anything where being wrong matters — don't answer from one page and don't
answer from memory.  Pull several INDEPENDENT sources, score each one's
credibility, flag the state-media / propaganda / satire outlets explicitly,
and signal whether the sources actually corroborate each other or fight.
Hand all of that back to the model so it can answer with a calibrated
confidence and cite who said what — instead of laundering one random
blog (or one propaganda outlet) into a confident-sounding "fact".

This does NOT pretend to be a truth oracle.  It does three concrete things
a single search can't:

  1. DIVERSITY — gather results spread across different registrable domains
     (never five links from one site), so a single source can't dominate.
  2. CREDIBILITY — tag each domain with a tier (primary / reputable /
     community / mixed / state-media / low-quality / unknown).  These are
     HEURISTIC PRIORS, openly editable below — not gospel.  A .gov page can
     be wrong and a personal blog can be right; the tier is a starting
     weight, not a verdict.
  3. CORROBORATION — a cheap signal of whether the sources' salient facts
     (numbers, dates, named entities) overlap (they agree) or diverge
     (treat with suspicion).

Design contract (basilisk_ext/__init__.py): imports nothing from the Basilisk core.
The web fetchers are injected — it reuses Basilisk's own robust search/read
stack (DDG+Mojeek+Wayback+reader-proxy) rather than re-implementing HTTP.
"""

from __future__ import annotations

import concurrent.futures
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ═════════════════════════════════════════════════════════════════════
# DOMAIN CREDIBILITY — heuristic priors, editable.  A tier is a weight,
# not a verdict.  Keep these honest and update them as you learn.
# ═════════════════════════════════════════════════════════════════════

# Primary / official / standards / peer-reviewed.  Closest thing to a
# source of record for its subject.
_PRIMARY = {
    "nvd.nist.gov", "cve.mitre.org", "cwe.mitre.org", "first.org",
    "exploit-db.com", "attack.mitre.org", "kb.cert.org", "cisa.gov",
    "ietf.org", "rfc-editor.org", "iana.org", "icann.org", "w3.org",
    "kernel.org", "python.org", "owasp.org", "postgresql.org",
    "developer.mozilla.org", "docs.python.org", "man7.org",
    "nature.com", "science.org", "sciencedirect.com", "arxiv.org",
    "pubmed.ncbi.nlm.nih.gov", "ncbi.nlm.nih.gov", "who.int",
    "europa.eu", "un.org", "imf.org", "worldbank.org", "oecd.org",
    "supremecourt.gov", "congress.gov", "govinfo.gov", "gov.uk",
    "ecdc.europa.eu", "cdc.gov", "fda.gov", "nasa.gov", "noaa.gov",
}

# Established outlets with editorial standards / corrections.  Reputable is
# not the same as infallible — they still get cross-checked.
_REPUTABLE = {
    "reuters.com", "apnews.com", "bbc.com", "bbc.co.uk", "npr.org",
    "theguardian.com", "nytimes.com", "washingtonpost.com", "wsj.com",
    "ft.com", "economist.com", "bloomberg.com", "axios.com",
    "politico.com", "propublica.org", "afp.com", "dw.com",
    "aljazeera.com", "cnbc.com", "theverge.com", "arstechnica.com",
    "wired.com", "nationalgeographic.com", "scientificamerican.com",
    "smithsonianmag.com", "snopes.com", "factcheck.org",
    "politifact.com", "fullfact.org", "bellingcat.com",
    "krebsonsecurity.com", "thehackernews.com", "bleepingcomputer.com",
    "schneier.com", "wikipedia.org",   # tertiary, but well-sourced
}

# State-controlled or state-aligned media / known propaganda outlets.  Not
# automatically false — but treat as INTERESTED parties and say so.
_STATE_MEDIA = {
    "rt.com", "sputniknews.com", "sputnikglobe.com", "tass.com",
    "tass.ru", "ria.ru", "globaltimes.cn", "cgtn.com", "xinhuanet.com",
    "chinadaily.com.cn", "people.cn", "presstv.ir", "presstv.co.uk",
    "mehrnews.com", "kcna.kp", "telesurenglish.net", "granma.cu",
    "en.mehrnews.com", "almasdarnews.com",
}

# Satire — facially false on purpose.  Flag hard; never treat as a fact.
_SATIRE = {
    "theonion.com", "babylonbee.com", "clickhole.com", "thebeaverton.com",
    "thedailymash.co.uk", "newsthump.com", "duffelblog.com",
    "reductress.com", "waterfordwhispersnews.com",
}

# User-generated / community.  Often useful, sometimes first to the truth,
# but not authoritative on its own — corroborate before relying.
_COMMUNITY = {
    "reddit.com", "quora.com", "stackexchange.com", "stackoverflow.com",
    "serverfault.com", "superuser.com", "news.ycombinator.com",
    "medium.com", "substack.com", "blogspot.com", "wordpress.com",
    "tumblr.com", "github.com", "gist.github.com", "gitlab.com",
    "discord.com", "x.com", "twitter.com", "facebook.com",
    "youtube.com", "tiktok.com",
}

# Outlets with a strong slant / mixed reliability record.  Read, but
# weight accordingly and look for an independent corroboration.
_MIXED = {
    "foxnews.com", "msnbc.com", "breitbart.com", "huffpost.com",
    "dailymail.co.uk", "nypost.com", "thegatewaypundit.com",
    "infowars.com", "zerohedge.com", "dailywire.com", "vox.com",
    "buzzfeednews.com", "newsmax.com", "theepochtimes.com",
    "naturalnews.com",
}

_TIER_RANK = {
    "primary": 5, "reputable": 4, "community": 2,
    "mixed": 2, "state_media": 1, "low_quality": 1, "satire": 0,
    "unknown": 3,
}

_TIER_LABEL = {
    "primary": "primary/official",
    "reputable": "reputable",
    "community": "community/UGC",
    "mixed": "mixed-reliability",
    "state_media": "STATE MEDIA — interested party",
    "satire": "SATIRE — not factual",
    "low_quality": "low-quality",
    "unknown": "unverified domain",
}


def registrable_domain(url: str) -> str:
    """Best-effort registrable domain (eTLD+1) without external deps.
    Handles the common multi-part public suffixes (co.uk, com.cn, gov.uk,
    org.uk, ac.uk, gob.mx, com.au, co.jp ...) well enough for grouping."""
    try:
        host = urlparse(url if "://" in url else "https://" + url).netloc.lower()
    except Exception:
        return ""
    host = host.split("@")[-1].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = {"co", "com", "org", "net", "gov", "edu", "ac", "gob", "go"}
    if parts[-2] in two and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def classify_domain(url: str) -> Tuple[str, str]:
    """Return (tier_key, registrable_domain).  Subdomain matches inherit the
    parent's tier (news.bbc.co.uk → reputable via bbc.co.uk)."""
    dom = registrable_domain(url)
    if not dom:
        return "unknown", ""
    host = urlparse(url if "://" in url else "https://" + url).netloc.lower()

    def _hit(s: set) -> bool:
        return dom in s or any(host == d or host.endswith("." + d) for d in s)

    if dom.endswith(".gov") or ".gov." in ("." + dom + ".") or \
       dom.endswith(".mil") or dom.endswith(".edu") or dom.endswith(".int"):
        return "primary", dom
    if _hit(_PRIMARY):
        return "primary", dom
    if _hit(_STATE_MEDIA):
        return "state_media", dom
    if _hit(_SATIRE):
        return "satire", dom
    if _hit(_REPUTABLE):
        return "reputable", dom
    if _hit(_MIXED):
        return "mixed", dom
    if _hit(_COMMUNITY):
        return "community", dom
    return "unknown", dom


# ═════════════════════════════════════════════════════════════════════
# CORROBORATION — cheap salient-token overlap between sources
# ═════════════════════════════════════════════════════════════════════

_NUM_RE = re.compile(r"\b\d[\d,]*(?:\.\d+)?\s?%?\b")
_ENTITY_RE = re.compile(r"\b(?:[A-Z][a-zA-Z0-9.&'-]+)(?:\s+[A-Z][a-zA-Z0-9.&'-]+){0,3}\b")
_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
_STOP_ENTITIES = {
    "The", "This", "That", "These", "Those", "There", "Here", "From",
    "With", "When", "What", "Which", "While", "After", "Before", "About",
    "According", "However", "Also", "More", "Most", "Some", "Many",
    "One", "Two", "Three", "First", "New", "News", "Read", "Home",
    "Search", "Menu", "Share", "Login", "Sign", "Subscribe", "Cookie",
}


def _salient(text: str) -> set:
    """Pull the tokens most likely to encode the actual claim: numbers,
    years, and multi-word proper nouns.  Used only for overlap scoring."""
    t = text[:4000]
    out: set = set()
    for m in _NUM_RE.findall(t):
        out.add(m.replace(",", "").strip())
    for y in _YEAR_RE.findall(t):
        out.add(y)
    for e in _ENTITY_RE.findall(t):
        e = e.strip()
        first = e.split()[0]
        if first in _STOP_ENTITIES or len(e) < 4:
            continue
        out.add(e.lower())
    return out


def _overlap(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / max(1, min(len(a), len(b)))


_ANCHOR_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_ANCHOR_VER_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")
_ANCHOR_ACRO_RE = re.compile(r"\b[A-Z]{2,6}\d*\b")


def _anchors(text: str) -> set:
    """High-signal identifiers that pin down WHICH thing is being discussed:
    CVE IDs, version/score numbers, short acronyms.  Two sources sharing these
    corroborate each other even when their prose is worded completely
    differently — which is exactly the CVE case prose-overlap scored too low."""
    t = text[:6000]
    out: set = set()
    for m in _ANCHOR_CVE_RE.findall(t):
        out.add(m.upper())
    for m in _ANCHOR_VER_RE.findall(t):
        out.add(m)
    for m in _ANCHOR_ACRO_RE.findall(t):
        if m not in _STOP_ACRONYMS:
            out.add(m)
    return out


# Common acronyms that don't pin down a specific claim.
_STOP_ACRONYMS = {"THE", "AND", "FOR", "WITH", "FROM", "THIS", "THAT", "HTTP",
                  "HTTPS", "HTML", "JSON", "API", "URL", "PDF", "FAQ", "CEO",
                  "USA", "UK", "EU", "AM", "PM", "GMT", "UTC"}


# ═════════════════════════════════════════════════════════════════════
# PUBLIC — verify(query, ...)
# ═════════════════════════════════════════════════════════════════════

def _pick_diverse(results: List[Dict[str, Any]], want: int,
                  per_domain: int = 1) -> List[Dict[str, Any]]:
    """Take search results and pick up to `want`, capping how many come from
    any one registrable domain, so the source set is actually independent."""
    picked: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for r in results:
        url = r.get("url") or ""
        if not url:
            continue
        dom = registrable_domain(url)
        if seen.get(dom, 0) >= per_domain:
            continue
        seen[dom] = seen.get(dom, 0) + 1
        picked.append(r)
        if len(picked) >= want:
            break
    return picked


def _best_excerpt(text: str, query: str, width: int = 320) -> str:
    """The chunk of a page most likely to carry the answer: the window
    around the densest cluster of query terms."""
    if not text:
        return ""
    terms = [w.lower() for w in re.findall(r"\w+", query) if len(w) > 2]
    low = text.lower()
    best_pos, best_hits = 0, -1
    step = 120
    for pos in range(0, max(1, len(text) - width), step):
        window = low[pos:pos + width]
        hits = sum(window.count(t) for t in terms)
        if hits > best_hits:
            best_hits, best_pos = hits, pos
    chunk = text[best_pos:best_pos + width].strip()
    chunk = re.sub(r"\s+", " ", chunk)
    return chunk


def verify(
    query: str,
    search_fn: Callable[..., Dict[str, Any]],
    read_fn: Callable[..., Dict[str, Any]],
    settings: Optional[Dict[str, Any]] = None,
    max_sources: int = 5,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Gather, score, and cross-check sources for `query`.

    search_fn(query, max_results) -> dict like tool_web_search
    read_fn(url, max_chars)        -> dict like tool_web_read

    Returns a structured dict (plus a `text` field rendered for the model).
    Never raises; on failure returns {"ok": False, "error": ...}.
    """
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "no query"}
    s = settings or {}
    try:
        max_sources = max(2, min(int(max_sources), 8))
    except (TypeError, ValueError):
        max_sources = 5

    if log:
        try:
            log(f"verify: searching '{query[:60]}'")
        except Exception:
            pass

    # 1 — search (Basilisk's stack already tries DDG html/lite + Mojeek).
    try:
        sr = search_fn(query, max_results=max(max_sources * 3, 10))
    except Exception as e:
        return {"ok": False, "error": f"search failed: {e}", "query": query}
    if not sr or not sr.get("ok"):
        return {"ok": False, "error": (sr or {}).get("error", "search failed"),
                "query": query, "instant_answer": (sr or {}).get("instant_answer", "")}

    results = sr.get("results") or []
    instant = sr.get("instant_answer") or ""

    # 2 — pick a diverse set, then over-sample one extra per domain only if
    # we're short on independent domains.
    picked = _pick_diverse(results, max_sources, per_domain=1)
    if len(picked) < max_sources:
        picked += [r for r in _pick_diverse(results, max_sources, per_domain=2)
                   if r not in picked][: max_sources - len(picked)]

    # 3 — fetch the picked pages in parallel and score each.
    def _fetch(r: Dict[str, Any]) -> Dict[str, Any]:
        url = r.get("url", "")
        tier, dom = classify_domain(url)
        rec: Dict[str, Any] = {
            "url": url, "domain": dom, "tier": tier,
            "tier_label": _TIER_LABEL.get(tier, tier),
            "title": r.get("title", ""), "snippet": r.get("snippet", ""),
            "excerpt": "", "salient": set(), "anchors": set(), "fetched": False,
        }
        # Don't waste a fetch on satire; flag and move on.
        if tier == "satire":
            rec["excerpt"] = "(satire site — not fetched)"
            return rec
        try:
            rr = read_fn(url, max_chars=4000)
            if rr and rr.get("ok"):
                body = rr.get("text", "")
                rec["excerpt"] = _best_excerpt(body, query)
                rec["salient"] = _salient(body)
                rec["anchors"] = _anchors(body)
                rec["fetched"] = True
                rec["read_via"] = rr.get("source", "")
        except Exception as e:
            rec["excerpt"] = f"(could not read: {type(e).__name__})"
        if not rec["excerpt"]:
            rec["excerpt"] = rec["snippet"] or "(no readable text)"
            if not rec["salient"]:
                rec["salient"] = _salient(rec["snippet"])
                rec["anchors"] = _anchors(rec["snippet"])
        return rec

    sources: List[Dict[str, Any]] = []
    if picked:
        workers = min(5, len(picked))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                sources = list(ex.map(_fetch, picked))
        except Exception:
            sources = [_fetch(r) for r in picked]

    # 4 — corroboration: per pair, the stronger of prose-token overlap and
    # anchor agreement.  Anchor agreement catches sources that plainly describe
    # the same CVE / version / figure in different words — prose overlap alone
    # scored those far too low (the regreSSHion case: 4 sources agreeing, 0.18).
    read_src = [x for x in sources if x.get("fetched") and x["salient"]]
    pair_scores: List[float] = []
    for i in range(len(read_src)):
        for j in range(i + 1, len(read_src)):
            prose = _overlap(read_src[i]["salient"], read_src[j]["salient"])
            anchor = _overlap(read_src[i].get("anchors", set()),
                              read_src[j].get("anchors", set()))
            pair_scores.append(max(prose, anchor))
    corroboration = round(sum(pair_scores) / len(pair_scores), 2) \
        if pair_scores else 0.0

    # 5 — tally tiers / flags.
    tiers = [x["tier"] for x in sources]
    domains = sorted({x["domain"] for x in sources if x["domain"]})
    n_independent = len(domains)
    state_media = [x["domain"] for x in sources if x["tier"] == "state_media"]
    satire = [x["domain"] for x in sources if x["tier"] == "satire"]
    credible = [x for x in sources if x["tier"] in ("primary", "reputable")]
    has_primary = any(t == "primary" for t in tiers)

    # 6 — confidence: independence + credibility + corroboration, knocked
    # down by propaganda/satire presence and thin sourcing.
    conf = 0.0
    conf += min(n_independent, 4) * 0.12          # up to 0.48 for breadth
    conf += min(len(credible), 3) * 0.10          # up to 0.30 for quality
    conf += corroboration * 0.30                  # up to 0.30 for agreement
    if has_primary:
        conf += 0.05
    if state_media and not credible:
        conf -= 0.25                              # only interested parties talk
    if satire:
        conf -= 0.10
    if n_independent < 2:
        conf -= 0.20                              # single-source: weak
    conf = max(0.0, min(1.0, conf))
    if conf >= 0.7:
        conf_label = "high"
    elif conf >= 0.45:
        conf_label = "moderate"
    elif conf >= 0.25:
        conf_label = "low"
    else:
        conf_label = "very low"

    # 7 — render a compact briefing the model can reason over.
    lines: List[str] = [f"VERIFICATION BRIEF — query: {query}"]
    if instant:
        lines.append(f"Instant answer (unverified): {instant}")
    lines.append(
        f"Independent domains: {n_independent} | corroboration: "
        f"{corroboration:.2f} | confidence: {conf_label} ({conf:.2f})")
    if state_media:
        lines.append(f"⚠ STATE MEDIA present: {', '.join(state_media)} — "
                     f"interested parties; weight accordingly.")
    if satire:
        lines.append(f"⚠ SATIRE present: {', '.join(satire)} — not factual.")
    if not credible:
        lines.append("⚠ No primary/reputable source in the set — treat the "
                     "answer as provisional and say so.")
    lines.append("")
    lines.append("Sources (tier — domain — what it says):")
    # Show highest-credibility first.
    for x in sorted(sources, key=lambda r: -_TIER_RANK.get(r["tier"], 3)):
        ex = x["excerpt"][:300]
        lines.append(f"  • [{x['tier_label']}] {x['domain']}")
        lines.append(f"    {x['url']}")
        if ex:
            lines.append(f"    “{ex}”")
    lines.append("")
    lines.append(
        "HOW TO USE THIS: state what the credible sources agree on; call out "
        "any disagreement explicitly; never present a state-media or satire "
        "claim as established fact; give the operator the confidence level and "
        "cite the domains.  If confidence is low, say what you'd need to be sure.")

    return {
        "ok": True,
        "query": query,
        "instant_answer": instant,
        "n_independent_domains": n_independent,
        "domains": domains,
        "corroboration": corroboration,
        "confidence": round(conf, 2),
        "confidence_label": conf_label,
        "has_primary_source": has_primary,
        "state_media": state_media,
        "satire": satire,
        # Sets are scoring scratch, not output, and json.dumps() cannot encode
        # them.  This used to exclude "salient" BY NAME; when the anchor channel
        # was added for the CVE case it produced a second set, "anchors", and
        # the name-list did not know about it — so the whole result became
        # unserialisable, which for a tool result is a crash at the point of
        # handing it to the model.  Filtering on TYPE states the actual rule, so
        # the next scratch set cannot reintroduce this.
        "sources": [
            {k: v for k, v in x.items() if not isinstance(v, (set, frozenset))}
            for x in sources
        ],
        "text": "\n".join(lines),
    }
