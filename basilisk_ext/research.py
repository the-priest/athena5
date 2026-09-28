"""
basilisk_ext.research — searching like a researcher instead of like a lucky guess.

WHAT WAS THERE BEFORE
=====================
"There is no search tool. Search IS web_read against a results page." One
query, one engine, read the first plausible link, answer. That works right
up until any of the four things that go wrong with it:

  * ONE PHRASING. The operator's words are not always the words the page
    uses. A single query against a single index either hits or it doesn't,
    and when it doesn't the model concludes the fact is unfindable.
  * ONE ENGINE. Every index has holes, and the one engine used was the one
    most likely to be rate-limiting or serving a bot check.
  * ONE SOURCE. A single page is a claim, not a fact. SEO spam, a stale
    mirror and a wrong-but-confident blog post all read exactly like an
    authoritative answer once they are the only thing in the context.
  * NO DISAGREEMENT SIGNAL. When two sources conflict, reading only one of
    them makes the conflict invisible — which is the single most expensive
    failure here, because the answer is confidently wrong and nothing in
    the transcript hints otherwise.

WHAT THIS DOES
==============
Several queries, several engines, several sources, and then it SAYS whether
the sources agreed. Concretely:

    expand(question)  -> a handful of real query phrasings
    search(...)       -> merged, de-duplicated results, ranked by how many
                         engines independently returned each URL
    research(...)     -> search, pick diverse sources, read them, and report
                         the agreements AND the contradictions

AGREEMENT IS THE PRODUCT. `research` does not decide what is true — it
reports that four sources say 7.95 and one says 7.94, and which is which,
and lets the model weigh them with its citations in hand. A tool that
silently picked a winner would be hiding exactly the information that makes
the answer trustworthy.

INJECTED I/O, ALWAYS. This module never opens a socket. The caller passes
`read_fn(url) -> dict`, which in the app is web_read — so the SSRF floor,
the shield, the browser and the operator's settings all apply here without
this file knowing anything about them. Same contract as every other module
in this package: stdlib only, no host imports.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Sequence, Tuple

__all__ = ["expand", "search", "research", "ENGINES", "extract_results"]

# Engines, in the order they are tried. Each is (name, url template).
# DuckDuckGo's html endpoint first because it is the most permissive; the
# others exist so ONE of them being down or challenging is not the end of
# the search. Mojeek has its own crawler rather than reselling Bing, which
# is the point of including it — a second opinion from a shared index is
# not a second opinion.
ENGINES: List[Tuple[str, str]] = [
    ("duckduckgo", "https://html.duckduckgo.com/html/?q={q}"),
    ("bing", "https://www.bing.com/search?q={q}&setlang=en"),
    ("mojeek", "https://www.mojeek.com/search?q={q}"),
    ("startpage", "https://www.startpage.com/sp/search?query={q}"),
]

MAX_QUERIES = 4
MAX_RESULTS = 12
MAX_READS = 5

# Junk that is never the answer to anything, and reliably outranks the
# thing that is. Not a quality judgement on the sites — an aggregator's
# copy of a changelog is a copy, and citing it instead of the changelog is
# how a stale number gets laundered into an answer.
_SKIP_HOST_RE = re.compile(
    r"(^|\.)(pinterest\.|facebook\.com|instagram\.com|x\.com|twitter\.com|"
    r"tiktok\.com|linkedin\.com|quora\.com|coursehero\.|scribd\.|"
    r"doubleclick\.|googleadservices\.|bing\.com/aclick)", re.I)

# Engine-internal links: settings pages, next-page links, "search for this
# on another engine" — all of which look exactly like results.
_ENGINE_HOST_RE = re.compile(
    r"(^|\.)(duckduckgo\.com|bing\.com|mojeek\.com|startpage\.com|"
    r"google\.[a-z.]+|yandex\.|ecosia\.org|search\.marcia)", re.I)


def _norm_url(u: str) -> str:
    """Canonical form for de-duplication across engines.

    Engines decorate the same URL differently (utm_*, a ref token, a
    trailing slash, http vs https), and without this the agreement count —
    which is the whole ranking signal — counts one source three times."""
    try:
        u = (u or "").strip()
        if not u:
            return ""
        p = urllib.parse.urlsplit(u)
        host = (p.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query)
             if not k.lower().startswith(("utm_", "fbclid", "gclid", "ref",
                                          "mc_", "_ga", "spm"))]
        path = (p.path or "/").rstrip("/") or "/"
        return urllib.parse.urlunsplit(
            ("https", host, path, urllib.parse.urlencode(q), ""))
    except Exception:
        return (u or "").strip()


def _host(u: str) -> str:
    try:
        h = (urllib.parse.urlsplit(u).hostname or "").lower()
        return h[4:] if h.startswith("www.") else h
    except Exception:
        return ""


# ── query expansion ──────────────────────────────────────────────────
_STOP = frozenset("""
a an the is are was were be been being do does did doing of for to in on at
by with from about as into like through after over between out against
during without before under around among can could should would may might
must will shall i you he she it we they me him her us them my your his its
our their this that these those and or but if then than so very just also
please tell show give me my what whats what's how why when where who which
""".split())

# Words that mean "right now" — a question carrying one gets a variant with
# the year spelled out, because an index ranks a 2019 page and a 2026 page
# identically for "latest".
_RECENCY_RE = re.compile(
    r"\b(latest|current|newest|recent|now|today|this year|up to date|"
    r"up-to-date|nowadays|these days)\b", re.I)


def _keywords(q: str, cap: int = 8) -> List[str]:
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+#_\-]*", q or "")
    out: List[str] = []
    for w in words:
        if w.lower() in _STOP:
            continue
        if len(w) < 2 and not w.isdigit():
            continue
        out.append(w)
        if len(out) >= cap:
            break
    return out


def expand(question: str, extra: Sequence[str] = (),
           year: str = "") -> List[str]:
    """Turn one question into a few real query phrasings.

    Deliberately NOT a model call: this runs before the model would get a
    chance to see any results, it must be instant, and a deterministic
    expansion can be tested. The model can always pass its own queries —
    `extra` goes to the front, because a query the model wrote on purpose
    beats anything generated from stop-word removal.
    """
    q = re.sub(r"\s+", " ", str(question or "")).strip()
    out: List[str] = []

    def _add(s: str) -> None:
        s = re.sub(r"\s+", " ", (s or "")).strip()
        if not s or len(s) < 2:
            return
        low = s.lower()
        if any(low == o.lower() for o in out):
            return
        out.append(s[:300])

    for e in (extra or ()):
        _add(str(e))
    if q:
        _add(q.rstrip("?"))
    kw = _keywords(q)
    if len(kw) >= 2:
        _add(" ".join(kw))
    if _RECENCY_RE.search(q):
        y = str(year or time.strftime("%Y"))
        # Keep the keyword form for this one: "what is the latest X 2026"
        # reads like a natural-language query and ranks like one, which is
        # not what we want from the recency variant.
        _add(" ".join(kw or [q]) + " " + y)
    return out[:MAX_QUERIES]


# ── result extraction ────────────────────────────────────────────────
# web_read hands back TEXT with links preserved as "title (url)" — see
# _wr_html_to_text in the host. So results are parsed out of that shape
# rather than out of HTML: it means one parser serves every engine, and it
# keeps working when an engine reshuffles its markup, which they all do.
_LINK_RE = re.compile(r"([^()\n]{0,180}?)\s*\((https?://[^\s()]{6,400})\)")


def extract_results(text: str, engine: str = "",
                    limit: int = MAX_RESULTS) -> List[Dict[str, Any]]:
    """Pull (title, url) pairs out of a rendered results page."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _LINK_RE.finditer(text or ""):
        title = (m.group(1) or "").strip(" -–—|·>\t")
        url = (m.group(2) or "").strip().rstrip(".,);")
        if not url:
            continue
        h = _host(url)
        if not h or _ENGINE_HOST_RE.search(h) or _SKIP_HOST_RE.search(h):
            continue
        key = _norm_url(url)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append({"title": title[:180], "url": url, "key": key,
                    "host": h, "engine": engine, "rank": len(out) + 1})
        if len(out) >= limit:
            break
    return out


def search(question: str,
           read_fn: Callable[[str], Dict[str, Any]],
           queries: Sequence[str] = (),
           engines: Sequence[str] = (),
           limit: int = MAX_RESULTS,
           max_pages: int = 4) -> Dict[str, Any]:
    """Run the query set across the engine set and merge what comes back.

    RANKING IS BY AGREEMENT, not by any one engine's order. A URL two
    independent indexes both surfaced for two different phrasings of the
    question is a better bet than whatever one engine put first, and
    unlike an engine's own ranking it cannot be bought.
    """
    qs = list(expand(question, extra=queries)) or [str(question or "")]
    names = [n for n, _ in ENGINES]
    if engines:
        want = {str(e).strip().lower() for e in engines}
        names = [n for n in names if n in want] or names
    tmpl = dict(ENGINES)

    merged: Dict[str, Dict[str, Any]] = {}
    pages: List[Dict[str, Any]] = []
    fetched = 0
    for q in qs:
        for name in names:
            if fetched >= max_pages:
                break
            url = tmpl[name].format(q=urllib.parse.quote_plus(q))
            fetched += 1
            try:
                r = read_fn(url) or {}
            except Exception as e:
                pages.append({"engine": name, "query": q, "ok": False,
                              "error": f"{type(e).__name__}: {e}"})
                continue
            if not r.get("ok"):
                pages.append({"engine": name, "query": q, "ok": False,
                              "error": str(r.get("error") or "")[:200]})
                continue
            res = extract_results(r.get("text") or "", engine=name,
                                  limit=limit)
            pages.append({"engine": name, "query": q, "ok": True,
                          "results": len(res),
                          "via": r.get("engine", "")})
            for item in res:
                k = item["key"]
                cur = merged.get(k)
                if cur is None:
                    merged[k] = {
                        "title": item["title"], "url": item["url"],
                        "host": item["host"],
                        "engines": [name], "queries": [q],
                        "best_rank": item["rank"],
                    }
                else:
                    if name not in cur["engines"]:
                        cur["engines"].append(name)
                    if q not in cur["queries"]:
                        cur["queries"].append(q)
                    cur["best_rank"] = min(cur["best_rank"], item["rank"])
                    if len(item["title"]) > len(cur["title"]):
                        cur["title"] = item["title"]
        # ENOUGH IS ENOUGH. Once several engines agree on a healthy set,
        # more queries cost round-trips and add nothing. A search that
        # keeps searching after it has the answer is the other half of
        # "knowing when to stop".
        if len(merged) >= limit and sum(
                1 for v in merged.values() if len(v["engines"]) > 1) >= 3:
            break

    ranked = sorted(
        merged.values(),
        key=lambda v: (-len(v["engines"]), -len(v["queries"]),
                       v["best_rank"], v["host"]))
    ok_pages = [p for p in pages if p.get("ok")]
    out: Dict[str, Any] = {
        "ok": bool(ranked),
        "queries": qs,
        "engines_tried": names,
        "pages": pages,
        "results": [{k: v for k, v in r.items() if k != "key"}
                    for r in ranked[:limit]],
        "count": len(ranked),
    }
    if not ranked:
        out["error"] = (
            "no results could be extracted from any engine. "
            + ("Every results page failed to load — check connectivity, or "
               "the engines are challenging this client; browser_status "
               "says which reader is in use."
               if not ok_pages else
               "The pages loaded but nothing parsed as a result link, which "
               "usually means a bot-check page was served instead. Try "
               "web_read on a specific site's own search, or a different "
               "phrasing."))
    return out


# ── reading and cross-checking ───────────────────────────────────────
# Facts worth cross-checking are the ones that are short, specific, and
# wrong in a way nobody notices: versions, dates, counts, prices.
_CLAIM_PATTERNS = (
    ("version", re.compile(r"\bv?(\d+\.\d+(?:\.\d+){0,2})\b")),
    ("year", re.compile(r"\b(20\d{2})\b")),
    ("date", re.compile(
        r"\b(\d{4}-\d{2}-\d{2}|\d{1,2}\s+"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})\b",
        re.I)),
    ("money", re.compile(r"([$€£]\s?\d[\d,]*(?:\.\d+)?)")),
)


def _claims(text: str, cap: int = 60) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    body = (text or "")[:40000]
    for kind, rx in _CLAIM_PATTERNS:
        vals: List[str] = []
        for m in rx.finditer(body):
            v = m.group(1).strip()
            if v not in vals:
                vals.append(v)
            if len(vals) >= cap:
                break
        if vals:
            out[kind] = vals
    return out


def _agreement(per_source: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Which specific values did several sources independently carry?

    Reported, never resolved. The point is to hand the model the shape of
    the evidence — "four sources say 7.95, one says 7.94" — not to pick a
    winner behind its back and present a vote as a fact."""
    tally: Dict[str, Dict[str, List[str]]] = {}
    for src in per_source:
        host = src.get("host") or ""
        for kind, vals in (src.get("claims") or {}).items():
            for v in vals[:20]:
                tally.setdefault(kind, {}).setdefault(v, [])
                if host not in tally[kind][v]:
                    tally[kind][v].append(host)
    out: Dict[str, Any] = {}
    for kind, vals in tally.items():
        multi = {v: hs for v, hs in vals.items() if len(hs) > 1}
        if not multi:
            continue
        out[kind] = [
            {"value": v, "sources": hs, "n": len(hs)}
            for v, hs in sorted(multi.items(),
                                key=lambda kv: (-len(kv[1]), kv[0]))
        ][:8]
    return out


def research(question: str,
             read_fn: Callable[[str], Dict[str, Any]],
             queries: Sequence[str] = (),
             max_sources: int = 3,
             per_source_chars: int = 4000,
             engines: Sequence[str] = ()) -> Dict[str, Any]:
    """Search, read several DIFFERENT sources, and report where they agree.

    DOMAIN DIVERSITY IS ENFORCED, one page per host. Three pages from the
    same site are one source with three URLs, and counting them as three
    agreeing sources is how a single wrong site becomes a consensus.
    """
    t0 = time.time()
    try:
        n = max(1, min(MAX_READS, int(max_sources or 3)))
    except Exception:
        n = 3
    s = search(question, read_fn, queries=queries, engines=engines)
    if not s.get("ok"):
        return {"ok": False, "stage": "search",
                "error": s.get("error"), "search": s}

    picked: List[Dict[str, Any]] = []
    hosts: set = set()
    for r in s["results"]:
        h = r.get("host") or ""
        if h in hosts:
            continue
        hosts.add(h)
        picked.append(r)
        if len(picked) >= n:
            break

    sources: List[Dict[str, Any]] = []
    for r in picked:
        try:
            page = read_fn(r["url"]) or {}
        except Exception as e:
            sources.append({"url": r["url"], "host": r.get("host"),
                            "ok": False,
                            "error": f"{type(e).__name__}: {e}"})
            continue
        if not page.get("ok"):
            sources.append({"url": r["url"], "host": r.get("host"),
                            "ok": False,
                            "error": str(page.get("error") or "")[:200]})
            continue
        txt = str(page.get("text") or "")
        sources.append({
            "url": page.get("final_url") or r["url"],
            "host": r.get("host"),
            "title": r.get("title"),
            "ok": True,
            "engines_that_found_it": r.get("engines"),
            "read_with": page.get("engine", ""),
            "text": txt[:per_source_chars],
            "truncated": len(txt) > per_source_chars,
            "claims": _claims(txt),
        })

    good = [x for x in sources if x.get("ok")]
    agree = _agreement(good)
    out: Dict[str, Any] = {
        "ok": bool(good),
        "question": question,
        "queries": s.get("queries"),
        "searched": s.get("engines_tried"),
        "candidates": len(s.get("results") or ()),
        "sources": [{k: v for k, v in x.items() if k != "claims"}
                    for x in sources],
        "agreement": agree,
        "elapsed": round(time.time() - t0, 2),
    }
    if not good:
        out["error"] = ("found results but could not read any of them. "
                        "The URLs are in `search_results` — try web_read on "
                        "one directly and report what it says.")
        out["search_results"] = s.get("results")
        return out
    out["how_to_use"] = (
        "These are %d INDEPENDENT sources (one per domain). `agreement` "
        "lists values more than one of them carried — that is corroboration, "
        "not proof. If two sources disagree, SAY SO and name which said "
        "what; do not average them and do not silently pick one. Cite the "
        "URL you actually took each fact from. Anything you could not "
        "confirm here, report as unconfirmed rather than filling it in."
        % len(good))
    if len(good) < 2:
        out["warning"] = (
            "Only ONE source could be read, so nothing is corroborated. Say "
            "in your answer that it rests on a single source, or read "
            "another before answering.")
    return out
