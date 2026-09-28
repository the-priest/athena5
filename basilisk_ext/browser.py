"""
basilisk_ext.browser — a REAL browser behind web_read, Camoufox first.

WHY
===
web_read has always been urllib: one GET, no JavaScript, a bot-shaped TLS
fingerprint and a static User-Agent.  That is fine for a changelog and
useless for most of the modern web — a JS-rendered page returns an empty
shell, a Cloudflare or DataDome interstitial returns a challenge page with
HTTP 200, and the model reads either as "the page was blank" and either
guesses or re-fetches until the repeat guard stops it.  Neither failure
looks like a failure from the inside, which is what makes it expensive.

Camoufox is a hardened Firefox with its anti-fingerprinting done at the C++
level rather than by patching `navigator` from JS, so it renders the page a
person would see.  It speaks the Playwright protocol, so this module is
written against the Playwright API and Camoufox is simply the preferred
launcher.  That is deliberate: the same code path serves Camoufox, a plain
Playwright Firefox, and Chromium, so the fallback ladder is one code path
with three entries rather than three implementations that drift.

THE SSRF FLOOR IS INJECTED, NOT REIMPLEMENTED
=============================================
This module does NOT decide what a private address is.  `fetch()` REQUIRES
a `host_ok` predicate from the caller and refuses to run without one —
fail closed.  The rule lives in exactly one place (basilisk_core), and a
second copy here is precisely the "one rule, two consumers" drift that has
produced a bug in this codebase every time it has been allowed to happen.

A browser makes the floor harder than urllib did, and the difference is the
whole reason this file is careful:

  * urllib fetches ONE url and the caller validates each redirect hop.
  * a browser follows its own redirects AND loads subresources AND runs
    script that can fetch anything it likes.

So the predicate is enforced by a route handler on EVERY request the page
makes, of every type, before it leaves the browser — not just on the URL we
asked for.  A page that tries to read 169.254.169.254 gets its request
aborted, and the abort is REPORTED in `blocked`, because a silent block is
how you end up trusting a page that was doing something interesting.

NEVER IMPORTS THE HOST.  Stdlib plus an optional third-party browser; the
whole module degrades to `available() -> False` if that browser is absent,
and web_read goes back to urllib with nothing else changed.
"""

from __future__ import annotations

import atexit
import queue
import os
import re
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = ["available", "engine_name", "fetch", "shutdown", "probe"]

# How long a launched browser is kept warm between fetches.  Launching
# Firefox costs 1-3 seconds; a research turn does five to fifteen reads, so
# a per-fetch launch would dominate the turn.  Idle-closing bounds the cost
# of keeping it: an operator who asks one question does not get a browser
# process resident for the rest of the day.
IDLE_CLOSE_S = 180.0
DEFAULT_TIMEOUT = 25
MAX_TIMEOUT = 120
# A page is read once the DOM is parsed and the network has gone quiet;
# `networkidle` alone hangs forever on pages with a live socket (chat
# widgets, analytics beacons), which is most news sites.
_SETTLE_MS = 1200

_LOCK = threading.RLock()
_STATE: Dict[str, Any] = {
    "engine": "",        # "camoufox" | "firefox" | "chromium"
    "pw": None,          # the sync_playwright context manager
    "browser": None,
    "cm": None,          # camoufox's own context manager, when used
    "last_used": 0.0,
    "timer": None,
    "failed": "",        # why launch failed last time, for the report
}

# "camoufox-bin" sits second on purpose: it is the SAME Camoufox Firefox build,
# launched straight from its on-disk binary via Playwright's executable_path,
# for the very common case where the operator ran `camoufox fetch` (so the
# browser tree is in ~/.cache/camoufox) but the `camoufox` PYTHON package is not
# importable in the interpreter Basilisk runs under. Without this tier that
# setup skipped all the way down to plain Playwright Firefox/Chromium — which
# the operator usually has NOT fetched — and fell to bare HTTP. That is the
# "camoufox doesn't work right" the operator saw: the browser was on disk the
# whole time, just behind a missing import.
_ENGINE_ORDER = ("camoufox", "camoufox-bin", "firefox", "chromium")


def _env_engine() -> str:
    """BASILISK_BROWSER=camoufox|camoufox-bin|firefox|chromium|off overrides."""
    v = (os.environ.get("BASILISK_BROWSER") or "").strip().lower()
    return v if v in _ENGINE_ORDER or v in ("off", "none") else ""


def _find_camoufox_binary() -> str:
    """Absolute path to an on-disk Camoufox Firefox executable, or "".

    Read-only and cheap: it does not import camoufox and does not launch
    anything. Tries the package's own resolver first (when importable), then
    the standard cache/opt locations Camoufox fetches into, on every OS.
    """
    # 1. If the package IS importable, ask it where the browser lives.
    try:
        from camoufox.pkgman import installed_path  # type: ignore
        p = str(installed_path() or "").strip()
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
        if p and os.path.isdir(p):
            for nm in ("camoufox-bin", "camoufox", "firefox"):
                q = os.path.join(p, nm)
                if os.path.isfile(q) and os.access(q, os.X_OK):
                    return q
    except Exception:
        pass
    # 2. Known install roots (Linux ~/.cache, macOS Caches, Windows LOCALAPPDATA,
    #    an explicit override, and the common system dirs).
    import glob
    home = os.path.expanduser("~")
    roots = [
        os.environ.get("CAMOUFOX_PATH", ""),
        os.path.join(home, ".cache", "camoufox"),
        os.path.join(home, "Library", "Caches", "camoufox"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "camoufox"),
        "/opt/camoufox", "/usr/local/share/camoufox", "/usr/share/camoufox",
    ]
    names = ("camoufox-bin", "camoufox", "firefox", "camoufox.exe",
             "firefox.exe")
    for r in roots:
        if not r or not os.path.isdir(r):
            continue
        for nm in names:
            q = os.path.join(r, nm)
            if os.path.isfile(q) and os.access(q, os.X_OK):
                return q
        # one level of nesting (some builds unpack into a versioned subdir)
        for nm in names:
            for q in glob.glob(os.path.join(r, "*", nm)):
                if os.path.isfile(q) and os.access(q, os.X_OK):
                    return q
    return ""


def available(prefer: str = "") -> bool:
    """True when SOME browser engine can be launched.

    Import-only check — it does not launch anything, so it is cheap enough
    to call on every web_read."""
    return bool(_pick_engine(prefer))


def _pick_engine(prefer: str = "") -> str:
    forced = _env_engine()
    if forced in ("off", "none"):
        return ""
    pref = (prefer or forced or "").strip().lower()
    order = list(_ENGINE_ORDER)
    if pref in order:
        order.remove(pref)
        order.insert(0, pref)
    elif pref in ("http", "urllib", "off", "none"):
        return ""
    for name in order:
        try:
            if name == "camoufox":
                import camoufox.sync_api  # noqa: F401
                # THE PACKAGE IS NOT THE BROWSER. `pip install camoufox`
                # installs a launcher; the Firefox build it drives arrives
                # separately via `camoufox fetch`. Choosing camoufox on the
                # strength of the import alone means every single web_read
                # pays a failed launch (seconds) before falling back — the
                # exact shape of "it got slower and I don't know why".
                from camoufox.pkgman import installed_verstr
                if not str(installed_verstr() or "").strip():
                    continue
                return "camoufox"
            elif name == "camoufox-bin":
                # The Camoufox browser is on disk but the python package is not
                # usable here — drive the binary directly through Playwright.
                # Needs the Playwright API (not its browser downloads) plus the
                # Camoufox executable; both are checked before we commit to it,
                # so this never becomes a slow failed-launch tier.
                import playwright.sync_api  # noqa: F401
                if not _find_camoufox_binary():
                    continue
                return "camoufox-bin"
            else:
                import playwright.sync_api  # noqa: F401
                return name
        except Exception:
            continue
    return ""


def engine_name() -> str:
    """The engine currently launched, or the one that would be."""
    with _LOCK:
        if _STATE["browser"] is not None:
            return _STATE["engine"]
    return _pick_engine()


def probe() -> Dict[str, Any]:
    """What is installed and what would be used. Read-only, launches nothing."""
    out: Dict[str, Any] = {"ok": True, "engines": {}, "chosen": "",
                           "env_override": _env_engine(), "running": ""}
    for name in _ENGINE_ORDER:
        try:
            if name == "camoufox":
                import camoufox  # noqa: F401
                v = ""
                try:
                    from camoufox.pkgman import installed_verstr
                    v = str(installed_verstr())
                except Exception as e:
                    v = f"python package present, browser NOT fetched ({e})"
                out["engines"]["camoufox"] = v or "present"
            elif name == "camoufox-bin":
                # Report the on-disk binary path if we can find one AND the
                # Playwright API is importable to drive it.
                import playwright  # noqa: F401
                binpath = _find_camoufox_binary()
                out["engines"]["camoufox-bin"] = (
                    f"on-disk binary: {binpath}" if binpath
                    else "no camoufox binary found on disk")
            else:
                import playwright  # noqa: F401
                out["engines"][name] = getattr(playwright, "__version__",
                                               "present")
        except Exception as e:
            out["engines"][name] = f"absent ({type(e).__name__})"
    out["chosen"] = _pick_engine()
    out["camoufox_binary"] = _find_camoufox_binary()
    with _LOCK:
        out["running"] = _STATE["engine"] if _STATE["browser"] else ""
        if _STATE["failed"]:
            out["last_launch_error"] = _STATE["failed"]
    if not out["chosen"]:
        if out["camoufox_binary"]:
            # The browser IS on disk; what's missing is the Playwright API to
            # drive it. This is the precise, actionable version of the message.
            out["note"] = (
                "A Camoufox browser is on disk at "
                f"{out['camoufox_binary']}, but neither the camoufox python "
                "package nor Playwright is importable in the interpreter "
                "Basilisk runs under, so web_read fell back to plain HTTP. "
                "Fix with:  pip install playwright   (that alone lets Basilisk "
                "drive the on-disk Camoufox), or  pip install camoufox && "
                "python3 -m camoufox fetch  for the full launcher.")
        else:
            out["note"] = (
                "No browser engine available — web_read falls back to a plain "
                "HTTP fetch, which cannot render JavaScript or pass a bot "
                "check. Install with: pip install camoufox && python3 -m "
                "camoufox fetch")
    return out


# ══════════════════════════════════════════════════════════════════════
#  THE OWNER THREAD — why this module is not just "call playwright"
# ══════════════════════════════════════════════════════════════════════
# Playwright's SYNC api pins every object it hands you to the thread that
# created it, and Basilisk dispatches each tool call on a FRESH daemon
# thread. So the obvious implementation — launch once, keep the browser in
# a module global, reuse it — works perfectly for the first web_read of a
# session and dies on the second with:
#
#     Error: cannot switch to a different thread (which happens to have
#     exited)
#
# Reproduced before this was written, because "works once, then breaks"
# is the kind of bug that ships: the happy path in a fresh session is
# exactly the path anybody testing it takes.
#
# So ONE dedicated thread owns playwright, the browser, and every page.
# Callers submit a closure and block on a result queue. That buys three
# things at once: thread affinity is correct by construction, the browser
# stays warm between fetches (a cold Firefox launch is 1-3s and a research
# turn does ten reads), and the idle-close timer runs in the same place
# that owns the objects it is closing, so there is no window where a fetch
# and a teardown race.
_JOBS: "queue.Queue[Any]" = queue.Queue()
_WORKER: Optional[threading.Thread] = None
_WORKER_LOCK = threading.Lock()


class _Job:
    __slots__ = ("fn", "out", "done")

    def __init__(self, fn):
        self.fn = fn
        self.out: Any = None
        self.done = threading.Event()


def _worker_loop() -> None:
    global _WORKER
    while True:
        try:
            job = _JOBS.get(timeout=IDLE_CLOSE_S)
        except queue.Empty:
            # Nothing for IDLE_CLOSE_S. Close the browser and retire the
            # thread; the next fetch starts a new one. An operator who
            # asked one question does not keep a Firefox resident all day.
            _teardown()
            with _WORKER_LOCK:
                if _JOBS.empty():
                    _WORKER = None
                    return
            continue
        if job is None:                      # shutdown sentinel
            _teardown()
            with _WORKER_LOCK:
                _WORKER = None
            return
        try:
            job.out = job.fn()
        except Exception as e:               # a job must never kill the owner
            job.out = {"ok": False,
                       "error": f"browser worker: {type(e).__name__}: {e}"}
        finally:
            job.done.set()


def _submit(fn, timeout: float):
    """Run `fn` on the owner thread and wait for it."""
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(target=_worker_loop,
                                       name="basilisk-browser", daemon=True)
            _WORKER.start()
    job = _Job(fn)
    _JOBS.put(job)
    if not job.done.wait(timeout):
        return {"ok": False, "timeout": True, "error": (
            f"the browser did not answer within {int(timeout)}s. The page may "
            f"be hanging on a script; try the same url again, or read a "
            f"lighter version of it.")}
    return job.out


# ── launch / teardown (OWNER THREAD ONLY) ────────────────────────────
def _proxy_from_env() -> Optional[Dict[str, str]]:
    """Honour the shell's proxy settings — INCLUDING no_proxy.

    Taking HTTPS_PROXY and ignoring NO_PROXY is the classic half of this:
    on a box behind a corporate proxy every intranet and localhost fetch
    then gets tunnelled to a gateway that answers 405, and the page comes
    back as a rendered error page with a 200-shaped story around it.
    Playwright takes the exclusion list as `bypass`, so the pair travels
    together or not at all."""
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        v = (os.environ.get(var) or "").strip()
        if v:
            out = {"server": v}
            npx = (os.environ.get("NO_PROXY")
                   or os.environ.get("no_proxy") or "").strip()
            if npx:
                out["bypass"] = npx
            return out
    return None


def _launch(prefer: str = "") -> Tuple[Any, str]:
    """Return (browser, engine). OWNER THREAD ONLY."""
    if _STATE["browser"] is not None:
        return _STATE["browser"], _STATE["engine"]
    name = _pick_engine(prefer)
    if not name:
        raise RuntimeError("no browser engine installed")
    proxy = _proxy_from_env()
    if name == "camoufox":
        from camoufox.sync_api import Camoufox
        kw: Dict[str, Any] = {"headless": True, "humanize": True}
        if proxy:
            kw["proxy"] = proxy
        # Camoufox's context manager IS the launcher; keep it so __exit__
        # can tear the whole thing down. Closing only the browser leaks the
        # Firefox process and its generated profile directory.
        cm = Camoufox(**kw)
        browser = cm.__enter__()
        _STATE["cm"] = cm
    else:
        from playwright.sync_api import sync_playwright
        pw = sync_playwright().start()
        _STATE["pw"] = pw
        kw = {"headless": True}
        if proxy:
            kw["proxy"] = proxy
        if name == "camoufox-bin":
            # Same Camoufox Firefox build, launched from its on-disk binary.
            # It renders JavaScript and carries Camoufox's compiled-in
            # anti-fingerprinting; what it does NOT get is the python launcher's
            # per-run fingerprint randomisation, so the reader labels it
            # "camoufox-bin", distinct from a full "camoufox" run.
            binpath = _find_camoufox_binary()
            if not binpath:
                raise RuntimeError("camoufox binary vanished between pick and "
                                   "launch")
            kw["executable_path"] = binpath
            browser = pw.firefox.launch(**kw)
        else:
            browser = getattr(pw, name).launch(**kw)
    _STATE["browser"] = browser
    _STATE["engine"] = name
    _STATE["failed"] = ""
    return browser, name


def _teardown() -> None:
    """Close whatever is open. OWNER THREAD ONLY (or after it has retired)."""
    cm, br, pw = _STATE["cm"], _STATE["browser"], _STATE["pw"]
    _STATE["cm"] = _STATE["browser"] = _STATE["pw"] = None
    _STATE["engine"] = ""
    if cm is not None:
        try:
            cm.__exit__(None, None, None)
        except Exception:
            pass
    elif br is not None:
        try:
            br.close()
        except Exception:
            pass
    if pw is not None:
        try:
            pw.stop()
        except Exception:
            pass


def shutdown() -> None:
    """Close the browser if one is running. Safe any time, from any thread,
    twice."""
    global _WORKER
    with _WORKER_LOCK:
        w = _WORKER
    if w is not None and w.is_alive():
        _JOBS.put(None)
        w.join(timeout=20)
    else:
        _teardown()


atexit.register(shutdown)


# ── the fetch ────────────────────────────────────────────────────────
_BLOCKED_TYPES = frozenset({"image", "media", "font"})
_FATAL_RE = re.compile(
    r"(target closed|browser has been closed|connection closed|"
    r"disconnected|has crashed|Target page, context or browser|"
    r"different thread)", re.I)


def _looks_fatal(msg: str) -> bool:
    return bool(_FATAL_RE.search(msg or ""))


def fetch(url: str,
          host_ok: Callable[[Optional[str]], bool],
          timeout: int = DEFAULT_TIMEOUT,
          prefer: str = "",
          block_heavy: bool = True) -> Dict[str, Any]:
    """Render `url` in a real browser and return its HTML.

    `host_ok(hostname) -> bool` is the SSRF floor and is MANDATORY: it is
    applied to the target, to every redirect hop, to every subresource the
    page requests, and to the final URL. Passing None refuses the fetch —
    this module must never be the reason the floor is not enforced.

    Returns {"ok": True, "status", "html", "final_url", "engine", "blocked",
    "elapsed"} or {"ok": False, "error", ...}. Never raises.
    """
    if not callable(host_ok):
        return {"ok": False, "error": (
            "browser.fetch requires a host_ok predicate — refusing to fetch "
            "without the SSRF floor")}
    u = (url or "").strip()
    if not u:
        return {"ok": False, "error": "no url"}
    if "://" not in u:
        u = "https://" + u
    try:
        p0 = urllib.parse.urlparse(u)
    except Exception as e:
        return {"ok": False, "error": f"unparseable url: {e}"}
    if p0.scheme not in ("http", "https"):
        return {"ok": False,
                "error": f"refusing '{p0.scheme}:' scheme — http/https only"}
    if not host_ok(p0.hostname):
        return {"ok": False, "error": (
            f"host '{p0.hostname}' is refused by the SSRF floor")}
    try:
        tmo = max(5, min(MAX_TIMEOUT, int(timeout or DEFAULT_TIMEOUT)))
    except Exception:
        tmo = DEFAULT_TIMEOUT

    def _work() -> Dict[str, Any]:
        blocked: List[str] = []
        t0 = time.time()
        try:
            browser, engine = _launch(prefer)
        except Exception as e:
            _STATE["failed"] = f"{type(e).__name__}: {e}"
            return {"ok": False, "engine": "", "launch_failed": True,
                    "error": (f"could not start a browser ({e}). web_read "
                              f"falls back to a plain HTTP fetch.")}
        ctx = None
        try:
            ctx = browser.new_context(
                ignore_https_errors=False,
                viewport={"width": 1366, "height": 900},
                java_script_enabled=True,
            )
            ctx.set_default_timeout(tmo * 1000)
            ctx.set_default_navigation_timeout(tmo * 1000)

            def _route(route, request):
                # THE FLOOR, ON EVERY REQUEST THE PAGE MAKES.
                # A browser is not one fetch: it is the navigation, its
                # redirects, and everything the page's own script asks
                # for. Checking only the URL we typed would leave the
                # floor guarding the one request that was never the risk.
                try:
                    rurl = request.url or ""
                    pr = urllib.parse.urlparse(rurl)
                    if pr.scheme in ("http", "https") and not host_ok(pr.hostname):
                        if len(blocked) < 20:
                            blocked.append(rurl[:200])
                        return route.abort()
                    if block_heavy and request.resource_type in _BLOCKED_TYPES:
                        # Nothing downstream reads pixels — we return text.
                        # Dropping them is most of the speed of this path.
                        return route.abort()
                except Exception:
                    pass
                try:
                    return route.continue_()
                except Exception:
                    return None

            ctx.route("**/*", _route)
            page = ctx.new_page()
            resp = page.goto(u, wait_until="domcontentloaded",
                             timeout=tmo * 1000)
            try:
                page.wait_for_load_state("networkidle", timeout=_SETTLE_MS)
            except Exception:
                pass                      # a live socket never goes idle
            try:
                status = int(resp.status) if resp is not None else 0
            except Exception:
                status = 0
            try:
                final_url = page.url or u
            except Exception:
                final_url = u
            fhost = urllib.parse.urlparse(final_url).hostname
            if not host_ok(fhost):
                # Belt and braces: the route handler should have stopped
                # this, so reaching here means a hop got past it and the
                # content must not be returned.
                return {"ok": False, "engine": engine, "error": (
                    f"the page ended at '{fhost}', which the SSRF floor "
                    f"refuses — content discarded")}
            try:
                html = page.content() or ""
            except Exception as e:
                return {"ok": False, "engine": engine,
                        "error": f"page produced no content: {e}"}
            if len(html) > 4_000_000:
                html = html[:4_000_000]
            _STATE["last_used"] = time.time()
            out: Dict[str, Any] = {
                "ok": True, "status": status or 200, "html": html,
                "final_url": final_url, "engine": engine,
                "elapsed": round(time.time() - t0, 2)}
            if blocked:
                out["blocked"] = blocked
            return out
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            if _looks_fatal(msg):
                # A dead browser takes every later fetch with it unless it
                # is dropped here; the next call then relaunches cleanly.
                _teardown()
            return {"ok": False, "engine": _STATE.get("engine", ""),
                    "error": f"browser fetch failed: {msg[:300]}"}
        finally:
            if ctx is not None:
                try:
                    ctx.close()
                except Exception:
                    pass

    # The wait is the page budget plus room for a cold launch; a browser
    # that has to download nothing still takes a second or two to come up.
    return _submit(_work, timeout=tmo + 45)
