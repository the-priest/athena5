"""
oracle.py — exploitation verification oracle for Basilisk.

An "oracle", in offensive security, is the thing that tells you whether an
exploit ACTUALLY worked — instead of guessing from a 200 response. This turns a
spray-and-pray agent into one that KNOWS what landed, and it feeds that back
into the loop so the next move is informed. Three real capabilities:

  1. A LEDGER of exploit attempts. Before it fires, the agent ARMS an attempt
     with an explicit success criterion; after, it CHECKS the attempt against
     the evidence it got back. Each attempt carries a verdict —
     CONFIRMED / FAILED / PENDING / INCONCLUSIVE — so "did it land?" is decided
     by evidence, not vibes, and the running ledger tells the loop exactly
     what's proven and what's still open.

  2. A VERDICT ENGINE that decides success from observed evidence:
       contains      — the response must contain a marker (dumped row, token…)
       absent        — a marker must be GONE (error cleared, filter bypassed)
       status        — an exact HTTP status code
       regex         — a pattern in the response
       differential  — the attempt response differs from a stored baseline
                       beyond a threshold (proves a boolean/blind channel)
       oob           — an out-of-band callback fired (see #3)

  3. An OUT-OF-BAND (OOB) CANARY listener — a tiny local HTTP server. For BLIND
     vulnerabilities (blind SSRF / RCE / XXE / SQLi) the payload carries a
     unique canary URL; if the target ever calls back to it, the blind exploit
     is confirmed with certainty. This is how real tooling (Burp Collaborator,
     interactsh) proves blind bugs, done locally and offline.

All state is local, per-engagement, filed next to the engagement record.
Nothing here touches a target on its own — the agent fires exploits with the
normal tools; the oracle only records intent and JUDGES the evidence.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

_LOCK = threading.RLock()
_DEFAULT_ENGAGEMENT = "default"
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Verdicts
CONFIRMED = "confirmed"
FAILED = "failed"
PENDING = "pending"
INCONCLUSIVE = "inconclusive"

_VALID_CRITERIA = ("contains", "absent", "status", "regex", "differential", "oob")


# ── storage (mirrors engage.py so the oracle files under the same case) ──

def _safe_name(name: Optional[str]) -> str:
    name = (name or "").strip() or _DEFAULT_ENGAGEMENT
    name = _SAFE_NAME_RE.sub("-", name).strip("-.") or _DEFAULT_ENGAGEMENT
    return name[:64]


def _base(base_dir: Optional[Path]) -> Path:
    if base_dir is None:
        base_dir = Path(os.path.expanduser("~")) / ".config" / "basilisk" / "engagements"
    return Path(base_dir)


def _path(engagement: str, base_dir: Optional[Path]) -> Path:
    return _base(base_dir) / f"{_safe_name(engagement)}.oracle.json"


def _blank(engagement: str) -> Dict[str, Any]:
    return {"engagement": _safe_name(engagement), "seq": 0, "attempts": []}


def _load(engagement: str, base_dir: Optional[Path]) -> Dict[str, Any]:
    p = _path(engagement, base_dir)
    if not p.exists():
        return _blank(engagement)
    try:
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        d.setdefault("seq", 0)
        d.setdefault("attempts", [])
        d["engagement"] = _safe_name(engagement)
        return d
    except Exception:
        return _blank(engagement)


def _save(state: Dict[str, Any], base_dir: Optional[Path]) -> bool:
    try:
        with _LOCK:
            d = _base(base_dir)
            d.mkdir(parents=True, exist_ok=True)
            p = d / f"{_safe_name(state.get('engagement'))}.oracle.json"
            tmp = p.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            os.replace(tmp, p)  # atomic
        return True
    except Exception:
        return False


def _now() -> float:
    return round(time.time(), 3)


def _clip(s: Any, n: int = 400) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + "…"


# ═════════════════════════════════════════════════════════════════════
# OUT-OF-BAND CANARY LISTENER — a local HTTP server that logs callbacks.
# For blind bugs: embed the canary URL in the payload; a hit == confirmation.
# ═════════════════════════════════════════════════════════════════════

_oob: Dict[str, Any] = {
    "server": None, "thread": None, "hits": [], "port": None, "host": None,
    "started": None,
}
_OOB_MAX_HITS = 500
_GIF_1PX = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
            b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
            b"\x00\x02\x02D\x01\x00;")


class _CanaryHandler(BaseHTTPRequestHandler):
    # Silence the default stderr logging; we keep our own log.
    def log_message(self, *_a):  # noqa: N802
        return

    def _record(self, method: str):
        try:
            hit = {
                "ts": _now(),
                "method": method,
                "path": self.path,
                "token": _token_from_path(self.path),
                "client": self.client_address[0] if self.client_address else "",
                "ua": self.headers.get("User-Agent", ""),
            }
            with _LOCK:
                _oob["hits"].append(hit)
                if len(_oob["hits"]) > _OOB_MAX_HITS:
                    del _oob["hits"][:-_OOB_MAX_HITS]
        except Exception:
            pass

    def _respond(self):
        try:
            body = _GIF_1PX
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):  # noqa: N802
        self._record("GET")
        self._respond()

    def do_POST(self):  # noqa: N802
        # drain the body so the client isn't left hanging
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > 0:
                self.rfile.read(min(n, 1 << 20))
        except Exception:
            pass
        self._record("POST")
        self._respond()

    # a handful of other verbs blind RCE might use
    do_HEAD = do_GET
    do_PUT = do_POST


def _token_from_path(path: str) -> str:
    """Canary tokens live at /c/<token>; also accept ?c=<token>."""
    try:
        u = urlparse(path)
        m = re.search(r"/c/([A-Za-z0-9]+)", u.path)
        if m:
            return m.group(1)
        m = re.search(r"[?&]c=([A-Za-z0-9]+)", path)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _lan_ip() -> str:
    """Best-guess LAN IP the target could call back to (no traffic sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def oob_start(port: int = 0, host: Optional[str] = None) -> Dict[str, Any]:
    """Start (idempotently) the local OOB canary server. Returns its base URL,
    the reachable host, the port, and the current hit count. host is the address
    the TARGET should call back to (auto-detected LAN IP by default; pass one for
    a specific interface). Binds 0.0.0.0 so a LAN target can reach it."""
    with _LOCK:
        if _oob["server"] is not None:
            return {
                "ok": True, "already_running": True,
                "base_url": _oob_base_url(), "host": _oob["host"],
                "port": _oob["port"], "hits": len(_oob["hits"]),
            }
        bind_port = int(port) if port else 0
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", bind_port), _CanaryHandler)
        except Exception as e:
            return {"ok": False, "error": f"could not bind OOB listener: {e}"}
        actual_port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, name="oracle-oob",
                              daemon=True)
        th.start()
        _oob.update({
            "server": srv, "thread": th, "port": actual_port,
            "host": (host or "").strip() or _lan_ip(), "started": _now(),
        })
        return {
            "ok": True, "already_running": False,
            "base_url": _oob_base_url(), "host": _oob["host"],
            "port": actual_port, "hits": len(_oob["hits"]),
        }


def _oob_base_url() -> str:
    if _oob["port"] is None:
        return ""
    return f"http://{_oob['host']}:{_oob['port']}"


def _canary_url_for(token: str) -> str:
    base = _oob_base_url()
    return f"{base}/c/{token}" if base else ""


def oob_hits(token: str = "") -> List[Dict[str, Any]]:
    with _LOCK:
        hits = list(_oob["hits"])
    if token:
        hits = [h for h in hits if h.get("token") == token]
    return hits


# ═════════════════════════════════════════════════════════════════════
# VERDICT ENGINE — decide success from evidence.
# ═════════════════════════════════════════════════════════════════════

def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()


def _judge(criterion: Dict[str, Any], evidence: str, status: Any,
           baseline: str) -> (str):
    """Return (verdict, reason)."""
    ctype = (criterion.get("type") or "").lower()
    value = criterion.get("value", "")
    ev = evidence or ""

    if ctype == "contains":
        if not value:
            return INCONCLUSIVE, "no marker value given for 'contains'"
        hit = str(value).lower() in ev.lower()
        return (CONFIRMED if hit else FAILED,
                f"marker {'found' if hit else 'not found'}: {_clip(value, 80)!r}")

    if ctype == "absent":
        if not value:
            return INCONCLUSIVE, "no marker value given for 'absent'"
        gone = str(value).lower() not in ev.lower()
        return (CONFIRMED if gone else FAILED,
                f"marker {'absent (good)' if gone else 'still present'}: "
                f"{_clip(value, 80)!r}")

    if ctype == "status":
        try:
            want = int(value)
        except (TypeError, ValueError):
            return INCONCLUSIVE, f"non-integer status value: {value!r}"
        try:
            got = int(status)
        except (TypeError, ValueError):
            return INCONCLUSIVE, "no numeric status supplied to check against"
        return (CONFIRMED if got == want else FAILED,
                f"status {got} vs expected {want}")

    if ctype == "regex":
        if not value:
            return INCONCLUSIVE, "no pattern given for 'regex'"
        try:
            m = re.search(str(value), ev, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            return INCONCLUSIVE, f"bad regex: {e}"
        return (CONFIRMED if m else FAILED,
                f"pattern {'matched' if m else 'no match'}: {_clip(value, 80)!r}"
                + (f" → {_clip(m.group(0), 60)!r}" if m else ""))

    if ctype == "differential":
        if not baseline:
            return INCONCLUSIVE, ("no baseline supplied — capture the FALSE/normal "
                                  "response first, then check with baseline set")
        sim = _similarity(baseline, ev)
        dlen = abs(len(ev) - len(baseline))
        try:
            thr = float(value) if value not in ("", None) else 0.95
        except (TypeError, ValueError):
            thr = 0.95
        differs = sim < thr or dlen > max(24, int(0.05 * max(len(baseline), 1)))
        return (CONFIRMED if differs else FAILED,
                f"similarity={sim:.3f} (thr {thr:.2f}), Δlen={dlen} → "
                f"{'distinct channel' if differs else 'indistinguishable'}")

    if ctype == "oob":
        tok = str(value) if value else ""
        hits = oob_hits(tok)
        if hits:
            last = hits[-1]
            return (CONFIRMED,
                    f"out-of-band callback received ({len(hits)}×): "
                    f"{last.get('method')} {_clip(last.get('path'), 80)} "
                    f"from {last.get('client')}")
        return (PENDING, "no out-of-band callback yet — re-check after the "
                         "payload has had time to fire")

    return INCONCLUSIVE, (f"unknown criterion type {ctype!r}; use one of: "
                          + ", ".join(_VALID_CRITERIA))


# ═════════════════════════════════════════════════════════════════════
# LEDGER — arm / check / status.
# ═════════════════════════════════════════════════════════════════════

def _find(state: Dict[str, Any], attempt_id: str) -> Optional[Dict[str, Any]]:
    if not attempt_id:
        # default to the most recent still-open attempt, else the last one
        openish = [a for a in state["attempts"]
                   if a.get("verdict") in (PENDING, INCONCLUSIVE)]
        if openish:
            return openish[-1]
        return state["attempts"][-1] if state["attempts"] else None
    for a in state["attempts"]:
        if a.get("id") == attempt_id:
            return a
    return None


def arm(engagement: str = "default", objective: str = "", target: str = "",
        technique: str = "", criterion_type: str = "contains",
        criterion_value: str = "", blind: bool = False,
        oob_host: str = "", base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Register an exploit attempt with an explicit success criterion, BEFORE
    firing it. Returns the attempt id and, if blind, a canary URL to embed in
    the payload. Marks the attempt PENDING until check() judges it."""
    ctype = (criterion_type or "contains").lower().strip()
    if ctype not in _VALID_CRITERIA:
        return {"ok": False,
                "error": f"criterion_type must be one of {_VALID_CRITERIA}"}
    state = _load(engagement, base_dir)
    state["seq"] = int(state.get("seq", 0)) + 1
    aid = f"atk-{state['seq']:04d}"
    token = ""
    canary = ""
    if blind or ctype == "oob":
        # short deterministic-ish token from the id + time
        token = re.sub(r"[^a-z0-9]", "",
                       f"{aid}{int(time.time()*1000)%100000:05d}".lower())[:16]
        started = oob_start(host=oob_host)
        canary = _canary_url_for(token) if started.get("ok") else ""
        if ctype != "oob":
            # blind attempt without an explicit oob criterion → make it oob
            ctype = "oob"
            criterion_value = token
        else:
            criterion_value = token
    attempt = {
        "id": aid,
        "objective": _clip(objective, 300),
        "target": _clip(target, 300),
        "technique": _clip(technique, 80),
        "criterion": {"type": ctype, "value": criterion_value},
        "token": token,
        "canary": canary,
        "verdict": PENDING,
        "reason": "",
        "evidence": "",
        "armed_ts": _now(),
        "checked_ts": None,
    }
    state["attempts"].append(attempt)
    _save(state, base_dir)
    out = {
        "ok": True, "id": aid, "verdict": PENDING,
        "criterion": attempt["criterion"],
        "note": ("armed — fire the exploit, then call oracle_check with the "
                 "response as evidence"),
    }
    if canary:
        out["canary_url"] = canary
        out["oob_note"] = ("embed this canary URL in the payload (SSRF url, RCE "
                           "`curl <canary>`, XXE SYSTEM, etc.). A callback to it "
                           "confirms the blind hit — then oracle_check this id.")
    return out


def check(engagement: str = "default", attempt_id: str = "", evidence: str = "",
          status: Any = None, baseline: str = "",
          base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Judge an armed attempt against the evidence you got back. Sets and
    persists its verdict (CONFIRMED / FAILED / PENDING / INCONCLUSIVE) and
    returns it with the reasoning — this is the signal the loop acts on."""
    state = _load(engagement, base_dir)
    if not state["attempts"]:
        return {"ok": False, "error": "no armed attempts — call oracle_arm first"}
    a = _find(state, attempt_id)
    if a is None:
        return {"ok": False, "error": f"no attempt with id {attempt_id!r}"}
    verdict, reason = _judge(a.get("criterion", {}), evidence, status, baseline)
    a["verdict"] = verdict
    a["reason"] = reason
    a["evidence"] = _clip(evidence, 600)
    a["checked_ts"] = _now()
    _save(state, base_dir)
    return {
        "ok": True, "id": a["id"], "verdict": verdict, "reason": reason,
        "objective": a["objective"], "technique": a["technique"],
        "next": ("objective proven — move on" if verdict == CONFIRMED else
                 "callback not in yet — fire/repeat the payload, then re-check"
                 if verdict == PENDING else
                 "did not land — mutate the payload (encoding/oracle/structure) "
                 "and try again, or move on"),
    }


def status(engagement: str = "default",
           base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """The running ledger: what's CONFIRMED, what's still PENDING/failed, and the
    counts. This is the memory that keeps the loop from re-doing solved work and
    tells it what's left — feed it back each planning turn."""
    state = _load(engagement, base_dir)
    atts = state["attempts"]
    counts = {CONFIRMED: 0, FAILED: 0, PENDING: 0, INCONCLUSIVE: 0}
    for a in atts:
        counts[a.get("verdict", PENDING)] = counts.get(a.get("verdict", PENDING), 0) + 1

    def _row(a):
        return {"id": a["id"], "verdict": a.get("verdict"),
                "objective": a.get("objective"), "technique": a.get("technique"),
                "reason": _clip(a.get("reason"), 160)}

    confirmed = [_row(a) for a in atts if a.get("verdict") == CONFIRMED]
    open_ = [_row(a) for a in atts
             if a.get("verdict") in (PENDING, INCONCLUSIVE)]
    failed = [_row(a) for a in atts if a.get("verdict") == FAILED]
    total = len(atts)
    return {
        "ok": True, "engagement": state["engagement"],
        "total": total, "counts": counts,
        "confirmed": confirmed, "open": open_, "failed": failed,
        "oob": {"listening": _oob["server"] is not None,
                "base_url": _oob_base_url(), "callbacks": len(_oob["hits"])},
        "summary": (f"{counts[CONFIRMED]} confirmed, {counts[PENDING]} pending, "
                    f"{counts[FAILED]} failed of {total} armed"),
        "all_confirmed": total > 0 and counts[CONFIRMED] == total,
    }


def listen(port: int = 0, host: str = "",
           base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Start / report the out-of-band canary listener directly (arm(blind=True)
    starts it for you). Returns its base URL and any callbacks recorded so far —
    use it to confirm blind SSRF/RCE/XXE/SQLi that never echo a response."""
    res = oob_start(port=port, host=host)
    if not res.get("ok"):
        return res
    res["recent_callbacks"] = oob_hits()[-10:]
    res["canary_example"] = _canary_url_for("TOKEN")
    return res
