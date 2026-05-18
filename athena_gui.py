#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║          ATHENA GUI — Native pentest assistant · v7.4            ║
# ║                                                                  ║
# ║   · Engagement wizard (target + goal in one form)                ║
# ║   · Per-command explanations via background Groq calls           ║
# ║   · "Watching for…" tips while commands run                      ║
# ║   · Auto manual-help when Athena errors or gets stuck            ║
# ║   · "I'm stuck" rescue button always visible                     ║
# ║   · Persistent config + Groq key (~/.athena/config.json)         ║
# ║   · No idle/disabled input — always allow typing                 ║
# ║   · libadwaita 1.6+ compatible dialogs                           ║
# ╚══════════════════════════════════════════════════════════════════╝
"""
   athena.py (unchanged 6000-line REPL)
        │  PTY stdout
        ▼
   AthenaProcess ──→ LineBuffer ──→ PanelParser ──→ events
        │                                              │
        │                                              ▼
        │                                  ConversationView (cards)
        │                                              │
        ▲                                              ▼
        └─── user input ── InputBar / decision buttons / wizard
                                                       │
                                                       ▼
                                              GroqExplainer (bg thread)
                                              annotates cards with
                                              plain-English help.
"""

from __future__ import annotations

import os
import sys
import re
import json
import pty
import fcntl
import termios
import struct
import signal
import subprocess
import shlex
import threading
import time
from typing import Callable, Optional, List, Dict, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False


# ═════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════

APP_ID = "io.thepriest.Athena"
VERSION = "7.4"

ATHENA_HOME = os.path.expanduser("~/.athena")
LOG_DIR = os.path.join(ATHENA_HOME, "logs")
CONFIG_PATH = os.path.join(ATHENA_HOME, "config.json")

SCRIPT_CANDIDATES = [
    os.environ.get("ATHENA_SCRIPT", ""),
    "/opt/athena5/athena.py",
    os.path.expanduser("~/.local/share/athena5/athena.py"),
    os.path.expanduser("~/Documents/athena5/athena.py"),
    os.path.expanduser("~/athena5/athena.py"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "athena.py"),
]

EXPLAIN_MODEL = "llama-3.1-8b-instant"  # fast model for UI annotations


def find_athena_script() -> Optional[str]:
    for c in SCRIPT_CANDIDATES:
        if c and os.path.isfile(c):
            return c
    return None


# ═════════════════════════════════════════════════════════════════════
# CONFIG — persistent settings, survives across launches
# ═════════════════════════════════════════════════════════════════════

class Config:
    DEFAULTS: Dict[str, Any] = {
        "groq_api_key": "",
        "show_explanations": True,
        "auto_help_on_error": True,
        "last_target": {"ip": "", "domain": "", "notes": "", "goal": ""},
    }

    @classmethod
    def load(cls) -> Dict[str, Any]:
        os.makedirs(ATHENA_HOME, exist_ok=True)
        data = dict(cls.DEFAULTS)
        try:
            with open(CONFIG_PATH) as f:
                data.update(json.load(f))
        except (OSError, json.JSONDecodeError):
            pass
        return data

    @classmethod
    def save(cls, data: Dict[str, Any]) -> None:
        os.makedirs(ATHENA_HOME, exist_ok=True)
        try:
            tmp = CONFIG_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, CONFIG_PATH)
            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            pass

    @classmethod
    def get(cls, key: str) -> Any:
        return cls.load().get(key, cls.DEFAULTS.get(key))

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        data = cls.load()
        data[key] = value
        cls.save(data)


# ═════════════════════════════════════════════════════════════════════
# GROQ EXPLAINER — background thread, never blocks UI
# ═════════════════════════════════════════════════════════════════════

class GroqExplainer:
    """Async Groq calls for plain-English help.  All results delivered
    back to the GTK main loop via GLib.idle_add()."""

    SYS_EXPLAIN = (
        "You are a concise pentest assistant. Explain shell commands in "
        "ONE short sentence (max 25 words). No preamble, no markdown. "
        "Just the plain-English purpose."
    )
    SYS_WATCHING = (
        "You are a pentest assistant. In ONE short sentence (max 20 words) "
        "tell the user what to look for in the output of this command. "
        "No preamble, no markdown."
    )
    SYS_MANUAL = (
        "You are a senior pentester guiding a junior through a tricky step. "
        "Athena (an AI agent) hit a problem it can't auto-resolve. Give "
        "3-5 short numbered manual steps the human should perform. "
        "Be concrete: exact commands, tools, file paths. "
        "No fluff, no caveats, no markdown headers. Just numbered steps."
    )
    SYS_TIP = (
        "You are a pentest assistant. In one short paragraph (max 50 words) "
        "give the user a tip about what they just learned or should try next. "
        "No preamble, no markdown."
    )

    def __init__(self):
        self._lock = threading.Lock()
        self._client: Optional[Any] = None

    def _get_client(self) -> Optional[Any]:
        if not HAS_GROQ:
            return None
        key = os.environ.get("GROQ_API_KEY", "").strip()
        if not key:
            return None
        with self._lock:
            if self._client is None:
                try:
                    self._client = Groq(api_key=key)
                except Exception:
                    return None
            return self._client

    def _ask(self, system: str, user: str, callback: Callable[[str], None]) -> None:
        def worker():
            client = self._get_client()
            if client is None:
                GLib.idle_add(callback, "")
                return
            try:
                resp = client.chat.completions.create(
                    model=EXPLAIN_MODEL,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2,
                    max_tokens=300,
                )
                text = resp.choices[0].message.content.strip()
            except Exception as e:
                text = f"(explanation unavailable: {type(e).__name__})"
            GLib.idle_add(callback, text)

        threading.Thread(target=worker, daemon=True).start()

    def explain_command(self, cmd: str, callback: Callable[[str], None]) -> None:
        self._ask(self.SYS_EXPLAIN, f"Command:\n{cmd}", callback)

    def watching_for(self, cmd: str, callback: Callable[[str], None]) -> None:
        self._ask(self.SYS_WATCHING, f"Command:\n{cmd}", callback)

    def manual_steps(self, context: str, callback: Callable[[str], None]) -> None:
        self._ask(self.SYS_MANUAL, context, callback)

    def general_tip(self, context: str, callback: Callable[[str], None]) -> None:
        self._ask(self.SYS_TIP, context, callback)


# Single shared instance
EXPLAINER = GroqExplainer()


# ═════════════════════════════════════════════════════════════════════
# CSS
# ═════════════════════════════════════════════════════════════════════

CSS = """
window, .background { background-color: #0a0612; }

headerbar {
    background-color: #15101f;
    border-bottom: 1px solid #2a1a3a;
    min-height: 48px;
}
.headerbar-target { color: #b9e9c9; font-family: monospace; font-size: 12px; }
.headerbar-agent  { color: #e9d9b9; font-family: monospace; font-size: 11px; }

.feed { background: #0a0612; padding: 8px; }
.feed-inner { padding-bottom: 80px; }

/* base card */
.card {
    background: #18102a;
    border: 1px solid #2a1a3a;
    border-radius: 14px;
    padding: 12px 14px;
    margin: 6px 4px;
}
.card-title {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.8px;
    color: #9d7da0;
    margin-bottom: 6px;
}
.card-body { color: #e6dcf0; font-size: 14px; }

/* welcome card */
.welcome {
    background: linear-gradient(180deg, #1a1030 0%, #0a0612 100%);
    border-color: #4a2a6a;
    padding: 18px;
}
.welcome-title {
    color: #cc66ff; font-size: 22px; font-weight: 700;
    letter-spacing: 1px; margin-bottom: 4px;
}
.welcome-sub  { color: #b8a8c8; font-size: 13px; margin-bottom: 12px; }
.welcome-btn  {
    background: #cc66ff; color: #0a0612;
    border-radius: 12px; padding: 14px; min-height: 52px;
    font-weight: 700; font-size: 14px;
}

/* thought */
.thought {
    background: linear-gradient(180deg, #1a1030 0%, #14082a 100%);
    border-color: #4a2a6a;
}
.thought .card-title { color: #cc88ff; }
.thought .card-body { font-style: italic; color: #d9c9e9; }

/* command */
.command { background: #0e1a22; border-color: #2a4a5a; }
.command .card-title { color: #66ccff; }
.cmd-code {
    background: #050a0e;
    border: 1px solid #1a3a4a;
    border-radius: 8px;
    padding: 10px 12px;
    color: #b9e9ff;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 13px;
}
.explain-block {
    background: #14202a;
    border-left: 3px solid #66ccff;
    border-radius: 6px;
    padding: 8px 12px;
    margin-top: 8px;
    color: #c8d8e8; font-size: 12px;
}
.explain-block .key { color: #88ccff; font-weight: 700; letter-spacing: 1px; }
.explain-loading { color: #6a7a8a; font-style: italic; }

.conf-pill {
    padding: 3px 9px; border-radius: 999px;
    font-size: 10px; font-weight: 700; letter-spacing: 1.2px; color: white;
}
.conf-green  { background: #2a8a3a; }
.conf-yellow { background: #aa8a1a; color: #1a1006; }
.conf-red    { background: #aa2a3a; }
.attack-pill {
    padding: 3px 9px; border-radius: 999px;
    font-size: 10px; font-weight: 600; letter-spacing: 1px;
    background: #2a1030; color: #cc88ff; border: 1px solid #4a2a6a;
}

/* decision buttons */
.decision-bar {
    margin-top: 12px; border-top: 1px solid #1a3a4a; padding-top: 12px;
}
.btn-run, .btn-skip, .btn-quit {
    padding: 14px 12px; border-radius: 10px; font-weight: 700;
    font-size: 14px; letter-spacing: 0.5px; min-height: 52px;
}
.btn-run  { background: #2a8a3a; color: white; border: 1px solid #3aa04a; }
.btn-skip { background: #6a5a1a; color: #fff5cc; border: 1px solid #8a7a2a; }
.btn-quit { background: #4a2a2a; color: #ffcccc; border: 1px solid #6a3a3a; }
.btn-run:hover  { background: #3aa04a; }
.btn-skip:hover { background: #7a6a2a; }
.btn-quit:hover { background: #5a3a3a; }
.decision-done {
    padding: 8px 12px; border-radius: 999px;
    background: #1a3a2a; color: #b9e9c9;
    font-size: 11px; font-weight: 600;
}
.decision-done.skipped { background: #3a2a1a; color: #e9d9b9; }
.decision-done.quit    { background: #3a1a1a; color: #e9b9b9; }

/* result */
.result { border-color: #2a3a4a; }
.result .card-title { color: #88c0a0; }
.result-output {
    background: #050810; border-radius: 8px; padding: 10px;
    color: #c0c8d0;
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
}

/* findings */
.findings { background: #0e1a14; border-color: #2a5a3a; }
.findings .card-title { color: #88dd99; }
.finding-row {
    padding: 6px 0; color: #d8f0e0; font-size: 13px;
    border-bottom: 1px solid #1a2a1a;
}

/* error */
.error { background: #1a0a0e; border-color: #5a2a2a; }
.error .card-title { color: #ff7788; }

/* manual help */
.manual {
    background: #1a1408; border-color: #6a5020;
    margin-top: 4px;
}
.manual .card-title { color: #ffcc66; }
.manual-step {
    background: #25200a; border-radius: 6px;
    padding: 8px 10px; margin: 3px 0;
    color: #f0e0c0; font-size: 13px;
}
.copy-pill {
    background: #2a2018; color: #ffcc88;
    padding: 4px 10px; border-radius: 999px;
    font-size: 10px; font-weight: 600;
}

/* dispatch + executing */
.dispatch, .executing {
    background: transparent; border: none;
    padding: 4px 12px; margin: 2px 8px;
}
.dispatch .card-body, .executing .card-body {
    color: #8d7da0; font-size: 11px; letter-spacing: 1px;
    font-family: monospace;
}
.exec-tip {
    background: #0e1a22;
    border-left: 3px solid #66ccff;
    border-radius: 6px;
    padding: 6px 10px;
    margin: 4px 8px;
    color: #c8d8e8; font-size: 11px;
}

/* banner */
.banner {
    background: #0a0612; border: 1px solid #4a2a6a;
    border-radius: 14px; padding: 10px; margin: 6px 4px;
}
.banner-art { font-family: monospace; font-size: 10px; color: #cc66ff; }

/* turn */
.turn-header {
    color: #6a5a7a; font-size: 10px; font-family: monospace;
    letter-spacing: 2px; padding: 12px 8px 4px 8px;
}

/* plain */
.plain { background: transparent; border: none; padding: 4px 12px; }
.plain .card-body { color: #b8a8c8; font-family: monospace; font-size: 12px; }

/* sidebar */
.athena-sidebar { background: #0e0a18; }
.sidebar-header {
    color: #6a5a7a; font-size: 10px; font-weight: 700;
    letter-spacing: 1.5px; margin: 14px 16px 4px;
}
.sidebar-button {
    padding: 12px 14px; border-radius: 10px; margin: 2px 8px;
    color: #d8c8e8; min-height: 44px;
}
.sidebar-button:hover { background: #1f1530; }

/* input bar */
.input-bar {
    background: #15101f;
    border-top: 1px solid #2a1a3a;
    padding: 8px 10px 10px 10px;
}
.input-entry {
    background: #0a0612; color: #e6dcf0;
    border: 1px solid #2a1a3a; border-radius: 22px;
    padding: 10px 14px; font-size: 14px; min-height: 44px;
}
.input-entry:focus { border-color: #cc66ff; }
.send-button {
    background: #cc66ff; color: #0a0612;
    border-radius: 22px; min-width: 44px; min-height: 44px;
    font-weight: 700;
}
.input-hint {
    color: #6a5a7a; font-size: 10px; letter-spacing: 1.2px;
    padding: 0 6px 4px;
}
.rescue-row {
    margin-top: 6px;
}
.rescue-btn {
    background: #2a1a3a; color: #ffcc88;
    border-radius: 8px; padding: 6px 10px;
    font-size: 11px; font-weight: 600;
}
.rescue-btn:hover { background: #3a2a4a; }

/* wizard */
.wizard-title {
    color: #cc66ff; font-size: 18px; font-weight: 700;
    margin-bottom: 4px;
}
.wizard-sub { color: #b8a8c8; font-size: 12px; margin-bottom: 12px; }
.wizard-label {
    color: #88aacc; font-size: 11px;
    font-weight: 700; letter-spacing: 1.2px;
    margin-top: 8px; margin-bottom: 2px;
}
.wizard-entry {
    background: #0a0612; color: #e6dcf0;
    border: 1px solid #2a1a3a; border-radius: 8px;
    padding: 8px 10px; font-size: 13px;
    min-height: 36px;
}
"""


# ═════════════════════════════════════════════════════════════════════
# CSS LOADER — handles both legacy and modern GTK4 APIs
# ═════════════════════════════════════════════════════════════════════

def load_css() -> None:
    css = Gtk.CssProvider()
    if hasattr(css, "load_from_string"):
        css.load_from_string(CSS)
    elif hasattr(css, "load_from_data"):
        try:
            css.load_from_data(CSS, -1)
        except TypeError:
            css.load_from_data(CSS.encode())
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        css,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


# ═════════════════════════════════════════════════════════════════════
# ANSI + LINE BUFFER
# ═════════════════════════════════════════════════════════════════════

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


class LineBuffer:
    def __init__(self, on_line: Callable[[str], None],
                 on_partial: Callable[[str], None]):
        self._buf = bytearray()
        self._on_line = on_line
        self._on_partial = on_partial

    def feed(self, data: bytes) -> None:
        self._buf += data
        while True:
            idx = self._buf.find(b"\n")
            if idx < 0:
                break
            line_bytes = bytes(self._buf[:idx])
            del self._buf[: idx + 1]
            text = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
            self._on_line(strip_ansi(text))
        if self._buf:
            text = self._buf.decode("utf-8", errors="replace")
            self._on_partial(strip_ansi(text))


# ═════════════════════════════════════════════════════════════════════
# PANEL PARSER
# ═════════════════════════════════════════════════════════════════════

BOX_TOP_RE = re.compile(r"^\s*[╭┌][─━].*?[─━][╮┐]\s*$")
BOX_BOT_RE = re.compile(r"^\s*[╰└][─━].*?[─━][╯┘]\s*$")
TITLE_RE   = re.compile(r"^\s*[╭┌][─━]+\s*([^─━╮┐]+?)\s*[─━]+")
SIDE_RE    = re.compile(r"^\s*│\s?(.*?)\s?│\s*$")
SIDE_ANY_RE = re.compile(r"^\s*│(.*?)│\s*$")
STATUS_RE  = re.compile(r"^\s*▍\s+(.+)$")

PROMPT_YNQ_HINT       = re.compile(r"y\s*run.*n\s*skip.*q\s*quit", re.IGNORECASE)
PROMPT_PRIEST_HINT    = re.compile(r"priest\s*[›>]")
PROMPT_TRAILING_COLON = re.compile(r":\s*$")
PROMPT_PASSWORD_HINT  = re.compile(r"\b(?:password|passphrase|sudo password)\b", re.IGNORECASE)


class PanelParser:
    def __init__(self, on_event: Callable[[dict], None]):
        self._on = on_event
        self._in_box = False
        self._title: Optional[str] = None
        self._content: List[str] = []
        self._last_partial = ""

    def on_line(self, line: str) -> None:
        if self._in_box:
            if BOX_BOT_RE.match(line):
                self._flush_box()
                return
            m = SIDE_RE.match(line)
            if m:
                self._content.append(m.group(1))
            else:
                m2 = SIDE_ANY_RE.match(line)
                if m2:
                    self._content.append(m2.group(1).strip())
                else:
                    self._content.append(line.strip())
            return

        if BOX_TOP_RE.match(line):
            self._in_box = True
            tm = TITLE_RE.match(line)
            self._title = tm.group(1).strip() if tm else ""
            self._content = []
            return

        sm = STATUS_RE.match(line)
        if sm:
            self._on({"type": "status", "text": sm.group(1)})
            return

        if BOX_BOT_RE.match(line):
            return

        if line.strip():
            self._on({"type": "text", "text": line})

    def on_partial(self, frag: str) -> None:
        if frag == self._last_partial:
            return
        self._last_partial = frag
        clean = frag.rstrip()
        if not clean:
            return
        if PROMPT_YNQ_HINT.search(clean):
            self._on({"type": "prompt_ynq", "text": clean})
            return
        if PROMPT_PASSWORD_HINT.search(clean) and PROMPT_TRAILING_COLON.search(clean):
            self._on({"type": "prompt_password", "text": clean})
            return
        if PROMPT_PRIEST_HINT.search(clean):
            self._on({"type": "prompt_text", "text": clean, "kind": "priest"})
            return
        if PROMPT_TRAILING_COLON.search(clean):
            self._on({"type": "prompt_text", "text": clean, "kind": "field"})
            return

    def _flush_box(self) -> None:
        title = (self._title or "").strip()
        body = "\n".join(self._content).rstrip()
        self._on({"type": "panel", "title": title, "body": body})
        self._in_box = False
        self._title = None
        self._content = []


# ═════════════════════════════════════════════════════════════════════
# ATHENA SUBPROCESS
# ═════════════════════════════════════════════════════════════════════

class AthenaProcess(GObject.Object):
    __gsignals__ = {
        "event":  (GObject.SignalFlags.RUN_FIRST, None, (object,)),
        "exited": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(self, script_path: str):
        super().__init__()
        self._script = script_path
        self._proc: Optional[subprocess.Popen] = None
        self._master_fd: Optional[int] = None
        self._buf = LineBuffer(self._on_line, self._on_partial)
        self._parser = PanelParser(self._emit_event)
        self._reader_id: Optional[int] = None

    def start(self) -> bool:
        master_fd, slave_fd = pty.openpty()
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", 36, 100, 0, 0))
        except OSError:
            pass

        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self._proc = subprocess.Popen(
                ["/usr/bin/python3", "-u", self._script],
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                env=env,
                close_fds=True,
                preexec_fn=os.setsid,
            )
        except OSError as e:
            os.close(master_fd); os.close(slave_fd)
            self._emit_event({"type": "fatal", "text": f"failed to spawn: {e}"})
            return False

        os.close(slave_fd)
        self._master_fd = master_fd

        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self._reader_id = GLib.io_add_watch(
            master_fd, GLib.PRIORITY_DEFAULT,
            GLib.IOCondition.IN | GLib.IOCondition.HUP,
            self._on_readable,
        )
        return True

    def stop(self) -> None:
        if self._reader_id is not None:
            GLib.source_remove(self._reader_id)
            self._reader_id = None
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None

    def write(self, text: str) -> None:
        if self._master_fd is None:
            return
        try:
            os.write(self._master_fd, text.encode("utf-8"))
        except OSError:
            pass

    def writeln(self, text: str = "") -> None:
        self.write(text + "\n")

    def _on_readable(self, fd, condition):
        if condition & GLib.IOCondition.HUP and not (condition & GLib.IOCondition.IN):
            self.emit("exited")
            return False
        try:
            data = os.read(fd, 8192)
        except OSError:
            self.emit("exited")
            return False
        if not data:
            self.emit("exited")
            return False
        self._buf.feed(data)
        return True

    def _on_line(self, line: str) -> None:
        self._parser.on_line(line)

    def _on_partial(self, frag: str) -> None:
        self._parser.on_partial(frag)

    def _emit_event(self, ev: dict) -> None:
        self.emit("event", ev)


# ═════════════════════════════════════════════════════════════════════
# CARDS
# ═════════════════════════════════════════════════════════════════════

def _card(title: str, css_class: str) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    box.add_css_class("card")
    box.add_css_class(css_class)
    if title:
        lbl = Gtk.Label(label=title.upper(), xalign=0)
        lbl.add_css_class("card-title")
        box.append(lbl)
    return box


def _body_label(text: str) -> Gtk.Label:
    lbl = Gtk.Label(label=text, xalign=0)
    lbl.add_css_class("card-body")
    lbl.set_wrap(True)
    lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    lbl.set_selectable(True)
    return lbl


class WelcomeCard(Gtk.Box):
    def __init__(self, on_start: Callable[[], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("", "welcome")
        t = Gtk.Label(label="Welcome to Athena", xalign=0)
        t.add_css_class("welcome-title")
        card.append(t)
        s = Gtk.Label(
            label="Your AI offensive-security partner.  Tell her a target "
                  "and what you want to do — she'll plan it, run it, and "
                  "explain every move.",
            xalign=0)
        s.set_wrap(True)
        s.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        s.add_css_class("welcome-sub")
        card.append(s)
        btn = Gtk.Button(label="▶  Start New Engagement")
        btn.add_css_class("welcome-btn")
        btn.connect("clicked", lambda _b: on_start())
        card.append(btn)
        self.append(card)


class ThoughtCard(Gtk.Box):
    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("🧠 Athena thinking", "thought")
        card.append(_body_label(body))
        self.append(card)


class CommandCard(Gtk.Box):
    """Command card with explanation, decision buttons, copy support."""

    def __init__(self, body: str, *,
                 on_decision: Callable[[str], None],
                 want_explanation: bool):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._on_decision = on_decision
        self._answered = False

        card = _card("⚡ Proposed command", "command")
        conf, attack, cmd_text = self._extract_meta(body)
        self._cmd_text = cmd_text

        if conf or attack:
            meta = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            meta.set_margin_bottom(4)
            if conf:
                p = Gtk.Label(label=conf.upper())
                p.add_css_class("conf-pill")
                p.add_css_class(f"conf-{conf.lower()}")
                meta.append(p)
            if attack:
                p = Gtk.Label(label=attack)
                p.add_css_class("attack-pill")
                meta.append(p)
            spacer = Gtk.Box(); spacer.set_hexpand(True)
            meta.append(spacer)
            card.append(meta)

        code = Gtk.Label(label=cmd_text, xalign=0)
        code.add_css_class("cmd-code")
        code.set_wrap(True)
        code.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        code.set_selectable(True)
        card.append(code)

        # Explanation block — populated async by Groq
        if want_explanation:
            self._explain = self._make_explain_block()
            card.append(self._explain)
            EXPLAINER.explain_command(cmd_text, self._set_explanation)
        else:
            self._explain = None

        # Decision bar (revealed when y/n/q prompt fires)
        self._decision_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._decision_bar.add_css_class("decision-bar")
        self._decision_bar.set_homogeneous(True)
        self._decision_bar.set_visible(False)

        self._btn_run  = self._make_button("✓ Run",  "btn-run",  "y")
        self._btn_skip = self._make_button("✗ Skip", "btn-skip", "n")
        self._btn_quit = self._make_button("✋ Quit", "btn-quit", "q")
        self._decision_bar.append(self._btn_run)
        self._decision_bar.append(self._btn_skip)
        self._decision_bar.append(self._btn_quit)

        self._chosen_pill = Gtk.Label(label="")
        self._chosen_pill.add_css_class("decision-done")
        self._chosen_pill.set_visible(False)
        self._chosen_pill.set_halign(Gtk.Align.START)
        self._chosen_pill.set_margin_top(8)

        card.append(self._decision_bar)
        card.append(self._chosen_pill)
        self.append(card)

    @property
    def command(self) -> str:
        return self._cmd_text

    def _make_explain_block(self) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.add_css_class("explain-block")
        head = Gtk.Label(label="💡 WHAT THIS DOES", xalign=0)
        head.add_css_class("key")
        box.append(head)
        self._explain_label = Gtk.Label(label="(asking Athena to explain…)", xalign=0)
        self._explain_label.set_wrap(True)
        self._explain_label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        self._explain_label.set_selectable(True)
        self._explain_label.add_css_class("explain-loading")
        box.append(self._explain_label)
        return box

    def _set_explanation(self, text: str) -> bool:
        if self._explain is None:
            return False
        if not text:
            text = "(no explanation available — check API key)"
        self._explain_label.set_text(text)
        self._explain_label.remove_css_class("explain-loading")
        return False

    def _extract_meta(self, body: str):
        conf = None
        attack = None
        lines = [l for l in body.splitlines() if l.strip()]
        if lines:
            head = lines[0]
            if   "GREEN"  in head: conf = "green"
            elif "YELLOW" in head: conf = "yellow"
            elif "RED"    in head: conf = "red"
            m = re.search(r"\bT\d{4}(?:\.\d{3})?\b[^\n]*", body)
            if m:
                attack = m.group(0).strip()[:48]
            if conf and ("EXECUTE" in head or "CAUTION" in head or "HOLD" in head):
                lines = lines[1:]
        cmd = "\n".join(lines).strip() or body.strip()
        return conf, attack, cmd

    def _make_button(self, label: str, css: str, value: str) -> Gtk.Button:
        b = Gtk.Button(label=label)
        b.add_css_class(css)
        b.connect("clicked", lambda _b: self._on_clicked(value))
        return b

    def enable_decision(self) -> None:
        if not self._answered:
            self._decision_bar.set_visible(True)

    def _on_clicked(self, value: str) -> None:
        if self._answered:
            return
        self._answered = True
        self._decision_bar.set_visible(False)
        words = {"y": "✓ RUN", "n": "✗ SKIPPED", "q": "✋ QUIT"}
        css_map = {"y": "", "n": "skipped", "q": "quit"}
        self._chosen_pill.set_label(words.get(value, value))
        for c in ("skipped", "quit"):
            self._chosen_pill.remove_css_class(c)
        if css_map[value]:
            self._chosen_pill.add_css_class(css_map[value])
        self._chosen_pill.set_visible(True)
        self._on_decision(value)


class ResultCard(Gtk.Box):
    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("📤 Result", "result")
        lines = body.splitlines()
        truncated = False
        if len(lines) > 40:
            body = "\n".join(lines[:20] + [f"  … {len(lines)-40} lines trimmed …"] + lines[-20:])
            truncated = True
        out = Gtk.Label(label=body, xalign=0)
        out.add_css_class("result-output")
        out.set_wrap(True)
        out.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        out.set_selectable(True)
        card.append(out)
        if truncated:
            hint = Gtk.Label(label="(full output in ~/.athena/logs)", xalign=0)
            hint.add_css_class("input-hint")
            card.append(hint)
        self.append(card)


class FindingsCard(Gtk.Box):
    def __init__(self, title: str, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card(f"🔍 {title}", "findings")
        for line in body.splitlines():
            if line.strip():
                row = Gtk.Label(label=line, xalign=0)
                row.add_css_class("finding-row")
                row.set_wrap(True)
                row.set_selectable(True)
                card.append(row)
        self.append(card)


class ErrorCard(Gtk.Box):
    def __init__(self, title: str, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card(f"⛔ {title}", "error")
        card.append(_body_label(body))
        self.append(card)
        self._body = body
        self._title = title

    @property
    def context(self) -> str:
        return f"Athena reported an error in [{self._title}]:\n{self._body}"


class ManualHelpCard(Gtk.Box):
    """Pentest-assistant guidance: Groq generates 3-5 numbered manual steps."""

    def __init__(self, context: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("🛠 Manual playbook", "manual")
        self._step_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)

        loading = Gtk.Label(label="Generating manual steps…", xalign=0)
        loading.add_css_class("manual-step")
        loading.add_css_class("explain-loading")
        self._loading_label = loading
        self._step_box.append(loading)

        card.append(self._step_box)
        self.append(card)
        EXPLAINER.manual_steps(context, self._populate)

    def _populate(self, text: str) -> bool:
        # remove the loading placeholder
        try:
            self._step_box.remove(self._loading_label)
        except Exception:
            pass

        if not text:
            row = Gtk.Label(label="(could not generate — check Groq API key)", xalign=0)
            row.add_css_class("manual-step")
            self._step_box.append(row)
            return False

        steps = self._split_steps(text)
        for step in steps:
            row = Gtk.Label(label=step, xalign=0)
            row.add_css_class("manual-step")
            row.set_wrap(True)
            row.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            row.set_selectable(True)
            self._step_box.append(row)
        return False

    def _split_steps(self, text: str) -> List[str]:
        # Split on numbered list markers like "1.", "1)", or newlines
        parts = re.split(r"\n(?=\s*\d+[.\)]\s)", text.strip())
        if len(parts) <= 1:
            parts = [p.strip() for p in text.split("\n") if p.strip()]
        return [p.strip() for p in parts if p.strip()]


class PlainCard(Gtk.Box):
    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("", "plain")
        card.append(_body_label(body))
        self.append(card)


class DispatchCard(Gtk.Box):
    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        card = _card("", "dispatch")
        card.append(_body_label("▸ " + body.replace("\n", " ").strip()))
        self.append(card)


class ExecutingCard(Gtk.Box):
    def __init__(self, body: str = "", last_command: str = ""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        card = _card("", "executing")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        spinner = Gtk.Spinner(); spinner.start()
        row.append(spinner)
        row.append(_body_label("EXECUTING " + body))
        card.append(row)
        self.append(card)
        if last_command:
            self._tip = Gtk.Label(label="🔎 watching for…", xalign=0)
            self._tip.add_css_class("exec-tip")
            self._tip.set_wrap(True)
            self._tip.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            self.append(self._tip)
            EXPLAINER.watching_for(last_command, self._set_tip)

    def _set_tip(self, text: str) -> bool:
        if text:
            self._tip.set_text("🔎 " + text)
        return False


class TurnHeader(Gtk.Box):
    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        lbl = Gtk.Label(label="── " + body.strip().replace("\n", " ") + " ──", xalign=0)
        lbl.add_css_class("turn-header")
        lbl.set_wrap(True)
        self.append(lbl)


class BannerCard(Gtk.Box):
    def __init__(self, art: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.add_css_class("banner")
        lbl = Gtk.Label(label=art, xalign=0.5)
        lbl.add_css_class("banner-art")
        box.append(lbl)
        self.append(box)


# ═════════════════════════════════════════════════════════════════════
# CONVERSATION VIEW
# ═════════════════════════════════════════════════════════════════════

def classify_panel_title(title: str) -> str:
    t = title.upper()
    if "THOUGHT" in t:   return "thought"
    if "DISPATCH" in t:  return "dispatch"
    if "EXECUTING" in t: return "executing"
    if "COMMAND" in t:   return "command"
    if "RESULT" in t:    return "result"
    if "FINDING" in t:   return "findings"
    if "ERROR" in t or "⛔" in title: return "error"
    if "TURN" in t:      return "turn"
    return "info"


class ConversationView(Gtk.ScrolledWindow):
    """Append-only feed of cards.  Tracks latest command for executing tips
    and latest error for auto-help generation."""

    def __init__(self, on_decision: Callable[[str], None],
                 want_explanations: bool, want_auto_help: bool):
        super().__init__()
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_kinetic_scrolling(True)
        self.set_hexpand(True); self.set_vexpand(True)
        self.add_css_class("feed")

        self._on_decision = on_decision
        self._want_explanations = want_explanations
        self._want_auto_help = want_auto_help

        self._inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._inner.add_css_class("feed-inner")
        self.set_child(self._inner)

        self._latest_command: Optional[CommandCard] = None
        self._latest_command_text: str = ""
        self._max_cards = 400
        self._stick_bottom = True
        adj = self.get_vadjustment()
        adj.connect("changed", self._on_adj_changed)

    def _on_adj_changed(self, adj):
        if self._stick_bottom:
            GLib.idle_add(lambda: adj.set_value(adj.get_upper()))

    @property
    def inner(self) -> Gtk.Box:
        return self._inner

    @property
    def latest_command_text(self) -> str:
        return self._latest_command_text

    def append(self, widget: Gtk.Widget) -> None:
        self._inner.append(widget)
        kids = []
        c = self._inner.get_first_child()
        while c is not None:
            kids.append(c)
            c = c.get_next_sibling()
        if len(kids) > self._max_cards:
            for k in kids[: len(kids) - self._max_cards]:
                self._inner.remove(k)

    def clear(self) -> None:
        c = self._inner.get_first_child()
        while c is not None:
            nxt = c.get_next_sibling()
            self._inner.remove(c)
            c = nxt
        self._latest_command = None
        self._latest_command_text = ""

    def handle_event(self, ev: dict) -> Optional[str]:
        t = ev.get("type")

        if t == "panel":
            return self._handle_panel(ev.get("title", ""), ev.get("body", ""))

        if t == "text":
            line = ev.get("text", "")
            if "█" in line:
                self.append(BannerCard(line))
            else:
                self.append(PlainCard(line))
            return None

        if t == "status":
            return None

        if t == "prompt_ynq":
            if self._latest_command is not None:
                self._latest_command.enable_decision()
            return "ynq"

        if t == "prompt_password":
            return "password"

        if t == "prompt_text":
            return "text"

        if t == "fatal":
            self.append(ErrorCard("Fatal", ev.get("text", "")))
            return None

        return None

    def _handle_panel(self, title: str, body: str) -> Optional[str]:
        kind = classify_panel_title(title)
        if kind == "thought":
            self.append(ThoughtCard(body))
        elif kind == "command":
            card = CommandCard(body,
                               on_decision=self._on_decision,
                               want_explanation=self._want_explanations)
            self._latest_command = card
            self._latest_command_text = card.command
            self.append(card)
        elif kind == "result":
            self.append(ResultCard(body))
        elif kind == "findings":
            self.append(FindingsCard(title, body))
        elif kind == "error":
            err = ErrorCard(title, body)
            self.append(err)
            if self._want_auto_help:
                self.append(ManualHelpCard(err.context))
        elif kind == "dispatch":
            self.append(DispatchCard(body))
        elif kind == "executing":
            self.append(ExecutingCard(body, last_command=self._latest_command_text))
        elif kind == "turn":
            self.append(TurnHeader(title + " " + body))
        else:
            card = _card(title, "plain")
            card.append(_body_label(body))
            wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrap.append(card)
            self.append(wrap)
        return None

    def request_manual_help(self) -> None:
        """User clicked 'I'm stuck' — generate manual steps for current state."""
        ctx = (
            "The user is currently working with Athena and feels stuck. "
            f"Last proposed command was: {self._latest_command_text or '(none yet)'}. "
            "Give them next-step guidance — what to try manually, what to look at, "
            "any debugging tips. Be specific."
        )
        self.append(ManualHelpCard(ctx))


# ═════════════════════════════════════════════════════════════════════
# INPUT BAR — always allows free text + dedicated rescue button
# ═════════════════════════════════════════════════════════════════════

class InputBar(Gtk.Box):
    def __init__(self,
                 on_send_text: Callable[[str], None],
                 on_rescue: Callable[[], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._on_send_text = on_send_text
        self._on_rescue = on_rescue
        self.add_css_class("input-bar")

        self._hint = Gtk.Label(label="Tell Athena what you want…", xalign=0)
        self._hint.add_css_class("input-hint")
        self.append(self._hint)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._entry = Gtk.Entry()
        self._entry.add_css_class("input-entry")
        self._entry.set_hexpand(True)
        self._entry.set_placeholder_text("type here, or use buttons above…")
        self._entry.connect("activate", lambda _e: self._send())
        row.append(self._entry)

        self._send_btn = Gtk.Button(label="➤")
        self._send_btn.add_css_class("send-button")
        self._send_btn.connect("clicked", lambda _b: self._send())
        row.append(self._send_btn)
        self.append(row)

        # Rescue row — always visible, one tap to summon manual help
        rescue_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        rescue_row.add_css_class("rescue-row")
        rescue_row.set_halign(Gtk.Align.START)
        rescue_btn = Gtk.Button(label="🛟 I'm stuck — show manual steps")
        rescue_btn.add_css_class("rescue-btn")
        rescue_btn.connect("clicked", lambda _b: self._on_rescue())
        rescue_row.append(rescue_btn)
        self.append(rescue_row)

        self.set_mode("text")

    def set_mode(self, mode: str) -> None:
        """Modes adjust HINTS only — input itself is always live."""
        if mode == "password":
            self._hint.set_label("PASSWORD REQUIRED")
            self._entry.set_visibility(False)
            self._entry.set_placeholder_text("(hidden)")
            self._entry.grab_focus()
        elif mode == "ynq":
            self._hint.set_label("TAP A BUTTON ABOVE — RUN · SKIP · QUIT")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("or type free text…")
        else:  # text or idle, treat same
            self._hint.set_label("Tell Athena what you want…")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("type here, or use buttons above…")

        # Input is ALWAYS sensitive
        self._entry.set_sensitive(True)
        self._send_btn.set_sensitive(True)

    def _send(self) -> None:
        text = self._entry.get_text()
        self._entry.set_text("")
        if text.strip():
            self._on_send_text(text)


# ═════════════════════════════════════════════════════════════════════
# ENGAGEMENT WIZARD
# ═════════════════════════════════════════════════════════════════════

def alert_dialog(parent, title: str, body: str = "") -> Any:
    """Returns either Adw.AlertDialog (libadwaita 1.5+) or Adw.MessageDialog."""
    if hasattr(Adw, "AlertDialog"):
        d = Adw.AlertDialog.new(title, body)
        return d
    return Adw.MessageDialog.new(parent, title, body)


def present_dialog(dlg: Any, parent: Any) -> None:
    if hasattr(dlg, "present") and isinstance(dlg, Adw.AlertDialog) if hasattr(Adw, "AlertDialog") else False:
        dlg.present(parent)
    else:
        try:
            dlg.present(parent)
        except TypeError:
            dlg.present()


class EngagementWizard:
    """A single-form dialog: target IP/domain + mission goal.
    Returns the four values athena.py wants: ip, domain, notes, goal."""

    def __init__(self, parent: Gtk.Window,
                 on_done: Callable[[Dict[str, str]], None],
                 on_cancel: Callable[[], None]):
        self._parent = parent
        self._on_done = on_done
        self._on_cancel = on_cancel
        self._last = Config.get("last_target") or {}

        self._ip = Gtk.Entry();     self._ip.add_css_class("wizard-entry")
        self._dom = Gtk.Entry();    self._dom.add_css_class("wizard-entry")
        self._notes = Gtk.Entry();  self._notes.add_css_class("wizard-entry")
        self._goal = Gtk.TextView();
        self._goal.add_css_class("wizard-entry")
        self._goal.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._goal.set_top_margin(6); self._goal.set_bottom_margin(6)
        self._goal.set_left_margin(8); self._goal.set_right_margin(8)

        self._ip.set_text(self._last.get("ip", ""))
        self._dom.set_text(self._last.get("domain", ""))
        self._notes.set_text(self._last.get("notes", ""))
        self._goal.get_buffer().set_text(
            self._last.get("goal") or
            "Enumerate the target — find services, vulnerabilities, and "
            "viable paths to initial access. Be thorough but stay in scope."
        )

        self._ip.set_placeholder_text("10.10.10.5  or  192.168.1.0/24")
        self._dom.set_placeholder_text("example.com  or  https://app.target.tld")
        self._notes.set_placeholder_text("HTB box · client X · CTF · …")

        self._build_and_present()

    def _build_and_present(self) -> None:
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        body.set_size_request(380, -1)

        sub = Gtk.Label(
            label="Set the target and your objective. Athena will plan from there.",
            xalign=0)
        sub.set_wrap(True); sub.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        sub.add_css_class("wizard-sub")
        body.append(sub)

        def add_field(label_text: str, widget: Gtk.Widget):
            l = Gtk.Label(label=label_text, xalign=0)
            l.add_css_class("wizard-label")
            body.append(l)
            body.append(widget)

        add_field("TARGET IP / CIDR", self._ip)
        add_field("DOMAIN / URL  (optional)", self._dom)
        add_field("NOTES  (HTB box, CTF, client tag…)", self._notes)

        l = Gtk.Label(label="WHAT DO YOU WANT FROM THIS TARGET?", xalign=0)
        l.add_css_class("wizard-label")
        body.append(l)
        goal_scroll = Gtk.ScrolledWindow()
        goal_scroll.set_min_content_height(100)
        goal_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        goal_scroll.set_child(self._goal)
        body.append(goal_scroll)

        if hasattr(Adw, "AlertDialog"):
            dlg = Adw.AlertDialog.new("New Engagement", "")
            dlg.set_extra_child(body)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("start",  "▶  Start")
            dlg.set_default_response("start")
            dlg.set_close_response("cancel")
            dlg.set_response_appearance("start", Adw.ResponseAppearance.SUGGESTED)
            dlg.connect("response", self._on_response)
            dlg.present(self._parent)
        else:
            dlg = Adw.MessageDialog.new(self._parent, "New Engagement", "")
            dlg.set_extra_child(body)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("start",  "▶  Start")
            dlg.set_default_response("start")
            dlg.set_close_response("cancel")
            dlg.set_response_appearance("start", Adw.ResponseAppearance.SUGGESTED)
            dlg.connect("response", self._on_response)
            dlg.present()

    def _on_response(self, _dlg, response: str) -> None:
        if response != "start":
            self._on_cancel()
            return
        buf = self._goal.get_buffer()
        goal_text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True).strip()
        values = {
            "ip":     self._ip.get_text().strip(),
            "domain": self._dom.get_text().strip(),
            "notes":  self._notes.get_text().strip(),
            "goal":   goal_text,
        }
        Config.set("last_target", values)
        self._on_done(values)


# ═════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═════════════════════════════════════════════════════════════════════

class AthenaWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application):
        super().__init__(application=application)
        self.set_title("Athena")
        self.set_default_size(420, 820)

        cfg = Config.load()
        self._show_explanations = bool(cfg.get("show_explanations", True))
        self._auto_help_on_error = bool(cfg.get("auto_help_on_error", True))

        # If config has a key but env doesn't, set it now
        key = cfg.get("groq_api_key", "")
        if key and not os.environ.get("GROQ_API_KEY"):
            os.environ["GROQ_API_KEY"] = key

        self._process: Optional[AthenaProcess] = None
        self._pending_inputs: List[str] = []  # auto-fed to athena's startup prompts
        self._wizard_open = False
        self._target_pill: Optional[Gtk.Label] = None
        self._agent_pill: Optional[Gtk.Label] = None

        self.split = Adw.OverlaySplitView()
        self.split.set_collapsed(True)
        self.split.set_show_sidebar(False)
        self.split.set_max_sidebar_width(280)
        self.split.set_sidebar_width_fraction(0.7)
        self.set_content(self.split)
        self.split.set_sidebar(self._build_sidebar())

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(self._build_header())

        self._conversation = ConversationView(
            on_decision=self._on_decision,
            want_explanations=self._show_explanations,
            want_auto_help=self._auto_help_on_error,
        )
        self._input = InputBar(
            on_send_text=self._on_send_text,
            on_rescue=self._on_rescue,
        )

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        body.append(self._conversation)
        toolbar.set_content(body)
        toolbar.add_bottom_bar(self._input)
        self.split.set_content(toolbar)

        self._install_actions()

        # Show welcome card and either prompt for API key or open wizard
        self._conversation.append(WelcomeCard(on_start=self._open_wizard))
        GLib.idle_add(self._initial_check)

    # ── startup choreography ──────────────────────────────────

    def _initial_check(self) -> bool:
        if not os.environ.get("GROQ_API_KEY"):
            self._show_api_key_dialog(then_open_wizard=True)
            return False
        # Have key — open wizard automatically
        self._open_wizard()
        return False

    def _open_wizard(self) -> None:
        if self._wizard_open:
            return
        self._wizard_open = True
        EngagementWizard(
            parent=self,
            on_done=self._on_wizard_done,
            on_cancel=self._on_wizard_cancel,
        )

    def _on_wizard_done(self, values: Dict[str, str]) -> None:
        self._wizard_open = False
        # Queue the four inputs athena.py will ask for at startup:
        #   IP, Domain, Notes, then a goal at priest prompt.
        self._pending_inputs = [
            values.get("ip", ""),
            values.get("domain", ""),
            values.get("notes", ""),
            values.get("goal", ""),
        ]
        self._conversation.clear()
        self._conversation.append(PlainCard(
            f"── New Engagement ──  target: {values.get('ip') or values.get('domain') or '?'}"
        ))
        self._start_athena()

    def _on_wizard_cancel(self) -> None:
        self._wizard_open = False
        # User can hit Start New Engagement again from welcome card

    # ── athena lifecycle ───────────────────────────────────────

    def _start_athena(self) -> bool:
        if self._process is not None:
            return False
        script = find_athena_script()
        if not script:
            self._conversation.append(ErrorCard(
                "athena.py not found",
                "Reinstall via install.sh or set ATHENA_SCRIPT.\n\nSearched:\n"
                + "\n".join(f"  · {c}" for c in SCRIPT_CANDIDATES if c)))
            return False

        self._process = AthenaProcess(script)
        self._process.connect("event", self._on_process_event)
        self._process.connect("exited", self._on_process_exited)
        if not self._process.start():
            self._conversation.append(ErrorCard(
                "Failed to spawn",
                "Could not start athena.py. Check ~/.athena/logs."))
        return False

    def _restart_athena(self) -> None:
        if self._process:
            self._process.stop()
            self._process = None
        self._conversation.clear()
        self._pending_inputs = []
        self._conversation.append(WelcomeCard(on_start=self._open_wizard))
        GLib.idle_add(self._open_wizard)

    def _on_process_event(self, _proc, ev: dict) -> None:
        if ev.get("type") == "status":
            self._update_status_pills(ev["text"])
            return

        # Auto-feed startup prompts (ip/domain/notes/goal) from the wizard
        if ev.get("type") == "prompt_text" and self._pending_inputs:
            text = self._pending_inputs.pop(0)
            self._process.writeln(text)
            self._input.set_mode("text")
            return

        mode = self._conversation.handle_event(ev)
        if mode is not None:
            self._input.set_mode(mode)

    def _on_process_exited(self, _proc) -> None:
        self._conversation.append(PlainCard("── session ended — tap ↻ to start again ──"))

    def _update_status_pills(self, text: str) -> None:
        parts = [p.strip() for p in re.split(r"│", text)]
        if len(parts) >= 2 and self._target_pill and self._agent_pill:
            self._target_pill.set_label(parts[0] or "no target")
            self._agent_pill.set_label(parts[1] or "·")

    def _on_send_text(self, text: str) -> None:
        if self._process is None:
            # No active process — start one and queue the text as a goal
            self._pending_inputs.append(text)
            self._start_athena()
            return
        self._process.writeln(text)

    def _on_decision(self, value: str) -> None:
        if self._process is None:
            return
        self._process.writeln(value)

    def _on_rescue(self) -> None:
        self._conversation.request_manual_help()

    # ── header ─────────────────────────────────────────────────

    def _build_header(self) -> Adw.HeaderBar:
        header = Adw.HeaderBar()
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        t1 = Gtk.Label(label="ATHENA"); t1.add_css_class("title")
        title_box.append(t1)
        pills = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        pills.set_halign(Gtk.Align.CENTER)
        self._target_pill = Gtk.Label(label="no target")
        self._target_pill.add_css_class("headerbar-target")
        self._agent_pill = Gtk.Label(label="·")
        self._agent_pill.add_css_class("headerbar-agent")
        pills.append(self._target_pill)
        pills.append(Gtk.Label(label="·"))
        pills.append(self._agent_pill)
        title_box.append(pills)
        header.set_title_widget(title_box)

        sidebar_btn = Gtk.Button.new_from_icon_name("view-sidebar-start-symbolic")
        sidebar_btn.connect(
            "clicked",
            lambda _b: self.split.set_show_sidebar(not self.split.get_show_sidebar()),
        )
        header.pack_start(sidebar_btn)

        new_btn = Gtk.Button.new_from_icon_name("document-new-symbolic")
        new_btn.set_tooltip_text("New engagement")
        new_btn.set_action_name("win.new-engagement")
        header.pack_end(new_btn)

        more = Gtk.MenuButton()
        more.set_icon_name("open-menu-symbolic")
        menu = Gio.Menu.new()
        menu.append("Restart session", "win.restart")
        menu.append("Open logs folder", "win.open-logs")
        menu.append("API key…", "win.api-key")
        menu.append("Settings…", "win.settings")
        menu.append("About", "win.about")
        more.set_menu_model(menu)
        header.pack_end(more)
        return header

    # ── sidebar ────────────────────────────────────────────────

    def _build_sidebar(self) -> Adw.NavigationPage:
        page = Adw.NavigationPage()
        page.set_title("Commands")
        scroll = Gtk.ScrolledWindow()
        scroll.add_css_class("athena-sidebar")
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        box.set_margin_top(4); box.set_margin_bottom(12)

        sections = [
            ("ENGAGEMENT", [
                ("🎯", "Re-set Target", "target"),
                ("📋", "Workflows",     "workflow"),
                ("📈", "Dashboard",     "dashboard"),
            ]),
            ("INTELLIGENCE", [
                ("🔍", "Findings",      "findings"),
                ("🌳", "Task Tree",     "tree"),
                ("🕸",  "Attack Graph", "graph"),
                ("🎖", "MITRE ATT&CK", "mitre"),
            ]),
            ("SYSTEM", [
                ("🛡", "Scope / RoE",  "scope"),
                ("🔧", "Tools",         "tools"),
                ("🤖", "Model Chain",   "model"),
                ("👥", "Agents",        "agents"),
            ]),
            ("SESSION", [
                ("💾", "Save",         "save"),
                ("📄", "Report",       "report"),
                ("🧹", "Clear Memory", "clear"),
                ("♻", "Full Reset",   "reset"),
                ("❓", "Help",         "help"),
            ]),
        ]
        for header_text, items in sections:
            h = Gtk.Label(label=header_text, xalign=0)
            h.add_css_class("sidebar-header")
            box.append(h)
            for icon, label, cmd in items:
                box.append(self._sidebar_button(icon, label, cmd))

        scroll.set_child(box)
        page.set_child(scroll)
        return page

    def _sidebar_button(self, icon: str, label: str, cmd: str) -> Gtk.Button:
        b = Gtk.Button()
        b.add_css_class("flat")
        b.add_css_class("sidebar-button")
        inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        inner.append(Gtk.Label(label=icon))
        l = Gtk.Label(label=label, xalign=0); l.set_hexpand(True)
        inner.append(l)
        b.set_child(inner)
        b.connect("clicked", lambda _x, c=cmd: self._send_command(c, close=True))
        return b

    def _send_command(self, cmd: str, close: bool = False) -> None:
        if self._process is not None:
            self._process.writeln(cmd)
        if close and self.split.get_collapsed():
            self.split.set_show_sidebar(False)

    # ── window actions ─────────────────────────────────────────

    def _install_actions(self) -> None:
        for name, fn in [
            ("restart",        self._action_restart),
            ("new-engagement", self._action_new_engagement),
            ("open-logs",      self._action_open_logs),
            ("api-key",        self._action_api_key),
            ("settings",       self._action_settings),
            ("about",          self._action_about),
        ]:
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", fn)
            self.add_action(act)

    def _action_restart(self, *_):
        self._restart_athena()

    def _action_new_engagement(self, *_):
        if self._process:
            self._process.stop()
            self._process = None
        self._conversation.clear()
        self._open_wizard()

    def _action_open_logs(self, *_):
        os.makedirs(LOG_DIR, exist_ok=True)
        try:
            Gtk.UriLauncher.new(GLib.filename_to_uri(LOG_DIR)).launch(self, None, None)
        except Exception:
            subprocess.Popen(["xdg-open", LOG_DIR],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _action_api_key(self, *_):
        self._show_api_key_dialog(then_open_wizard=False)

    def _action_settings(self, *_):
        self._show_settings_dialog()

    def _action_about(self, *_):
        if hasattr(Adw, "AboutDialog"):
            a = Adw.AboutDialog()
            a.set_application_name("Athena")
            a.set_application_icon(APP_ID)
            a.set_developer_name("The Priest")
            a.set_version(VERSION)
            a.set_comments("AI-driven offensive security agent.\n"
                           "Native GTK4 pentest assistant.")
            a.set_website("https://github.com/the-priest/athena5")
            a.set_license_type(Gtk.License.MIT_X11)
            a.present(self)
        else:
            a = Adw.AboutWindow(
                transient_for=self,
                application_name="Athena",
                application_icon=APP_ID,
                developer_name="The Priest",
                version=VERSION,
                comments="AI-driven offensive security agent.\n"
                         "Native GTK4 pentest assistant.",
                website="https://github.com/the-priest/athena5",
                license_type=Gtk.License.MIT_X11,
            )
            a.present()

    # ── API key dialog ─────────────────────────────────────────

    def _show_api_key_dialog(self, then_open_wizard: bool):
        entry = Gtk.PasswordEntry(); entry.set_show_peek_icon(True)
        entry.add_css_class("wizard-entry")
        entry.set_text(os.environ.get("GROQ_API_KEY", "") or
                       Config.get("groq_api_key") or "")

        wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        wrap.set_size_request(360, -1)
        info = Gtk.Label(
            label="Get a free key (no card) at console.groq.com. "
                  "Saved to ~/.athena/config.json — only on this device.",
            xalign=0)
        info.set_wrap(True); info.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        info.add_css_class("wizard-sub")
        wrap.append(info)
        wrap.append(entry)

        def on_resp(_d, r):
            if r == "save":
                k = entry.get_text().strip()
                if k:
                    os.environ["GROQ_API_KEY"] = k
                    Config.set("groq_api_key", k)
                    # Also push to bashrc/zshrc for CLI usage
                    self._persist_to_shell_rcs(k)
                if then_open_wizard:
                    GLib.idle_add(self._open_wizard)

        if hasattr(Adw, "AlertDialog"):
            dlg = Adw.AlertDialog.new("Groq API Key", "")
            dlg.set_extra_child(wrap)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("save",   "Save")
            dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
            dlg.set_default_response("save")
            dlg.connect("response", on_resp)
            dlg.present(self)
        else:
            dlg = Adw.MessageDialog.new(self, "Groq API Key", "")
            dlg.set_extra_child(wrap)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("save",   "Save")
            dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
            dlg.set_default_response("save")
            dlg.connect("response", on_resp)
            dlg.present()

    def _persist_to_shell_rcs(self, key: str) -> None:
        for rc in ("~/.bashrc", "~/.zshrc"):
            p = os.path.expanduser(rc)
            if not os.path.exists(p):
                continue
            try:
                with open(p) as f:
                    body = f.read()
                lines = [l for l in body.splitlines() if "GROQ_API_KEY" not in l]
                lines.append(f"export GROQ_API_KEY={shlex.quote(key)}")
                with open(p, "w") as f:
                    f.write("\n".join(lines) + "\n")
            except OSError:
                pass

    # ── settings dialog ────────────────────────────────────────

    def _show_settings_dialog(self):
        wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        wrap.set_size_request(340, -1)

        sw_explain = Gtk.Switch()
        sw_explain.set_active(self._show_explanations)
        row1 = self._setting_row("Explain each command (uses Groq)", sw_explain)
        wrap.append(row1)

        sw_help = Gtk.Switch()
        sw_help.set_active(self._auto_help_on_error)
        row2 = self._setting_row("Auto manual help on errors", sw_help)
        wrap.append(row2)

        def on_resp(_d, r):
            if r == "save":
                self._show_explanations = sw_explain.get_active()
                self._auto_help_on_error = sw_help.get_active()
                Config.set("show_explanations", self._show_explanations)
                Config.set("auto_help_on_error", self._auto_help_on_error)
                # Apply to conversation view immediately
                self._conversation._want_explanations = self._show_explanations
                self._conversation._want_auto_help = self._auto_help_on_error

        if hasattr(Adw, "AlertDialog"):
            dlg = Adw.AlertDialog.new("Settings", "")
            dlg.set_extra_child(wrap)
            dlg.add_response("close", "Close")
            dlg.add_response("save",  "Save")
            dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
            dlg.connect("response", on_resp)
            dlg.present(self)
        else:
            dlg = Adw.MessageDialog.new(self, "Settings", "")
            dlg.set_extra_child(wrap)
            dlg.add_response("close", "Close")
            dlg.add_response("save",  "Save")
            dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
            dlg.connect("response", on_resp)
            dlg.present()

    def _setting_row(self, label: str, control: Gtk.Widget) -> Gtk.Box:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        l = Gtk.Label(label=label, xalign=0); l.set_hexpand(True)
        l.set_wrap(True); l.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        row.append(l)
        row.append(control)
        return row

    def do_close_request(self):
        if self._process:
            self._process.stop()
        return False


# ═════════════════════════════════════════════════════════════════════
# APP
# ═════════════════════════════════════════════════════════════════════

class AthenaApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)

    def do_activate(self):
        load_css()
        win = self.props.active_window
        if not win:
            win = AthenaWindow(application=self)
        win.present()


def main() -> int:
    return AthenaApp().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
