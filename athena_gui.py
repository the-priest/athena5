#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║          ATHENA GUI — Native cards · v7.3                        ║
# ║   No terminal.  No typing y/n.  Spawns athena.py through a PTY,  ║
# ║   parses its boxed output, renders every event as a GTK card,    ║
# ║   intercepts the [y]/[n]/[q] gate as three tap buttons.          ║
# ╚══════════════════════════════════════════════════════════════════╝
"""
Architecture
────────────
   athena.py (unchanged 6000-line REPL)
        │  prints panels / banner / status bar / prompts to a PTY
        ▼
   AthenaProcess   ── pty.openpty() + subprocess
        │  raw bytes from master_fd
        ▼
   LineBuffer       ── ANSI strip, split on \\n, also emit trailing partial
        │  clean text lines
        ▼
   PanelParser      ── state machine: outside-box / inside-box
        │  events: {type:'panel', title, body} | 'text' | 'status' |
        │          'prompt_ynq' | 'prompt_text' | 'prompt_password'
        ▼
   ConversationView ── creates the right Card widget for each event
        │
        ▼
   Cards            ── ThoughtCard, CommandCard (with y/n/q buttons),
                       ResultCard, FindingsCard, ErrorCard, BannerCard,
                       PlainCard, StatusStrip…
"""

from __future__ import annotations

import os
import sys
import re
import pty
import fcntl
import termios
import struct
import signal
import subprocess
import shlex
from typing import Callable, Optional, List

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

# ═════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════

APP_ID = "io.thepriest.Athena"
VERSION = "7.3"
ATHENA_HOME = os.path.expanduser("~/.athena")
LOG_DIR = os.path.join(ATHENA_HOME, "logs")

SCRIPT_CANDIDATES = [
    os.environ.get("ATHENA_SCRIPT", ""),
    "/opt/athena5/athena.py",
    os.path.expanduser("~/.local/share/athena5/athena.py"),
    os.path.expanduser("~/Documents/athena5/athena.py"),
    os.path.expanduser("~/athena5/athena.py"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "athena.py"),
]


def find_athena_script() -> Optional[str]:
    for c in SCRIPT_CANDIDATES:
        if c and os.path.isfile(c):
            return c
    return None


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

/* feed */
.feed { background: #0a0612; padding: 8px; }
.feed-inner { padding-bottom: 60px; }

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

/* thought card */
.thought {
    background: linear-gradient(180deg, #1a1030 0%, #14082a 100%);
    border-color: #4a2a6a;
}
.thought .card-title { color: #cc88ff; }
.thought .card-body { font-style: italic; color: #d9c9e9; }

/* command card */
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
    padding: 12px; border-radius: 10px; font-weight: 700;
    font-size: 13px; letter-spacing: 0.5px; min-height: 48px;
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

/* dispatch + executing pills */
.dispatch, .executing {
    background: transparent; border: none;
    padding: 4px 12px; margin: 2px 8px;
}
.dispatch .card-body, .executing .card-body {
    color: #8d7da0; font-size: 11px; letter-spacing: 1px;
    font-family: monospace;
}

/* banner */
.banner {
    background: #0a0612; border: 1px solid #4a2a6a;
    border-radius: 14px; padding: 10px; margin: 6px 4px;
}
.banner-art { font-family: monospace; font-size: 10px; color: #cc66ff; }

/* turn header */
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
    padding: 10px;
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
"""


# ═════════════════════════════════════════════════════════════════════
# ANSI STRIP + LINE BUFFER
# ═════════════════════════════════════════════════════════════════════

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


class LineBuffer:
    """Accumulates bytes, calls on_line per complete line (ANSI-stripped),
    and on_partial with any unfinished trailing fragment (used to detect
    prompts that have no trailing newline)."""

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

PROMPT_YNQ_HINT     = re.compile(r"y\s*run.*n\s*skip.*q\s*quit", re.IGNORECASE)
PROMPT_PRIEST_HINT  = re.compile(r"priest\s*[›>]")
PROMPT_TRAILING_COLON = re.compile(r":\s*$")
PROMPT_PASSWORD_HINT = re.compile(r"\b(?:password|passphrase|sudo password)\b", re.IGNORECASE)


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
            self._on({"type": "prompt_text", "text": clean})
            return
        if PROMPT_TRAILING_COLON.search(clean):
            self._on({"type": "prompt_text", "text": clean})
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
    lbl.set_xalign(0)
    return lbl


class ThoughtCard(Gtk.Box):
    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("🧠 Athena thinking", "thought")
        card.append(_body_label(body))
        self.append(card)


class CommandCard(Gtk.Box):
    """The interactive heart of the UI — shows the command and three big
    decision buttons (Run / Skip / Quit) instead of typing y/n/q."""

    def __init__(self, body: str, *, on_decision: Callable[[str], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._on_decision = on_decision
        self._answered = False

        card = _card("⚡ Proposed command", "command")
        conf, attack, cmd_text = self._extract_meta(body)

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
    def __init__(self, body: str = ""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        card = _card("", "executing")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        spinner = Gtk.Spinner(); spinner.start()
        row.append(spinner)
        row.append(_body_label("EXECUTING " + body))
        card.append(row)
        self.append(card)


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
    def __init__(self, on_decision: Callable[[str], None]):
        super().__init__()
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_kinetic_scrolling(True)
        self.set_hexpand(True); self.set_vexpand(True)
        self.add_css_class("feed")

        self._on_decision = on_decision
        self._inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._inner.add_css_class("feed-inner")
        self.set_child(self._inner)

        self._latest_command: Optional[CommandCard] = None
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
            card = CommandCard(body, on_decision=self._on_decision)
            self._latest_command = card
            self.append(card)
        elif kind == "result":
            self.append(ResultCard(body))
        elif kind == "findings":
            self.append(FindingsCard(title, body))
        elif kind == "error":
            self.append(ErrorCard(title, body))
        elif kind == "dispatch":
            self.append(DispatchCard(body))
        elif kind == "executing":
            self.append(ExecutingCard(body))
        elif kind == "turn":
            self.append(TurnHeader(title + " " + body))
        else:
            card = _card(title, "plain")
            card.append(_body_label(body))
            wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrap.append(card)
            self.append(wrap)
        return None


# ═════════════════════════════════════════════════════════════════════
# INPUT BAR
# ═════════════════════════════════════════════════════════════════════

class InputBar(Gtk.Box):
    def __init__(self, on_send_text: Callable[[str], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._on_send_text = on_send_text
        self.add_css_class("input-bar")

        self._hint = Gtk.Label(label="WAITING…", xalign=0)
        self._hint.add_css_class("input-hint")
        self.append(self._hint)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._entry = Gtk.Entry()
        self._entry.add_css_class("input-entry")
        self._entry.set_hexpand(True)
        self._entry.set_placeholder_text("type a command or objective…")
        self._entry.connect("activate", lambda _e: self._send())
        row.append(self._entry)

        self._send_btn = Gtk.Button(label="➤")
        self._send_btn.add_css_class("send-button")
        self._send_btn.connect("clicked", lambda _b: self._send())
        row.append(self._send_btn)

        self.append(row)
        self.set_mode("text")

    def set_mode(self, mode: str) -> None:
        if mode == "text":
            self._hint.set_label("YOUR TURN — TYPE BELOW")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("type a command or objective…")
            self._entry.set_sensitive(True)
            self._send_btn.set_sensitive(True)
            self._entry.grab_focus()
        elif mode == "password":
            self._hint.set_label("PASSWORD REQUIRED")
            self._entry.set_visibility(False)
            self._entry.set_placeholder_text("(hidden)")
            self._entry.set_sensitive(True)
            self._send_btn.set_sensitive(True)
            self._entry.grab_focus()
        elif mode == "ynq":
            self._hint.set_label("TAP A BUTTON ABOVE — RUN · SKIP · QUIT")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("or type a free-form reply…")
            self._entry.set_sensitive(True)
            self._send_btn.set_sensitive(True)
        else:
            self._hint.set_label("ATHENA IS WORKING…")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("…")
            self._entry.set_sensitive(False)
            self._send_btn.set_sensitive(False)

    def _send(self) -> None:
        text = self._entry.get_text()
        self._entry.set_text("")
        self._on_send_text(text)


# ═════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═════════════════════════════════════════════════════════════════════

class AthenaWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application):
        super().__init__(application=application)
        self.set_title("Athena")
        self.set_default_size(420, 820)

        self._process: Optional[AthenaProcess] = None

        self.split = Adw.OverlaySplitView()
        self.split.set_collapsed(True)
        self.split.set_show_sidebar(False)
        self.split.set_max_sidebar_width(280)
        self.split.set_sidebar_width_fraction(0.7)
        self.set_content(self.split)
        self.split.set_sidebar(self._build_sidebar())

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(self._build_header())

        self._conversation = ConversationView(on_decision=self._on_decision)
        self._input = InputBar(on_send_text=self._on_send_text)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        body.append(self._conversation)
        toolbar.set_content(body)
        toolbar.add_bottom_bar(self._input)
        self.split.set_content(toolbar)

        self._install_actions()
        GLib.idle_add(self._start_athena)

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

        restart_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        restart_btn.set_action_name("win.restart")
        restart_btn.set_tooltip_text("Restart")
        header.pack_end(restart_btn)

        more = Gtk.MenuButton()
        more.set_icon_name("open-menu-symbolic")
        menu = Gio.Menu.new()
        menu.append("Open logs folder", "win.open-logs")
        menu.append("API key…", "win.api-key")
        menu.append("About", "win.about")
        more.set_menu_model(menu)
        header.pack_end(more)
        return header

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
                ("🎯", "Set Target", "target"),
                ("📋", "Workflows",  "workflow"),
                ("📈", "Dashboard",  "dashboard"),
            ]),
            ("INTELLIGENCE", [
                ("🔍", "Findings",     "findings"),
                ("🌳", "Task Tree",    "tree"),
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

    # ── athena lifecycle ───────────────────────────────────────

    def _start_athena(self) -> bool:
        script = find_athena_script()
        if not script:
            self._conversation.append(ErrorCard(
                "athena.py not found",
                "Reinstall via install.sh, or set ATHENA_SCRIPT.\n\nSearched:\n"
                + "\n".join(f"  · {c}" for c in SCRIPT_CANDIDATES if c)))
            return False
        if not os.environ.get("GROQ_API_KEY"):
            self._show_api_key_dialog(then_spawn=True)
            return False

        self._process = AthenaProcess(script)
        self._process.connect("event", self._on_process_event)
        self._process.connect("exited", self._on_process_exited)
        if not self._process.start():
            self._conversation.append(ErrorCard(
                "Failed to spawn",
                "Could not start athena.py.  Check ~/.athena/logs."))
        return False

    def _restart_athena(self) -> None:
        if self._process:
            self._process.stop()
            self._process = None
        c = self._conversation.inner.get_first_child()
        while c is not None:
            nxt = c.get_next_sibling()
            self._conversation.inner.remove(c)
            c = nxt
        GLib.idle_add(self._start_athena)

    def _on_process_event(self, _proc, ev: dict) -> None:
        if ev.get("type") == "status":
            self._update_status_pills(ev["text"])
            return
        mode = self._conversation.handle_event(ev)
        if mode is not None:
            self._input.set_mode(mode)

    def _on_process_exited(self, _proc) -> None:
        self._conversation.append(PlainCard("── session ended ── tap ↻ to restart ──"))
        self._input.set_mode("idle")

    def _update_status_pills(self, text: str) -> None:
        parts = [p.strip() for p in re.split(r"│", text)]
        if len(parts) >= 2:
            self._target_pill.set_label(parts[0] or "no target")
            self._agent_pill.set_label(parts[1] or "·")

    def _on_send_text(self, text: str) -> None:
        if self._process is None:
            return
        self._process.writeln(text)
        self._input.set_mode("idle")

    def _on_decision(self, value: str) -> None:
        if self._process is None:
            return
        self._process.writeln(value)
        self._input.set_mode("idle")

    # ── window actions ─────────────────────────────────────────

    def _install_actions(self) -> None:
        for name, fn in [
            ("restart",   self._action_restart),
            ("open-logs", self._action_open_logs),
            ("api-key",   self._action_api_key),
            ("about",     self._action_about),
        ]:
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", fn)
            self.add_action(act)

    def _action_restart(self, *_):
        dlg = Adw.MessageDialog.new(self, "Restart Athena?",
            "Kills the current REPL and starts a fresh one.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("restart", "Restart")
        dlg.set_response_appearance("restart", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.connect("response",
            lambda _d, r: self._restart_athena() if r == "restart" else None)
        dlg.present()

    def _action_open_logs(self, *_):
        os.makedirs(LOG_DIR, exist_ok=True)
        Gtk.UriLauncher.new(GLib.filename_to_uri(LOG_DIR)).launch(self, None, None, None)

    def _action_api_key(self, *_):
        self._show_api_key_dialog(then_spawn=False)

    def _action_about(self, *_):
        a = Adw.AboutWindow(
            transient_for=self,
            application_name="Athena",
            application_icon=APP_ID,
            developer_name="The Priest",
            version=VERSION,
            comments="AI-driven offensive security agent.\n"
                     "Native GTK4 frontend over the athena.py REPL.",
            website="https://github.com/the-priest/athena5",
            license_type=Gtk.License.MIT_X11,
        )
        a.present()

    def _show_api_key_dialog(self, then_spawn: bool):
        dlg = Adw.MessageDialog.new(self, "Groq API Key",
            "Athena uses Groq for inference. Get a free key (no card) "
            "at console.groq.com and paste below.")
        entry = Gtk.PasswordEntry(); entry.set_show_peek_icon(True)
        entry.set_margin_top(8); entry.set_margin_bottom(8)
        if os.environ.get("GROQ_API_KEY"):
            entry.set_text(os.environ["GROQ_API_KEY"])
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("save", "Save & Launch" if then_spawn else "Save")
        dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(_d, r):
            if r == "save":
                k = entry.get_text().strip()
                if k:
                    os.environ["GROQ_API_KEY"] = k
                    self._persist_api_key(k)
                if then_spawn:
                    GLib.idle_add(self._start_athena)
        dlg.connect("response", on_resp)
        dlg.present()

    def _persist_api_key(self, key: str) -> None:
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
        css = Gtk.CssProvider()
        css.load_from_data(CSS.encode())
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
        win = self.props.active_window
        if not win:
            win = AthenaWindow(application=self)
        win.present()


def main() -> int:
    return AthenaApp().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
