#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║          ATHENA GUI — Native pentest assistant · v7.8            ║
# ║                                                                  ║
# ║   Dark, glassy libadwaita shell for the confirmation-gated       ║
# ║   Athena agent.                                                   ║
# ║                                                                  ║
# ║   · Engagement wizard (target + goal in one form)                ║
# ║   · Renders athena's [MANUAL] playbook panels as cards           ║
# ║   · Live header status dot: idle · thinking · executing · await  ║
# ║   · Filterable command sidebar + toast feedback                  ║
# ║   · Native Settings dialog — providers, live models, engines     ║
# ║   · Persistent config + provider keys (~/.athena/settings.json)  ║
# ║   · No idle/disabled input — always allow typing                 ║
# ║   · libadwaita 1.6+ compatible dialogs with fallbacks            ║
# ╚══════════════════════════════════════════════════════════════════╝

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
from typing import Callable, Optional, List, Dict, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402


# ═════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════

APP_ID = "io.thepriest.Athena"
VERSION = "7.8"

ATHENA_HOME = os.path.expanduser("~/.athena")
LOG_DIR = os.path.join(ATHENA_HOME, "logs")
CONFIG_PATH = os.path.join(ATHENA_HOME, "config.json")
SETTINGS_PATH = os.path.join(ATHENA_HOME, "settings.json")

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
# CONFIG — persistent settings, survives across launches
# ═════════════════════════════════════════════════════════════════════

class Config:
    DEFAULTS: Dict[str, Any] = {
        "groq_api_key": "",
        "last_target":  {"ip": "", "domain": "", "notes": "", "goal": ""},
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
# SHARED SETTINGS  (~/.athena/settings.json — same file athena.py uses)
# ═════════════════════════════════════════════════════════════════════

def load_settings() -> Dict[str, Any]:
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH) as f:
                d = json.load(f)
            if isinstance(d, dict):
                return d
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_settings(data: Dict[str, Any]) -> bool:
    os.makedirs(ATHENA_HOME, exist_ok=True)
    try:
        tmp = SETTINGS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, SETTINGS_PATH)
        os.chmod(SETTINGS_PATH, 0o600)
        return True
    except OSError:
        return False


def load_providers_module():
    """Import athena_ext.providers from the install dir, or None.

    Keeps the GUI DRY (one provider registry) without making the GUI depend on
    the CLI starting first.  Fail-soft: None just means a static provider list.
    """
    script = find_athena_script()
    if script:
        d = os.path.dirname(script)
        if d and d not in sys.path:
            sys.path.insert(0, d)
    try:
        from athena_ext import providers as _p   # type: ignore
        return _p
    except Exception:
        return None


# Static fallback so the Settings dialog still works if athena_ext is missing.
STATIC_PROVIDERS = [
    ("groq", "Groq", "GROQ_API_KEY", True),
    ("cerebras", "Cerebras (free)", "CEREBRAS_API_KEY", True),
    ("siliconflow", "SiliconFlow", "SILICONFLOW_API_KEY", False),
    ("openrouter", "OpenRouter (free tiers)", "OPENROUTER_API_KEY", True),
    ("together", "Together AI", "TOGETHER_API_KEY", True),
    ("mistral", "Mistral (free tier)", "MISTRAL_API_KEY", True),
    ("deepseek", "DeepSeek", "DEEPSEEK_API_KEY", False),
    ("google", "Google Gemini", "GEMINI_API_KEY", True),
    ("openai", "OpenAI", "OPENAI_API_KEY", False),
    ("xai", "xAI Grok", "XAI_API_KEY", False),
    ("ollama", "Ollama (local)", "", True),
]


def provider_rows() -> List[Dict[str, Any]]:
    """[{provider,label,env,free}] — from the live registry when possible."""
    mod = load_providers_module()
    if mod is not None:
        try:
            rows = []
            for p in mod.ORDER:
                meta = mod.REGISTRY.get(p, {})
                rows.append({"provider": p, "label": meta.get("label", p),
                             "env": meta.get("env", ""), "free": meta.get("free", False)})
            if rows:
                return rows
        except Exception:
            pass
    return [{"provider": p, "label": l, "env": e, "free": f}
            for (p, l, e, f) in STATIC_PROVIDERS]


# ═════════════════════════════════════════════════════════════════════
# CSS
# ═════════════════════════════════════════════════════════════════════

CSS = """

/* ═══════════════════════════════════════════════════════════════════
   ATHENA · design system  (v7.8)
   ───────────────────────────────────────────────────────────────────
   void     #07050e   surface  #120f1e   raised  #181328
   line     #241d38   line-hi  #3a2f5c
   violet   #a855f7   magenta  #e879f9   cyan    #22d3ee
   emerald  #34d399   amber    #fbbf24   rose    #fb7185
   text     #ece7f7   text-2   #b3a9cf   text-3  #756c93
   ═══════════════════════════════════════════════════════════════════ */

window, .background {
    background-color: #07050e;
    background-image:
        radial-gradient(circle at 16% 0%, rgba(124, 58, 237, 0.20) 0%, rgba(7, 5, 14, 0) 48%),
        radial-gradient(circle at 100% 100%, rgba(34, 211, 238, 0.10) 0%, rgba(7, 5, 14, 0) 44%);
    color: #ece7f7;
}

/* ── header bar ─────────────────────────────────────────────────── */
headerbar {
    background: linear-gradient(180deg, #16112a 0%, #110d20 100%);
    border-bottom: 1px solid #241d38;
    min-height: 46px;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.02), 0 6px 24px rgba(0, 0, 0, 0.5);
}
headerbar button {
    background: transparent;
    border: none;
    border-radius: 9px;
    color: #b3a9cf;
}
headerbar button:hover { background: #221a3a; color: #ece7f7; }

.app-title {
    color: #f5f2ff;
    font-size: 15px;
    font-weight: 800;
    letter-spacing: 5px;
}
.version-pill {
    background: #1c1530;
    border: 1px solid #322652;
    color: #a78bfa;
    border-radius: 999px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 1px 7px;
}
.status-dot {
    min-width: 9px;
    min-height: 9px;
    border-radius: 999px;
    background: #4b4266;
}
.status-dot.st-idle      { background: #4b4266; }
.status-dot.st-thinking  { background: #a855f7; box-shadow: 0 0 10px rgba(168, 85, 247, 0.85); }
.status-dot.st-executing { background: #22d3ee; box-shadow: 0 0 10px rgba(34, 211, 238, 0.85); }
.status-dot.st-await     { background: #fbbf24; box-shadow: 0 0 10px rgba(251, 191, 36, 0.85); }
.status-dot.st-done      { background: #34d399; box-shadow: 0 0 10px rgba(52, 211, 153, 0.85); }

.headerbar-target {
    color: #9ee7c1;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 11px;
}
.headerbar-agent {
    color: #8b82a8;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 10px;
}

/* ── feed ───────────────────────────────────────────────────────── */
.feed { background: transparent; padding: 10px 6px; }
.feed-inner { padding: 4px 6px 96px 6px; }

/* ── cards ──────────────────────────────────────────────────────── */
.card {
    background-image: linear-gradient(180deg, #15112a 0%, #110e21 100%);
    background-color: #120f1e;
    border: 1px solid #241d38;
    border-radius: 14px;
    padding: 12px 14px;
    margin: 6px 4px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
    transition: border-color 160ms ease, box-shadow 160ms ease;
}
.card:hover {
    border-color: #3a2f5c;
    box-shadow: 0 4px 22px rgba(88, 28, 135, 0.22);
}
.card-title {
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1.8px;
    color: #8b82a8;
    margin-bottom: 6px;
}
.card-body { color: #dfd8f2; font-size: 14px; }

/* type accents */
.thought   { border-left: 3px solid #7c3aed; background-image: linear-gradient(180deg, #171033 0%, #120d24 100%); }
.command   { border-left: 3px solid #22d3ee; background-image: linear-gradient(180deg, #0c1a26 0%, #0a1420 100%); }
.result    { border-left: 3px solid #64748b; }
.findings  { border-left: 3px solid #34d399; background-image: linear-gradient(180deg, #0c1d18 0%, #0a1512 100%); }
.error     { border-left: 3px solid #fb7185; background-image: linear-gradient(180deg, #220e17 0%, #170a11 100%); }
.manual    { border-left: 3px solid #fbbf24; background-image: linear-gradient(180deg, #1f1607 0%, #150f06 100%); }

.thought .card-title  { color: #c084fc; }
.command .card-title  { color: #67e8f9; }
.result .card-title   { color: #94a3b8; }
.findings .card-title { color: #6ee7b7; }
.error .card-title    { color: #fda4af; }
.manual .card-title   { color: #fcd34d; }

.thought .card-body { font-style: italic; color: #ddd0f2; }

/* ── welcome ────────────────────────────────────────────────────── */
.welcome {
    background-color: #120d24;
    background-image:
        radial-gradient(circle at 0% 0%, rgba(168, 85, 247, 0.28) 0%, rgba(168, 85, 247, 0) 55%),
        linear-gradient(180deg, #1a1236 0%, #0d0a1c 100%);
    border: 1px solid #4c2f7a;
    border-left: 3px solid #a855f7;
    padding: 20px 18px;
    box-shadow: 0 10px 40px rgba(88, 28, 135, 0.28);
}
.welcome-mark {
    color: #e879f9;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 4px;
    margin-bottom: 4px;
}
.welcome-title {
    color: #f5f2ff;
    font-size: 24px;
    font-weight: 800;
    letter-spacing: 0.2px;
    margin-bottom: 6px;
}
.welcome-sub { color: #b3a9cf; font-size: 13px; margin-bottom: 14px; }
.welcome-chips { margin-bottom: 14px; }
.chip {
    background: #1e1638;
    border: 1px solid #33265a;
    color: #c4b5fd;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.6px;
    padding: 4px 10px;
}
.welcome-btn {
    background-image: linear-gradient(180deg, #c084fc 0%, #a855f7 100%);
    background-color: #a855f7;
    color: #14091f;
    border: none;
    border-radius: 12px;
    padding: 14px;
    min-height: 52px;
    font-weight: 800;
    font-size: 14px;
    letter-spacing: 0.4px;
    box-shadow: 0 8px 24px rgba(168, 85, 247, 0.35);
}
.welcome-btn:hover { background-image: linear-gradient(180deg, #d8b4fe 0%, #b975f8 100%); }

/* ── command ────────────────────────────────────────────────────── */
.cmd-code {
    background-color: #05040c;
    border: 1px solid #1b2f42;
    border-left: 2px solid #22d3ee;
    border-radius: 9px;
    padding: 12px 14px;
    color: #b9f0ff;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 13px;
}

.conf-pill {
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1.2px;
    color: #08060f;
}
.conf-green  { background: #34d399; }
.conf-yellow { background: #fbbf24; }
.conf-red    { background: #fb7185; color: #ffffff; }
.attack-pill {
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    background: #241640;
    color: #c4b5fd;
    border: 1px solid #4c2f7a;
}

.decision-bar { margin-top: 12px; border-top: 1px solid #1b2f42; padding-top: 12px; }
.btn-run, .btn-skip, .btn-quit {
    padding: 13px 12px;
    border-radius: 11px;
    font-weight: 800;
    font-size: 14px;
    letter-spacing: 0.4px;
    min-height: 50px;
    border: none;
}
.btn-run  { background-image: linear-gradient(180deg, #34d399, #059669); color: #04140d; box-shadow: 0 6px 18px rgba(5, 150, 105, 0.30); }
.btn-skip { background-image: linear-gradient(180deg, #fbbf24, #d97706); color: #1a1203; }
.btn-quit { background-image: linear-gradient(180deg, #fb7185, #e11d48); color: #ffffff; }
.btn-run:hover  { background-image: linear-gradient(180deg, #5eead4, #10b981); }
.btn-skip:hover { background-image: linear-gradient(180deg, #fcd34d, #f59e0b); }
.btn-quit:hover { background-image: linear-gradient(180deg, #fda4af, #f43f5e); }

.decision-done {
    padding: 8px 14px;
    border-radius: 999px;
    background: #0f2e22;
    color: #6ee7b7;
    font-size: 11px;
    font-weight: 700;
    border: 1px solid #155e3f;
}
.decision-done.skipped { background: #2e2408; color: #fcd34d; border-color: #5a4409; }
.decision-done.quit    { background: #2e0f15; color: #fda4af; border-color: #5a1b26; }

/* ── result ─────────────────────────────────────────────────────── */
.result-output {
    background-color: #05040c;
    border: 1px solid #1e293b;
    border-radius: 9px;
    padding: 11px 13px;
    color: #cbd5e1;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 12px;
}

/* ── findings ───────────────────────────────────────────────────── */
.finding-row {
    padding: 7px 0;
    color: #d1fae5;
    font-size: 13px;
    border-bottom: 1px solid #123024;
}
.finding-row:last-child { border-bottom: none; }

/* ── manual playbook ────────────────────────────────────────────── */
.manual-step {
    background: #1f1607;
    border: 1px solid #3a2c0a;
    border-left: 2px solid #fbbf24;
    border-radius: 7px;
    padding: 10px 12px;
    margin: 4px 0;
    color: #fde9c0;
    font-size: 13px;
}

/* ── dispatch / executing / turn / plain ────────────────────────── */
.dispatch, .executing {
    background: transparent;
    border: none;
    padding: 4px 12px;
    margin: 2px 8px;
    box-shadow: none;
}
.dispatch .card-body, .executing .card-body {
    color: #756c93;
    font-size: 11px;
    letter-spacing: 1.2px;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
}
.executing .card-body { color: #67e8f9; }

.turn-header {
    color: #4b4266;
    font-size: 10px;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    letter-spacing: 2px;
    padding: 14px 8px 4px 8px;
}
.plain { background: transparent; border: none; box-shadow: none; padding: 4px 12px; }
.plain .card-body {
    color: #8b82a8;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 12px;
}

/* ── banner art ─────────────────────────────────────────────────── */
.banner {
    background-image: linear-gradient(180deg, #120d24, #0a0716);
    background-color: #0a0716;
    border: 1px solid #3a2f5c;
    border-radius: 14px;
    padding: 12px;
    margin: 6px 4px;
    box-shadow: inset 0 0 30px rgba(124, 58, 237, 0.12);
}
.banner-art {
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 10px;
    color: #c084fc;
}

/* ── sidebar ────────────────────────────────────────────────────── */
.athena-sidebar {
    background-image: linear-gradient(180deg, #0d0a1a 0%, #0a0814 100%);
    background-color: #0b0816;
    border-right: 1px solid #1d1730;
}
.sidebar-search {
    background-color: #14102a;
    border: 1px solid #241d38;
    border-radius: 10px;
    color: #ece7f7;
    margin: 10px 12px 2px 12px;
    min-height: 38px;
}
.sidebar-search:focus { border-color: #a855f7; }
.sidebar-brand {
    color: #c084fc;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 4px;
    margin: 14px 18px 2px 18px;
}
.sidebar-header {
    color: #5b5278;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1.6px;
    margin: 16px 18px 4px;
}
.sidebar-button {
    padding: 11px 14px;
    border-radius: 10px;
    margin: 1px 8px;
    color: #cdc3e8;
    min-height: 42px;
    transition: background 120ms ease, color 120ms ease;
}
.sidebar-button:hover { background: #1a1330; color: #f5f2ff; }
.sidebar-button:active, .sidebar-button:checked { background: #241640; }
.sidebar-icon { font-size: 15px; }
.sidebar-sep { min-height: 1px; background: #1d1730; margin: 10px 16px 4px 16px; }

/* ── input bar ──────────────────────────────────────────────────── */
.input-bar {
    background-image: linear-gradient(180deg, #120f22 0%, #0d0a18 100%);
    background-color: #0f0c1d;
    border-top: 1px solid #241d38;
    padding: 10px 12px 12px 12px;
    box-shadow: 0 -6px 24px rgba(0, 0, 0, 0.4);
}
.input-entry {
    background-color: #08060f;
    color: #ece7f7;
    border: 1px solid #2c2444;
    border-radius: 22px;
    padding: 11px 16px;
    font-size: 14px;
    min-height: 46px;
}
.input-entry:focus { border-color: #a855f7; box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.18); }
.send-button {
    background-image: linear-gradient(180deg, #c084fc, #a855f7);
    background-color: #a855f7;
    color: #14091f;
    border: none;
    border-radius: 22px;
    min-width: 46px;
    min-height: 46px;
    font-weight: 800;
    box-shadow: 0 6px 18px rgba(168, 85, 247, 0.30);
}
.send-button:hover { background-image: linear-gradient(180deg, #d8b4fe, #b975f8); }
.input-hint {
    color: #5b5278;
    font-size: 10px;
    letter-spacing: 1.2px;
    padding: 0 8px 6px;
}
.rescue-row { margin-top: 6px; }
.rescue-btn {
    background: #1a1330;
    color: #fcd34d;
    border: 1px solid #33265a;
    border-radius: 9px;
    padding: 7px 12px;
    font-size: 11px;
    font-weight: 700;
}
.rescue-btn:hover { background: #241640; }

/* ── settings dialog ────────────────────────────────────────────── */
.sheet-title { color: #f5f2ff; font-size: 17px; font-weight: 800; letter-spacing: 0.3px; }
.sheet-sub { color: #8b82a8; font-size: 12px; }
.section-rule { min-height: 1px; background: #241d38; margin: 14px 0 4px 0; }
.field-label {
    color: #a78bfa;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1.5px;
    margin-top: 8px;
}
.toggle-row {
    background: #14102a;
    border: 1px solid #241d38;
    border-radius: 11px;
    padding: 9px 13px;
    margin: 4px 0;
}
.toggle-title { color: #ece7f7; font-size: 13px; font-weight: 700; }
.toggle-sub { color: #756c93; font-size: 11px; }
.provider-row {
    background-image: linear-gradient(180deg, #14102a, #110d21);
    background-color: #130f24;
    border: 1px solid #221a38;
    border-left: 3px solid #4c2f7a;
    border-radius: 11px;
    padding: 9px 11px;
    margin: 4px 0;
}
.provider-name { color: #ece7f7; font-size: 13px; font-weight: 700; }
.model-count { color: #6ee7b7; font-size: 11px; }
.badge-free {
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 1px;
    background: #12301c;
    color: #6ee59a;
    border: 1px solid #1f5a34;
}
.badge-key {
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 1px;
    background: #141830;
    color: #9ab4ff;
    border: 1px solid #263466;
}
.primary-btn {
    background-image: linear-gradient(180deg, #c084fc, #a855f7);
    background-color: #a855f7;
    color: #14091f;
    border: none;
    border-radius: 11px;
    padding: 11px 18px;
    font-weight: 800;
}
.danger-btn {
    background: #2e0f15;
    color: #fda4af;
    border: 1px solid #5a1b26;
    border-radius: 11px;
    padding: 9px 15px;
    font-weight: 700;
}
.icon-btn {
    background: transparent;
    border: none;
    color: #8b82a8;
    border-radius: 8px;
    padding: 4px;
}
.icon-btn:hover { background: #221a3a; color: #ece7f7; }

/* ── misc widgets ───────────────────────────────────────────────── */
scrollbar slider { background: #241d38; border-radius: 8px; min-width: 6px; min-height: 6px; }
scrollbar slider:hover { background: #4c2f7a; }
dropdown > button {
    background-color: #14102a;
    border: 1px solid #241d38;
    border-radius: 9px;
    color: #ece7f7;
}
spinbutton {
    background-color: #14102a;
    border: 1px solid #241d38;
    border-radius: 9px;
    color: #ece7f7;
}
popover > contents {
    background-color: #16112a;
    border: 1px solid #2c2444;
    border-radius: 12px;
}

"""


def load_css() -> None:
    """Compatible across GTK4 4.10+ (load_from_string) and older (load_from_data)."""
    css = Gtk.CssProvider()
    if hasattr(css, "load_from_string"):
        css.load_from_string(CSS)
    else:
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
        # Newlines INSIDE the text would split the input into multiple
        # responses to athena's prompts — collapse them to spaces.
        clean = text.replace("\n", " ").replace("\r", " ")
        self.write(clean + "\n")

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

        mark = Gtk.Label(label="◈  ATHENA  ·  v" + VERSION, xalign=0)
        mark.add_css_class("welcome-mark")
        card.append(mark)

        t = Gtk.Label(label="Offensive security, on tap", xalign=0)
        t.add_css_class("welcome-title")
        card.append(t)

        s = Gtk.Label(
            label="Give me a target and an objective.  I'll pick the "
                  "specialist, plan the path, and run every command through "
                  "your y/n gate — explaining each move as we go.",
            xalign=0)
        s.set_wrap(True)
        s.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        s.add_css_class("welcome-sub")
        card.append(s)

        chips = Gtk.FlowBox()
        chips.set_selection_mode(Gtk.SelectionMode.NONE)
        chips.set_column_spacing(6)
        chips.set_row_spacing(6)
        chips.set_max_children_per_line(4)
        chips.add_css_class("welcome-chips")
        for name in ("RECON", "WEB / API", "EXPLOITATION", "ACTIVE DIRECTORY",
                     "PRIVESC", "REPORTING"):
            c = Gtk.Label(label=name)
            c.add_css_class("chip")
            chips.append(c)
        card.append(chips)

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
    """Command card with confidence pill, ATT&CK tag, and tap buttons."""

    def __init__(self, body: str, *, on_decision: Callable[[str], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._on_decision = on_decision
        self._answered = False

        card = _card("⚡ Proposed command", "command")
        conf, attack, cmd_text = self._extract_meta(body)
        self._cmd_text = cmd_text

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
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        meta.append(spacer)
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.add_css_class("icon-btn")
        copy_btn.set_tooltip_text("Copy command")
        copy_btn.connect("clicked", lambda _b: self._copy_command())
        meta.append(copy_btn)
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

    @property
    def command(self) -> str:
        return self._cmd_text

    def _copy_command(self) -> None:
        try:
            Gdk.Display.get_default().get_clipboard().set(self._cmd_text)
        except Exception:
            return
        root = self.get_root()
        if root is not None and hasattr(root, "toast"):
            try:
                root.toast("Command copied")
            except Exception:
                pass

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


class ManualPlaybookCard(Gtk.Box):
    """Renders Athena's [MANUAL] panel body as numbered cards.  Zero Groq
    cost — the steps already came from her response."""

    def __init__(self, body: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card = _card("🛠 Manual playbook — your turn", "manual")
        steps = self._split_steps(body)
        for step in steps:
            row = Gtk.Label(label=step, xalign=0)
            row.add_css_class("manual-step")
            row.set_wrap(True)
            row.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            row.set_selectable(True)
            card.append(row)
        self.append(card)

    def _split_steps(self, text: str) -> List[str]:
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
    if "MANUAL" in t and ("PLAYBOOK" in t or "MANUAL" == t.strip()): return "manual"
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

    def clear(self) -> None:
        c = self._inner.get_first_child()
        while c is not None:
            nxt = c.get_next_sibling()
            self._inner.remove(c)
            c = nxt
        self._latest_command = None

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
        elif kind == "manual":
            self.append(ManualPlaybookCard(body))
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
# INPUT BAR — always enabled, dedicated rescue button
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

        rescue_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        rescue_row.add_css_class("rescue-row")
        rescue_row.set_halign(Gtk.Align.START)
        rescue_btn = Gtk.Button(label="🛟 I'm stuck — ask Athena for manual steps")
        rescue_btn.add_css_class("rescue-btn")
        rescue_btn.connect("clicked", lambda _b: self._on_rescue())
        rescue_row.append(rescue_btn)
        self.append(rescue_row)

        self.set_mode("text")

    def set_mode(self, mode: str) -> None:
        """Hints only — input itself is ALWAYS enabled."""
        if mode == "password":
            self._hint.set_label("PASSWORD REQUIRED")
            self._entry.set_visibility(False)
            self._entry.set_placeholder_text("(hidden)")
            self._entry.grab_focus()
        elif mode == "ynq":
            self._hint.set_label("TAP A BUTTON ABOVE — RUN · SKIP · QUIT")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("or type free text…")
        else:
            self._hint.set_label("Tell Athena what you want…")
            self._entry.set_visibility(True)
            self._entry.set_placeholder_text("type here, or use buttons above…")
        self._entry.set_sensitive(True)
        self._send_btn.set_sensitive(True)

    def _send(self) -> None:
        text = self._entry.get_text()
        self._entry.set_text("")
        if text.strip():
            self._on_send_text(text)


# ═════════════════════════════════════════════════════════════════════
# ENGAGEMENT WIZARD — defensive dialog construction
# ═════════════════════════════════════════════════════════════════════

class EngagementWizard:
    """Single-form: target IP, domain, notes, goal.  Sends them as
    sequential inputs to athena.py's startup prompts."""

    def __init__(self, parent: Gtk.Window,
                 on_done: Callable[[Dict[str, str]], None],
                 on_cancel: Callable[[], None]):
        self._parent = parent
        self._on_done = on_done
        self._on_cancel = on_cancel
        self._last = Config.get("last_target") or {}

        self._ip = Gtk.Entry();    self._ip.add_css_class("wizard-entry")
        self._dom = Gtk.Entry();   self._dom.add_css_class("wizard-entry")
        self._notes = Gtk.Entry(); self._notes.add_css_class("wizard-entry")
        self._goal = Gtk.Entry();  self._goal.add_css_class("wizard-entry")

        self._ip.set_text(self._last.get("ip", ""))
        self._dom.set_text(self._last.get("domain", ""))
        self._notes.set_text(self._last.get("notes", ""))
        self._goal.set_text(
            self._last.get("goal") or
            "Enumerate services, find low-hanging vulns, get a foothold."
        )

        self._ip.set_placeholder_text("10.10.10.5  or  192.168.1.0/24")
        self._dom.set_placeholder_text("example.com  or  https://app.target.tld")
        self._notes.set_placeholder_text("HTB box · CTF · client X · …")
        self._goal.set_placeholder_text(
            "what do you want Athena to do with this target?")

        self._build_and_present()

    def _build_and_present(self) -> None:
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        body.set_size_request(360, -1)

        sub = Gtk.Label(
            label="Set the target and your objective.  Athena plans from there.",
            xalign=0)
        sub.set_wrap(True); sub.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        sub.add_css_class("wizard-sub")
        body.append(sub)

        def add_field(label_text: str, widget: Gtk.Widget):
            l = Gtk.Label(label=label_text, xalign=0)
            l.add_css_class("wizard-label")
            body.append(l)
            body.append(widget)

        add_field("TARGET IP / CIDR",                 self._ip)
        add_field("DOMAIN / URL  (optional)",         self._dom)
        add_field("NOTES  (HTB, CTF, client tag…)",   self._notes)
        add_field("WHAT DO YOU WANT FROM THIS TARGET?", self._goal)

        # Use Adw.AlertDialog if available (1.5+), else MessageDialog
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
        # Strip newlines from goal so it doesn't break athena's input pipe
        goal = self._goal.get_text().strip().replace("\n", " ").replace("\r", " ")
        values = {
            "ip":     self._ip.get_text().strip(),
            "domain": self._dom.get_text().strip(),
            "notes":  self._notes.get_text().strip(),
            "goal":   goal,
        }
        Config.set("last_target", values)
        self._on_done(values)


# ═════════════════════════════════════════════════════════════════════
# SETTINGS DIALOG  (v7.8) — providers, keys, live models, feature toggles
# ═════════════════════════════════════════════════════════════════════

class SettingsDialog:
    """Native control panel.  Writes the SAME ~/.athena/settings.json the CLI
    reads, exports keys into the environment before Athena is (re)spawned, and
    lists each provider's LIVE model catalogue on demand."""

    def __init__(self, parent: Gtk.Window, on_saved: Callable[[], None]):
        self._parent = parent
        self._on_saved = on_saved
        self._settings = load_settings()
        self._rows = provider_rows()
        self._entries: Dict[str, Gtk.PasswordEntry] = {}
        self._notes: Dict[str, Gtk.Label] = {}
        self._live: Dict[str, List[str]] = {}
        self._toggles: Dict[str, Gtk.Switch] = {}
        self._build_and_present()

    # ── construction ──────────────────────────────────────────────
    def _build_and_present(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(500)
        scroll.set_size_request(400, 540)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(8)
        scroll.set_child(box)

        t = Gtk.Label(label="Providers & models", xalign=0)
        t.add_css_class("sheet-title")
        s = Gtk.Label(
            label="Paste a key for any provider (all free tiers welcome).  "
                  "Keys are saved to ~/.athena/settings.json (chmod 600) and "
                  "exported to Athena on launch.",
            xalign=0)
        s.set_wrap(True); s.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        s.add_css_class("sheet-sub")
        box.append(t); box.append(s)

        keys = self._settings.get("provider_keys") or {}
        for row in self._rows:
            p = row["provider"]
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            card.add_css_class("provider-row")

            head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            name = Gtk.Label(label=row["label"], xalign=0)
            name.add_css_class("provider-name"); name.set_hexpand(True)
            head.append(name)
            note = Gtk.Label(label=""); note.add_css_class("model-count")
            self._notes[p] = note
            head.append(note)
            if row["free"]:
                fb = Gtk.Label(label="FREE"); fb.add_css_class("badge-free")
                head.append(fb)
            card.append(head)

            entry = Gtk.PasswordEntry()
            entry.set_show_peek_icon(True)
            entry.set_hexpand(True)
            entry.add_css_class("wizard-entry")
            entry.set_tooltip_text("paste API key")
            env = row.get("env") or ""
            entry.set_text(keys.get(p, "") or (os.environ.get(env, "") if env else ""))
            self._entries[p] = entry
            card.append(entry)

            brow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            rbtn = Gtk.Button(label="List live models")
            rbtn.connect("clicked", lambda _b, pp=p: self._refresh(pp))
            brow.append(rbtn)
            card.append(brow)
            box.append(card)

        # ── active model ──
        rule = Gtk.Box(); rule.add_css_class("section-rule"); box.append(rule)
        al = Gtk.Label(label="ACTIVE MODEL  (leave on auto for best available)",
                       xalign=0); al.add_css_class("field-label")
        box.append(al)
        self._active_dd = Gtk.DropDown.new_from_strings(["(auto)"])
        box.append(self._active_dd)

        # ── generation ──
        rule2 = Gtk.Box(); rule2.add_css_class("section-rule"); box.append(rule2)
        gl = Gtk.Label(label="GENERATION", xalign=0); gl.add_css_class("field-label")
        box.append(gl)

        grow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        grow.append(Gtk.Label(label="Temperature", xalign=0))
        self._temp = Gtk.SpinButton.new_with_range(0.0, 2.0, 0.05)
        self._temp.set_value(float(self._settings.get("temperature", 0.2)))
        self._temp.set_hexpand(True)
        grow.append(self._temp)
        box.append(grow)

        grow2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        grow2.append(Gtk.Label(label="Max tokens", xalign=0))
        self._max = Gtk.SpinButton.new_with_range(256, 32768, 256)
        self._max.set_value(float(self._settings.get("max_tokens", 4096)))
        self._max.set_hexpand(True)
        grow2.append(self._max)
        box.append(grow2)

        # ── opt-in engines ──
        rule3 = Gtk.Box(); rule3.add_css_class("section-rule"); box.append(rule3)
        ol = Gtk.Label(label="OPT-IN ENGINES  (sensitive — off by default)",
                       xalign=0); ol.add_css_class("field-label")
        box.append(ol)
        for feat, title, sub in (
            ("skills_enabled", "Skills (sandboxed code)",
             "Let Athena write & run helper scripts in the bubblewrap sandbox."),
            ("mcp_enabled", "MCP servers",
             "Connect stdio MCP servers from ~/.athena/mcp.json."),
            ("reach_enabled", "Reach (semantic web/GitHub)",
             "External search surface; output is webshield-sanitised."),
        ):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row.add_css_class("toggle-row")
            txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            txt.set_hexpand(True)
            tt = Gtk.Label(label=title, xalign=0); tt.add_css_class("toggle-title")
            st = Gtk.Label(label=sub, xalign=0); st.add_css_class("toggle-sub")
            st.set_wrap(True); st.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            txt.append(tt); txt.append(st)
            row.append(txt)
            sw = Gtk.Switch()
            sw.set_active(bool(self._settings.get(feat, False)))
            sw.set_valign(Gtk.Align.CENTER)
            self._toggles[feat] = sw
            row.append(sw)
            box.append(row)

        # ── present ──
        if hasattr(Adw, "AlertDialog"):
            dlg = Adw.AlertDialog.new("Settings", "")
            dlg.set_extra_child(scroll)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("save", "Save")
            dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
            dlg.set_default_response("save")
            try:
                dlg.set_content_width(420)
            except Exception:
                pass
            dlg.connect("response", self._on_response)
            dlg.present(self._parent)
            self._dlg = dlg
        else:
            dlg = Adw.MessageDialog.new(self._parent, "Settings", "")
            dlg.set_extra_child(scroll)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("save", "Save")
            dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
            dlg.set_default_response("save")
            dlg.connect("response", self._on_response)
            dlg.present()
            self._dlg = dlg

    # ── live model listing ────────────────────────────────────────
    def _refresh(self, provider: str) -> None:
        mod = load_providers_module()
        if mod is None:
            self._notes[provider].set_label("providers module missing")
            return
        key = self._entries[provider].get_text().strip()
        self._settings.setdefault("provider_keys", {})[provider] = key
        env = next((r.get("env") for r in self._rows
                    if r["provider"] == provider), "")
        if env and key:
            os.environ[env] = key
        self._notes[provider].set_label("loading…")

        def work():
            try:
                got = mod.list_models(provider, timeout=8, use_cache=False,
                                      settings=self._settings)
                models = got.get("models") or []
                err = got.get("error", "")
            except Exception as e:  # noqa: BLE001
                models, err = [], f"{type(e).__name__}: {e}"
            GLib.idle_add(self._apply_models, provider, models, err)
        threading.Thread(target=work, daemon=True).start()

    def _apply_models(self, provider: str, models: List[str], err: str) -> bool:
        if models:
            self._live[provider] = models
            self._notes[provider].set_label(f"{len(models)} live")
            self._rebuild_active_dd()
        else:
            self._notes[provider].set_label(
                ("no models" if not err else err[:40]))
        return False

    def _rebuild_active_dd(self) -> None:
        opts = ["(auto)"]
        for p, models in self._live.items():
            for m in models[:25]:
                opts.append(f"{p}/{m}")
        self._active_dd.set_model(Gtk.StringList.new(opts))
        cur = str(self._settings.get("active_model") or "")
        for i, o in enumerate(opts):
            if o == cur:
                self._active_dd.set_selected(i)
                break

    # ── save ──────────────────────────────────────────────────────
    def _on_response(self, _dlg, response: str) -> None:
        if response != "save":
            return
        keys = dict(self._settings.get("provider_keys") or {})
        enabled = dict(self._settings.get("provider_enabled") or {})
        for row in self._rows:
            p = row["provider"]
            val = self._entries[p].get_text().strip()
            if val:
                keys[p] = val
                env = row.get("env") or ""
                if env:
                    os.environ[env] = val
            # Keyed providers: a saved key means enabled. Keyless/local
            # providers (Ollama) are left to auto-detection, not forced off.
            if row.get("env"):
                enabled[p] = bool(val)
            else:
                enabled.pop(p, None)
        self._settings["provider_keys"] = keys
        self._settings["provider_enabled"] = enabled
        for feat, sw in self._toggles.items():
            self._settings[feat] = bool(sw.get_active())
        self._settings["temperature"] = round(self._temp.get_value(), 2)
        self._settings["max_tokens"] = int(self._max.get_value())
        sel = self._active_dd.get_selected_item()
        sel_txt = sel.get_string() if sel is not None else "(auto)"
        self._settings["active_model"] = "" if sel_txt == "(auto)" else sel_txt
        save_settings(self._settings)
        if self._on_saved:
            self._on_saved()


# ═════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═════════════════════════════════════════════════════════════════════

class AthenaWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application):
        super().__init__(application=application)
        self.set_title("Athena")
        self.set_default_size(460, 880)
        self.set_size_request(360, 560)

        cfg = Config.load()
        key = cfg.get("groq_api_key", "")
        if key and not os.environ.get("GROQ_API_KEY"):
            os.environ["GROQ_API_KEY"] = key
        # v7.8 — export every provider key from the shared settings file so a
        # key saved in the GUI (or by the CLI) reaches the spawned agent.
        try:
            _s = load_settings()
            _envs = {r["provider"]: r.get("env") for r in provider_rows()}
            for _p, _k in (_s.get("provider_keys") or {}).items():
                _env = _envs.get(_p) or ""
                if _env and _k and not os.environ.get(_env):
                    os.environ[_env] = str(_k)
        except Exception:
            pass

        self._process: Optional[AthenaProcess] = None
        self._pending_inputs: List[str] = []
        self._wizard_open = False
        self._target_pill: Optional[Gtk.Label] = None
        self._agent_pill: Optional[Gtk.Label] = None
        self._activity_dot: Optional[Gtk.Box] = None
        self._sidebar_entries: List[Any] = []

        self.split = Adw.OverlaySplitView()
        self.split.set_collapsed(True)
        self.split.set_show_sidebar(False)
        self.split.set_max_sidebar_width(292)
        self.split.set_sidebar_width_fraction(0.72)
        self.split.set_sidebar(self._build_sidebar())

        self.toast_overlay = Adw.ToastOverlay()
        self.toast_overlay.set_child(self.split)
        self.set_content(self.toast_overlay)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(self._build_header())

        self._conversation = ConversationView(on_decision=self._on_decision)
        self._input = InputBar(on_send_text=self._on_send_text,
                               on_rescue=self._on_rescue)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        body.append(self._conversation)
        toolbar.set_content(body)
        toolbar.add_bottom_bar(self._input)
        self.split.set_content(toolbar)

        self._install_actions()

        self._conversation.append(WelcomeCard(on_start=self._open_wizard))
        GLib.idle_add(self._initial_check)

    def _initial_check(self) -> bool:
        if not os.environ.get("GROQ_API_KEY"):
            self._show_api_key_dialog(then_open_wizard=True)
            return False
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
        # athena.py asks for: IP, Domain, Notes (set_target), then the
        # priest prompt accepts free text.  Queue all four in order.
        self._pending_inputs = [
            values.get("ip", ""),
            values.get("domain", ""),
            values.get("notes", ""),
            values.get("goal", ""),
        ]
        self._conversation.clear()
        tag = values.get("ip") or values.get("domain") or "?"
        self._conversation.append(PlainCard(f"── New Engagement ──  target: {tag}"))
        self._start_athena()

    def _on_wizard_cancel(self) -> None:
        self._wizard_open = False

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
        t = ev.get("type")
        if t == "status":
            self._update_status_pills(ev["text"])
            return

        # Auto-feed startup prompts from the wizard
        if t == "prompt_text" and self._pending_inputs:
            text = self._pending_inputs.pop(0)
            self._process.writeln(text)
            self._input.set_mode("text")
            return

        # Status-dot activity
        if t == "panel":
            kind = classify_panel_title(ev.get("title", ""))
            if kind == "thought":
                self._set_activity("thinking")
            elif kind in ("executing", "dispatch"):
                self._set_activity("executing")
            elif kind == "command":
                self._set_activity("await")
            elif kind == "error":
                self._set_activity("idle")
        elif t == "prompt_ynq":
            self._set_activity("await")
        elif t in ("prompt_text", "prompt_password"):
            self._set_activity("idle")
        elif t == "fatal":
            self._set_activity("idle")

        mode = self._conversation.handle_event(ev)
        if mode is not None:
            self._input.set_mode(mode)

    def _on_process_exited(self, _proc) -> None:
        self._set_activity("idle")
        self._conversation.append(PlainCard("── session ended — tap ↻ to start again ──"))

    def _update_status_pills(self, text: str) -> None:
        parts = [p.strip() for p in re.split(r"│", text)]
        if len(parts) >= 2 and self._target_pill and self._agent_pill:
            self._target_pill.set_label(parts[0] or "no target")
            self._agent_pill.set_label(parts[1] or "·")

    def toast(self, message: str) -> None:
        """Transient feedback in the corner — never blocks the feed."""
        try:
            self.toast_overlay.add_toast(Adw.Toast.new(message))
        except Exception:
            pass

    def _set_activity(self, state: str) -> None:
        """Drive the header status dot: idle · thinking · executing · await."""
        if self._activity_dot is None:
            return
        for c in ("st-idle", "st-thinking", "st-executing", "st-await", "st-done"):
            self._activity_dot.remove_css_class(c)
        self._activity_dot.add_css_class("st-" + state)

    def _on_send_text(self, text: str) -> None:
        if self._process is None:
            self._pending_inputs.append(text)
            self._start_athena()
            return
        self._set_activity("thinking")
        self._process.writeln(text)

    def _on_decision(self, value: str) -> None:
        if self._process is None:
            return
        if value == "y":
            self._set_activity("executing")
        elif value == "n":
            self._set_activity("thinking")
        else:
            self._set_activity("idle")
        self._process.writeln(value)

    def _on_rescue(self) -> None:
        """Stuck button: just tell Athena. Her mentor persona handles it
        by emitting a [MANUAL] block instead of a [CMD]."""
        if self._process is None:
            return
        self._process.writeln(
            "stuck — give me manual next steps i should try by hand"
        )

    # ── header ─────────────────────────────────────────────────

    def _build_header(self) -> Adw.HeaderBar:
        header = Adw.HeaderBar()
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        title_box.set_valign(Gtk.Align.CENTER)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row.set_halign(Gtk.Align.CENTER)
        self._activity_dot = Gtk.Box()
        self._activity_dot.add_css_class("status-dot")
        self._activity_dot.add_css_class("st-idle")
        self._activity_dot.set_valign(Gtk.Align.CENTER)
        row.append(self._activity_dot)
        t1 = Gtk.Label(label="ATHENA")
        t1.add_css_class("app-title")
        row.append(t1)
        ver = Gtk.Label(label="v" + VERSION)
        ver.add_css_class("version-pill")
        ver.set_valign(Gtk.Align.CENTER)
        row.append(ver)
        title_box.append(row)

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

        sidebar_btn = Gtk.Button.new_from_icon_name("view-list-symbolic")
        sidebar_btn.set_tooltip_text("Commands")
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
        menu.append("New engagement", "win.new-engagement")
        menu.append("Restart session", "win.restart")
        menu.append("Settings…", "win.settings")
        menu.append("API key…", "win.api-key")
        menu.append("Open logs folder", "win.open-logs")
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
        box.set_margin_top(2)
        box.set_margin_bottom(16)

        brand = Gtk.Label(label="◈  ATHENA", xalign=0)
        brand.add_css_class("sidebar-brand")
        box.append(brand)

        self._sidebar_search = Gtk.SearchEntry()
        self._sidebar_search.add_css_class("sidebar-search")
        self._sidebar_search.set_placeholder_text("Filter commands…")
        self._sidebar_search.connect("search-changed", self._filter_sidebar)
        box.append(self._sidebar_search)

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
                ("🔌", "Providers",    "model providers"),
                ("🧠", "Engines",      "engines"),
                ("⚙", "Settings",     "settings"),
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
            group = []
            for icon, label, cmd in items:
                btn = self._sidebar_button(icon, label, cmd)
                group.append(btn)
                box.append(btn)
            self._sidebar_entries.append((h, group))

        scroll.set_child(box)
        page.set_child(scroll)
        return page

    def _filter_sidebar(self, entry: Gtk.SearchEntry) -> None:
        q = entry.get_text().strip().lower()
        for header, buttons in self._sidebar_entries:
            any_visible = False
            for btn in buttons:
                visible = (not q) or (q in getattr(btn, "_search_text", ""))
                btn.set_visible(visible)
                any_visible = any_visible or visible
            header.set_visible(any_visible)

    def _sidebar_button(self, icon: str, label: str, cmd: str) -> Gtk.Button:
        b = Gtk.Button()
        b.add_css_class("flat")
        b.add_css_class("sidebar-button")
        b._search_text = f"{icon} {label} {cmd}".lower()
        inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        ic = Gtk.Label(label=icon)
        ic.add_css_class("sidebar-icon")
        inner.append(ic)
        l = Gtk.Label(label=label, xalign=0)
        l.set_hexpand(True)
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
            launcher = Gtk.UriLauncher.new(GLib.filename_to_uri(LOG_DIR))
            launcher.launch(self, None, None)
        except Exception:
            subprocess.Popen(["xdg-open", LOG_DIR],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _action_api_key(self, *_):
        self._show_api_key_dialog(then_open_wizard=False)

    def _action_settings(self, *_):
        SettingsDialog(parent=self, on_saved=self._on_settings_saved)

    def _on_settings_saved(self):
        self._conversation.append(PlainCard(
            "── Settings saved — tap ↻ (Restart session) to apply to the "
            "running agent ──"))
        self.toast("Settings saved")

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
        wrap.set_size_request(340, -1)
        info = Gtk.Label(
            label="Get a free key at console.groq.com.  Saved to "
                  "~/.athena/config.json (chmod 600).",
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
