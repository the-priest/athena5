"""
settings — Athena's single, user-editable settings store.

One JSON file, ~/.athena/settings.json, that BOTH the CLI (athena.py) and the
GTK GUI read and write.  It is deliberately dependency-free and fail-soft: a
missing or corrupt file yields the defaults, never an exception.

Why a separate file from ~/.athena/config.json
----------------------------------------------
config.json predates this and holds the GUI's own bits (last_target, the groq
key it prompts for).  settings.json is the operator control panel: provider
keys, feature toggles, generation params.  We read a legacy groq key from
config.json as a fallback so an existing install keeps working, but we never
rewrite it.

Nothing here is secret-guarded beyond chmod 600 — it can hold API keys, so it
is written atomically and chmod'd like config.json already is.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

_HOME = Path(os.path.expanduser("~/.athena"))
PATH = _HOME / "settings.json"
_LEGACY = _HOME / "config.json"

# ── the control panel ─────────────────────────────────────────────────
# Every key is documented because the `settings` REPL command prints this.
DEFAULTS: Dict[str, Any] = {
    # provider keys, provider -> key.  Also honoured from the usual env vars.
    "provider_keys": {},
    # provider -> bool; absent means "auto" (enabled iff a key is present).
    "provider_enabled": {},
    # optional pinned fallback chain: [{"model": id, "provider": p, "name": n}]
    "model_chain": [],
    # preferred starting model as "provider/model-id" (empty = chain head)
    "active_model": "",
    # generation
    "temperature": 0.2,
    "max_tokens": 4096,
    # opt-in engines (the three the safety notes require OFF by default)
    "skills_enabled": False,
    "mcp_enabled": False,
    "reach_enabled": False,
    # UX
    "show_banner": True,
    "stream_thinking": True,
    "confirm_note": "Every command still requires an explicit y/n.",
    # provider discovery
    "discover_timeout": 6,
    "max_chain": 12,
}


def path() -> str:
    return str(PATH)


def load() -> Dict[str, Any]:
    """Return the merged settings dict (defaults <- file).  Never raises."""
    data: Dict[str, Any] = json.loads(json.dumps(DEFAULTS))  # deep copy
    try:
        if PATH.exists():
            raw = json.loads(PATH.read_text() or "{}")
            if isinstance(raw, dict):
                data.update(raw)
    except Exception:
        pass
    # legacy: lift a groq key out of the GUI's config.json if we have none
    try:
        pk = data.setdefault("provider_keys", {})
        if not pk.get("groq") and _LEGACY.exists():
            legacy = json.loads(_LEGACY.read_text() or "{}")
            if isinstance(legacy, dict) and legacy.get("groq_api_key"):
                pk["groq"] = str(legacy["groq_api_key"])
    except Exception:
        pass
    return data


def save(data: Dict[str, Any]) -> bool:
    """Atomically write settings, chmod 600.  Returns success."""
    try:
        _HOME.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(_HOME), prefix=".settings-", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, PATH)
        try:
            os.chmod(PATH, 0o600)
        except OSError:
            pass
        return True
    except Exception:
        return False


def get(key: str, default: Any = None) -> Any:
    return load().get(key, DEFAULTS.get(key, default))


def set(key: str, value: Any) -> bool:  # noqa: A001 - matches dict.set naming
    data = load()
    data[key] = value
    return save(data)


def update(values: Dict[str, Any]) -> bool:
    data = load()
    data.update(values or {})
    return save(data)


def describe() -> str:
    """Human-readable dump for the `settings` REPL command."""
    d = load()
    lines = [f"settings file: {PATH}", ""]
    for k in DEFAULTS:
        v = d.get(k)
        if k == "provider_keys":
            shown = {p: ("set" if k2 else "—") for p, k2 in (v or {}).items()}
            lines.append(f"  {k:<18} {shown or '(none)'}")
        else:
            lines.append(f"  {k:<18} {v!r}")
    return "\n".join(lines)