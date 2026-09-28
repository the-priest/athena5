# Wiring basilisk_ext into Basilisk

Two ways. Pick one. Read both first.

The sidecar's **hook modules** — the ones core calls into (`headroom`,
`verify`, `pentest`, `memory`, `skills`, `sandbox`, `foresight`) — depend only
on stdlib + two callables you inject, and import nothing from `basilisk.py` /
`basilisk_core.py` / `basilisk_persona.py`. That one-way dependency is what keeps the
sidecar optional and null-safe: core lazily imports these at call time, so a
missing or broken sidecar can never break startup, and the whole thing deletes
cleanly. (The sole exception is `worker.py`, the standalone `systemd --user`
background **entry point** — it runs as its own process, *off* the core→ext
call path, and may `import basilisk_core` to do headless jobs. It never imports back
into the UI.)

---

## Option A — minimal hooks (recommended)

Six additive lines across `basilisk.py`, each guarded so deleting the `basilisk_ext/`
folder reverts Basilisk to exactly today's behaviour. This is the maintainable
choice: explicit seams beat monkeypatch magic.

### 1. Boot — once, at the end of `MainWindow.__init__`

```python
try:
    from basilisk_ext import extman
    extman.init(
        settings=self.settings,
        data_dir="~/.local/share/basilisk",
        complete_fn=self._ext_complete,
        embed_fn=None,                      # wire later if you add embeddings
    )
    self._ext = extman
except Exception:
    self._ext = None
```

### 2. The injected completer — add this method to `MainWindow`

A short, synchronous, non-streaming completion using your existing router.
Used for memory consolidation and the optional foresight model pass. It is
allowed to fail; the sidecar tolerates it.

```python
def _ext_complete(self, system: str, user: str) -> str:
    backend, model = self.router.pick()
    if not backend:
        return ""
    out = {"txt": ""}
    done = threading.Event()
    msgs = [{"role": "system", "content": system},
            {"role": "user", "content": user}]
    backend.stream_chat(
        model, msgs,
        on_token=lambda t: out.__setitem__("txt", out["txt"] + t),
        on_done=lambda meta: done.set(),
        on_error=lambda e: done.set(),
        cancel=threading.Event(),
    )
    done.wait(timeout=30)
    return out["txt"]
```

### 3. System-prompt block — in `_kick_assistant_turn`, where you build `sysprompt`

Append the sidecar's tool docs through the addendum you already support.
No edit to `basilisk_persona.py`.

```python
addendum = self.settings.get("system_prompt", "")
if getattr(self, "_ext", None):
    addendum = (addendum + "\n\n" + self._ext.system_prompt_block()).strip()
sysprompt = build_system_prompt(
    agent_mode=self.current_agent_mode,
    custom_addendum=addendum)
```

### 4. Memory recall — in `_kick_assistant_turn`, right after `full = assemble_messages(...)`

```python
if getattr(self, "_ext", None):
    full = self._ext.inject_memory(full)
```

### 5. Turn recorder — in `_on_stream_done`, after `self.store.update_message(...)`

```python
if getattr(self, "_ext", None):
    user_text = self._last_user_text_for(chat_id="" )  # your last user msg
    threading.Thread(
        target=self._ext.record_turn,
        args=(user_text, final),
        daemon=True).start()
```

(You already have the final assistant text as `final`; grab the matching user
turn however is cleanest in your store — a `list_messages` tail works.)

### 6. Extra tools — in `_execute_tool_calls`, after the `dispatch = {...}` literal

```python
if getattr(self, "_ext", None):
    dispatch.update(self._ext.extra_tools(self))
```

### Foresight on actions — in `_execute_command`, before you run

Enrich the gate. A `block` should refuse even in auto-mode and require an
explicit operator override; a `caution` should force the confirm dialog even
when "Confirm every command" is off.

```python
if getattr(self, "_ext", None):
    v = self._ext.foresight(command)
    if v.get("verdict") == "block":
        from basilisk_ext.foresight import render_card
        self._feed_tool_result("REFUSED by foresight:\n" + render_card(v))
        return
    if v.get("verdict") == "caution":
        # force confirmation regardless of the auto toggle, and show the card
        ...
```

### Skill Apply handler — reuse your propose_edit card path

When the operator clicks Apply on a `skill_write` card, call:

```python
res = self._ext.commit_skill(name, code, test, description, capabilities)
```

The `skill_write` tool returns a payload containing `_code` and `_test`; carry
those onto the card so the Apply handler has them.

---

## Option B — zero core edits (monkeypatch launcher)

If you want `basilisk.py` literally untouched, launch through a shim that imports
Basilisk, wraps the same methods at runtime, then runs. Trade-off: it binds to
private method names, so it can break on a refactor. Option A won't.

Create `basilisk_boot.py` next to `basilisk.py`:

```python
import threading, basilisk
from basilisk_ext import extman

_orig_init = basilisk.MainWindow.__init__
def _init(self, app):
    _orig_init(self, app)
    extman.init(settings=self.settings,
                complete_fn=lambda s, u: "",   # wire _ext_complete here
                embed_fn=None)
    self._ext = extman
basilisk.MainWindow.__init__ = _init

_orig_kick = basilisk.MainWindow._kick_assistant_turn
# ... wrap _kick_assistant_turn / _on_stream_done / _execute_tool_calls
#     the same way, calling the extman hooks. (Left as an exercise; Option A
#     is genuinely the cleaner path.)

basilisk.main() if hasattr(basilisk, "main") else basilisk.BasiliskApp().run(None)
```

---

## Settings flags (all default OFF — opt in per feature)

Add to your `DEFAULT_SETTINGS` (or just set them in `settings.json`):

```python
"memory_enabled":      False,
"memory_recall_k":     6,
"memory_consolidate":  False,   # model-based extraction; needs a completer
"skills_enabled":      False,
"foresight_enabled":   False,
"foresight_model":     False,   # model pass on top of the rule floor
"worker_interval_seconds": 300,
```

---

## Install the sidecar

Drop the folder next to your other files:

```
cp -r basilisk_ext ~/.local/share/basilisk/basilisk_ext
```

Add the install dir to the path Basilisk runs under (your launcher already runs
from `~/.local/share/basilisk`, so `from basilisk_ext import extman` resolves).

Sandbox: install bubblewrap for real skill isolation.

```
sudo apt install bubblewrap
```

Daemon (optional): see `packaging/basilisk-ext.service`.

---

## Removal

```
rm -rf ~/.local/share/basilisk/basilisk_ext
```

Delete the six hook lines (or just stop importing — they're all guarded by
`getattr(self, "_ext", None)`, so a missing package no-ops every one). Disable
the user service if you enabled it. Basilisk is back to today's build.
