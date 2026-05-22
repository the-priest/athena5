# Athena — AI Offensive Security Agent

**v7.3** · Bare-metal Kali NetHunter · Commander: The Priest

Athena is an AI-driven pentesting copilot. You give it a target and an
objective, it picks the right specialist agent, picks the right tool,
and runs commands one at a time through a `y/n` confirmation gate. Every
finding is regex-extracted from real subprocess output (no AI
hallucinations), tagged with MITRE ATT&CK, and tracked in a Pentesting
Task Tree (PTT) plus a networkx-backed attack graph.

---

## One-command install

```
curl -fsSL https://raw.githubusercontent.com/the-priest/athena5/main/bootstrap.sh | bash
```

Clones the repo to `~/athena5`, runs `install.sh`, installs system packages
(GTK4 · libadwaita · VTE · python3-gi), pip deps (groq · networkx), drops a
desktop entry and icon, and links both `athena` (CLI) and `athena-gui` into
`/usr/local/bin`.

Re-runnable: re-running pulls the latest commit and re-installs without
touching your API key or scope.

### Flags

```
bash install.sh             # full install (GUI + CLI)
```
```
bash install.sh --cli-only  # skip GTK/VTE, terminal only
```
```
bash install.sh --gui-only  # skip CLI link
```

### Manual install

```
git clone https://github.com/the-priest/athena5.git
```
```
cd athena5
```
```
bash install.sh
```

---

## Launching

**GUI (Phosh / GNOME / anything libadwaita):**
```
athena-gui
```

**CLI (just the REPL):**
```
athena
```

First launch prompts for your Groq API key (free — console.groq.com) and
writes it to `~/.bashrc` and `~/.zshrc`.

---

## What's in v7.3 — Token savings + bug fixes

### Token savings (~1200 tokens saved per turn after turn 2)

The main complaint with v7.2 was burning through the free Groq tier too fast.
The system prompt was sending ~2800 chars of tool registry + Kali arsenal
**every single turn**, even after the model had already seen them.

**What changed:**
- `kali_tool_summary_for_prompt()` + `tool_registry_for_prompt()` (~2800 chars
  combined) now only sent on **turns 1–2**. After that the model has the tool
  set in context. Use `[NEED]tools[/NEED]` if you need it back.
- KB sections capped at **4 per turn** (was 5 for the recon agent). Section 14
  removed from most role defaults — it's generic and duplicates other KB content.
- `MENTOR_PERSONA` trimmed: removed the verbose voice/slang examples block (~400
  chars). Teaching duty is intact.
- `EXPANDED_HISTORY_SLICE` reduced from 8 → 6 turns. Stops the context blowup
  when Athena gets stuck.
- `CORE_RULES` tightened: removed 2 duplicate tool format examples.

### Bug fixes

- **Provider chain:** `openai/gpt-oss-20b`, `openai/gpt-oss-120b`, and
  `allam-2-7b` were 404-ing on every session and burning retries. Removed.
  `groq/compound` / `groq/compound-mini` renamed to their correct API names
  (`compound-beta` / `compound-beta-mini`). Added `gemma2-9b-it` and
  `deepseek-r1-distill-llama-70b` as solid verified fallbacks.
- **Instance variables:** `_sudo_password` and `_sudo_skip_session` were
  class-level attributes (shared state across session resets). Moved to
  `__init__`. Also properly initialized `_turn_no`, `_prompt_turn`,
  `_pending_dispatch_error`, `_pending_dispatch_error_to_prompt`,
  `_no_cmd_retries` — no more `getattr` hacks scattered through the codebase.
- **Output compression:** Added noise filters for hydra banners, nmap progress
  lines, and bare comment lines. Head/tail split tightened to 650+500 chars
  (was 800+600).

### Carried from v7.2

Pentesting Task Tree · 11 specialist agents · 28 typed tool builders ·
200+ Kali tool registry · MITRE ATT&CK auto-tagging · scope / RoE
enforcement · networkx attack graph · smart context manager with
`[NEED]` re-fetches · auto credential fanout · source-tagged finding
extraction · Groq fallback chain · per-command timeouts · sudo escalation ·
loop breaker · failure-aware confidence · `y/n/q` confirmation gate ·
native GTK4 / libadwaita GUI shell.

---

## Files installed

```
/opt/athena5/
  ├── athena.py            # the agent REPL
  ├── athena_gui.py        # GTK4 shell
  ├── athena-gui           # launcher script
  └── requirements.txt
/usr/local/bin/athena      # → athena.py
/usr/local/bin/athena-gui  # → athena-gui
~/.local/share/applications/io.thepriest.Athena.desktop
~/.local/share/icons/hicolor/scalable/apps/io.thepriest.Athena.svg
~/.athena/logs/            # per-session logs + reports
~/.athena/scope.json       # engagement scope (if set)
```

---

## REPL commands

| Command    | What it does |
|------------|--------------|
| `workflow` | 23 pre-built engagement templates |
| `target`   | Set or update the engagement target |
| `findings` | Show every extracted finding (verified + unverified) |
| `tree`     | Render the Pentesting Task Tree |
| `graph`    | Show the attack graph + pivot suggestions |
| `scope`    | Show / toggle engagement scope (RoE) |
| `mitre`    | MITRE ATT&CK techniques used this session |
| `tools`    | Tool availability + auto-install missing |
| `model`    | Provider chain status |
| `agent`    | List all specialist agents |
| `dashboard`| Concise session status panel |
| `save`     | Save conversation to file |
| `report`   | Generate the engagement report now |
| `clear`    | Clear AI memory (PTT preserved) |
| `reset`    | Full reset (PTT + findings + history + sudo cache) |
| `help`     | Help menu |
| `exit` / `q` | End session and generate report |

Or just type any objective in plain English — Athena routes to the right specialist.

---

## Groq API key

Free tier at [console.groq.com](https://console.groq.com). No card required.

```
export GROQ_API_KEY='gsk_...'
```

Add to `~/.bashrc` to persist. The installer does this automatically.

---

## Tested on

- Kali NetHunter Pro · OnePlus 6 · Phosh (primary target)
- Kali Linux x86_64
- Debian Bookworm / Trixie

Requires Python ≥ 3.10. GUI needs `python3-gi`, `gir1.2-gtk-4.0`,
`gir1.2-adw-1` (install.sh handles it).

---

## Safety

Athena refuses: `apt upgrade` variants, destructive commands (`rm -rf /`,
`dd if=`, `mkfs`, fork bombs, shutdown), interactive shells without proper
flags, out-of-scope targets when scope is enabled. Every other command goes
through the `y/n/q` gate. System-modifying commands get a second confirmation.
Sudo is opt-in, prompted once via `getpass`, cached only in RAM.

---

## License

Personal project by The Priest. Use on systems you own or have explicit
written authorisation to test.
