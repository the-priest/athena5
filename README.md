# Athena — AI Offensive Security Agent

**v7.3** · Bare-metal Kali NetHunter · Commander: The Priest

Athena is an AI-driven pentesting copilot. You give it a target and an
objective, it picks the right specialist agent, picks the right tool,
and runs commands one at a time through a `y/n` confirmation gate. Every
finding is regex-extracted from real subprocess output (no AI
hallucinations), tagged with MITRE ATT&CK, and tracked in a Pentesting
Task Tree (PTT) plus a networkx-backed attack graph.

v7.3 adds a **native GTK4 / libadwaita GUI shell** so Athena runs as a
proper Phosh app on bare-metal NetHunter — tap an icon, get a polished
window with a sidebar of touch commands and the full agent in a VTE
terminal. The agent core is identical; this is a presentation layer.

---

## One-command install

```
curl -fsSL https://raw.githubusercontent.com/the-priest/athena5/main/bootstrap.sh | bash
```

That clones the repo to `~/athena5`, runs `install.sh`, installs
system packages (GTK4 · libadwaita · VTE · python3-gi), pip deps
(groq · networkx), drops a desktop entry and icon, and links both
`athena` (CLI) and `athena-gui` into `/usr/local/bin`.

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

### Manual install (if you don't trust curl|bash)

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

**GUI (Phosh, GNOME, anything libadwaita-aware):**
Tap the **Athena** icon in your app grid, or run:

```
athena-gui
```

**CLI (no GUI, just the REPL):**

```
athena
```

First launch will prompt for your Groq API key (free, no card —
console.groq.com) and persist it to `~/.bashrc` and `~/.zshrc`.
You can update it later from the GUI: header menu (⋮) ▸ API key…

---

## What's in v7.3

### New: native GTK4 UI — no terminal

The agent core is untouched.  athena.py still runs as the 6000-line REPL
underneath, but its output never reaches a terminal widget.  Instead the
GUI process spawns it through a PTY, parses every panel it prints, and
renders each one as a native GTK card:

- **Thought** — italic magenta card with the agent's reasoning.
- **Proposed command** — dark code-block with the shell command,
  confidence pill (GREEN/YELLOW/RED), ATT&CK tag, and three big
  tap buttons: **✓ Run · ✗ Skip · ✋ Quit**.  No typing y/n.
- **Result** — collapsed output with line trimming (full output stays
  in `~/.athena/logs`).
- **Findings** — green card listing each extracted finding.
- **⛔ Error** — red card with structured failure info.
- **Status bar** — target and current agent live in the header,
  parsed from athena's status strip on every turn.

The sidebar (swipe in from the left, or tap the menu icon) has every
REPL command as a labelled tap button — workflows, findings, tree,
scope, MITRE, save, report, reset, etc.

The bottom input bar adapts to context: free-form text by default,
hidden password field when a password is needed, "tap a button above"
hint when the y/n/q gate is open.

### Carried from v7.2

Pentesting Task Tree · 11 specialist agents · 28 typed tool builders ·
200+ Kali tool registry · MITRE ATT&CK auto-tagging · scope / RoE
enforcement · networkx attack graph · smart context manager with
`[NEED]` re-fetches · auto credential fanout · source-tagged finding
extraction · Groq 9-model fallback chain · per-command timeouts ·
sudo escalation · loop breaker · failure-aware confidence ·
`y/n/q` confirmation gate.

---

## Files installed

```
/opt/athena5/                                 # install dir
  ├── athena.py                                 # the agent (untouched)
  ├── athena_gui.py                             # GTK4 shell
  ├── athena-gui                                # launcher script
  └── requirements.txt
/usr/local/bin/athena                         # → athena.py
/usr/local/bin/athena-gui                     # → athena-gui
~/.local/share/applications/io.thepriest.Athena.desktop
~/.local/share/icons/hicolor/scalable/apps/io.thepriest.Athena.svg
~/.athena/logs/                               # per-session logs + reports
~/.athena/scope.json                          # engagement scope (if you set one)
```

---

## REPL commands (typed into the terminal or tapped in the sidebar)

| Command  | What it does |
|----------|--------------|
| `workflow` | Open the workflow menu (23 pre-built engagement templates) |
| `target`   | Set or update the engagement target |
| `findings` | Show every extracted finding (verified + unverified) |
| `tree`     | Render the Pentesting Task Tree |
| `graph`    | Show the attack graph state + pivot suggestions |
| `scope`    | Show / toggle engagement scope (RoE) |
| `mitre`    | Show MITRE ATT&CK techniques used this session |
| `tools`    | Tool availability + auto-install missing |
| `model`    | Show provider chain status |
| `agent`    | List all specialist agents |
| `dashboard` | Concise session status panel |
| `save`     | Save conversation to file |
| `report`   | Generate the engagement report now |
| `clear`    | Clear AI memory (PTT preserved) |
| `reset`    | Reset everything (PTT + findings + history + sudo cache) |
| `help`     | Show the help menu |
| `exit` / `q` | End session and generate report |

Or just type any objective in plain English — Athena routes to the
right specialist.

---

## Tested on

- Kali NetHunter Pro · OnePlus 6 · Phosh (primary target — bare metal)
- Kali Linux on x86_64 laptop
- Debian Bookworm / Trixie
- Should work on any GTK4 + libadwaita-capable Linux

Requires Python ≥ 3.10.  GUI needs `python3-gi`, `gir1.2-gtk-4.0`,
`gir1.2-adw-1` (install.sh handles all of it).

---

## Safety

Athena will **refuse**:

- `apt upgrade` / `apt full-upgrade` / `apt dist-upgrade` and any
  variants (Phosh + UI packages stay stable on a NetHunter phone).
- Destructive commands (`rm -rf /`, `dd if=`, `mkfs`, fork bombs,
  `shutdown`, `chmod -R 777 /`, `chown -R … /`).
- Interactive shells that would hijack the terminal (msfconsole
  without `-q -r`, ssh interactive, vi/nano/less/top, mysql/psql
  REPL). Each gets a non-interactive replacement hint.
- Out-of-scope targets when scope enforcement is enabled.

Every other command goes through the `y/n/q` gate before execution.
System-modifying commands get a second confirmation. Sudo is opt-in,
prompted once per session via `getpass`, cached only in RAM, and fed
to commands via `sudo -S` from stdin.

---

## License

Personal project by The Priest. Use at your own risk on systems you
own or have explicit written authorisation to test.
