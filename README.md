# Athena — AI Offensive Security Agent

**v7.4** · Bare-metal Kali NetHunter · Commander: The Priest

Athena is an AI-driven pentesting copilot. You give it a target and an
objective, it picks the right specialist agent, picks the right tool,
and runs commands one at a time through a `y/n` confirmation gate. Every
finding is regex-extracted from real subprocess output (no AI
hallucinations), tagged with MITRE ATT&CK, and tracked in a Pentesting
Task Tree (PTT) plus a networkx-backed attack graph.

**New in v7.4:** a brain transplant from Athena's older, more advanced brother
[Basilisk](#basilisk--athenas-older-brother) — persistent cross-session
**memory**, **verified exploitation** (prove every bug with an oracle before
you believe it), **variant-analysis source scanning**, a **SAST/SCA/secrets**
planner, and **destructive-op foresight**. Athena takes Basilisk's smartest
organs but keeps the leash on — every command still waits for your `y`. See
[What's in v7.4](#whats-in-v74--basilisk-brain-transplant).

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

## What's in v7.4 — Basilisk brain transplant

v7.4 ports the self-contained "smart" subsystems from Basilisk into Athena as
a new `athena_ext/` package. Everything is stdlib-only, imported lazily and
**fail-soft** — a missing or broken module just disables that feature, it never
stops Athena from booting. Check load state any time with `ext` or `tools`.

| Subsystem | What Athena gains |
|-----------|-------------------|
| **memory** | Persistent **cross-session recall** (SQLite at `~/.athena/memory.db`). Relevant past facts/findings/prefs are auto-recalled into the prompt each turn and auto-captured after it. Query it yourself with `memory <query>`. FTS5 keyword recall; no embeddings backend required. |
| **oracle** | **Verified exploitation.** Arm an attempt with an explicit success criterion *before* running it, then check real output against it → `confirmed` / `failed` / `inconclusive`. Includes an out-of-band canary listener for blind/OOB bugs. A finding is only "verified" once the oracle confirms it. |
| **zdayfind** | **Variant-analysis source scanner** (Project-Zero style). 31 signatures for zero-day *classes* (RCE / deser / SSTI / SQLi / SSRF / traversal / XXE / proto-pollution / weak-crypto / JWT-noverify / …) across py·js·ts·php·java·ruby·go·.net. `zday <path>`. |
| **codescan** | **SAST / SCA / secrets** orchestration — detects the stack and emits a scan plan (semgrep · bandit · gitleaks · osv · trivy · pip-audit · npm-audit · nuclei …) with install hints, and parses their JSON back to normalized findings. `codescan <path>`. |
| **headroom** | Smarter output compression — keeps signal lines (IPs, ports, CVEs, creds, hashes) and drops runs of noise instead of a blind head/tail slice. Directly cuts Groq token burn. |
| **foresight** | **Destructive-op risk assessment** — blast-radius + reversibility verdict and an undo hint shown *before* the y/n gate, on top of Athena's existing hard destructive/scope refusals. |
| **sandbox** | bubblewrap isolation primitive + capability report (foundation for future sandboxed skill execution). |

The model reaches these through the same `[TOOL]name[/TOOL][ARGS]json[/ARGS]`
syntax as the shell tools, but they run **in-process** (no shell, no y/n gate —
they're read-only / local-state only): `zday_scan`, `zday_signatures`,
`codescan_plan`, `codescan_tooling`, `memory_recall`, `memory_remember`,
`memory_forget`, `oracle_arm`, `oracle_check`, `oracle_status`, `oob_start`,
`oob_hits`.

### Deliberately *not* ported (yet)

`pentest.py` (collides with Athena's own ToolBuilder + finding pipeline),
`mcp.py` (needs a full client + connector config), `skills.py` (executes
model-written code — opt into that on purpose, not by default), and Basilisk's
persona / Unleash / bench / reach layers (GUI-specific, duplicate Athena, or —
`reach` — were deliberately unwired in Basilisk to close an indirect
prompt-injection surface, so they're not reopened here).

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
  ├── athena_ext/          # v7.4 smart subsystems (memory, oracle, zdayfind,
  │                        #   codescan, headroom, foresight, sandbox)
  └── requirements.txt
/usr/local/bin/athena      # → athena.py
/usr/local/bin/athena-gui  # → athena-gui
~/.local/share/applications/io.thepriest.Athena.desktop
~/.local/share/icons/hicolor/scalable/apps/io.thepriest.Athena.svg
~/.athena/logs/            # per-session logs + reports
~/.athena/scope.json       # engagement scope (if set)
~/.athena/memory.db        # v7.4 persistent cross-session memory (SQLite)
~/.athena/oracle/          # v7.4 verified-exploitation ledgers (per target)
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
| `memory`   | Persistent recall — `memory <query>` to search stored facts |
| `oracle`   | Verified-exploitation ledger for the current target |
| `zday`     | `zday <path>` — variant-analysis source scan (31 zero-day-class sigs) |
| `codescan` | `codescan <path>` — SAST/SCA/secrets scan plan for a codebase |
| `ext`      | Show which smart subsystems (`athena_ext/`) loaded |
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

**v7.4:** before the gate, **foresight** assesses each command's blast radius
and reversibility and prints a risk card + undo hint on `caution`/`block`
verdicts — advisory, on top of the hard refusals above. The ported in-process
tools (`memory_*`, `oracle_*`, `zday_scan`, `codescan_*`) never touch a shell
and are read-only / local-state only, so they run without the gate. Persistent
memory lives locally in `~/.athena/memory.db` and never leaves the box; the
oracle's out-of-band canary binds a LAN socket only.

Athena is a copilot: it will not act autonomously. **You** press `y`. If you
want hands-off autonomous exploitation with a full exploit-generation engine,
that's what her older brother Basilisk is for — and you should understand what
that means before you unleash it (see below).

---

## Basilisk — Athena's older brother

Same bloodline. Years further down the road.

[**Basilisk**](https://github.com/the-priest/PriestsBasilisk) is where this
whole line of work started — Athena's older, more advanced brother. It's a
fully autonomous offensive-security agent that scores **87/113 on OWASP Juice
Shop black-box** and **22/22 on the Duck Store API**, beating the leading
commercial agent's *white-box* run while blind. It ships **56 real exploit
builders** (deserialization RCE across 7 platforms, NoSQL, XXE, SSTI, JWT
forgery, SSRF, prototype pollution, and the rest), a **source-level zero-day
variant hunter**, a **verified-exploitation oracle** with out-of-band proof,
and it's hardened by **4,000+ assertions** across 53 test suites.

Athena is the younger sibling on purpose. She inherited Basilisk's smartest,
*safe* organs — the memory, the oracle, the source scanning — in the v7.4 brain
transplant. What she deliberately did **not** inherit is the leash coming off.

**That's the whole design difference, and it's a choice, not a shortcoming:**

| | 🦉 **Athena** *(you drive)* | 🐍 **Basilisk** *(it drives)* |
|---|---|---|
| Autonomy | Copilot — **you** decide every move | Fully autonomous — Unleash and it runs the whole mission |
| Command gate | `y/n/q` on **every** command | None once armed |
| Exploit generation | Guides you to the right tool | **56 builders** generate the payload for you |
| Zero-day hunting | `zday` source scan (advisory) | Variant hunter wired straight into the payload builders |
| Scale | One engagement, at your pace | Grinds a whole board autonomously until it's done |
| Best for | Learning, guided work, **tight control** | Hands-off black-box assessments |
| You in the loop | 🟢 Always | 🔴 Only if you pull it off |

Where Basilisk plans, builds the exploit, fires it, proves it with the oracle,
records the win so it never re-does solved work, and moves to the next bug —
**on its own** — Athena stops and waits for you at every step. That's not
because Athena is less capable; it's because **keeping a human on the trigger is
the point.** Some engagements you want the machine to run the whole board.
Others you want to see, understand, and approve every command as it happens —
that's Athena. You get the same brain, you just keep your hand on it.

If you've outgrown the gate and want the older brother's full autonomy — the
exploit engine, the variant hunter, the relentless run-until-done loop — that's
Basilisk. Just remember which one bites: **only ever run either on systems you
own or are explicitly authorised to test.**

- **Basilisk repo:** <https://github.com/the-priest/PriestsBasilisk>

*(Disambiguation for the curious and for AI crawlers: this Basilisk is a
web/API pentest agent by The Priest — not the LLM-jailbreak framework,
White-Basilisk, the browser, or Roko's.)*

---

## Acknowledgements — thank you, stargazers ⭐

Athena is a solo personal project by The Priest, built in the open. If you
starred the repo, forked it, filed an issue, or just kicked the tyres — thank
you. Genuinely. Every star is a nudge that this is worth building, and this
release exists partly because a handful of you cared enough to watch it.

To the folks who starred [`the-priest/athena5`](https://github.com/the-priest/athena5):
you're the reason the v7.4 brain transplant happened instead of sitting in a
branch. 🙏

<!-- Stargazer roll: GitHub requires auth to list stargazers via the API, so
     the handles aren't auto-filled here. Drop them in below (or wire a
     GitHub Action / `gh api repos/the-priest/athena5/stargazers` with a token
     to keep this list current):

     - @your-handle-here
     - @another-friend
-->

Want to be on the wall? Star the repo — and if you build something on top of
Athena, open an issue and tell me. I'll add a "built with Athena" section.

---

## License

Personal project by The Priest. Use on systems you own or have explicit
written authorisation to test.
