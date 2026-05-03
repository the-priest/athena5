# Athena — AI Offensive Security Agent

**v7.2** · Bare-metal Kali NetHunter · Commander: The Priest

Athena is an AI-driven pentesting copilot. You give it a target and an
objective, it picks the right specialist agent, picks the right tool,
and runs commands one at a time through a `y/n` confirmation gate. Every
finding is regex-extracted from real subprocess output (no AI
hallucinations), tagged with MITRE ATT&CK, and tracked in a Pentesting
Task Tree (PTT) plus a networkx-backed attack graph.

---

## What's new in v7.2

This release is a reliability + UI overhaul fixing every bug surfaced
during field testing of v7.1.

### Reliability

- **Tool dispatch no longer silently drops kwargs.** Common LLM
  emissions like `scan_type`, `skip_host_discovery`, `timing_template`,
  `open_only`, `script`, `nse_scripts`, `service_version`,
  `port_range`, `T`, etc. are now mapped to the correct builder
  parameter via a synonym table. Truly unknown kwargs return a hard
  `ERROR:` that gets fed back into the LLM's next prompt — so the
  agent learns and corrects, instead of looping with the same bad args.
- **Sudo escalation.** After a non-sudo command fails with markers
  like `cap_net_raw`, `permission denied`, `pcap_activate`,
  `must be root`, etc., Athena offers a one-tap retry with `sudo`
  prefix using the in-RAM cached password.
- **Tool availability pre-flight.** Dispatcher refuses to build a shell
  string for a tool that isn't installed and suggests an alternative
  (e.g. `rustscan` missing → suggests `nmap`).
- **Script-param type safety.** `nmap.scripts` accepts list / tuple /
  dict / repr-string and always normalises to `--script=a,b,c`. The
  `--script=['default']` literal-list bug is dead.
- **Loop breaker.** Same shell command twice in last 5 → forced RED
  confidence, agent rotation hint, and a different-approach prompt.
  Three repeats → stuck-handler picks 3 alternative angles.
- **Workflow completion gate.** `WORKFLOW_COMPLETE` is refused on a
  node with 0 successful commands AND 0 findings — the LLM cannot
  bail out of a streak of failures by claiming "done".
- **Failure-aware confidence.** Multiple attempts on a node force
  yellow → red regardless of what the LLM self-reports.
- **UI-threat false-positive guard.** Boot check confirms with
  `dpkg-query` that a flagged package is actually installed before
  warning. The boot lock auto-expires after 6 hours.
- **Per-command timeouts.** `nmap` full-range 600s, `--top-ports`
  90s, `hydra` 1800s, `hashcat`/`john` 3600s, default 300s. A hung
  command can no longer freeze the session.

### Visual

Every event now renders as its own titled, colour-coded box:

```
┌─ TURN N · target · node · ✓v/?u · ATT&CK · model ─┐
┌─ THOUGHT ─────────────────────────────────────────┐
┌─ DISPATCH ─ T1046 Network Service Discovery ─────┐
┌─ COMMAND  conf=GREEN ▶ ─ ATT&CK=T1046 ───────────┐
┌─ FINDINGS +N ────────────────────────────────────┐
┌─ ⛔ ERROR / PERMISSION DENIED ───────────────────┐
```

Persistent status bar still renders before each prompt.

### Preserved from v7.1

- Pentesting Task Tree (PTT) — hierarchical task state with
  natural-language serialisation for the LLM.
- 11 specialist agents (strategist · recon · web · network · ad ·
  linux/win privesc · credential · exfil · evasion · reporter)
  with deterministic phase-based dispatch.
- 28 structured tool builders (typed signatures, no flag drift).
- 200+ Kali tool registry, auto-install on demand.
- MITRE ATT&CK auto-tagging on every command and finding (50
  technique mappings).
- Scope / RoE enforcement via `~/.athena/scope.json`.
- Attack graph (networkx) with pivot suggestions.
- Smart context manager with `[NEED]ptt|history|graph|kb N[/NEED]`
  re-fetch protocol.
- Auto credential fanout queue.
- Source-tagged finding extraction (no AI hallucinations enter the
  finding store — only raw subprocess output is parsed).
- Groq provider chain with automatic fallback (9 models,
  biggest → smallest).
- Confirmation gate (`y/n/q`) on every command.
- No on-disk persistence except scope, logs, and reports.

---

## Install

Tested on Kali Linux NetHunter (sdm845, Phosh). Should work on any
Debian / Ubuntu / Arch system with python ≥ 3.10.

```bash
git clone https://github.com/the-priest/athena5.git
cd athena5
pip install groq networkx --break-system-packages
export GROQ_API_KEY='your_key_here'   # add to ~/.bashrc to persist
python3 athena.py
```

If `groq` install fails on a managed Python, drop the
`--break-system-packages` flag and use a virtualenv.

---

## Usage

```
$ python3 athena.py
```

You'll see the v7.2 banner, then the boot sequence, then a prompt
to set the target (IP, domain, mission notes). After that, type
any objective or one of the built-in commands.

### Commands

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

### Output format the AI uses

```
[THOUGHT]<reasoning>[/THOUGHT]
[TOOL]<tool_name>[/TOOL][ARGS]<json>[/ARGS]    # or [CMD]<shell>[/CMD]
[CONF]green|yellow|red[/CONF]
[VERIFY]<verify_command>[/VERIFY]              # optional
[HANDOFF]<other_agent>[/HANDOFF]               # optional
[NEED]ptt|history|findings|graph|kb N[/NEED]   # optional, re-fetch
```

---

## Files

```
athena.py                    # the whole agent, single file
~/.athena/scope.json         # engagement scope / RoE
~/.athena/logs/session_*.txt # per-session command + output log
~/.athena/logs/report_*.md   # markdown report at end of session
/tmp/athena_session.lock     # boot-check TTL marker (6h)
```

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

This is a personal project by The Priest. Use at your own risk on
systems you own or have explicit written authorisation to test.
