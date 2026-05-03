<div align="center">

# Athena

**AI Offensive Security Agent for Kali Linux / NetHunter**

`v7.1` — single-file Python — operator-in-the-loop

</div>

---

Athena is an AI-driven pentesting assistant that runs in your terminal, plans engagements as a hierarchical task tree, and dispatches specialist agents (recon, web, AD, privesc, credential, exfil, evasion, reporter) per phase. Every command is gated by `y/n` confirmation. Every finding is source-tagged to the exact subprocess output it came from. Out-of-scope commands are refused before execution. Reports are deliverable-grade with MITRE ATT&CK coverage tables.

It is not a chat wrapper around an LLM. It is a stateful agent framework with deterministic dispatch, typed tool builders, scope enforcement, an attack graph, and smart-context token discipline.

## What v7.1 actually does

- **Pentesting Task Tree (PTT)** — hierarchical state with status, confidence, attempt counters, last-command tracking, and per-node attack history. Replaces the flat finding lists most LLM pentest tools use.
- **11 specialist agents** dispatched deterministically by phase: strategist, recon, web, network, AD, linux\_privesc, windows\_privesc, credential, exfil, evasion, reporter. Each has its own persona and KB context.
- **Source-tagged finding extraction** — regex runs on raw subprocess stdout only. Phantom findings (LLM hallucinations) cannot enter state because every finding records its originating shell command.
- **MITRE ATT&CK auto-tagging** — 50 command patterns and 17 finding-type fallbacks map every action to a technique ID (T1046, T1110.003, T1003.006, T1558.003...). Reports include a coverage table grouped by tactic.
- **Engagement scope / Rules of Engagement** — `~/.athena/scope.json` defines allowed CIDRs, allowed/blocked domains, and time windows. Every command's targets are checked before execution. Out-of-scope commands are refused with a clear reason. Wildcards supported (`*.target.com`).
- **Smart context manager** — minimal context per turn (active node + verified findings + 4 history turns) saves ~50% tokens vs sending everything every turn. The LLM can request more on demand via `[NEED]ptt[/NEED]`, `[NEED]graph[/NEED]`, `[NEED]findings[/NEED]`, `[NEED]history[/NEED]`, or `[NEED]kb 4[/NEED]` and the system re-calls with the extra context attached.
- **Attack graph** — `networkx`-backed. Hosts, services, credentials, hashes, and CVEs as nodes; `runs_on` / `works_on` / `affects` / `for_user` / `can_pivot_to` as edges. Surfaces pivot suggestions ("untested cred × N services") the LLM might miss in the flat finding list.
- **Auto credential fanout** — when a credential verifies, the framework queues PTT subnodes for testing it across every auth-able service in the graph. Deterministic, not LLM-dependent.
- **28 structured tool builders** — typed wrappers for nmap, rustscan, masscan, gobuster, feroxbuster, ffuf, hydra, sqlmap, hashcat, hashid, impacket-* family, kerbrute, msfvenom, nuclei, nikto, sslscan, theharvester, dnsrecon, and more. The LLM picks args, the framework constructs the shell string. Unknown args dropped gracefully with a soft warning.
- **PoC verification queue** — claimed credentials get re-tested through a separate gate before being marked verified. Reports cleanly separate verified from unverified.
- **Sudo handling** — password prompted once via `getpass`, kept in RAM only, fed via `sudo -S` to all subsequent privileged commands. Works regardless of TTY context.
- **Provider chain** — 9 Groq models with automatic fallback, biggest first.
- **23 workflows** for common engagement patterns: external recon, web app pentest, AD kill chain, container escape, lateral movement, IDS evasion, etc.
- **Five-voice UI** — every line shows who's speaking: `⚔ priest` (you), `◈ ATHENA` (framework), `🔍 RECON` (AI agent), `▌ proposed command`, `✓` / `⚠` / `✕` for ok/warn/error.
- **Always y/n gated** — Athena never executes anything without an explicit operator confirmation. Destructive patterns (rm -rf /, dd if=/dev/zero, fork bombs) are refused outright. System-modifying commands require double confirmation.

## Install

```bash
git clone https://github.com/the-priest/athena5
cd athena5
./install.sh
```

The installer:

1. Verifies Python 3.10+
2. Installs Python dependencies (`groq`, `networkx`)
3. Symlinks `/usr/local/bin/athena` → the script (falls back to a `~/.bashrc` alias if no sudo)
4. Creates `~/.athena/` for logs and scope config
5. Prompts for `GROQ_API_KEY` if not set, writes it to `~/.bashrc`

## Quickstart

```bash
export GROQ_API_KEY=gsk_...
athena
```

Set a target, then either type a free-form objective or pick a workflow:

```
   ⚔ priest › find smb shares and check for ms17-010
```

```
   ⚔ priest › workflow
```

Athena proposes one command at a time. Press `y` to run, `n` to skip, `q` to quit.

## Configuration

### `GROQ_API_KEY`

Get a free key at <https://console.groq.com> (no credit card). Set it in your shell:

```bash
export GROQ_API_KEY=gsk_your_key_here
```

### Scope (Rules of Engagement)

First run creates `~/.athena/scope.json` with `enabled: false`. To enforce engagement boundaries:

```json
{
  "enabled": true,
  "allowed_cidrs":   ["10.10.10.0/24", "192.168.50.0/24"],
  "blocked_cidrs":   ["192.168.50.99"],
  "allowed_domains": ["target.com", "*.target.com"],
  "blocked_domains": ["admin.target.com"],
  "time_window": {
    "start": "2026-05-04T09:00",
    "end":   "2026-05-04T17:00"
  }
}
```

Out-of-scope commands are refused before subprocess. The `scope` REPL command shows current state and toggles enforcement.

## Commands

| Command | What it does |
| --- | --- |
| `workflow` | Pick from 23 engagement templates |
| `target` | Set or change target |
| `tree` | Show the Pentesting Task Tree |
| `findings` | List verified + unverified findings |
| `graph` | Show attack graph state and pivot hints |
| `mitre` | ATT&CK techniques exercised this session |
| `scope` | Toggle / view engagement scope |
| `dashboard` | Full session status panel |
| `tools` | Tool availability check + auto-install missing |
| `model` | Provider chain status |
| `agent` | List specialist agents |
| `report` | Generate report now (also runs at exit) |
| `save` | Dump conversation transcript |
| `clear` | Clear LLM history (PTT preserved) |
| `reset` | Wipe everything for a fresh engagement |
| `help` | Full command listing |
| `exit` / `q` | End session and write report |

Anything else goes to the agent dispatcher as a free-form objective.

## Reports

Reports are written to `~/.athena/logs/report_<timestamp>.md` and include:

- Executive summary + remediation (LLM-cleaned, verified findings only)
- MITRE ATT&CK coverage table (techniques exercised, findings grouped by technique)
- Attack graph summary with pivot hints
- Pentesting Task Tree final state
- Raw findings with provenance — every finding shows the exact command that produced it
- Token savings from smart context

## Requirements

- Kali Linux (or NetHunter, or another Debian-based distro with the standard pentest toolset)
- Python 3.10+
- Standard Kali tools: nmap, gobuster / feroxbuster, hydra, sqlmap, hashcat, impacket-* etc. The `tools` command can auto-install missing ones via `apt`.
- A free Groq API key

## Architecture overview

```
┌───────────────────────────────────────────────────────────────────┐
│                            REPL loop                              │
│   priest input → agent_loop → think_turn → run_command → output   │
└───────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────┐   ┌────────────────────┐   ┌────────────────┐
│   ContextManager   │   │     PTT (state)    │   │ ScopeConfig    │
│                    │   │                    │   │                │
│ minimal by default │   │ hierarchical nodes │   │ CIDR + domain  │
│ [NEED] re-fetches  │   │ findings, attempts │   │ time windows   │
│ ~50% token savings │   │ confidence, status │   │ enforced pre-  │
│                    │   │                    │   │ subprocess     │
└────────────────────┘   └────────────────────┘   └────────────────┘
                                │
                                ▼
┌────────────────────┐   ┌────────────────────┐   ┌────────────────┐
│  Specialist agents │   │  ToolBuilder + 28  │   │  AttackGraph   │
│                    │   │  structured tools  │   │  (networkx)    │
│ recon · web · AD   │   │                    │   │                │
│ network · privesc  │   │ [TOOL]name[/TOOL]  │   │ host · service │
│ credential · exfil │   │ [ARGS]json[/ARGS]  │   │ cred · vuln    │
│ evasion · reporter │   │ → typed shell str  │   │ pivot graph    │
└────────────────────┘   └────────────────────┘   └────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│  Source-tagged finding extraction · MITRE ATT&CK auto-tagging     │
│  PoC verification queue · Auto credential fanout · Provider chain │
└───────────────────────────────────────────────────────────────────┘
```

## Authorized testing only

This is an offensive tool. Run it only against systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal in most jurisdictions. The author accepts no responsibility for misuse.

## License

MIT. See [LICENSE](LICENSE).
