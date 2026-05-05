# Athena — User Manual

**v7.2** · Bare-metal Kali NetHunter · Commander: The Priest

This manual covers **how to use Athena** once it's installed. For
install instructions, see `README.md`. For development notes, read the
top of `athena.py`.

---

## Table of Contents

1. [Mental model — what Athena actually is](#1-mental-model)
2. [Starting a session](#2-starting-a-session)
3. [Reading the screen](#3-reading-the-screen)
4. [Speaking to Athena — the prompt](#4-the-prompt)
5. [Built-in commands](#5-built-in-commands)
6. [Workflows](#6-workflows)
7. [Specialist agents](#7-specialist-agents)
8. [Findings, PTT, and the attack graph](#8-findings-ptt-graph)
9. [The confirmation gate](#9-the-confirmation-gate)
10. [Sudo handling](#10-sudo-handling)
11. [Confidence and the loop breaker](#11-confidence-and-loops)
12. [Scope / Rules of Engagement](#12-scope-roe)
13. [MITRE ATT&CK tracking](#13-mitre)
14. [Reporting](#14-reporting)
15. [Tool registry — structured vs ad-hoc](#15-tools)
16. [Common operator patterns](#16-patterns)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Mental model

Athena is a **conversational pentest copilot**. You don't tell it
*how* to do things — you tell it *what* you want, and it picks the
right specialist agent, picks the right tool, builds the command,
asks you for `y/n`, and runs it. It then parses the output for IPs,
ports, services, hashes, credentials, CVEs, etc., tracks them as
findings, and pivots.

Three things make it different from "ChatGPT but for pentesting":

- **Deterministic dispatch.** When the AI says "use nmap with these
  flags", the framework builds the command from a typed schema — the
  AI cannot hallucinate a flag that doesn't exist. 28 tools are
  registered this way.
- **Source-tagged findings.** Findings only enter the database from
  real subprocess output, regex-extracted from raw stdout. The AI's
  prose is never trusted for facts.
- **Confirmation on every command.** Athena proposes; you decide.
  `y` runs it, `n` rejects it (the AI then proposes something else),
  `q` ends the session. There is no "auto-yes" mode.

You stay in the driver's seat. Athena does the boring parts.

---

## 2. Starting a session

Just run:

```
athena
```

You'll see:

1. The **v7.2 banner** with the Athena logo and capability list.
2. The **boot sequence** — 9 status lines confirming subsystems are
   online (cognitive matrix, PTT, agents, tool dispatch, ATT&CK
   mappings, graph, smart-context, loop-breaker + sudo-retry, Groq
   chain).
3. The **boot check** — verifies no UI packages have pending upgrades
   that could destabilise your phone (auto-skipped if checked in the
   last 6h).
4. The **status panel** + the **priest prompt** `⚔ priest ›`.

Athena does **not** auto-load a target. Set one when you're ready
(see the `target` command below) — or just type a goal and Athena
will ask.

The first time Athena needs `sudo`, it'll prompt once via `getpass`
and cache the password in RAM only (never written to disk). Type
`reset` to clear it.

---

## 3. Reading the screen

Athena v7.2 renders every event as a separate titled box. From top
of a turn to bottom you'll see:

```
┌─ TURN N ────────── target · agent · ✓v/?u · ATT&CK · model ── v7.2 ─┐
│                                                                       │
│  192.168.1.150 · node 1.1 · ✓0/?0 · ATT&CK ×0 · GPT-OSS 120B          │
│  ⚔ RECON SPECIALIST                                                   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

┌─ THOUGHT ─────────────────────────────────────────────────────────────┐
│ ▎ Initial scan should be a top-1000 ports with version detection,    │
│ ▎ -Pn since the target appears to drop ICMP. This gives us a baseline │
│ ▎ to pivot from.                                                      │
└───────────────────────────────────────────────────────────────────────┘

┌─ DISPATCH ──────────── T1046 Network Service Discovery ──────────────┐
│   nmap →                                                              │
│   nmap -sV -Pn --top-ports 1000 192.168.1.150                         │
└───────────────────────────────────────────────────────────────────────┘

┌─ COMMAND ─────────────── T1046 Network Service Discovery ────────────┐
│   nmap -sV -Pn --top-ports 1000 192.168.1.150                         │
│                                                                       │
│   conf:  GREEN ▶                                                      │
└───────────────────────────────────────────────────────────────────────┘

   y run   n skip   q quit  › y

   ▶ EXECUTING   timeout=90s · Ctrl+C aborts this command only

[... actual nmap output ...]

┌─ FINDINGS +7 ─────────────────────────────────────────────────────────┐
│   🌐  ip          192.168.1.150  T1046                               │
│   🔌  port        22  T1046                                           │
│   🔌  port        80  T1046                                           │
│   ⚙   svc         OpenSSH 8.4p1  T1046                               │
│   ...                                                                 │
└───────────────────────────────────────────────────────────────────────┘
```

### Box colours

| Colour     | Meaning                                            |
|------------|----------------------------------------------------|
| 🟪 magenta | Turn header, command card (operational state)     |
| 🟦 cyan    | Dispatch card (structured tool resolution)         |
| 🟩 green   | Result, findings, success states                   |
| 🟥 red     | Errors, refused commands, RED confidence, alerts   |
| 🟨 yellow  | Warnings, handoffs, YELLOW confidence              |
| ⬜ grey    | Status, secondary info, dimmed prose               |

### The persistent status bar

Before each `priest ›` prompt, you see a single-line status:

```
▍ 192.168.1.150  │ recon  │ GPT-OSS 120B  │ ✓2/?5  │ ATT&CK ×3  │ ●scope
```

Reads as:
- **target** · **active agent** · **active model** · **✓verified
  / ?unverified findings** · **MITRE techniques used** ·
  **scope on (●) / off (○)**

---

## 4. The prompt

The `⚔ priest ›` prompt accepts three kinds of input:

### a. A built-in command

Single word, lowercase. See [§5](#5-built-in-commands) for the full
list. Examples: `findings`, `tree`, `workflow`, `target`, `help`.

### b. A workflow number

After typing `workflow`, Athena shows a numbered menu. You pick a
number (`1`–`23`), Athena seeds the PTT and starts working.

### c. Free-text objective

Any other input is treated as an objective and sent to the
strategist, who picks the right specialist and starts.

Examples that work:

```
find any unauth services on this host
the SMB null session works — see what shares we can read
crack this hash: 31d6cfe0d16ae931b73c59d7e0c089c0
do a full AD recon, the DC is dc01.corp.local
the web app is at https://app.target.com — find injection points
```

The fuzzier you are, the more turns Athena uses to clarify. Be
precise when you can: paste hashes, paste URLs, name the credential
you got, say which subnet you're on.

---

## 5. Built-in commands

Type any of these at the `⚔ priest ›` prompt.

| Command                | What it does                                     |
|------------------------|--------------------------------------------------|
| `target`               | Set or update the engagement target              |
| `workflow`             | Open the 23-workflow menu                        |
| `help`                 | Reprint the help screen                          |
| `findings`             | List every extracted finding (verified + unverified) by type |
| `tree`                 | Render the Pentesting Task Tree (PTT)            |
| `graph`                | Show the attack graph state + pivot suggestions  |
| `scope`                | Show / toggle Rules of Engagement                |
| `mitre` or `attack`    | Show MITRE ATT&CK techniques used this session   |
| `tools`                | Tool availability + auto-install missing         |
| `model`                | Show provider chain status (which Groq model is active) |
| `agent` or `agents`    | List all 11 specialist agents and their personas |
| `status`/`dashboard`/`stat` | Concise session status panel                |
| `save`                 | Save conversation to a markdown file in `~/.athena/logs/` |
| `report`               | Generate the engagement report **right now** (without exiting) |
| `clear`                | Clear AI conversation memory (PTT preserved)     |
| `reset`                | Reset everything (PTT + findings + history + sudo cache) |
| `exit` / `quit` / `q`  | End session and generate report                  |

All commands are case-insensitive. The prompt also accepts plain
Enter (does nothing — useful to redraw the status bar).

---

## 6. Workflows

Type `workflow` to see the menu. Pick a number `1`–`23`:

| #  | Name                              | Strategy                                                       |
|----|-----------------------------------|----------------------------------------------------------------|
|  1 | Network Recon                     | ARP sweep → port scan → service detection → CVE correlation    |
|  2 | Web Enumeration                   | Tech fingerprint → vuln scan → dir/vhost brute                 |
|  3 | Linux Post-Exploitation           | Identity → sudo → SUID → cron → caps → cred hunt               |
|  4 | Metasploit Exploit                | Verify module → resource script → non-interactive run          |
|  5 | SQL Injection Assessment          | Manual probe → sqlmap → dump → cred reuse                      |
|  6 | Hash Cracking                     | Identify → cached check → wordlist → rules → mask              |
|  7 | Password Spraying                 | Service enum → policy check → spray → reuse                    |
|  8 | Active Directory Recon & Attack   | Anon enum → AS-REP → spray → Kerberoast → DCSync               |
|  9 | Payload Generation & Listener     | msfvenom payloads → handler resource script                    |
| 10 | Bluetooth Recon                   | Interface check → classic + LE scan → service browse           |
| 11 | OSINT Profiling                   | whois → DNS → certs → harvester → subdomains                   |
| 12 | SSL/TLS Audit                     | sslscan → testssl → cipher review                              |
| 13 | DNS Enumeration                   | dnsrecon → zone transfer → fierce → resolver checks            |
| 14 | SMB Attack Chain                  | ms17-010 check → enum → share → relay → SAM                    |
| 15 | API Security Testing              | Discovery → params → auth bypass → IDOR → JWT                  |
| 16 | Linux Privilege Escalation        | linpeas → GTFOBins → kernel → docker/lxd                       |
| 17 | Windows Privilege Escalation      | winpeas → tokens → service ACL → AlwaysInstallElevated         |
| 18 | Lateral Movement                  | PTH → wmiexec → DCSync → pivot tunnels                         |
| 19 | Container & Cloud Escape          | Container detect → docker socket → metadata → IAM              |
| 20 | IDS/IPS Evasion                   | MAC spoof → fragment → decoy → timing → source-port            |
| 21 | Data Exfiltration                 | Channel test → HTTPS → DNS → ICMP fallbacks                    |
| 22 | Forensics & Evidence              | Hash → strings → binwalk → volatility                          |
| 23 | Steganography                     | Metadata → strings → steghide → zsteg → binwalk                |

When you pick a workflow:

1. Athena seeds the **PTT** with the workflow's nodes (each one a
   sub-task with a phase tag).
2. The first node becomes `in_progress`.
3. Athena routes to the right specialist for that phase.
4. Each command goes through the `y/n/q` gate.
5. When all nodes complete (or hit the dead-end limit), Athena prints
   `WORKFLOW COMPLETE` and waits for your next prompt.

You can interrupt a workflow at any time — type any command at the
prompt. The PTT state is preserved.

---

## 7. Specialist agents

Athena has 11 specialist personas, each with its own colour, icon,
focus, and biased KB sections. The strategist routes work; the rest
execute.

| Agent              | Icon | Focus                                                          |
|--------------------|------|----------------------------------------------------------------|
| `strategist`       | 🜲    | Plans the campaign, breaks objectives into PTT nodes           |
| `recon`            | 👁    | Host discovery, port scans, service version detection          |
| `web`              | 🌐    | HTTP enum, SQLi, XSS, IDOR, dir/vhost, JWT, API                |
| `network`          | ⚡    | Network exploitation, MS17-010, exposed services, Metasploit   |
| `ad`               | 👑    | AD recon, Kerberoast, AS-REP, DCSync, BloodHound               |
| `linux_privesc`    | 🐧    | sudo, SUID, capabilities, cron, kernel CVEs, GTFOBins          |
| `windows_privesc`  | 🪟    | Tokens, service ACL, AlwaysInstallElevated, UAC bypass         |
| `credential`       | 🔑    | Hash cracking, password spraying, cred reuse                   |
| `exfil`            | 📤    | Tunnels, HTTPS/DNS/ICMP exfil, staging                         |
| `evasion`          | 🥷    | AV bypass, obfuscation, timing, fragmentation                  |
| `reporter`         | 📋    | Cleanup, executive summary, ATT&CK coverage table              |

You don't pick the agent yourself — Athena routes based on the phase
of the active PTT node. But agents can request a **handoff** to
another agent in their thought (`[HANDOFF]credential[/HANDOFF]`),
and you'll see a yellow handoff box when this happens.

Type `agent` or `agents` to see the live list with personas.

---

## 8. Findings, PTT, and the attack graph

Three different views of "what we know so far":

### Findings (`findings`)

A flat list of every extracted artifact, by type:

```
IP            : 192.168.1.150, 192.168.1.151
PORT          : 22, 80, 443, 3306
SVC           : OpenSSH 8.4p1, nginx 1.18.0, MySQL 8.0.32
USER          : admin, devops, jdoe
HASH_NTLM     : aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
CRED          : admin:Password123!
CVE           : CVE-2017-0144, CVE-2021-41773
URL           : http://192.168.1.150/admin
SMB_SHARE     : \\192.168.1.150\public
EMAIL         : admin@target.com
SSH_KEY       : (private key extracted)
```

Each finding is tagged with a confidence (verified ✓ / unverified ?)
and an ATT&CK technique. **Verified** means a follow-up command
proved the finding was real (e.g., a credential successfully logged
in somewhere). **Unverified** means a regex pulled it from output
but it hasn't been confirmed yet.

### PTT (`tree`)

The Pentesting Task Tree — a hierarchical to-do list with status:

```
[~] 1. Network Recon  ★ active
    [✓] 1.1. Host discovery (arp-scan / ping sweep)
    [~] 1.2. Top-port scan with version detection  ★
    [ ] 1.3. Full TCP scan (-p-)
    [ ] 1.4. OS fingerprint
    [X] 1.5. CVE correlation       ← dead-end (4 attempts)
```

Markers:
- `[ ]` pending
- `[~]` in progress
- `[✓]` done
- `[x]` failed (will retry)
- `[X]` dead-end (max attempts hit)
- `★`  this is the currently-active node

### Attack graph (`graph`)

Networkx-backed map of hosts ↔ services ↔ credentials:

```
HOSTS       : 192.168.1.150, 192.168.1.151
SERVICES    : 192.168.1.150:22 (ssh), 192.168.1.150:445 (smb)
CREDENTIALS : admin:Password123! → works on 192.168.1.150:445
PIVOTS      : Try admin:Password123! against 192.168.1.151:445
              Try admin:Password123! against 192.168.1.151:22
```

Pivot suggestions surface things the LLM might miss — like reusing a
working credential against every other host on the network.

---

## 9. The confirmation gate

Every command Athena proposes goes through a y/n/q gate:

```
   y run   n skip   q quit  ›
```

- **`y` / yes / Enter** → Execute the command.
- **`n` / no** → Reject. Athena hears "find another way" and proposes
  a different command. After 4 rejections on the same PTT node,
  Athena marks it dead-end and moves on.
- **`q` / quit** → End the session, generate the report, exit cleanly.

For **system-modifying** commands (anything in the double-confirm
list — installing packages, modifying firewall, etc.), you'll get a
**second** prompt asking you to type the word `confirm` exactly.

For **destructive** commands (`rm -rf`, `dd`, `mkfs`, fork bombs,
`shutdown`, etc.), Athena flat-out refuses. There's no override.

For **interactive** commands (`msfconsole` without `-q -r`, `ssh`
without a command, `vi`/`nano`/`less`/`top`, MySQL/psql REPL),
Athena refuses and tells the AI how to make it non-interactive. No
override needed because the AI usually corrects on the next turn.

For **out-of-scope** commands (when scope is enabled), Athena refuses
with the reason. Edit `~/.athena/scope.json` to adjust scope, or
disable enforcement with `scope` → `off`.

You can always abort a running command with `Ctrl+C` — that aborts
the command only, not the session. Athena returns to the prompt.

---

## 10. Sudo handling

Athena handles `sudo` carefully because most pentest tools need root
for raw sockets but most users don't want to type a password 30 times
per session.

**Three behaviours:**

1. **AI-proposed sudo command.** If the AI explicitly emits
   `sudo nmap -sS ...` in `[CMD]`, Athena prompts for the password
   once via `getpass` and runs it. Subsequent sudo commands reuse
   the cached password (RAM only).
2. **Sudo-preferred tools.** Tools that almost always need root
   (`arp-scan`, `masscan`, `tcpdump`, `responder`, `bettercap`, raw
   nmap with `-sS`/`-sU`/`-O`/`-PR`) are auto-prefixed with `sudo`
   even if the AI didn't ask for it.
3. **Sudo retry on permission denied.** If a non-sudo command fails
   with markers like `cap_net_raw`, `permission denied`,
   `pcap_activate: ... You don't have permission`, `must be root`
   (16 markers total), you'll see a red retry box:

   ```
   ┌─ ⛔ PERMISSION DENIED — needs root ────────────────────┐
   │  `arp-scan -l` failed without sudo.                    │
   │                                                         │
   │  ▸ Press y to re-run prefixed with sudo (one-time,     │
   │    uses cached password).                               │
   └─────────────────────────────────────────────────────────┘

      y retry as sudo   n keep failure  ›
   ```

   Press `y` and Athena reruns `sudo ` + the same command.

To **clear cached sudo credentials**, type `reset` at the prompt.
This is also useful if you ran Athena under the wrong user.

---

## 11. Confidence and the loop breaker

Every command the AI proposes carries a self-rated confidence:

- **GREEN ▶** — High confidence, executes immediately on `y`.
- **YELLOW ·** — Medium, executes on `y` but Athena pulls in extra
  context for the next turn.
- **RED ✕** — Low confidence. Athena **refuses to execute** and
  tells the AI to do recon instead.

### Failure-aware overrides (v7.2)

The framework upgrades the confidence rating itself:

| Condition                                 | Override            |
|-------------------------------------------|---------------------|
| Same node failed 2+ times, AI says GREEN  | Downgraded to YELLOW |
| Same node about to hit attempt limit (4)  | Forced to RED        |
| Same shell command run twice in last 5    | Forced loop-breaker  |

### The loop breaker

If the AI emits the same shell command twice in the last 5
turns:

```
┌─ ⛔ LOOP DETECTED ──────────────────────────────────────┐
│  You just ran this exact command. Repeating means the   │
│  previous result didn't change anything you can act on. │
│                                                          │
│  ▸ Forcing pivot to a different approach now.          │
└──────────────────────────────────────────────────────────┘
```

The next prompt is rewritten to demand a different tool, different
angle, or different specialist. Three loops in a row → Athena
triggers `_handle_stuck()` which generates 3 alternative angles for
you to pick from manually.

### Workflow completion gate

The AI cannot exit a node by emitting `WORKFLOW_COMPLETE` if that
node has produced **0 findings AND 0 successful commands**. This
stops the AI from bailing on a streak of failures. If you really
want to skip a node, reject 4 commands on it (`n n n n`) and Athena
will mark it dead-end and move on.

---

## 12. Scope / RoE

Type `scope` to see and toggle engagement scope.

The scope is loaded from `~/.athena/scope.json`. A working example
is in the repo (`scope.example.json`):

```json
{
  "enabled": true,
  "allowed_cidrs":   ["10.0.0.0/8", "192.168.1.0/24"],
  "allowed_domains": ["target.com", "*.target.com"],
  "blocked_cidrs":   [],
  "blocked_domains": [],
  "time_window": {
    "start": "09:00",
    "end":   "17:00",
    "timezone": "Europe/Zagreb"
  }
}
```

When scope is **enabled**:

- Every command's target IP/domain is checked against allowed lists
- Out-of-scope targets are refused with a red error box
- Time-window violations (outside business hours) are also refused
- The status bar shows `●scope` (filled dot)

When scope is **disabled** (toggle from `scope` menu):

- Athena lets every command through — your y/n is the only gate
- Status bar shows `○scope` (hollow dot)

Use scope when you have a written engagement letter with explicit
allowed ranges. Don't rely on it as a safety net for personal
security research.

---

## 13. MITRE ATT&CK tracking

Type `mitre` or `attack` to see which ATT&CK techniques have been
used this session. 50 technique mappings are baked in.

Every command Athena runs is auto-tagged at execution time. The tag
appears:

- In the **DISPATCH** box (`T1046 Network Service Discovery`)
- In the **COMMAND** box title bar
- In the **status panel** (`ATT&CK ×3`)
- In the **report** (grouped by technique)

The mapping is regex-based (e.g., `nmap -sS` → T1046, `responder`
→ T1557.001, `sqlmap` → T1190, `mimikatz` → T1003.001). If a
command doesn't match a known technique, no tag is emitted —
Athena never invents one.

Tags are also attached to findings: a credential found via
`secretsdump` gets T1003.002, a hash from a `responder` capture
gets T1557.001.

---

## 14. Reporting

Two ways to generate a report:

1. **`report`** at the prompt — generate now, keep working.
2. **`exit` / `q`** — generate on session end.

Reports go to `~/.athena/logs/report_<timestamp>.md`. They contain:

- **Executive summary** — auto-generated from verified findings
- **ATT&CK coverage table** — every technique used, grouped by
  tactic
- **Findings appendix** — all verified findings with sources
- **Unverified candidates** — findings that didn't get confirmed
  (worth following up manually)
- **PTT trace** — what got tried, what worked, what was dead-end
- **Attack graph state** — final state of host/service/cred map

The report is plain markdown — render it anywhere (GitHub, Obsidian,
pandoc to PDF, etc.).

A separate **session log** is written live to
`~/.athena/logs/session_<timestamp>.txt` — every command, every raw
output, every refusal. Useful for debugging or for grep-as-you-go.

---

## 15. Tool registry — structured vs ad-hoc

The AI has two ways to issue a command:

### Structured (`[TOOL]` + `[ARGS]`)

```
[TOOL]nmap[/TOOL][ARGS]{"target":"10.0.0.5","top_ports":1000,"version":true}[/ARGS]
```

The framework looks up `nmap` in the registry, validates the args,
and builds the shell string itself. **No flag drift possible.** 28
tools registered:

| Category    | Tools                                                                |
|-------------|----------------------------------------------------------------------|
| Recon       | `nmap`, `rustscan`, `masscan`, `whatweb`, `dnsrecon`, `theharvester` |
| Web         | `gobuster_dir`, `gobuster_vhost`, `feroxbuster`, `ffuf`, `nikto`, `nuclei`, `sqlmap`, `curl_basic` |
| AD / SMB    | `smbclient_list`, `crackmapexec`, `enum4linux`, `kerbrute_userenum`, `impacket_asreproast`, `impacket_kerberoast`, `impacket_secretsdump` |
| Creds       | `hydra`, `hashcat`, `hashid`                                         |
| Exploit     | `searchsploit`, `msfvenom_payload`                                   |
| TLS         | `sslscan`, `testssl`                                                 |

### Ad-hoc (`[CMD]`)

```
[CMD]curl -s -k -H 'X-Forwarded-For: 127.0.0.1' https://target/admin[/CMD]
```

For anything not in the registry, or anything needing pipes, custom
headers, or unusual flag combinations. The AI types the shell verbatim,
and you confirm with `y/n/q`.

The framework auto-prefers structured for registered tools (the AI's
prompt explicitly tells it to). If it falls back to `[CMD]` for a
registered tool, that's usually a sign the args don't fit the schema
— not a failure.

---

## 16. Common operator patterns

### Quick "what's exposed?" recon

```
target → 192.168.1.150
workflow → 1
```

→ runs Network Recon end-to-end, ends with a service list and CVE
correlation.

### "I have a hash, crack it"

```
crack this hash: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

→ Athena routes to credential agent, runs `hashid` to identify, then
hashcat with the right mode and rockyou.

### "I have a credential, see where else it works"

```
admin:Password123! works on 192.168.1.150 SMB. Try it everywhere else.
```

→ Cred fanout queue picks up the credential and tests it against
every service in the attack graph. Each test is y/n gated.

### "Full AD engagement"

```
target → dc01.corp.local
workflow → 8
```

→ Anonymous enum, AS-REP roasting, password spray, Kerberoasting,
DCSync (pending creds). Each phase routes to the AD specialist.

### "I want to see one finding fully verified before moving on"

After Athena adds an unverified finding, you can reject the next
proposed action and ask:

```
n
```

```
verify the SSH credentials we just found by actually logging in
```

→ The AI proposes `ssh -o BatchMode=yes ...` and on success the
finding flips from unverified `?` to verified `✓`.

---

## 17. Troubleshooting

### "All providers exhausted: 401 Invalid API Key"

Your `GROQ_API_KEY` is wrong, expired, or wasn't loaded into the
shell that launched Athena. Open a fresh terminal and check:

```
echo "$GROQ_API_KEY" | head -c 12
```

Should print `gsk_` followed by 8 alphanumerics. If empty, your rc
file isn't being sourced. If different, the install set it wrong.
See `README.md` install section.

### "tool 'rustscan' not installed"

Pre-flight check working as designed. The AI will pivot to nmap on
its next turn. To install it anyway, type `tools` for the
auto-installer menu.

### A command hangs

Per-command timeouts kill anything taking longer than its policy
limit (90s for top-ports nmap, 600s for full-range nmap, 1800s for
hydra, 3600s for hashcat, 300s default). You'll see
`[COMMAND TIMED OUT after Ns — killed]`. If a hang happens before
the timeout, hit `Ctrl+C` to abort just that command.

### "UI THREAT BLOCKED: phosh" on boot

If `phosh` is in `apt list --upgradable` AND `dpkg-query` confirms
it's installed, this is a real warning — don't `apt upgrade` blindly,
your phone UI may break. The boot check just informs; it doesn't
block anything.

### Athena keeps proposing the same broken command

The loop breaker should catch this in 1–2 turns. If it doesn't, type
`n` 3–4 times to push past the dead-end limit, then guide the AI
manually: `try a completely different angle, e.g. <X>`.

### Findings list shows things that aren't real

Findings only enter the database from raw subprocess output via
strict regex. If you see something wrong, the regex was too greedy
on a particular tool's output. Use `findings` to check, then ignore
or move on — the next verification step will mark them unverified.

### Session feels slow

Athena cycles through 9 Groq models on rate-limit. The fastest
(GPT-OSS 120B, LLaMA 4 Scout 17B) are first in the chain. If you're
seeing falls to LLaMA 3.1 8B or Compound Mini, you're rate-limited
on the bigger models. Wait or type `model` to see the chain status.

### I want to start completely fresh

```
reset
```

Wipes PTT, findings, conversation history, sudo cache, attack graph,
and ATT&CK tracking. Target stays. Use `target` afterward to set a
new one.

---

**Read carefully, type clearly, respect the y/n gate, and Athena
will keep up.**
