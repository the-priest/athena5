<div align="center">

```
 █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗
██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
```

**AI Offensive Security Agent v6.1**  
*Bare-metal Kali NetHunter · sdm845 · Phosh UI*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Groq](https://img.shields.io/badge/Powered%20by-Groq-orange?style=flat-square)
![Model](https://img.shields.io/badge/Model-LLaMA%203.3%2070B-purple?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red?style=flat-square)
![Workflows](https://img.shields.io/badge/Workflows-23-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-grey?style=flat-square)

</div>

---

## What Is Athena?

Athena is an elite AI offensive security agent that runs entirely in your terminal on Kali Linux. It combines a large language model with a comprehensive expert knowledge base covering the full offensive security kill chain — from initial recon through exploitation, privilege escalation, lateral movement, and exfiltration.

You give it a target or an objective. It thinks like a senior penetration tester, proposes one command at a time, and waits for your approval before running anything. Every decision is explained. Nothing executes silently.

**This is not a script kiddie tool. Athena reasons about what she finds, and now she actually exploits them.**

---

## What's New in v6.1

### 🔥 Auto-Exploit Engine
When Athena finds a CVE, she doesn't just tell you about it anymore:
1. **Auto-runs searchsploit** to find matching exploits
2. **Identifies exploit type** (Metasploit module vs standalone script)
3. **Generates ready-to-run commands** with proper syntax
4. **Asks permission** before executing

Example flow:
```
[nmap finds Apache 2.4.49]
⚔️  EXPLOIT AVAILABLE: CVE-2021-41773
[OPTION 1] Apache 2.4.49 Path Traversal
Type: Metasploit Module
Suggested command:
  echo 'use exploit/multi/http/apache_normalize_path_rce' > /tmp/exploit.rc
  echo 'set RHOSTS 192.168.1.1' >> /tmp/exploit.rc
  ...
  msfconsole -q -r /tmp/exploit.rc

Execute? [y/n]
```

### 💾 Persistent Findings
- All findings saved to `~/.athena/findings.json` after **every command**
- Auto-loads on startup — never lose progress on crash
- Survives reboots, crashes, API rate limits
- Token-efficient storage (only unique values, max 30 per type)

### 🔄 Stuck Recovery (Actually Works)
When Athena hits a wall (3 consecutive failures/skips/repeats):
1. **Detects the stuck state** automatically
2. **Asks AI for 3 completely different approaches**
3. **You pick** which direction to pursue
4. **Pivots immediately** to the new strategy

No more infinite loops of the same failed command.

### 🛡️ Rate Limit Resilience
- **Retries failed requests** on next provider instead of losing them
- **9-provider fallback chain** (LLaMA 3.3 70B → GPT-OSS 120B → LLaMA 4 Scout → Qwen3 → ...)
- **Cloudflare detection** with automatic provider skip
- **Never crashes** on API errors — falls back gracefully

### 🔑 Smarter Credential Attacks
- **Uses wordlist files** instead of 4 hardcoded passwords
- **Auto-loads** `/usr/share/wordlists/metasploit/common_passwords.txt` (top 20)
- **Fallback list** of 11 common passwords if files missing
- **Lockout-aware** timing built into workflows

### 🧠 Intelligent Output Compression
- **Exploit results**: Kept intact (shell output, credentials, proof)
- **Scan noise**: Compressed aggressively (saves ~60% tokens)
- **History optimized**: Removes [THOUGHT] blocks from old messages (saves ~40% tokens)

---

## What Made v5.0→v6.1 Different

The core upgrade in v5.0 was a **14-section expert knowledge base baked permanently into the AI brain** — injected into every single turn of every session. v6.1 keeps all that expertise and adds **action**:

- **Elite pentester mindset** — objective-first thinking, trust boundary analysis, noise level awareness, fallback planning, APT-style decision making
- **Complete web exploitation** — SQLi cheat sheet, XSS filter bypass, SSRF cloud metadata chains, LFI→RCE full path, XXE, template injection for every engine, JWT attacks, OAuth flaws, deserialization fingerprinting
- **Full AD kill chain** — AS-REP roasting, Kerberoasting, pass-the-hash, DCSync, Golden Ticket, Zerologon, PetitPotam, ADCS certificate abuse ESC1-8, ACL abuse paths with exact impacket commands
- **Linux privesc complete** — every GTFOBins sudo path, SUID exploitation, cron abuse, capabilities, Docker escape, NFS no_root_squash, kernel exploit reference
- **Windows privesc complete** — SeImpersonatePrivilege with all Potato variants, unquoted service paths, AlwaysInstallElevated, DLL hijacking, stored credentials
- **Post-exploitation tradecraft** — living off the land, persistence without detection, log cleaning, evidence removal, pivoting with SSH/socat/chisel
- **High-value CVEs with exact exploitation** — EternalBlue, Zerologon, ProxyLogon, PrintNightmare, Shellshock, Dirty COW, Log4Shell, Heartbleed, Sudo Baron Samedit
- **Evasion** — AMSI bypass, ETW patching, payload encoding, LOTL delivery, file upload bypass, network blending
- **Credential chains** — password reuse logic, default credential database for every major service, hash mode table, spray timing to avoid lockout
- **Verified MSF modules** — only real module names, never hallucinated
- **Complete reverse shell reference** — bash, python, nc, php, perl, powershell + full TTY upgrade
- **Every network service** — FTP, SSH, SMTP, SMB, RDP, MySQL, Redis, MongoDB, Elasticsearch exploitation

---

## Features

- **Free to run** — Groq free tier, no paid subscription needed
- **Human-in-the-loop** — you approve every command before execution
- **Transparent reasoning** — [THOUGHT] block explains every decision before every command
- **Auto-exploit engine** — searchsploit + ready-to-run commands when CVE found
- **CVE auto-lookup** — runs automatically after every service discovery
- **Persistent findings** — saved to disk after every command, survives crashes
- **Stuck recovery** — detects loops and suggests 3 alternative approaches
- **Findings memory** — extracts IPs, ports, usernames, hashes, credentials, CVEs from every command and remembers them all session
- **Auto-pivot** — every prompt includes live findings so Athena connects a username from one step to a service from another automatically
- **LHOST auto-detection** — your attack IP detected at launch, injected into all payload workflows
- **Session logging** — every session saves to `~/.athena/logs/` automatically
- **Session report** — structured report generated on exit with all findings
- **23 pre-built workflows** covering the complete offensive security kill chain
- **Phosh-safe** — hard-blocks all `apt upgrade` variants that would destroy the Phosh UI
- **Rate limit resilient** — 9-provider fallback chain, never crashes on API errors

---

## Quick Start

```bash
git clone https://github.com/the-priest/athena5.git
cd athena5
bash install.sh
athena
```

---

## Full Setup

### Step 1 — Get a Free Groq API Key

1. Go to **https://console.groq.com**
2. Sign up for a free account
3. Click **API Keys** → **Create API Key**
4. Copy the key — it starts with `gsk_` and you only see it once

### Step 2 — Clone and Install

```bash
# Install git if needed
sudo apt install -y git

# Clone the repo
git clone https://github.com/the-priest/athena5.git
cd athena5

# Run the installer — handles everything
bash install.sh
```

The installer automatically:
- Checks Python 3
- Installs the `groq` Python package
- Installs missing security tools (nmap, arp-scan, nikto, gobuster, whatweb, searchsploit, hydra)
- Prompts for your Groq API key and saves it permanently to `~/.bashrc` or `~/.zshrc`
- Copies Athena to `~/.athena/athena.py`
- Creates the `athena` command at `/usr/local/bin/athena`

### Step 3 — Launch

```bash
athena
```

If `athena` returns command not found, run `source ~/.bashrc` first then try again.

---

## All 23 Workflows

| # | Workflow | Tools |
|---|---|---|
| 1 | Network Recon | arp-scan, nmap, searchsploit |
| 2 | Web Enumeration | whatweb, nikto, gobuster, ffuf |
| 3 | Post-Exploitation | native shell, GTFOBins |
| 4 | Metasploit Exploit | msfconsole (non-interactive) |
| 5 | SQL Injection | sqlmap + manual |
| 6 | Hash Cracking | hashcat, hashid |
| 7 | Password Spraying | hydra, crackmapexec |
| 8 | Active Directory Recon | enum4linux, impacket, crackmapexec |
| 9 | Payload Generation | msfvenom |
| 10 | Bluetooth Recon | hcitool, sdptool |
| 11 | OSINT Profiling | theHarvester, whois, dig |
| 12 | SSL/TLS Audit | sslscan, testssl.sh, sslyze |
| 13 | DNS Enumeration | dnsrecon, fierce, dnsenum |
| 14 | SMB Attack | smbclient, crackmapexec, enum4linux |
| 15 | API Security Testing | curl, arjun, ffuf |
| 16 | Linux Privilege Escalation | linpeas, linux-exploit-suggester |
| 17 | Windows Privilege Escalation | winpeas, accesschk |
| 18 | Lateral Movement | impacket, crackmapexec, chisel |
| 19 | Container & Cloud Escape | docker, kubectl, cloud metadata |
| 20 | IDS/IPS Evasion | nmap evasion, macchanger |
| 21 | Data Exfiltration | curl, DNS, ICMP covert channels |
| 22 | Forensics | volatility, binwalk, strings |
| 23 | Steganography | steghide, zsteg, exiftool |

---

## How It Works

```
You type an objective
        │
        ▼
Athena sends it to Groq API (LLaMA 3.3 70B)
with full expert knowledge base injected
        │
        ▼
Model returns [THOUGHT] (expert reasoning) + [CMD] (one command)
        │
        ▼
You see the reasoning and proposed command
        │
     [y / n / q]
        │
   y = execute ──→ output captured ──→ CVE auto-lookup ──→ exploit suggestion
                                               │
                              findings extracted ──→ saved to disk
                                               │
                              fed back to model with pivot context
                                               │
                                         loop continues
```

---

## REPL Commands

| Command | What it does |
|---|---|
| `workflow` | Open the 23-workflow menu |
| `target` | Set or update the session target |
| `findings` | Show all findings extracted this session |
| `remember` | Save important findings (persistent across sessions) |
| `recall` | Load remembered facts into AI context |
| `tools` | Show tool availability + auto-install missing |
| `save` | Save conversation to file |
| `report` | Generate structured session report |
| `model` | Show current provider and full chain |
| `clear` | Clear AI memory (findings preserved) |
| `help` | Show command reference |
| `exit` / `q` | End session and generate report |

---

## File Structure

```
athena5/
├── athena.py          Complete agent — single Python file, 2000+ lines
├── install.sh         Automated installer
├── requirements.txt   Python deps (groq only)
├── LICENSE            MIT
└── README.md          This file
```

After first run:
```
~/.athena/
├── findings.json      Persistent findings (survives crashes)
├── remembered.txt     User-saved facts (remember/recall)
└── logs/
    ├── session_*.txt  Full session logs
    └── report_*.txt   Structured reports
```

---

## Troubleshooting

**`athena: command not found`** — Run `source ~/.bashrc` then try again

**`GROQ_API_KEY is not set`** — Run `source ~/.bashrc` or re-run `bash install.sh`

**`No [CMD] block found`** — Rephrase objective more specifically or type `clear` to reset memory

**Boot check is slow** — Only runs once per boot, cached after via `/tmp/athena_session.lock`

**Tools not found** — Re-run `bash install.sh`, it installs only what is missing

**Running from Termux** — Web tools work fine, raw socket tools (arp-scan) need root

**Stuck in loop** — Wait for 3 failures, stuck recovery will trigger automatically

**Rate limit hit** — Athena auto-switches to next provider in chain, no action needed

**Findings lost on crash** — They're saved to `~/.athena/findings.json`, just restart athena

---

## Legal Notice

> This tool is for authorized security testing only. Use only on systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal. The authors accept no liability for misuse.

---

## Changelog

### v6.1 (2024)
- ✅ Auto-exploit engine with ready-to-run commands
- ✅ Persistent findings saved to disk
- ✅ Stuck recovery that actually works
- ✅ Rate limit resilience with 9-provider chain
- ✅ Smarter credential attacks using wordlist files
- ✅ Intelligent output compression
- ✅ Enhanced CVE lookup by number and service
- ✅ Remember/recall system for cross-session facts

### v5.0 (2024)
- 14-section expert knowledge base
- 23 pre-built workflows
- Dynamic KB injection
- Auto-pivot on findings
- Session logging and reporting

---

<div align="center">
<sub>Built for Kali NetHunter · Powered by Groq · MIT License · Commander: The Priest</sub>
</div>
