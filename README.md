<div align="center">

```
 █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗
██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
```

**AI Offensive Security Agent v5.0**  
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

**This is not a script kiddie tool. Athena reasons about what she finds.**

---

## What Makes v5.0 Different

The core upgrade in v5.0 is a **14-section expert knowledge base baked permanently into the AI brain** — injected into every single turn of every session. This means Athena reasons from deep expertise rather than general knowledge:

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
- **CVE auto-lookup** — searchsploit runs automatically after every service discovery
- **Findings memory** — extracts IPs, ports, usernames, hashes, credentials, CVEs from every command and remembers them all session
- **Auto-pivot** — every prompt includes live findings so Athena connects a username from one step to a service from another automatically
- **LHOST auto-detection** — your attack IP detected at launch, injected into all payload workflows
- **Session logging** — every session saves to `~/.athena/logs/` automatically
- **Session report** — structured report generated on exit with all findings
- **23 pre-built workflows** covering the complete offensive security kill chain
- **Phosh-safe** — hard-blocks all `apt upgrade` variants that would destroy the Phosh UI

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/athena.git
cd athena
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
git clone https://github.com/YOUR_USERNAME/athena.git
cd athena

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
   y = execute ──→ output captured ──→ CVE auto-lookup ──→ findings extracted
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
| `save` | Save conversation to file |
| `report` | Generate structured session report |
| `clear` | Clear AI memory (findings preserved) |
| `help` | Show command reference |
| `exit` / `q` | End session and generate report |

---

## File Structure

```
athena/
├── athena.py          Complete agent — single Python file, 1700+ lines
├── install.sh         Automated installer
├── requirements.txt   Python deps (groq only)
├── LICENSE            MIT
└── README.md          This file
```

---

## Troubleshooting

**`athena: command not found`** — Run `source ~/.bashrc` then try again

**`GROQ_API_KEY is not set`** — Run `source ~/.bashrc` or re-run `bash install.sh`

**`No [CMD] block found`** — Rephrase objective more specifically or type `clear` to reset memory

**Boot check is slow** — Only runs once per boot, cached after via `/tmp/athena_session.lock`

**Tools not found** — Re-run `bash install.sh`, it installs only what is missing

**Running from Termux** — Web tools work fine, raw socket tools (arp-scan) need root

---

## Legal Notice

> This tool is for authorized security testing only. Use only on systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal. The authors accept no liability for misuse.

---

<div align="center">
<sub>Built for Kali NetHunter · Powered by Groq · MIT License · Commander: The Priest</sub>
</div>
