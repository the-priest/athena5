"""
foresight — predict the consequences of an action before it runs, and judge
whether it should.

This is the part that takes LeCun's complaint seriously inside the narrow
world Basilisk actually operates: a shell on one machine.  Basilisk can't model
physics, but it CAN model "what does this command do to this system, is it
reversible, how big is the blast radius, and does that match what the operator
seems to want."  The output enriches the confirmation card and can hard-block
catastrophes even in auto mode.

Two tiers:

  1. DETERMINISTIC rules (always on, free, instant).  Pattern-match the
     command against known-catastrophic and known-risky shapes.  These set a
     FLOOR: a rule-block cannot be argued down by the model.
  2. MODEL pass (optional).  If a completer is supplied, ask it to predict
     consequences as structured JSON.  It may ESCALATE a verdict (allow->
     caution, caution->block) but never DE-escalate below the rule floor.
     Fail-open on error (returns the rule verdict) so a flaky model never
     blocks legitimate work.

Verdict the host acts on:
    allow   — run normally (still subject to the operator's confirm gate)
    caution — run allowed, but the card shows the predicted consequences and
              undo hint; in auto-mode the host SHOULD still confirm these
    block   — refuse to run even in auto-mode; require an explicit override
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional


PROMPT_BLOCK = (
    "FORESIGHT: before any state-changing command runs, its consequences are "
    "predicted and a verdict (allow/caution/block) is attached. Catastrophic, "
    "irreversible commands are blocked outright even in auto-mode and need an "
    "explicit override from the operator. When you propose a command, prefer "
    "the reversible form and name the undo path — it clears foresight faster."
)


# (compiled_pattern, reversibility, blast_radius, reason)
# Order matters: first match wins for the rule floor.
_CATASTROPHIC: List = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b.*(/|~|\*|\$HOME)"),
     "irreversible", "user",
     "recursive force-delete of a broad path — data loss, no undo"),
    (re.compile(r"\b(mkfs|mke2fs|mkfs\.\w+)\b"),
     "irreversible", "system", "formats a filesystem — destroys all data on it"),
    (re.compile(r"\bdd\b.*\bof=/dev/(sd|nvme|mmcblk|loop)"),
     "irreversible", "system", "raw write to a block device — wipes the disk/partition"),
    (re.compile(r"\b(fdisk|sfdisk|parted|gdisk)\b.*?/dev/"),
     "irreversible", "system", "edits the partition table — can brick the boot/data layout"),
    (re.compile(r"\bfastboot\s+(flash|erase|format)\b"),
     "irreversible", "system",
     "flashes/erases a device partition — A/B slot or boot brick risk on the OnePlus 6"),
    (re.compile(r"(:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|fork\s*bomb)"),
     "irreversible", "system", "fork bomb — exhausts the process table, hangs the box"),
    (re.compile(r">\s*/dev/(sd|nvme|mmcblk)"),
     "irreversible", "system", "redirects output straight onto a block device"),
    (re.compile(r"\bchmod\s+-R\s+0*7{3}\s+/(?![a-zA-Z])"),
     "hard", "system", "recursive 777 from root — wrecks the permission model"),
]

_RISKY: List = [
    (re.compile(r"\b(iptables|nft)\b.*(-F|flush)"),
     "hard", "network", "flushes firewall rules — drops your packet filtering"),
    (re.compile(r"\bufw\s+(disable|reset)\b"),
     "hard", "network", "disables/resets the host firewall"),
    (re.compile(r"\bsystemctl\s+(stop|disable|mask)\s+(ssh|sshd|NetworkManager|network)"),
     "reversible", "network", "stops/disables connectivity or remote access — lockout risk"),
    (re.compile(r"\bip\s+link\s+set\s+\w+\s+down\b"),
     "reversible", "network", "brings an interface down — you may lose the link you're on"),
    (re.compile(r"(?<![\w/])(passwd|usermod|chsh)\b"),
     "hard", "user", "changes an account credential/shell"),
    (re.compile(r"\bapt(-get)?\s+(remove|purge|autoremove)\b"),
     "hard", "system", "removes packages — may pull dependencies with them"),
    (re.compile(r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|push\s+.*--force)"),
     "hard", "user", "discards/overwrites git history or working tree"),
    (re.compile(r"\bkill(all)?\s+-9\b"),
     "reversible", "process", "hard-kills processes — unsaved state in them is lost"),
    (re.compile(r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(bash|sh|python)"),
     "hard", "system", "pipes a remote script straight into a shell — runs unaudited code"),
    (re.compile(r"\bchown\s+-R\b.*/(?!home|tmp|opt)"),
     "hard", "system", "recursive ownership change on a system path"),
]

_UNDO_HINTS = {
    "apt": "reinstall with: apt install <pkg>  (apt keeps removed-pkg lists in /var/log/apt/history.log)",
    "pacman": "reinstall with: sudo pacman -S <pkg>  (removed-pkg history is in /var/log/pacman.log; cached .pkg.tar.zst files under /var/cache/pacman/pkg let you reinstall the exact version offline)",
    "dnf": "reinstall with: sudo dnf install <pkg>  (undo the whole transaction with: sudo dnf history undo last)",
    "iptables": "rules are not saved unless you persisted them; reboot or reload your saved ruleset to restore",
    "ufw": "re-enable with: ufw enable  (and reload your rule profile)",
    "systemctl": "restart/enable the unit: systemctl enable --now <unit>",
    "git_reset": "recover via: git reflog  (reachable commits survive ~30 days)",
}


# Offensive-security tooling. Running these against an AUTHORISED target is
# normal work that does not touch the operator's OWN machine — so once the
# catastrophic/risky floor is clear, they don't need consequence-prediction and
# must never be escalated for merely carrying scary-looking payload strings.
_OFFENSIVE_TOOLS = frozenset({
    "nmap", "masscan", "rustscan", "naabu", "sqlmap", "nikto", "nuclei", "ffuf",
    "gobuster", "feroxbuster", "dirb", "dirbuster", "dirsearch", "wfuzz",
    "whatweb", "wpscan", "httpx", "katana", "subfinder", "amass", "dnsx",
    "assetfinder", "arjun", "paramspider", "dalfox", "xsstrike", "commix",
    "tplmap", "jwt_tool", "hydra", "medusa", "patator", "kerbrute", "netexec",
    "crackmapexec", "nxc", "smbmap", "enum4linux", "enum4linux-ng", "hashcat",
    "john", "hashid", "hash-identifier", "responder", "evil-winrm", "gowitness",
    "eyewitness", "testssl", "testssl.sh", "sslscan", "wafw00f", "gau",
    "waybackurls", "httprobe", "dnsrecon", "fierce", "sublist3r", "cewl",
    "nc", "ncat", "socat",
})

# Writing fetched/scanned output to a SENSITIVE local path is not benign recon —
# let the floor/model judge those instead of auto-allowing.
_LOCAL_WRITE_DANGER = re.compile(
    r"(-[oO]\s+|>>?\s*)\s*("
    r"/etc/|/root/|/boot/|/usr/|/bin/|/sbin/|/lib/|/var/spool/cron|"
    r"/etc/systemd|~/\.ssh|\$HOME/\.ssh|"
    r"[~/][^\s]*(authorized_keys|\.bashrc|\.zshrc|\.profile|crontab|id_rsa))")


def _is_offensive(command: str) -> bool:
    """True when the command is recognisable authorised-target offensive work
    (a scanner/exploit tool, or curl/wget/httpie carrying a request) that poses
    no risk to the OPERATOR'S OWN system. Deliberately excludes a remote-script-
    into-shell pipe and writes to a sensitive local path."""
    cmd = (command or "").strip()
    if not cmd:
        return False
    low = cmd.lower()
    if re.search(r"\|\s*(sudo\s+)?(bash|sh|zsh|python)\b", low):
        return False   # curl | bash and friends stay under the risky floor
    if _LOCAL_WRITE_DANGER.search(cmd):
        return False
    toks = low.split()
    first = toks[0].rsplit("/", 1)[-1] if toks else ""
    if first in _OFFENSIVE_TOOLS:
        return True
    if first in ("curl", "wget", "http", "https", "httpie"):
        return True   # web requests — payload CONTENTS never touch the local box
    return False


def _rule_floor(command: str) -> Dict[str, Any]:
    cmd = command.strip()
    for rx, rev, blast, reason in _CATASTROPHIC:
        if rx.search(cmd):
            return {"verdict": "block", "reversibility": rev,
                    "blast_radius": blast, "reasons": [reason],
                    "undo": None, "rule": "catastrophic"}
    for rx, rev, blast, reason in _RISKY:
        if rx.search(cmd):
            undo = None
            for key, hint in _UNDO_HINTS.items():
                if key.split("_")[0] in cmd:
                    undo = hint
                    break
            return {"verdict": "caution", "reversibility": rev,
                    "blast_radius": blast, "reasons": [reason],
                    "undo": undo, "rule": "risky"}
    # default: nothing matched
    blast = "system" if re.search(r"\bsudo\b", cmd) else "user"
    return {"verdict": "allow", "reversibility": "reversible",
            "blast_radius": blast, "reasons": [], "undo": None, "rule": None}


_ORDER = {"allow": 0, "caution": 1, "block": 2}


def _merge(floor: Dict[str, Any], model: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not model:
        return floor
    # The model may only escalate (>= floor).  Never below the rule floor.
    mv = model.get("verdict", "allow")
    if _ORDER.get(mv, 0) > _ORDER.get(floor["verdict"], 0):
        merged = dict(floor)
        merged["verdict"] = mv
        merged["reversibility"] = model.get("reversibility", floor["reversibility"])
        merged["blast_radius"] = model.get("blast_radius", floor["blast_radius"])
        extra = model.get("reasons") or []
        merged["reasons"] = list(floor["reasons"]) + [r for r in extra
                                                      if r not in floor["reasons"]]
        merged["undo"] = floor.get("undo") or model.get("undo")
        merged["refined_by"] = "model"
        return merged
    # Model agreed or under-called; keep the floor but fold in any reasons.
    if model.get("reasons"):
        floor = dict(floor)
        floor["reasons"] = list(floor["reasons"]) + [
            r for r in model["reasons"] if r not in floor["reasons"]]
    return floor


def _model_assess(command: str, kind: str,
                  complete_fn: Callable[[str, str], str]) -> Optional[Dict[str, Any]]:
    sys = ("You are a consequence predictor for shell commands on a Linux "
           "operator's own machine. Predict what the command DOES and judge "
           "risk. Output ONE JSON object, no prose, no markdown:\n"
           '{"verdict":"allow|caution|block",'
           '"reversibility":"reversible|hard|irreversible",'
           '"blast_radius":"process|user|system|network",'
           '"reasons":["short, concrete"],"undo":"how to reverse, or null"}\n'
           "block only for irreversible destruction (wiping disks/data, "
           "bricking boot, fork bombs). caution for risky-but-recoverable. "
           "IMPORTANT: this is an authorised security operator. A command may be "
           "offensive-security work against a REMOTE authorised target — "
           "requests carrying payloads (SQLi/XSS/traversal/command-injection "
           "test strings, JWT tokens, a benign `id`/`whoami` RCE proof), "
           "scanners, and injection strings that LOOK alarming do NOT affect this "
           "machine. Judge only the risk to the OPERATOR'S OWN system; a "
           "payload's contents are not a local action, so a curl/scanner "
           "carrying one is `allow`. Be terse and specific.")
    usr = f"kind={kind}\ncommand:\n{command[:1200]}"
    try:
        raw = (complete_fn(sys, usr) or "").strip().strip("`")
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1:
            return None
        obj = json.loads(raw[start:end + 1])
        if obj.get("verdict") in _ORDER:
            return obj
    except Exception:
        return None
    return None


def assess(command: str, kind: str = "shell",
           complete_fn: Optional[Callable[[str, str], str]] = None
           ) -> Dict[str, Any]:
    floor = _rule_floor(command or "")
    # A hard rule-block needs no model spend.
    if floor["verdict"] == "block":
        return floor
    # Authorised offensive work is normal and safe to the operator's OWN box. The
    # consequence-predictor kept mistaking scary-LOOKING payload STRINGS (DROP
    # TABLE, ;id, <script>, an 'rm' inside a test value) for local danger and
    # pausing autonomous engagements. When the floor is clear AND the command is
    # recognisable offensive tooling (not piping a remote script into a shell,
    # not writing to a sensitive local path), allow it without model spend. The
    # catastrophic + risky rule floors above still run FIRST and are untouched.
    if floor["verdict"] == "allow" and _is_offensive(command or ""):
        out = dict(floor)
        out["rule"] = "offensive-allow"
        return out
    model = _model_assess(command, kind, complete_fn) if complete_fn else None
    return _merge(floor, model)


def render_card(verdict: Dict[str, Any]) -> str:
    """One-line-per-fact summary for the confirm card / chat."""
    v = verdict.get("verdict", "allow")
    if v == "allow" and not verdict.get("reasons"):
        return ""
    icon = {"allow": "○", "caution": "▲", "block": "■"}.get(v, "•")
    lines = [f"{icon} foresight: {v.upper()} "
             f"({verdict.get('reversibility','?')}, "
             f"blast={verdict.get('blast_radius','?')})"]
    for r in verdict.get("reasons", []):
        lines.append(f"   · {r}")
    if verdict.get("undo"):
        lines.append(f"   undo: {verdict['undo']}")
    return "\n".join(lines)
