# Changelog

All notable changes to Athena are documented here.
Format: version, date, what changed, what broke or is still broken.

---

## v7.0 — 2026-05

Complete architectural rewrite. The main driver was v6.1 having a phantom-
credential pollution loop that made it almost useless after a few sessions.

**Removed**
- On-disk persistence (`~/.athena/findings.json`, `remembered.txt`)
  These were the root cause of v6.1's core bug. The AI would hallucinate
  credentials in its prose, those got regex-extracted and saved, then got
  loaded next session as "known facts" and fed back into prompts.
  Result: infinite loops trying garbage creds like `helper:helper`, `200:not`.
  v7.0 is stateless per session. No persistence anywhere.
- `remember` and `recall` REPL commands (no persistence = nothing to recall)
- Cerebras provider (unused and untested)
- Ollama provider (caused more problems than it solved on NetHunter)

**Added**
- Pentesting Task Tree (PTT): hierarchical task state replacing the flat
  findings dict. Nodes track status (todo/in_progress/done/dead_end),
  attempt counts, and the last command run. The `tree` command renders it.
- Source-tagged findings: every Finding dataclass records the exact subprocess
  command that produced the value. The regex extractor only runs against raw
  stdout, never against the LLM's own output.
- 11 specialist system prompts: strategist, recon, web, network, ad,
  linux_privesc, windows_privesc, credential, exfil, evasion, reporter.
  Dispatched deterministically based on the current PTT node's phase.
  This is not multi-agent in the parallel-processes sense — it's one LLM
  call per turn, same rate-limit budget as v6.1.
- PoC verification: when the LLM emits [VERIFY]<cmd>[/VERIFY], the verify
  command goes through the same y/n gate. Verified findings are tagged;
  reports only include verified findings.
- Confidence filter: every turn includes [CONF]green|yellow|red[/CONF].
  Red blocks the command and forces a recon pivot.
- ToolBuilder class: typed builders for ~25 tools (nmap, feroxbuster, hydra,
  sqlmap, crackmapexec/nxc, impacket-*, hashcat, etc.) that produce
  non-interactive shell strings. Reduces the "AI suggested nano/ssh/msfconsole"
  failures.
- Kali tool registry: 298 tools in 28 categories baked into every system
  prompt. `tools` command shows availability per category.
- `tree` REPL command: colored PTT render.
- `agents` REPL command: list all specialist roles.
- `reset` REPL command: wipe PTT + history + findings, keep target.
- Groq model chain extended to 9 models, ordered biggest→smallest.
- max_tokens raised from 1024 to 2048.
- History window raised from 10 to 16 messages.

**Fixed**
- Port regex: v6.1 had two capture groups, causing service names ("ssh",
  "http") to get added as "port" findings. Fixed to single capture group.
- nmap ToolBuilder: was emitting `-sV -sV` (double flag). Fixed.
- Credential regex: tightened to require colon or equals separator after
  the field name, which rejects AI prose patterns like "password not"
  while still matching real tool output like "password: hunter2".

**Known issues / still missing**
- Tool wrapper coverage is partial. ~25 of 298 tools have typed wrappers.
  The rest the LLM constructs by hand and is more error-prone.
- PoC verification heuristic is crude. Checks for "permission denied" / "401"
  strings in output. Complex real-world output will fool it.
- Confidence is LLM self-reported. Not a measurement.
- Reports are LLM-generated prose. The raw findings appendix at the bottom
  is more reliable than the narrative sections.
- No interactive tool support. msfconsole, ssh sessions, gdb, etc. require
  a separate terminal.
- 16-message history still loses context on long engagements.

---

## v6.1 — 2026-04

**What it tried to do**
- Added auto-exploit engine: searchsploit on CVE finds, MSF resource scripts
- Persistent findings saved to `~/.athena/findings.json`
- Stuck recovery (3 failures → 3 alternative approaches)
- 9-provider Groq fallback chain
- Remember/recall commands for cross-session facts

**What went wrong**
- The persistent findings system caused the core bug that killed v6.1's
  usefulness. AI hallucinated credentials in its reasoning text, regex
  extracted them as real findings, saved them, loaded them next session.
  By session 2-3, the AI was using "200:not" and "helper:helper" as real
  credentials in every engagement. `_handle_remember` and the
  `~/.athena/findings.json` auto-load were removed entirely in v7.0.
- Provider fallback would silently retry a request the AI had already started
  composing, causing duplicate or split outputs in some edge cases.
- Regex extraction ran against AI prose, not just subprocess stdout. This was
  the architectural mistake that made the phantom-credential problem possible.

---

## v6.0 — 2026-04

- Groq API only (Cerebras and Ollama dropped due to reliability issues)
- Tool availability check on startup
- Interactive tool detection with fix messages
- Destructive command safety list

---

## v5.0 — 2026-04

- 14-section knowledge base baked into system prompts
- 23 pre-built workflows
- Dynamic KB section injection (only relevant sections per workflow)
- Auto-pivot: live findings injected into every subsequent prompt
- Session logging and report generation
- LHOST auto-detection
- rockyou.txt auto-unzip

---

## v4.0 — 2026-04

- CVE auto-lookup via searchsploit after recon commands
- Findings extraction (IPs, ports, hashes, creds, CVEs) into in-memory dict
- Session report on exit
- `findings` and `report` REPL commands

---

## v1.0–v3.0 — early 2026

Initial versions: single Groq API call with a basic security system prompt,
no state, no findings extraction, no safety gates. Used for proof-of-concept.
