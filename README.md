# Athena

An AI-assisted REPL for offensive security work on Kali. Wraps the Groq API,
adds a y/n approval gate, a task-tree state model, and pattern-matching to
extract findings from command output. Everything is gated — Athena never runs
anything without you pressing `y`.

This is a tool that helps an operator move faster. It is not autonomous.
It does not replace knowing what you're doing.

---

## What v7.0 changed

v6.1 had real problems. v7.0 fixes them:

- **No more on-disk persistence.** v6.1 wrote findings to `~/.athena/findings.json`
  and reloaded them every launch. That file got polluted with phantom credentials
  the AI hallucinated in prior sessions, which then got fed back into the next
  session as "known facts" and the loop kept trying garbage like `helper:helper`
  and `200:not`. v7.0 has zero on-disk state. Every launch is fresh.

- **Findings are now source-tagged.** Every finding records the exact subprocess
  command that produced it. The regex extractor only runs against raw `stdout`
  from a real command. It never runs against the LLM's own prose. This kills
  the phantom-credential problem at the source.

- **Pentesting Task Tree (PTT).** Replaces v6.1's flat `findings` dict.
  Hierarchical state — todo → in_progress → done → dead_end. Each node tracks
  its own attempt count and gets marked dead-end after 4 failed tries so the
  loop stops looping.

- **Specialist system prompts.** Eleven role-specific prompts (recon, web, ad,
  linux_privesc, etc.) get selected based on the current PTT node's phase.
  This is *not* multi-agent in the sense of separate agents running in parallel
  — it's deterministic prompt-swapping. One LLM call per turn. Same rate-limit
  budget as v6.1.

- **Tool wrappers.** Typed builders for ~25 common tools (nmap, feroxbuster,
  hydra, sqlmap, impacket-*, hashcat, nxc, etc.). The LLM picks args, the
  wrapper produces the shell string. This catches a lot of the "AI suggested
  `nano`/interactive `msfconsole`/raw `ssh user@host`" failures from v6.1.

- **Confidence flag on every turn.** The LLM has to emit `[CONF]green|yellow|red[/CONF]`.
  Red blocks the command and forces a recon pivot. Yellow warns. This is
  self-reported by the LLM — it's a hint, not a measurement.

- **PoC verification (optional).** When the LLM emits `[VERIFY]<cmd>[/VERIFY]`,
  the verify command runs through the same y/n gate. If it exits cleanly and
  doesn't contain auth-failure strings, the finding gets promoted to verified.
  Reports only include verified findings unless you ask otherwise.

- **Groq-only.** Cerebras and Ollama are gone. Provider chain is 9 Groq models
  biggest → smallest, fallback on 429/CF/404.

---

## What it can do

- Drives common Kali workflows (port scan → service enum → CVE lookup →
  exploit suggestion → privesc) with the LLM picking the next step
- Auto-runs `searchsploit` on CVEs and service versions found in output, and
  surfaces ready-to-run MSF resource scripts when an exploit exists
- Extracts IPs, ports, services, hashes, credentials, CVEs, SSH keys, AWS
  keys, sensitive paths from real command output
- Builds non-interactive forms of common commands (msfconsole resource
  scripts, sshpass for SSH, sqlmap --batch, etc.)
- Falls through 9 Groq models when one rate-limits
- Generates a markdown report at session end with verified findings + raw
  appendix with provenance

---

## What it can't do (be realistic)

- **It's not autonomous.** Every command requires `y`. If you don't read the
  command before approving, you're trusting the LLM blindly.
- **The "agents" are prompt fragments, not separate processes.** "Multi-agent"
  here means "the system prompt changes based on what phase we're in." It
  doesn't mean parallel agents collaborating.
- **Tool wrapper coverage is partial.** ~25 of the 298 tools in the registry
  have typed wrappers. The rest, the LLM constructs by hand and is more likely
  to get wrong.
- **Finding extraction is regex.** It will miss things. It will sometimes
  extract noise. The "verified vs unverified" split helps but isn't perfect.
- **PoC verification is heuristic.** It checks the verify command's output
  for "permission denied" / "401" / etc. Real-world output is messier than
  that, so verification can produce false positives and false negatives.
- **Confidence is LLM self-reported.** Don't treat green as "this is safe."
  Treat it as "the model is willing to commit to this answer."
- **Knowledge is frozen at session start.** No retrieval, no online docs
  lookup, no learning between sessions. The KB is a hand-written ~16-section
  cheatsheet baked into the system prompt.
- **Context window is finite.** History is truncated to 16 messages. Long
  engagements will lose early context. Use the report at the end to preserve
  what mattered.
- **Reports are LLM-generated prose.** They can contain inaccuracies. The raw
  findings appendix at the bottom of the report file is the source of truth.
- **No interactive tool support.** `msfconsole` interactive, live `ssh`
  sessions, `gdb` debugging — Athena blocks these. Use them in a separate
  terminal if you need them.
- **Dependent on Groq.** No Groq API key, no Athena. No Groq service, no
  Athena.

---

## Requirements

- Kali Linux (or anything with the Kali tool set)
- Python 3.10+
- `pip install groq`
- A Groq API key in `~/.bashrc`:
  ```bash
  export GROQ_API_KEY='gsk_...'
  ```

Common Kali tools should be on PATH. Athena's `tools` command will show
which are missing and offer to apt-install them.

---

## Install

```bash
git clone https://github.com/<your-username>/athena-public.git
cd athena-public
# Drop your Groq key into ~/.bashrc, then source it
source ~/.bashrc
# Run
python3 examples/scripts/hybrid_think.py
```

Or if you have an `athena` launcher already, just `athena`.

---

## Usage

The REPL accepts plain English ("scan 10.0.0.5 for SMB vulns") or these
commands:

| Command    | What it does                                            |
|------------|---------------------------------------------------------|
| `workflow` | Pick from 23 pre-built workflows (recon, AD, web, etc.) |
| `target`   | Set or update target IP / domain / mission notes        |
| `findings` | Show extracted findings (verified + unverified)         |
| `tree`     | Show the Pentesting Task Tree                           |
| `tools`    | Show Kali tool availability + auto-install missing      |
| `model`    | Show provider chain status                              |
| `agents`   | List all specialist agent roles                         |
| `save`     | Save conversation transcript                            |
| `report`   | Generate report now (also runs on exit)                 |
| `clear`    | Clear LLM history (keeps PTT + findings)                |
| `reset`    | Wipe everything and start fresh                         |
| `help`     | Command reference                                       |
| `exit`     | End session and write report                            |

Logs go to `~/.athena/logs/`. Reports go to `~/.athena/logs/report_*.md`.

---

## How a turn works

1. Athena picks a specialist system prompt based on the current PTT node's phase.
2. It sends one Groq API call with: persona + KB sections + PTT state +
   findings + Kali tool registry + recent history.
3. LLM responds with `[THOUGHT][CMD][CONF]` (and optionally `[VERIFY]`/`[HANDOFF]`).
4. Athena prints the thought, shows the command, and asks for `y/n/q`.
5. On `y`, the command runs. Output is parsed for findings (source-tagged
   to this command).
6. If `[VERIFY]` was set, the verify command also runs through the gate.
7. The output is compressed and fed back to the next turn.
8. If the LLM says `WORKFLOW_COMPLETE`, Athena moves to the next PTT node.
9. After 3 consecutive rejected/repeated commands, Athena stops and asks the
   LLM for 3 alternative approaches.

---

## Architecture

- `hybrid_think.py` is one file (~3700 lines). No external state.
- Classes: `Finding`, `PTTNode`, `PTT`, `ToolBuilder`, `AthenaSession`.
- Constants up top: `PROVIDER_CHAIN`, `KALI_TOOLS`, `FINDING_PATTERNS`,
  `BANNED_COMMANDS`, `DESTRUCTIVE_COMMANDS`, `INTERACTIVE_BLOCKED`,
  `AGENT_SPECS`, `WORKFLOWS`.
- `KB[1]` through `KB[16]` are the hand-written knowledge sections that get
  selectively included in system prompts.

---

## Known limitations / things I'd improve next

- Tool wrapper coverage should grow. Big gaps: bloodhound-python, wireless
  tools, mobile tools, container/cloud tools.
- The verify heuristic is too crude. A proper verifier would parse tool-
  specific output (e.g. nxc returns `[+]` for success, `[-]` for fail).
- No support for interactive tools is sometimes a real limitation. A `tmux`
  spawn mode would help — let the operator drop into an interactive session
  and come back.
- The 16-message history window is too small for long engagements. A
  rolling-summary approach would let context survive longer.
- The KB is static. A retrieval layer over a notes folder would let the
  operator add custom playbooks without editing source.
- No tests in the repo. Should be.

---

## Safety

Athena will refuse:
- `rm -rf /` and similar wipes
- `dd if=...of=/dev/sd*`
- `mkfs`, fork bombs, `shutdown`, `init 0/6`
- `apt upgrade` (because it can break Phosh/X11 on Kali NetHunter)

Athena requires double-confirmation for:
- Anything writing to `/etc/`
- Service stop/disable
- User add/delete
- iptables/ufw flush

Athena blocks (with a fix message):
- Interactive tools that would hijack the terminal — `msfconsole` (without
  `-q -r`), `ssh user@host` without `sshpass`, `nano`, `vim`, `top`, `mysql`
  without `-e`, etc.

The y/n gate is the real safety. The lists above just catch the obvious stuff.

---

## License

Whatever the rest of the repo is licensed under.

## Credits

Built by The Priest. Iterated with Claude (Anthropic).
