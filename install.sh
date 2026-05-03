#!/usr/bin/env bash
# Athena installer — sets up Python deps, /usr/local/bin shortcut,
# ~/.athena directory, and (optionally) GROQ_API_KEY in your shell rc.

set -euo pipefail

ATHENA_DIR="$HOME/.athena"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/athena.py"
TARGET="/usr/local/bin/athena"
SHELL_RC="$HOME/.bashrc"
[[ -n "${ZSH_VERSION:-}" ]] && SHELL_RC="$HOME/.zshrc"

c_blue()   { printf '\033[34m%s\033[0m\n' "$*"; }
c_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
c_red()    { printf '\033[31m%s\033[0m\n' "$*"; }

c_blue "==> Athena installer"
echo

# ── Python check ──────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    c_red "Python 3 not found. Install python3 (3.10+) and re-run."
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')
if [[ "$PY_OK" != "1" ]]; then
    c_red "Python 3.10+ required, found $PY_VER"
    exit 1
fi
c_green "[ok] Python $PY_VER"

# ── Athena script presence ────────────────────────────────────────
if [[ ! -f "$SCRIPT" ]]; then
    c_red "athena.py not found at $SCRIPT"
    exit 1
fi
chmod +x "$SCRIPT"
c_green "[ok] athena.py present"

# ── Python dependencies ───────────────────────────────────────────
c_blue "==> Installing Python dependencies (groq, networkx)"
PIP_FLAGS=""
# Kali / Debian Bookworm+ ships PEP 668-protected Python — need this
if pip3 install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_FLAGS="--break-system-packages"
fi
if ! pip3 install -q $PIP_FLAGS -r "$SCRIPT_DIR/requirements.txt"; then
    c_yellow "[!] pip install failed — trying with --user"
    pip3 install -q --user $PIP_FLAGS -r "$SCRIPT_DIR/requirements.txt"
fi
c_green "[ok] dependencies installed"

# ── Athena directory ──────────────────────────────────────────────
mkdir -p "$ATHENA_DIR/logs"
c_green "[ok] $ATHENA_DIR/"

# ── Symlink to /usr/local/bin (or fall back to alias) ─────────────
LINK_OK=0
if sudo -n true 2>/dev/null || [[ -w "/usr/local/bin" ]]; then
    if [[ -L "$TARGET" || -e "$TARGET" ]]; then
        sudo rm -f "$TARGET" 2>/dev/null || rm -f "$TARGET"
    fi
    if [[ -w "/usr/local/bin" ]]; then
        ln -s "$SCRIPT" "$TARGET"
    else
        sudo ln -s "$SCRIPT" "$TARGET"
    fi
    c_green "[ok] $TARGET → $SCRIPT"
    LINK_OK=1
else
    c_yellow "==> sudo not available — using bash/zsh alias instead"
    if ! grep -q "^alias athena=" "$SHELL_RC" 2>/dev/null; then
        echo "alias athena='python3 $SCRIPT'" >> "$SHELL_RC"
        c_green "[ok] alias athena added to $SHELL_RC"
    else
        c_green "[ok] alias athena already present in $SHELL_RC"
    fi
fi

# ── GROQ_API_KEY ──────────────────────────────────────────────────
if [[ -z "${GROQ_API_KEY:-}" ]] && ! grep -q "GROQ_API_KEY" "$SHELL_RC" 2>/dev/null; then
    echo
    c_yellow "==> No GROQ_API_KEY found in your environment or shell rc"
    echo "    Get a free key at: https://console.groq.com (no credit card)"
    read -r -p "    Paste your Groq API key (or press Enter to skip): " key
    if [[ -n "$key" ]]; then
        echo "export GROQ_API_KEY=$key" >> "$SHELL_RC"
        c_green "[ok] GROQ_API_KEY written to $SHELL_RC"
        c_yellow "    Reload your shell:  source $SHELL_RC"
    else
        c_yellow "[!] Skipped. Set GROQ_API_KEY before running athena."
    fi
fi

# ── Optional: copy example scope to ~/.athena if not present ──────
if [[ ! -f "$ATHENA_DIR/scope.json" && -f "$SCRIPT_DIR/scope.example.json" ]]; then
    cp "$SCRIPT_DIR/scope.example.json" "$ATHENA_DIR/scope.json"
    c_green "[ok] example scope.json copied to $ATHENA_DIR/"
fi

echo
c_blue "==> Install complete"
if [[ "$LINK_OK" == "1" ]]; then
    echo "    Run:  athena"
else
    echo "    Run:  source $SHELL_RC && athena"
fi
echo
