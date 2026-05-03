#!/usr/bin/env bash
# Athena installer — sets up Python deps, /usr/local/bin shortcut,
# ~/.athena directory, and (optionally) GROQ_API_KEY in your shell rc.
#
# v7.2 — works correctly for both bash and zsh users.  v7.1 had a
# detection bug where it always picked .bashrc because ZSH_VERSION is
# only set inside zsh itself, not when zsh users run `bash install.sh`.
# Now we detect the actual login shell via $SHELL and additionally
# write to every rc file that already exists on the system, so the
# install works regardless of which shell you launch later.

set -euo pipefail

ATHENA_DIR="$HOME/.athena"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/athena.py"
TARGET="/usr/local/bin/athena"

c_blue()   { printf '\033[34m%s\033[0m\n' "$*"; }
c_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
c_red()    { printf '\033[31m%s\033[0m\n' "$*"; }

c_blue "==> Athena installer (v7.2)"
echo

# ── Detect rc files to update ─────────────────────────────────────
# Strategy: figure out the user's login shell from $SHELL (set by the
# OS, not by whatever shell is running this script).  Then collect
# every rc file that already exists — we'll write to all of them so
# the install works in bash AND zsh sessions interchangeably.
LOGIN_SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
PRIMARY_RC="$HOME/.bashrc"
case "$LOGIN_SHELL_NAME" in
    zsh)  PRIMARY_RC="$HOME/.zshrc" ;;
    bash) PRIMARY_RC="$HOME/.bashrc" ;;
    *)    PRIMARY_RC="$HOME/.profile" ;;
esac

RC_FILES=()
for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [[ -f "$rc" ]] && RC_FILES+=("$rc")
done
# If the primary rc doesn't exist yet, create it (touch) so we can
# write to it.  This handles a fresh user account.
if [[ ! -f "$PRIMARY_RC" ]]; then
    touch "$PRIMARY_RC"
    RC_FILES+=("$PRIMARY_RC")
fi

c_green "[ok] login shell: $LOGIN_SHELL_NAME"
c_green "[ok] will update: ${RC_FILES[*]}"

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
    c_yellow "==> sudo not available — adding 'athena' alias to your rc files"
    for rc in "${RC_FILES[@]}"; do
        if ! grep -q "^alias athena=" "$rc" 2>/dev/null; then
            echo "alias athena='python3 $SCRIPT'" >> "$rc"
            c_green "[ok] alias added to $rc"
        else
            c_green "[ok] alias already present in $rc"
        fi
    done
fi

# ── GROQ_API_KEY ──────────────────────────────────────────────────
# Skip the prompt entirely if either:
#   (a) GROQ_API_KEY is already set in the current environment, or
#   (b) any of the rc files we'd write to already contains it.
HAS_KEY_IN_RC=0
for rc in "${RC_FILES[@]}"; do
    if grep -q "GROQ_API_KEY" "$rc" 2>/dev/null; then
        HAS_KEY_IN_RC=1
        break
    fi
done

if [[ -z "${GROQ_API_KEY:-}" && "$HAS_KEY_IN_RC" == "0" ]]; then
    echo
    c_yellow "==> No GROQ_API_KEY found in your environment or rc files"
    echo "    Get a free key at: https://console.groq.com (no credit card)"
    read -r -p "    Paste your Groq API key (or press Enter to skip): " key
    if [[ -n "$key" ]]; then
        for rc in "${RC_FILES[@]}"; do
            echo "export GROQ_API_KEY=$key" >> "$rc"
            c_green "[ok] GROQ_API_KEY written to $rc"
        done
        c_yellow "    Reload your shell:  source $PRIMARY_RC"
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
    echo "    Run:  source $PRIMARY_RC && athena"
fi
echo
