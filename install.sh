#!/usr/bin/env bash
# Athena installer — v7.0
# Sets up the Python dep, API key, and launcher alias.
# Run as your normal user (not root). sudo is used only where needed.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/athena.py"
BASHRC="$HOME/.bashrc"
INSTALL_DIR="$HOME/.athena"

echo ""
echo "  Athena v7.0 installer"
echo "  ─────────────────────────────────────────────────"
echo ""

# ── Python dep ────────────────────────────────────────────────────────
echo "  [1/4] Installing Python dep (groq)..."
if pip install groq --quiet --break-system-packages 2>/dev/null; then
    echo "        groq installed"
elif pip3 install groq --quiet 2>/dev/null; then
    echo "        groq installed (pip3)"
else
    echo "        pip install groq failed — try manually:"
    echo "        pip install groq --break-system-packages"
fi

# ── API key ───────────────────────────────────────────────────────────
echo ""
echo "  [2/4] Groq API key"
echo ""

EXISTING_KEY=$(grep -oP '(?<=GROQ_API_KEY=)["\047]?\K[^"'\'']+' "$BASHRC" 2>/dev/null | head -1 || true)
if [[ -n "$EXISTING_KEY" ]]; then
    echo "        Found existing GROQ_API_KEY in $BASHRC — keeping it."
else
    read -rp "        Paste your Groq API key (from console.groq.com): " API_KEY
    if [[ -n "$API_KEY" ]]; then
        echo "export GROQ_API_KEY='$API_KEY'" >> "$BASHRC"
        echo "        Saved to $BASHRC"
    else
        echo "        Skipped. Add manually: export GROQ_API_KEY='gsk_...'"
    fi
fi

# ── Log dir ───────────────────────────────────────────────────────────
echo ""
echo "  [3/4] Creating ~/.athena/logs/..."
mkdir -p "$INSTALL_DIR/logs"
echo "        Done"

# ── Launcher alias ────────────────────────────────────────────────────
echo ""
echo "  [4/4] Setting up 'athena' launcher alias..."
chmod +x "$SCRIPT_PATH" 2>/dev/null || true

ALIAS_LINE="alias athena='python3 $SCRIPT_PATH'"
if grep -qF "alias athena=" "$BASHRC" 2>/dev/null; then
    # Update the existing alias in place
    sed -i "s|alias athena=.*|$ALIAS_LINE|" "$BASHRC"
    echo "        Updated existing alias in $BASHRC"
else
    echo "" >> "$BASHRC"
    echo "# Athena AI offensive security agent" >> "$BASHRC"
    echo "$ALIAS_LINE" >> "$BASHRC"
    echo "        Added alias to $BASHRC"
fi

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo "  ─────────────────────────────────────────────────"
echo "  Done. Run:"
echo ""
echo "    source ~/.bashrc"
echo "    athena"
echo ""
echo "  Logs and reports go to: ~/.athena/logs/"
echo ""
echo "  NOTE: This tool is for authorized security testing only."
echo "  Only use it against systems you own or have permission to test."
echo ""
