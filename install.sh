#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#   ATHENA v5.0 — Automated Installer
#   Elite AI Offensive Security Agent
# ═══════════════════════════════════════════════════════════════

set -e

PURPLE='\033[35m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
WHITE='\033[97m'
GREY='\033[90m'
RESET='\033[0m'

INSTALL_DIR="$HOME/.athena"
BIN_PATH="/usr/local/bin/athena"
SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/athena.py"

detect_shell_config() {
    if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ]; then
        echo "$HOME/.zshrc"
    else
        echo "$HOME/.bashrc"
    fi
}

SHELL_CONFIG=$(detect_shell_config)

echo ""
echo -e "${PURPLE}"
echo " █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗ "
echo "██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗"
echo "███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║"
echo "██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║"
echo "██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║"
echo "╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝"
echo -e "${RESET}${GREY}         Installer v5.0 | Elite AI Security Agent${RESET}"
echo ""

# ── Step 1: Python 3 ─────────────────────────────────────────
echo -e "${PURPLE}[1/6]${RESET} Checking Python 3..."
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}❌ Python 3 not found. Run: sudo apt install python3${RESET}"
    exit 1
fi
echo -e "${GREEN}✅ $(python3 --version)${RESET}"

# ── Step 2: groq package ─────────────────────────────────────
echo ""
echo -e "${PURPLE}[2/6]${RESET} Installing Python dependency (groq)..."
if python3 -c "from groq import Groq" &>/dev/null; then
    echo -e "${GREEN}✅ groq already installed.${RESET}"
else
    pip install groq --break-system-packages -q \
        || pip install groq -q \
        || { echo -e "${RED}❌ pip install failed. Try: pip install groq${RESET}"; exit 1; }
    echo -e "${GREEN}✅ groq installed.${RESET}"
fi

# ── Step 3: Security tools ────────────────────────────────────
echo ""
echo -e "${PURPLE}[3/6]${RESET} Checking security tools..."
MISSING=()
for tool in nmap arp-scan nikto gobuster whatweb searchsploit hydra crackmapexec; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING+=("$tool")
    fi
done

if [ "${#MISSING[@]}" -eq 0 ]; then
    echo -e "${GREEN}✅ All tools present.${RESET}"
else
    echo -e "${YELLOW}   Installing missing: ${MISSING[*]}${RESET}"
    sudo apt install -y nmap arp-scan nikto gobuster whatweb exploitdb hydra dirb 2>/dev/null \
        || echo -e "${YELLOW}⚠️  Some tools may need manual install.${RESET}"
    # crackmapexec via pip if not available via apt
    if ! command -v crackmapexec &>/dev/null; then
        pip install crackmapexec --break-system-packages -q 2>/dev/null || true
    fi
    echo -e "${GREEN}✅ Done.${RESET}"
fi

# ── Step 4: API key ───────────────────────────────────────────
echo ""
echo -e "${PURPLE}[4/6]${RESET} Groq API key setup..."

EXISTING_KEY=$(grep -s 'GROQ_API_KEY' "$SHELL_CONFIG" | head -1 | sed "s/.*GROQ_API_KEY='//;s/'.*//")

if [ -n "$GROQ_API_KEY" ] && [ "$GROQ_API_KEY" != "your_key_here" ]; then
    echo -e "${GREEN}✅ GROQ_API_KEY already set in environment.${RESET}"
elif [ -n "$EXISTING_KEY" ] && [ "$EXISTING_KEY" != "your_key_here" ]; then
    echo -e "${GREEN}✅ GROQ_API_KEY already saved in $SHELL_CONFIG.${RESET}"
else
    echo ""
    echo -e "${WHITE}   Get your free key at: https://console.groq.com${RESET}"
    echo -e "${GREY}   Sign up -> API Keys -> Create API Key -> Copy it${RESET}"
    echo ""
    read -rp "   Paste your Groq API key here: " USER_KEY
    echo ""
    if [ -z "$USER_KEY" ]; then
        echo -e "${YELLOW}⚠️  No key entered. Add manually to $SHELL_CONFIG later.${RESET}"
    else
        sed -i '/GROQ_API_KEY/d' "$SHELL_CONFIG" 2>/dev/null || true
        echo "export GROQ_API_KEY='$USER_KEY'" >> "$SHELL_CONFIG"
        export GROQ_API_KEY="$USER_KEY"
        echo -e "${GREEN}✅ API key saved to $SHELL_CONFIG${RESET}"
    fi
fi

# ── Step 5: Install Athena ────────────────────────────────────
echo ""
echo -e "${PURPLE}[5/6]${RESET} Installing Athena v5.0..."

mkdir -p "$INSTALL_DIR"

if [ ! -f "$SCRIPT_SRC" ]; then
    echo -e "${RED}❌ Cannot find athena.py. Run this from inside the cloned repo.${RESET}"
    exit 1
fi

cp "$SCRIPT_SRC" "$INSTALL_DIR/athena.py"
chmod +x "$INSTALL_DIR/athena.py"

sudo tee "$BIN_PATH" > /dev/null << 'LAUNCHER'
#!/usr/bin/env bash
if [ -f "$HOME/.bashrc" ]; then
    source "$HOME/.bashrc" 2>/dev/null
elif [ -f "$HOME/.zshrc" ]; then
    source "$HOME/.zshrc" 2>/dev/null
fi
exec python3 "$HOME/.athena/athena.py" "$@"
LAUNCHER

sudo chmod +x "$BIN_PATH"
echo -e "${GREEN}✅ Installed to ~/.athena/athena.py${RESET}"
echo -e "${GREEN}✅ Launcher: $BIN_PATH${RESET}"

# ── Step 6: Verify ────────────────────────────────────────────
echo ""
echo -e "${PURPLE}[6/6]${RESET} Verifying..."
if command -v athena &>/dev/null; then
    echo -e "${GREEN}✅ 'athena' command is ready.${RESET}"
else
    echo -e "${YELLOW}⚠️  Run: source $SHELL_CONFIG  then try athena${RESET}"
fi

echo ""
echo -e "${PURPLE}════════════════════════════════════${RESET}"
echo -e "${GREEN}  ✅ ATHENA v5.0 READY${RESET}"
echo -e "${PURPLE}════════════════════════════════════${RESET}"
echo ""
echo -e "  Type ${WHITE}athena${RESET} to start"
echo ""
