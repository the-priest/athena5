#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║              ATHENA INSTALLER — v7.3 (GUI + CLI)                 ║
# ║   Smart install: detects what's missing, installs only that.     ║
# ║   Sets up both the CLI shortcut and the Phosh app icon.          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Usage:
#   bash install.sh             # full install (CLI + GUI)
#   bash install.sh --cli-only  # skip GTK/VTE, CLI only
#   bash install.sh --gui-only  # skip the /usr/local/bin/athena CLI link
#   bash install.sh --quiet     # less chatty
#
# Re-runnable.  Existing config / API keys are preserved.

set -euo pipefail

# ── flags ──────────────────────────────────────────────────────────
CLI_ONLY=0
GUI_ONLY=0
QUIET=0
for arg in "$@"; do
    case "$arg" in
        --cli-only) CLI_ONLY=1 ;;
        --gui-only) GUI_ONLY=1 ;;
        --quiet)    QUIET=1 ;;
        -h|--help)
            sed -n '8,15p' "$0"; exit 0 ;;
    esac
done

# ── colours ────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BLU=$'\033[34m'; GRN=$'\033[32m'; YEL=$'\033[33m'
    RED=$'\033[31m'; DIM=$'\033[90m'; MAG=$'\033[35m'; RST=$'\033[0m'
else
    BLU= GRN= YEL= RED= DIM= MAG= RST=
fi
say()  { [[ $QUIET == 1 ]] || printf '%s\n' "$*"; }
ok()   { say "${GRN}[ok]${RST} $*"; }
warn() { printf '%s\n' "${YEL}[!]${RST}  $*" >&2; }
err()  { printf '%s\n' "${RED}[x]${RST}  $*" >&2; }
step() { say ""; say "${BLU}==>${RST} ${MAG}$*${RST}"; }

# ── banner ─────────────────────────────────────────────────────────
if [[ $QUIET == 0 ]]; then
cat <<EOF
${MAG}
   █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗
  ██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
  ███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
  ██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
  ██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝${DIM}
                 v7.3 · GUI + CLI installer${RST}

EOF
fi

# ── paths ──────────────────────────────────────────────────────────
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${ATHENA_INSTALL_DIR:-/opt/athena5}"
DATA_DIR="$HOME/.athena"
APPS_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
CLI_BIN="/usr/local/bin/athena"
GUI_BIN="/usr/local/bin/athena-gui"

# ── helpers ────────────────────────────────────────────────────────
has() { command -v "$1" >/dev/null 2>&1; }

# Run a command with sudo only when needed and available.
sudo_run() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif has sudo; then
        sudo "$@"
    else
        warn "sudo not available — skipping: $*"
        return 1
    fi
}

# Detect package manager (apt only for now — extend if needed)
PKG=""
if has apt-get; then PKG="apt"
elif has pacman; then PKG="pacman"
elif has dnf;    then PKG="dnf"
else
    warn "no supported package manager found — system deps must be installed manually"
fi

# Map logical dep → distro package name
declare -A PKG_APT=(
    [python3]=python3
    [pip]=python3-pip
    [git]=git
    [gtk4]=libgtk-4-1
    [adw]=gir1.2-adw-1
    [pygobject]=python3-gi
    [pygobject-cairo]=python3-gi-cairo
    [fonts]=fonts-jetbrains-mono
)
declare -A PKG_PAC=(
    [python3]=python
    [pip]=python-pip
    [git]=git
    [gtk4]=gtk4
    [adw]=libadwaita
    [pygobject]=python-gobject
    [pygobject-cairo]=python-cairo
    [fonts]=ttf-jetbrains-mono
)
declare -A PKG_DNF=(
    [python3]=python3
    [pip]=python3-pip
    [git]=git
    [gtk4]=gtk4
    [adw]=libadwaita
    [pygobject]=python3-gobject
    [pygobject-cairo]=python3-cairo
    [fonts]=jetbrains-mono-fonts
)

pkg_name() {
    local key="$1"
    case "$PKG" in
        apt)    echo "${PKG_APT[$key]:-}" ;;
        pacman) echo "${PKG_PAC[$key]:-}" ;;
        dnf)    echo "${PKG_DNF[$key]:-}" ;;
    esac
}

# Check whether a package is installed (apt only — best-effort elsewhere)
pkg_installed() {
    local name="$1"
    case "$PKG" in
        apt)    dpkg-query -W -f='${Status}' "$name" 2>/dev/null | grep -q 'install ok installed' ;;
        pacman) pacman -Qi "$name" >/dev/null 2>&1 ;;
        dnf)    rpm -q "$name" >/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

pkg_install_many() {
    local pkgs=()
    for key in "$@"; do
        local n; n="$(pkg_name "$key")"
        [[ -z "$n" ]] && continue
        if ! pkg_installed "$n"; then
            pkgs+=("$n")
        fi
    done
    if [[ ${#pkgs[@]} -eq 0 ]]; then
        ok "all system packages already present"
        return 0
    fi
    say "    installing: ${pkgs[*]}"
    case "$PKG" in
        apt)
            sudo_run apt-get update -qq || true
            # Install one at a time so a single missing package (e.g.
            # fonts-jetbrains-mono not in Kali aarch64) doesn't fail the
            # whole batch.
            for p in "${pkgs[@]}"; do
                if ! sudo_run apt-get install -y --no-install-recommends "$p" 2>/dev/null; then
                    warn "skipped (not in repo): $p"
                fi
            done
            ;;
        pacman)
            for p in "${pkgs[@]}"; do
                sudo_run pacman -S --needed --noconfirm "$p" 2>/dev/null || warn "skipped: $p"
            done
            ;;
        dnf)
            for p in "${pkgs[@]}"; do
                sudo_run dnf install -y "$p" 2>/dev/null || warn "skipped: $p"
            done
            ;;
    esac
}

# ── 1. Python check ────────────────────────────────────────────────
step "Python 3.10+"
if ! has python3; then
    err "python3 missing"
    [[ -n "$PKG" ]] && pkg_install_many python3 pip || exit 1
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')
[[ "$PY_OK" == "1" ]] || { err "Python 3.10+ required, found $PY_VER"; exit 1; }
ok "Python $PY_VER"

# ── 2. system deps ─────────────────────────────────────────────────
if [[ $CLI_ONLY == 0 && -n "$PKG" ]]; then
    step "System packages (GTK4 · libadwaita · python3-gi)"
    pkg_install_many gtk4 adw pygobject pygobject-cairo fonts pip git || true
else
    step "System packages (CLI only)"
    [[ -n "$PKG" ]] && pkg_install_many pip git || true
fi

# ── 3. python deps ─────────────────────────────────────────────────
step "Python dependencies"
PIP_FLAGS=()
if pip3 install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_FLAGS+=("--break-system-packages")
fi
if ! pip3 install --quiet "${PIP_FLAGS[@]}" -r "$SRC_DIR/requirements.txt"; then
    warn "system pip failed — retrying with --user"
    pip3 install --quiet --user "${PIP_FLAGS[@]}" -r "$SRC_DIR/requirements.txt"
fi
ok "groq · networkx installed"

# ── 4. copy files to install dir ───────────────────────────────────
step "Install files → $INSTALL_DIR"
PARENT_DIR="$(dirname "$INSTALL_DIR")"
if [[ -d "$INSTALL_DIR" && -w "$INSTALL_DIR" ]] || [[ ! -d "$INSTALL_DIR" && -w "$PARENT_DIR" ]]; then
    mkdir -p "$INSTALL_DIR"
else
    sudo_run mkdir -p "$INSTALL_DIR"
    sudo_run chown "$USER:$USER" "$INSTALL_DIR"
fi

for f in athena.py athena_gui.py athena-gui requirements.txt README.md; do
    if [[ -f "$SRC_DIR/$f" ]]; then
        cp -f "$SRC_DIR/$f" "$INSTALL_DIR/$f"
    fi
done
chmod +x "$INSTALL_DIR/athena.py" "$INSTALL_DIR/athena-gui" 2>/dev/null || true
ok "files copied"

# ── 5. ~/.athena dirs ──────────────────────────────────────────────
mkdir -p "$DATA_DIR/logs"
ok "$DATA_DIR/ ready"

# ── 6. CLI symlink ─────────────────────────────────────────────────
if [[ $GUI_ONLY == 0 ]]; then
    step "CLI shortcut: $CLI_BIN"
    if sudo_run ln -sf "$INSTALL_DIR/athena.py" "$CLI_BIN" 2>/dev/null; then
        ok "$CLI_BIN → $INSTALL_DIR/athena.py"
    else
        warn "no sudo — adding alias to shell rc files instead"
        for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            [[ -f "$rc" ]] || continue
            if ! grep -q "^alias athena=" "$rc" 2>/dev/null; then
                printf "alias athena='python3 %s'\n" "$INSTALL_DIR/athena.py" >> "$rc"
                ok "alias added to $rc"
            fi
        done
    fi
fi

# ── 7. GUI launcher + desktop entry + icon ─────────────────────────
if [[ $CLI_ONLY == 0 ]]; then
    step "GUI shortcut: $GUI_BIN"
    if sudo_run ln -sf "$INSTALL_DIR/athena-gui" "$GUI_BIN" 2>/dev/null; then
        ok "$GUI_BIN → $INSTALL_DIR/athena-gui"
    else
        warn "no sudo — $GUI_BIN not linked (run athena-gui from $INSTALL_DIR)"
    fi

    step "Desktop entry + icon"
    mkdir -p "$APPS_DIR" "$ICON_DIR"

    # Look for desktop+icon in data/ (preferred) or repo root (legacy layout)
    DESKTOP_SRC=""
    ICON_SRC=""
    for d in "$SRC_DIR/data" "$SRC_DIR"; do
        [[ -z "$DESKTOP_SRC" && -f "$d/io.thepriest.Athena.desktop" ]] && DESKTOP_SRC="$d/io.thepriest.Athena.desktop"
        [[ -z "$ICON_SRC"    && -f "$d/io.thepriest.Athena.svg"     ]] && ICON_SRC="$d/io.thepriest.Athena.svg"
    done

    if [[ -n "$DESKTOP_SRC" ]]; then
        cp -f "$DESKTOP_SRC" "$APPS_DIR/io.thepriest.Athena.desktop"
        ok "app registered: $APPS_DIR/io.thepriest.Athena.desktop"
    else
        warn "io.thepriest.Athena.desktop not found in repo — app icon won't appear in launcher"
        warn "(run 'athena-gui' from terminal anyway)"
    fi

    if [[ -n "$ICON_SRC" ]]; then
        cp -f "$ICON_SRC" "$ICON_DIR/io.thepriest.Athena.svg"
        ok "icon installed:  $ICON_DIR/io.thepriest.Athena.svg"
    else
        warn "io.thepriest.Athena.svg not found — using default icon"
    fi

    # Refresh caches (best-effort)
    if has update-desktop-database; then
        update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
    fi
    if has gtk-update-icon-cache; then
        gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
    fi
fi

# ── 8. GROQ_API_KEY ────────────────────────────────────────────────
step "Groq API key"
KEY_IN_RC=0
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f "$rc" ]] && grep -q "GROQ_API_KEY" "$rc" && KEY_IN_RC=1 && break
done
if [[ -z "${GROQ_API_KEY:-}" && $KEY_IN_RC == 0 ]]; then
    if [[ -t 0 ]]; then
        warn "GROQ_API_KEY not set"
        say "    Free key (no card): https://console.groq.com"
        read -r -p "    Paste key (or Enter to skip and set later in the GUI): " key
        if [[ -n "${key:-}" ]]; then
            for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
                [[ -f "$rc" ]] || continue
                printf "export GROQ_API_KEY=%s\n" "$key" >> "$rc"
                ok "key written to $rc"
            done
        else
            warn "skipped — set later via GUI ▸ ⋮ ▸ API key…"
        fi
    else
        warn "GROQ_API_KEY not set — paste it in the GUI on first launch"
    fi
else
    ok "GROQ_API_KEY already configured"
fi

# ── done ───────────────────────────────────────────────────────────
say ""
say "${GRN}${MAG}╭──────────────────────────────────────────────────╮${RST}"
say "${GRN}${MAG}│${RST}  install complete                                ${MAG}│${RST}"
say "${GRN}${MAG}├──────────────────────────────────────────────────┤${RST}"
if [[ $CLI_ONLY == 0 ]]; then
say "${MAG}│${RST}  ${GRN}GUI${RST}   tap the Athena icon in your app grid    ${MAG}│${RST}"
say "${MAG}│${RST}        or run:  ${YEL}athena-gui${RST}                       ${MAG}│${RST}"
fi
if [[ $GUI_ONLY == 0 ]]; then
say "${MAG}│${RST}  ${GRN}CLI${RST}   run:  ${YEL}athena${RST}                            ${MAG}│${RST}"
fi
say "${GRN}${MAG}╰──────────────────────────────────────────────────╯${RST}"
say ""
