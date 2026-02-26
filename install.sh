#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()   { echo -e "${GREEN}[+]${NC} $*"; }
info()  { echo -e "${BLUE}[i]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; exit 1; }


[[ $EUID -ne 0 ]] && err "Must run as root: sudo bash install.sh"

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

INSTALL_DIR="/opt/mergen"
VENV_DIR="$INSTALL_DIR/venv"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "User: $REAL_USER ($REAL_HOME)"
info "Source: $SRC_DIR"
info "Target: $INSTALL_DIR"


log "Updating package lists..."
apt-get update -qq

PACKAGES=(
    git curl wget unzip rsync build-essential
    python3-venv python3-pip python3-dev
    libpcap-dev libssl-dev libffi-dev
    nmap masscan
    gobuster ffuf feroxbuster dirsearch
    subfinder httpx
    whatweb wafw00f dnsenum fierce
    nikto wpscan sqlmap
    hydra enum4linux enum4linux-ng smbmap netexec responder
    john hashcat
    binwalk checksec radare2 python3-pwntools
    trufflehog
)

log "Installing ${#PACKAGES[@]} system packages..."
apt-get install -y -qq "${PACKAGES[@]}" 2>/dev/null || warn "Some packages failed. Verify manually."


log "Installing Go-based tools (katana, gau, waybackurls, dalfox)..."

if ! command -v go &>/dev/null; then
    apt-get install -y -qq golang-go 2>/dev/null || warn "Failed to install golang-go"
fi

run_as_user() {
    sudo -u "$REAL_USER" bash -c "$1"
}

if command -v go &>/dev/null; then
    info "Installing Go tools as $REAL_USER..."
    run_as_user "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    run_as_user "go install github.com/lc/gau/v2/cmd/gau@latest"
    run_as_user "go install github.com/tomnomnom/waybackurls@latest"
    run_as_user "go install github.com/hahwul/dalfox/v2@latest"

    GOPATH_BIN="$REAL_HOME/go/bin"
    for tool in katana gau waybackurls dalfox; do
        if [[ -f "$GOPATH_BIN/$tool" ]]; then
            ln -sf "$GOPATH_BIN/$tool" "/usr/local/bin/$tool"
            log "Linked $tool -> /usr/local/bin/$tool"
        else
            warn "Go tool $tool failed to install."
        fi
    done
else
    warn "Go not found. Skipping Go tools."
fi


if ! command -v arjun &>/dev/null; then
    pip3 install arjun -q 2>/dev/null || warn "arjun install failed"
fi


if ! command -v nuclei &>/dev/null; then
    log "Installing Nuclei binary..."
    NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4)
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" -O /tmp/nuclei.zip
    unzip -q -o /tmp/nuclei.zip -d /usr/local/bin/
    rm /tmp/nuclei.zip
    nuclei -update-templates -silent 2>/dev/null || true
fi


if [[ ! -d /usr/share/seclists ]]; then
    log "Cloning SecLists (this may take a while)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists -q || warn "SecLists clone failed"
fi

log "Deploying Mergen to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR"
rsync -a --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='venv' \
    --exclude='data' \
    "$SRC_DIR/" "$INSTALL_DIR/"

mkdir -p "$INSTALL_DIR/data"
chown -R "$REAL_USER":"$REAL_USER" "$INSTALL_DIR"


log "Setting up Python venv..."
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip -q
log "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install -r "$SRC_DIR/requirements.txt" || err "Pip install failed — check requirements.txt"

log "Installing launcher..."

cat > /usr/local/bin/mergen << LAUNCHER
#!/bin/bash
INSTALL_DIR="$INSTALL_DIR"
VENV="\$INSTALL_DIR/venv/bin/python3"
cd "\$INSTALL_DIR"

case "\${1:-}" in
    --stop)
        pkill -f "server.py" && echo "Stopped." || echo "Not running."
        ;;
    --status)
        pgrep -a -f "server.py" && echo "Running." || echo "Not running."
        ;;
    *)
        exec "\$VENV" -u server.py "\$@"
        ;;
esac
LAUNCHER
chmod +x /usr/local/bin/mergen

KALI_IP=$(hostname -I | awk '{print $1}')
log "Installation complete."
info "Start:  mergen"
info "Stop:   mergen --stop"
info "Status: mergen --status"
info "Dashboard: http://$KALI_IP:8000/dashboard"
