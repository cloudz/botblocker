#!/usr/bin/env bash
set -euo pipefail

# BotBlocker installer — run as root

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/usr/local/botblocker"
BIN_DIR="/usr/local/bin"
LOG_DIR="/var/log/botblocker"
STATE_DIR="/var/lib/botblocker"
SYSTEMD_DIR="/etc/systemd/system"

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Check CSF
if ! command -v csf &>/dev/null; then
    error "CSF (ConfigServer Security & Firewall) is not installed"
    error "Install CSF first: https://configserver.com/cp/csf.html"
    exit 1
fi

# Check binary exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${SCRIPT_DIR}/botblocker"

if [[ ! -f "$BINARY" ]]; then
    error "Binary not found at $BINARY"
    error "Build first: go build -ldflags='-s -w' -o botblocker ./cmd/botblocker"
    exit 1
fi

# Verify it's the right architecture
if ! file "$BINARY" | grep -q "ELF"; then
    error "Binary is not a Linux ELF executable"
    error "Cross-compile with: GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o botblocker ./cmd/botblocker"
    exit 1
fi

info "Installing BotBlocker..."

# Create directories
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$STATE_DIR"
chmod 750 "$INSTALL_DIR" "$LOG_DIR" "$STATE_DIR"

# Install binary
install -m 755 "$BINARY" "$BIN_DIR/botblocker"
info "Binary → $BIN_DIR/botblocker"

# Install config (don't overwrite existing)
if [[ ! -f "$INSTALL_DIR/config.ini" ]]; then
    install -m 640 "$SCRIPT_DIR/config.ini" "$INSTALL_DIR/config.ini"
    info "Config → $INSTALL_DIR/config.ini"
else
    warn "Config already exists, not overwriting"
fi

# Install whitelist (don't overwrite existing)
if [[ ! -f "$INSTALL_DIR/whitelist.txt" ]]; then
    install -m 640 "$SCRIPT_DIR/whitelist.txt" "$INSTALL_DIR/whitelist.txt"
    info "Whitelist → $INSTALL_DIR/whitelist.txt"
    warn "⚠ ADD YOUR OWN IPs TO whitelist.txt BEFORE STARTING"
else
    warn "Whitelist already exists, not overwriting"
fi

# Install honeypot paths (don't overwrite existing)
if [[ ! -f "$INSTALL_DIR/honeypot_paths.txt" ]]; then
    install -m 640 "$SCRIPT_DIR/honeypot_paths.txt" "$INSTALL_DIR/honeypot_paths.txt"
    info "Honeypot paths → $INSTALL_DIR/honeypot_paths.txt"
else
    warn "Honeypot paths already exists, not overwriting"
fi

# Install update script (always overwrite — not user config)
install -m 755 "$SCRIPT_DIR/scripts/update.sh" "$INSTALL_DIR/update.sh"
info "Update script → $INSTALL_DIR/update.sh"

# Install systemd service
install -m 644 "$SCRIPT_DIR/botblocker.service" "$SYSTEMD_DIR/botblocker.service"
systemctl daemon-reload
info "Systemd service installed"

# Enable and start
systemctl enable botblocker
systemctl start botblocker
info "Service enabled and started"

echo ""
info "=== Installation complete ==="
info ""
info "Quick checks:"
info "  systemctl status botblocker"
info "  tail -f /var/log/botblocker/botblocker.log"
info "  botblocker --config $INSTALL_DIR/config.ini"
info "  $INSTALL_DIR/update.sh"
echo ""
warn "IMPORTANT: Verify your own IPs are in $INSTALL_DIR/whitelist.txt"
