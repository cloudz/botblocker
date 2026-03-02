#!/usr/bin/env bash
set -euo pipefail

# BotBlocker self-updater — pulls the latest release from GitHub
# Usage: update.sh [--force] [--check]

REPO="cloudz/botblocker"
ASSET_NAME="botblocker-linux-amd64"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

BIN_PATH="/usr/local/bin/botblocker"
SERVICE_FILE="/etc/systemd/system/botblocker.service"
INSTALL_DIR="/usr/local/botblocker"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

FORCE=false
CHECK_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        --check) CHECK_ONLY=true ;;
        *)
            error "Unknown flag: $arg"
            echo "Usage: update.sh [--force] [--check]"
            exit 1
            ;;
    esac
done

# --- Prerequisites ---

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        error "'$cmd' is required but not installed"
        exit 1
    fi
done

if [[ ! -x "$BIN_PATH" ]]; then
    error "BotBlocker binary not found at $BIN_PATH"
    error "Run the installer first"
    exit 1
fi

# --- Fetch latest release ---

info "Checking for updates..."

RELEASE_JSON=$(curl -fsSL "$API_URL") || {
    error "Failed to fetch release info from GitHub"
    exit 1
}

LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r '.tag_name')
if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
    error "Could not determine latest release tag"
    exit 1
fi

# Strip leading 'v' for comparison
LATEST_VERSION="${LATEST_TAG#v}"

CURRENT_VERSION=$("$BIN_PATH" --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' || echo "unknown")

info "Current version: ${CURRENT_VERSION}"
info "Latest version:  ${LATEST_VERSION}"

# --- Compare versions ---

if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
    if [[ "$FORCE" == false ]]; then
        info "Already up-to-date (use --force to reinstall)"
        exit 0
    fi
    warn "Forcing reinstall of ${LATEST_VERSION}"
fi

if [[ "$CHECK_ONLY" == true ]]; then
    if [[ "$CURRENT_VERSION" != "$LATEST_VERSION" ]]; then
        info "Update available: ${CURRENT_VERSION} → ${LATEST_VERSION}"
    fi
    exit 0
fi

# --- Download binary ---

DOWNLOAD_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name == \"${ASSET_NAME}\") | .browser_download_url")
if [[ -z "$DOWNLOAD_URL" || "$DOWNLOAD_URL" == "null" ]]; then
    error "Asset '${ASSET_NAME}' not found in release ${LATEST_TAG}"
    exit 1
fi

TMPDIR=$(mktemp -d)
TMPBIN="${TMPDIR}/botblocker"
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${ASSET_NAME} from ${LATEST_TAG}..."
curl -fsSL -o "$TMPBIN" "$DOWNLOAD_URL" || {
    error "Download failed"
    exit 1
}

# --- Validate download ---

if [[ ! -s "$TMPBIN" ]]; then
    error "Downloaded file is empty"
    exit 1
fi

if ! file "$TMPBIN" | grep -q "ELF"; then
    error "Downloaded file is not a valid Linux ELF binary"
    exit 1
fi

chmod +x "$TMPBIN"

DL_VERSION=$("$TMPBIN" --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' || echo "")
if [[ -z "$DL_VERSION" ]]; then
    error "Downloaded binary failed sanity check (--version returned nothing)"
    exit 1
fi

info "Download verified: v${DL_VERSION}"

# --- Backup current binary ---

BACKUP="${TMPDIR}/botblocker.bak"
cp "$BIN_PATH" "$BACKUP"

# --- Stop service ---

info "Stopping botblocker service..."
systemctl stop botblocker 2>/dev/null || warn "Service was not running"

# --- Replace binary ---

install -m 755 "$TMPBIN" "$BIN_PATH" || {
    error "Failed to install new binary, rolling back..."
    cp "$BACKUP" "$BIN_PATH"
    chmod 755 "$BIN_PATH"
    systemctl start botblocker 2>/dev/null || true
    error "Rollback complete, old binary restored"
    exit 1
}

# --- Sanity-check the installed binary ---

INSTALLED_VERSION=$("$BIN_PATH" --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' || echo "")
if [[ -z "$INSTALLED_VERSION" ]]; then
    error "Installed binary failed sanity check, rolling back..."
    cp "$BACKUP" "$BIN_PATH"
    chmod 755 "$BIN_PATH"
    systemctl start botblocker 2>/dev/null || true
    error "Rollback complete, old binary restored"
    exit 1
fi

# --- Update service file ---

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_SERVICE="${SCRIPT_DIR}/../botblocker.service"

if [[ -f "$LOCAL_SERVICE" ]]; then
    install -m 644 "$LOCAL_SERVICE" "$SERVICE_FILE"
    systemctl daemon-reload
    info "Service file updated"
else
    # If update.sh is installed to /usr/local/botblocker, the bundled service
    # file won't be alongside it. Skip the service file update in that case —
    # the release binary is the important part.
    warn "Service file source not found, skipping service file update"
fi

# --- Start service ---

info "Starting botblocker service..."
systemctl start botblocker || {
    error "Failed to start service with new binary, rolling back..."
    cp "$BACKUP" "$BIN_PATH"
    chmod 755 "$BIN_PATH"
    systemctl start botblocker 2>/dev/null || true
    error "Rollback complete, old binary restored"
    exit 1
}

# --- Summary ---

echo ""
info "=== Update complete ==="
info "  ${CURRENT_VERSION} → ${INSTALLED_VERSION}"
info ""
info "Service status:"
systemctl --no-pager status botblocker | head -5
