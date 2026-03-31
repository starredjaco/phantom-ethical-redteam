#!/bin/bash
# Phantom – Ethical RedTeam — One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/kmdn-ch/phantom-ethical-redteam/main/get.sh | bash
set -e

REPO="https://github.com/kmdn-ch/phantom-ethical-redteam.git"
DEST="/opt/phantom"

echo ""
echo "========================================"
echo "  Phantom - Ethical RedTeam"
echo "  One-line installer"
echo "========================================"
echo ""

# --- Require root (needed to write to /opt) ---
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This installer must be run as root (use sudo)."
    echo "        Run: sudo bash <(curl -fsSL https://raw.githubusercontent.com/kmdn-ch/phantom-ethical-redteam/main/get.sh)"
    exit 1
fi

# --- Check git ---
if ! command -v git &>/dev/null; then
    echo "[ERROR] git is required. Install it first."
    exit 1
fi

# --- Check Python 3.11+ ---
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")
        maj=$("$cmd" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
        if [ "$maj" = "3" ] && [ "$ver" -ge 11 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done
if [ -z "$PYTHON" ]; then
    echo "[ERROR] Python 3.11+ is required. Install it from https://python.org"
    exit 1
fi
echo "  [OK] Found $PYTHON ($($PYTHON --version))"

# --- Clone or update ---
if [ -d "$DEST/.git" ]; then
    echo "  [i] Existing installation found at $DEST"
    echo "  --> Updating to latest version..."
    git -C "$DEST" pull --quiet origin main
else
    if [ -d "$DEST" ]; then
        echo "  [i] Directory $DEST exists but is not a git repo — removing it."
        rm -rf "$DEST"
    fi
    echo "  --> Cloning Phantom to $DEST ..."
    git clone --quiet "$REPO" "$DEST"
    echo "  [OK] Cloned successfully"
fi

# --- Launch installer ---
echo ""
echo "  --> Launching installer..."
echo ""
cd "$DEST"
chmod +x install.sh
./install.sh
