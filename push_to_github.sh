#!/bin/bash
# Helper script to link and push WisaProtectX-Server to GitHub
# Organization: wisabuilds
# Repository: WisaProtectX-Server

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

echo "╔══════════════════════════════════════════════╗"
echo "║   🚀  Pushing WisaProtectX-Server to GitHub  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Ensure git repo is initialized
if [ ! -d ".git" ]; then
    echo "→ Initializing git repository..."
    git init -b main
fi

# Configure remote origin
REMOTE_SSH="git@github.com:wisabuilds/WisaProtectX-Server.git"
REMOTE_HTTPS="https://github.com/wisabuilds/WisaProtectX-Server.git"

if ! git remote | grep -q "^origin$"; then
    echo "→ Adding remote origin ($REMOTE_SSH)..."
    git remote add origin "$REMOTE_SSH"
fi

# Stage and commit
echo "→ Staging files..."
git add .
if git diff --staged --quiet; then
    echo "→ Working tree clean, nothing to commit."
else
    echo "→ Committing initial release..."
    git commit -m "feat: initial release of WisaProtectX-Server & harvester"
fi

echo ""
echo "To push to GitHub, run:"
echo "  cd \"$REPO_DIR\""
echo "  git push -u origin main"
echo ""
echo "If your SSH key is not set, use HTTPS:"
echo "  git remote set-url origin $REMOTE_HTTPS"
echo "  git push -u origin main"
