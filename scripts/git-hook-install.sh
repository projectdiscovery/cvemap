#!/bin/bash

# Simple Git Hook Installer
# Alternative to pre-commit package - uses our manual script directly

set -e

echo "🔧 Installing manual pre-commit script as Git hook..."

# Check if we're in a Git repository
if [ ! -d ".git" ]; then
    echo "❌ Error: Not in a Git repository"
    exit 1
fi

# Check if our script exists
if [ ! -f "scripts/pre-commit.sh" ]; then
    echo "❌ Error: scripts/pre-commit.sh not found"
    exit 1
fi

# Copy our script to Git hooks directory
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

echo "✅ Git pre-commit hook installed!"
echo ""
echo "Now every 'git commit' will automatically run quality checks."
echo "To bypass hooks in emergencies: git commit --no-verify"
echo ""
