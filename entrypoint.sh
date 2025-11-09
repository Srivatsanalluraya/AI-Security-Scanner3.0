#!/usr/bin/env bash
set -euo pipefail

echo "Starting AI-Vulnerability-Scanner..."

# Ensure variables are passed properly
SCAN_PATH="${INPUT_SCAN_PATH:-.}"
WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
OUTDIR="/app/out"

# Make sure GITHUB_TOKEN is exported
export GITHUB_TOKEN="${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"

# Debug prints
echo "Workspace: $WORKSPACE"
echo "Scan path: $SCAN_PATH"

# Run scanner.py
python3 /app/src/scanner.py --workspace "$WORKSPACE" --scan-path "$SCAN_PATH"
