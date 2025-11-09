#!/usr/bin/env bash
set -euo pipefail

echo "Starting AI-Vulnerability-Scanner..."
export GITHUB_TOKEN="${INPUT_GITHUB_TOKEN}"
python3 /app/src/scanner.py
