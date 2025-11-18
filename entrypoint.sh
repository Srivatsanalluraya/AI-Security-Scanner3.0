#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

SCAN_PATH=${1:-"."}
echo "🔍 Scanning path: $SCAN_PATH"

mkdir -p reports

echo "▶ Running Bandit..."
bandit -r "$SCAN_PATH" -f json -o reports/bandit-report.json || true

echo "▶ Running Semgrep..."
semgrep --config auto --json --output reports/semgrep-report.json "$SCAN_PATH" || true

echo "▶ Running pip-audit..."
pip-audit -f json -o reports/pip-audit-report.json || true

echo "📝 Merging reports..."
python /app/src/reporters/report_builder.py \
  --reports-dir reports \
  --out reports/final_report.json

echo "🤖 Generating AI summary..."
python /app/src/ai/summarizer.py

echo "📄 Writing SARIF..."
python /app/src/reporters/sarif_writer.py \
  --input reports/final_report.json \
  --out reports/report.sarif

# Post PR comment if PR exists
if [[ -n "$GITHUB_EVENT_PATH" ]]; then
    PR_NUMBER=$(jq -r ".pull_request.number // empty" "$GITHUB_EVENT_PATH")
    if [[ -n "$PR_NUMBER" ]]; then
        echo "💬 Posting PR comment..."
        python /app/src/reporters/pr_commenter.py \
            --summary reports/summary.txt \
            --repo "$GITHUB_REPOSITORY" \
            --pr "$PR_NUMBER" \
            --token "$GITHUB_TOKEN"
    fi
fi

echo "✅ Completed AI Vulnerability Scan"
