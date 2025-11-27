#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

SCAN_PATH=${1:-"."}
echo "🔍 Scanning path: $SCAN_PATH"

# Store reports only inside container
REPORT_DIR="reports"
mkdir -p "$REPORT_DIR"

echo "▶ Running Bandit..."
bandit -r "$SCAN_PATH" -f json -o "$REPORT_DIR/bandit-report.json" || true

echo "▶ Running Semgrep..."
semgrep --config auto --json --output "$REPORT_DIR/semgrep-report.json" "$SCAN_PATH" || true

echo "▶ Running pip-audit..."
pip-audit -f json -o "$REPORT_DIR/pip-audit-report.json" || true

echo "📝 Merging reports..."
python /app/src/reporters/report_builder.py \
  --reports-dir "$REPORT_DIR" \
  --out "$REPORT_DIR/final_report.json"

echo "🤖 Generating AI summary..."
python /app/src/ai/summarizer.py \
  --input "$REPORT_DIR/final_report.json" \
  --output "$REPORT_DIR/summary.txt"

echo ""
echo "============================="
echo "📢 AI SECURITY SUMMARY"
echo "============================="
cat "$REPORT_DIR/summary.txt"
echo ""

echo "============================="
echo "📢 MERGED SECURITY REPORT"
echo "============================="
cat "$REPORT_DIR/final_report.json"
echo ""

echo "============================="
echo "📢 BANDIT RAW RESULTS"
echo "============================="
cat "$REPORT_DIR/bandit-report.json"
echo ""

echo "============================="
echo "📢 SEMGREP RAW RESULTS"
echo "============================="
cat "$REPORT_DIR/semgrep-report.json"
echo ""

echo "============================="
echo "📢 PIP-AUDIT RAW RESULTS"
echo "============================="
cat "$REPORT_DIR/pip-audit-report.json"
echo ""

# Post PR comment if PR exists
if [[ -n "$GITHUB_EVENT_PATH" ]]; then
    PR_NUMBER=$(jq -r ".pull_request.number // empty" "$GITHUB_EVENT_PATH")
    if [[ -n "$PR_NUMBER" ]]; then
        echo "💬 Posting PR comment..."
        python /app/src/reporters/pr_commenter.py \
            --summary "$REPORT_DIR/summary.txt" \
            --repo "$GITHUB_REPOSITORY" \
            --pr "$PR_NUMBER" \
            --token "$GITHUB_TOKEN"
    fi
fi

echo "🎉 All reports printed above. Scan complete!"
