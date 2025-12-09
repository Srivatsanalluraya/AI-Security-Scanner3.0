#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

SCAN_PATH=${1:-"."}
RAW_TOKEN="$2"

# Prefer explicit token argument → fallback to env
GITHUB_TOKEN="${RAW_TOKEN:-$GITHUB_TOKEN}"

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "❌ ERROR: GitHub token missing. Provide via 'github_token' input."
    exit 1
fi

echo "🔍 Scanning path: $SCAN_PATH"
REPORT_DIR="reports"
mkdir -p "$REPORT_DIR"

# Run scanners silently (capture output only if needed)
echo "▶ Running security scanners..."

echo "  - Bandit..."
bandit -r "$SCAN_PATH" -f json -o "$REPORT_DIR/bandit-report.json" 2>/dev/null || true

echo "  - Semgrep..."
semgrep --config auto --json --output "$REPORT_DIR/semgrep-report.json" "$SCAN_PATH" 2>/dev/null || true

echo "  - pip-audit..."
pip-audit -f json -o "$REPORT_DIR/pip-audit-report.json" 2>/dev/null || true

echo ""
echo "▶ Merging reports..."
python /app/src/reporters/report_builder.py \
  --reports-dir "$REPORT_DIR" \
  --out "$REPORT_DIR/final_report.json" 2>/dev/null || echo "  ⚠️ Report merge encountered an issue"

echo "▶ Generating AI summaries..."
python /app/src/ai/summarizer.py 2>/dev/null || echo "  ⚠️ Summarization encountered an issue"

# Display concise summary report
echo ""
python /app/src/reporters/report_display.py \
  --report-dir "$REPORT_DIR" \
  --summary-only 2>/dev/null || echo "Could not display summary"

# Display detailed findings
python /app/src/reporters/report_display.py \
  --report-dir "$REPORT_DIR" \
  --downloads-only 2>/dev/null || echo "Could not display download options"

# === PR Comment Handling ===
if [[ -n "$GITHUB_EVENT_PATH" ]]; then
    PR_NUMBER=$(jq -r ".pull_request.number // empty" "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")

    if [[ -n "$PR_NUMBER" ]]; then
        echo ""
        echo "▶ Posting PR comment..."
        python /app/src/reporters/pr_commenter.py \
            --report "$REPORT_DIR/final_report.json" \
            --repo "$GITHUB_REPOSITORY" \
            --pr "$PR_NUMBER" \
            --token "$GITHUB_TOKEN" 2>/dev/null || echo "  ⚠️ Failed to post PR comment"
    fi
fi

echo "✅ Scan complete!"
