#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

SCAN_PATH=${1:-"."}
RAW_TOKEN="$2"
ENFORCE_POLICY="${INPUT_ENFORCE_POLICY:-false}"

# Prefer explicit token argument → fallback to env
GITHUB_TOKEN="${RAW_TOKEN:-$GITHUB_TOKEN}"

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "❌ ERROR: GitHub token missing. Provide via 'github_token' input."
    exit 1
fi

echo "🔍 Scanning path: $SCAN_PATH"
echo "🔐 Policy enforcement: $ENFORCE_POLICY"
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

# Display dashboard-style report
echo ""
python /app/src/reporters/dashboard.py \
  --report-dir "$REPORT_DIR" 2>/dev/null || echo "Could not display dashboard"

# Display detailed findings and download info
python /app/src/reporters/report_display.py \
  --report-dir "$REPORT_DIR" \
  --downloads-only 2>/dev/null || echo "Could not display download options"

# === SECURITY POLICY ENFORCEMENT ===
POLICY_EXIT_CODE=0
echo ""
echo "▶ Checking security policy..."
python -c "
import json
from pathlib import Path
from src.security_policy import SecurityPolicy

# Load issues from detailed report
detail_file = Path('$REPORT_DIR/issues_detailed.json')
if detail_file.exists():
    data = json.loads(detail_file.read_text())
    issues = data.get('detailed_issues', [])
    policy = SecurityPolicy(issues)
    print(policy.get_report())
    
    if '$ENFORCE_POLICY' == 'true' and not policy.allow_push:
        exit(1)
" 2>/dev/null || POLICY_EXIT_CODE=$?

# === PR COMMENT HANDLING ===
if [[ -n "$GITHUB_EVENT_PATH" ]]; then
    PR_NUMBER=$(jq -r ".pull_request.number // empty" "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")

    if [[ -n "$PR_NUMBER" ]]; then
        echo ""
        echo "▶ Posting enhanced PR comment with dashboard..."
        
        POLICY_FLAG=""
        if [[ "$ENFORCE_POLICY" == "true" ]]; then
            POLICY_FLAG="--enforce-policy"
        fi
        
        python /app/src/reporters/pr_commenter.py \
            --report "$REPORT_DIR/final_report.json" \
            --repo "$GITHUB_REPOSITORY" \
            --pr "$PR_NUMBER" \
            --token "$GITHUB_TOKEN" \
            $POLICY_FLAG 2>/dev/null || echo "  ⚠️ Failed to post PR comment"
    fi
fi

echo ""
if [[ $POLICY_EXIT_CODE -ne 0 ]]; then
    echo "❌ Scan complete - Push blocked by security policy"
else
    echo "✅ Scan complete!"
fi

exit $POLICY_EXIT_CODE
