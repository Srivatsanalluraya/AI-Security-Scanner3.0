#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

# ===============================
# Inputs
# ===============================
SCAN_PATH=${1:-"."}
RAW_TOKEN="$2"

ENFORCE_POLICY="${INPUT_ENFORCE_POLICY:-false}"

# Prefer explicit token → fallback
GITHUB_TOKEN="${RAW_TOKEN:-$GITHUB_TOKEN}"


# ===============================
# AI Backend Setup
# ===============================

# Default backend (override via env if needed)
export AI_BACKEND_URL="${AI_BACKEND_URL:-https://ai-security-backend.onrender.com/analyze}"

echo "🤖 Connecting to AI backend:"
echo "   → $AI_BACKEND_URL"


# ===============================
# Validate GitHub Token
# ===============================

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "❌ ERROR: GitHub token missing."
    exit 1
fi


# ===============================
# Export Scan Path
# ===============================

export SCAN_PATH="$SCAN_PATH"

echo "🔍 Scanning path: $SCAN_PATH"
echo "🔐 Policy enforcement: $ENFORCE_POLICY"


# ===============================
# Run In-Memory Scanner
# ===============================

echo ""
echo "▶ Running in-memory security + AI analysis..."

python /app/src/ai/live_scanner.py || {
    echo "❌ Live scan failed"
    exit 1
}


# ===============================
# Artifact Export
# ===============================

echo ""
echo "▶ Saving scan reports..."

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

ARTIFACTS_DIR="${GITHUB_WORKSPACE}/security-reports"
mkdir -p "$ARTIFACTS_DIR"


LIVE_REPORT="security-reports/live_report.json"


if [[ -f "$LIVE_REPORT" ]]; then
    cp "$LIVE_REPORT" "$ARTIFACTS_DIR/scan-${TIMESTAMP}.json"
    echo "  ✓ scan-${TIMESTAMP}.json"
else
    echo "⚠ No live report found"
fi


# ===============================
# Summary Markdown
# ===============================

cat > "$ARTIFACTS_DIR/summary-${TIMESTAMP}.md" << EOF
# Security Scan Report

**Timestamp:** ${TIMESTAMP}
**Date:** $(date)
**Repository:** ${GITHUB_REPOSITORY:-Unknown}
**Branch:** ${GITHUB_REF_NAME:-Unknown}

## Available Reports
- \`scan-${TIMESTAMP}.json\` - AI-enhanced live scan output

## Note
Generated using centralized AI backend.
EOF


echo "  ✓ summary-${TIMESTAMP}.md"
echo "  📁 Location: security-reports/"


# ===============================
# Policy Enforcement
# ===============================

echo ""
echo "▶ Checking security policy..."

POLICY_EXIT_CODE=0

set +e

python - <<EOF
import json
from pathlib import Path
from src.security_policy import SecurityPolicy

report = Path("security-reports/live_report.json")

if report.exists():

    data = json.loads(report.read_text())

    policy = SecurityPolicy(data)

    print(policy.get_report())

    if "$ENFORCE_POLICY" == "true" and not policy.allow_push:
        exit(1)

else:
    print("⚠ No report found for policy check")
EOF

POLICY_EXIT_CODE=$?

set -e

# ===============================
# Console Dashboard (always runs)
# ===============================
echo ""
echo "▶ Generating console report..."
python /app/src/reporters/dashboard.py \
  --report "reports/issues_detailed.json" \
  2>/dev/null || echo "⚠ Dashboard display failed"


# ===============================
# PR Comment
# ===============================

if [[ -n "$GITHUB_EVENT_PATH" ]]; then

    PR_NUMBER=$(jq -r ".pull_request.number // empty" "$GITHUB_EVENT_PATH" 2>/dev/null)

    if [[ -n "$PR_NUMBER" ]]; then

        echo ""
        echo "▶ Posting PR comment..."

        COMMIT_SHA=$(jq -r ".pull_request.head.sha // empty" "$GITHUB_EVENT_PATH")

        python /app/src/reporters/pr_commenter.py \
            --report "reports/issues_detailed.json" \
            --repo "$GITHUB_REPOSITORY" \
            --pr "$PR_NUMBER" \
            --token "$GITHUB_TOKEN" \
            --sha "$COMMIT_SHA" \
            2>/dev/null || echo "⚠ PR comment failed"

    fi
fi


# ===============================
# Final Status
# ===============================

echo ""
echo "======================================================================"

if [[ $POLICY_EXIT_CODE -ne 0 ]]; then

    echo "❌ WORKFLOW FAILED - SECURITY POLICY VIOLATION"

else

    echo "✅ SECURITY SCAN COMPLETED SUCCESSFULLY"
    echo "🎉 AI-powered pipeline executed"

fi

echo "======================================================================"

exit $POLICY_EXIT_CODE
