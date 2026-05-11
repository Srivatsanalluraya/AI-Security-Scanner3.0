#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

# ===============================
# Inputs
# ===============================
SCAN_PATH=${1:-"."}
RAW_TOKEN="$2"

ENFORCE_POLICY="${INPUT_ENFORCE_POLICY:-false}"
GITHUB_TOKEN="${RAW_TOKEN:-$GITHUB_TOKEN}"

echo "🔎 Event: $GITHUB_EVENT_NAME"


# ===============================
# AI Backend Setup
# ===============================
export AI_BACKEND_URL="${AI_BACKEND_URL:-https://ai-security-backend.onrender.com/analyze}"

echo "🤖 Connecting to AI backend:"
echo "   → $AI_BACKEND_URL"


# ===============================
# Validate Token
# ===============================
if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "❌ ERROR: GitHub token missing."
    exit 1
fi


# ===============================
# Scan Setup
# ===============================
export SCAN_PATH="$SCAN_PATH"

echo "🔍 Scanning path: $SCAN_PATH"
echo "🔐 Policy enforcement: $ENFORCE_POLICY"


# ===============================
# Warm Up
# ===============================
echo "🔥 Warming up AI backend..."
curl -s --max-time 60 "$AI_BACKEND_URL" > /dev/null 2>&1 || true
sleep 5


# ===============================
# Run Scanner
# ===============================
# ===============================
# Gitleaks Secret Scan
# ===============================

echo "▶ Gitleaks (Secrets Detection)"

git config --global --add safe.directory /github/workspace
mkdir -p reports

gitleaks detect \
  --source "$SCAN_PATH" \
  --report-format json \
  --report-path reports/gitleaks-report.json \
  || true

echo ""
echo "▶ Running in-memory security + AI analysis..."

python /app/src/ai/live_scanner.py || {
    echo "❌ Live scan failed"
    exit 1
}


# ===============================
# Save Artifacts
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
- \`scan-${TIMESTAMP}.json\`

EOF

echo "  ✓ summary-${TIMESTAMP}.md"


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
# Dashboard (always)
# ===============================
echo ""
echo "▶ Generating dashboard..."

python /app/src/reporters/dashboard.py \
  --report-dir "${GITHUB_WORKSPACE}/reports" \
  || echo "⚠ Dashboard failed"


# ===============================
# PR Detection (robust)
# ===============================
PR_NUMBER=""
COMMIT_SHA=""

if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
    PR_NUMBER=$(jq -r ".pull_request.number" "$GITHUB_EVENT_PATH")
    COMMIT_SHA=$(jq -r ".pull_request.head.sha" "$GITHUB_EVENT_PATH")
fi

echo "DEBUG: PR_NUMBER=$PR_NUMBER"
echo "DEBUG: COMMIT_SHA=$COMMIT_SHA"


# ===============================
# Detailed Report (single call)
# ===============================
echo ""
echo "▶ Generating detailed console report..."

if [[ -f "reports/issues_detailed.json" ]]; then

    CMD="python /app/src/reporters/pr_commenter.py \
        --report reports/issues_detailed.json \
        --repo $GITHUB_REPOSITORY \
        --token $GITHUB_TOKEN"

    # Add PR only if exists
    if [[ -n "$PR_NUMBER" ]]; then
        CMD="$CMD --pr $PR_NUMBER"
    fi

    # Add SHA only if exists
    if [[ -n "$COMMIT_SHA" ]]; then
        CMD="$CMD --sha $COMMIT_SHA"
    fi

    eval $CMD || echo "⚠ Detailed report generation failed"

else
    echo "⚠ No detailed report found"
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
fi

echo "======================================================================"

exit $POLICY_EXIT_CODE
