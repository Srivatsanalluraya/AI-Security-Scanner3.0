#!/bin/bash
set -e

echo "🔥 AI Vulnerability Scanner Starting..."

SCAN_PATH=${1:-"."}
RAW_TOKEN="$2"
ENFORCE_POLICY="${INPUT_ENFORCE_POLICY:-false}"
GOOGLE_API_KEY="${INPUT_GOOGLE_API_KEY:-}"

# Prefer explicit token argument → fallback to env
GITHUB_TOKEN="${RAW_TOKEN:-$GITHUB_TOKEN}"

# Export API key for Python scripts (optional AI enhancement)
if [[ -n "$GOOGLE_API_KEY" ]]; then
    export GOOGLE_API_KEY
    echo "🤖 AI enhancement enabled (Gemini)"
else
    echo "📊 Using pattern-based analysis (AI disabled)"
fi

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "❌ ERROR: GitHub token missing. Provide via 'github_token' input."
    exit 1
fi

echo "🔍 Scanning path: $SCAN_PATH"
echo "🔐 Policy enforcement: $ENFORCE_POLICY"
REPORT_DIR="reports"
mkdir -p "$REPORT_DIR"

# Detect languages in workspace
echo ""
echo "🔎 Detecting languages..."
python /app/src/language_detector.py "$SCAN_PATH" > "$REPORT_DIR/languages.txt" 2>/dev/null || echo "Python"
cat "$REPORT_DIR/languages.txt" 2>/dev/null || true

# Run scanners silently (capture output only if needed)
echo ""
echo "▶ Running security scanners..."

echo "  - Bandit (Python)..."
bandit -r "$SCAN_PATH" -f json -o "$REPORT_DIR/bandit-report.json" 2>/dev/null || true

echo "  - Semgrep (multi-language: Python, JavaScript, Java, Go, etc.)..."
semgrep --config auto --json --output "$REPORT_DIR/semgrep-report.json" "$SCAN_PATH" 2>/dev/null || true

echo "  - pip-audit (Python dependencies)..."
pip-audit -f json -o "$REPORT_DIR/pip-audit-report.json" 2>/dev/null || true

echo "  - Safety (Python dependencies)..."
safety check --json --output "$REPORT_DIR/safety-report.json" 2>/dev/null || true

# JavaScript/Node.js scanners
if [ -f "package.json" ]; then
    echo "  - npm audit (JavaScript dependencies)..."
    npm audit --json > "$REPORT_DIR/npm-audit-report.json" 2>/dev/null || true
    
    echo "  - RetireJS (JavaScript vulnerabilities)..."
    retire --js --outputformat json --outputpath "$REPORT_DIR/retire-report.json" 2>/dev/null || true
fi

echo ""
echo "▶ Merging reports..."
python /app/src/reporters/report_builder.py \
  --reports-dir "$REPORT_DIR" \
  --out "$REPORT_DIR/final_report.json" 2>/dev/null || echo "  ⚠️ Report merge encountered an issue"

echo "Γû╢ Generating AI summaries..."
python /app/src/ai/summarizer.py 2>/dev/null || echo "  ΓÜá∩╕Å Summarization encountered an issue"

# Display dashboard-style report
echo ""
python /app/src/reporters/dashboard.py \
  --report-dir "$REPORT_DIR" 2>/dev/null || echo "Could not display dashboard"

# Display detailed findings and download info
python /app/src/reporters/report_display.py \
  --report-dir "$REPORT_DIR" \
  --downloads-only 2>/dev/null || echo "Could not display download options"

# === SAVE ARTIFACTS TO TARGET REPOSITORY ===
echo ""
echo "▶ Saving scan reports to target repository..."
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
ARTIFACTS_DIR="${GITHUB_WORKSPACE}/security-reports"
mkdir -p "$ARTIFACTS_DIR"

# Copy timestamped reports
if [ -f "$REPORT_DIR/issues_detailed.json" ]; then
    cp "$REPORT_DIR/issues_detailed.json" "$ARTIFACTS_DIR/scan-${TIMESTAMP}.json"
    echo "  ✓ scan-${TIMESTAMP}.json"
fi

if [ -f "$REPORT_DIR/final_report.json" ]; then
    cp "$REPORT_DIR/final_report.json" "$ARTIFACTS_DIR/full-${TIMESTAMP}.json"
    echo "  ✓ full-${TIMESTAMP}.json"
fi

# Create summary markdown
cat > "$ARTIFACTS_DIR/summary-${TIMESTAMP}.md" << EOF
# Security Scan Report

**Timestamp:** ${TIMESTAMP}
**Date:** $(date)
**Repository:** ${GITHUB_REPOSITORY:-Unknown}
**Branch:** ${GITHUB_REF_NAME:-Unknown}

## Available Reports
- \`scan-${TIMESTAMP}.json\` - Detailed issues with AI analysis
- \`full-${TIMESTAMP}.json\` - Complete merged scanner output

## Note
Reports are automatically saved in the \`security-reports/\` directory.
To commit them, add a git commit step in your workflow.
EOF

echo "  ✓ summary-${TIMESTAMP}.md"
echo "  📁 Location: security-reports/"

# === SECURITY POLICY ENFORCEMENT ===
POLICY_EXIT_CODE=0
echo ""
echo "Γû╢ Checking security policy..."
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
        echo "Γû╢ Posting enhanced PR comment with dashboard..."
        
        POLICY_FLAG=""
        if [[ "$ENFORCE_POLICY" == "true" ]]; then
            POLICY_FLAG="--enforce-policy"
        fi
        
        # Use issues_detailed.json for consistent counts with dashboard
        python /app/src/reporters/pr_commenter.py \
            --report "$REPORT_DIR/issues_detailed.json" \
            --repo "$GITHUB_REPOSITORY" \
            --pr "$PR_NUMBER" \
            --token "$GITHUB_TOKEN" \
            $POLICY_FLAG 2>/dev/null || echo "  ΓÜá∩╕Å Failed to post PR comment"
    fi
fi

echo ""
echo "======================================================================"
if [[ $POLICY_EXIT_CODE -ne 0 ]]; then
    echo "❌ WORKFLOW FAILED - MERGE BLOCKED BY SECURITY POLICY"
    echo "======================================================================"
    echo ""
    echo "🚨 HIGH severity vulnerabilities exceed 25% threshold"
    echo "📋 Review security scan results above"
    echo "🔧 Fix critical issues and push changes to unblock"
    echo ""
    echo "This PR cannot be merged until security issues are resolved."
    echo "======================================================================"
else
    echo "✅ SECURITY SCAN COMPLETED SUCCESSFULLY"
    echo "======================================================================"
    if [[ "$ENFORCE_POLICY" == "true" ]]; then
        echo ""
        echo "✓ Security policy check passed"
        echo "✓ Merge is allowed (review recommended)"
    fi
    echo ""
    echo "🎉 Scan complete!"
    echo "======================================================================"
fi

exit $POLICY_EXIT_CODE
