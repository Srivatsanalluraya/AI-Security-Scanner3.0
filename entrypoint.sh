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

# Detect languages in workspace
echo ""
echo "🔎 Detecting languages..."
python /app/src/language_detector.py "$SCAN_PATH" > "$REPORT_DIR/languages.txt" || echo "Language detection skipped"
cat "$REPORT_DIR/languages.txt" 2>/dev/null || true

echo ""
echo "▶ Running security scanners..."

# === PYTHON SCANNERS ===
if [ -f "requirements.txt" ] || find . -name "*.py" -type f | head -n 1 | grep -q .; then
    echo "  🐍 Python detected"
    
    echo "    - Bandit (Python security)"
    bandit -r "$SCAN_PATH" -f json -o "$REPORT_DIR/bandit-report.json" 2>/dev/null || true
    
    if [ -f "requirements.txt" ]; then
        echo "    - pip-audit (Python dependencies)"
        pip-audit -f json -o "$REPORT_DIR/pip-audit-report.json" 2>/dev/null || true
    fi
fi

# === JAVASCRIPT/NODE.JS SCANNERS ===
if [ -f "package.json" ] || find . -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" | head -n 1 | grep -q .; then
    echo "  📦 JavaScript/Node.js detected"
    
    if [ -f "package.json" ]; then
        echo "    - npm audit (Node.js dependencies)"
        npm audit --json > "$REPORT_DIR/npm-audit-report.json" 2>/dev/null || true
        
        echo "    - npm outdated"
        npm outdated --json > "$REPORT_DIR/npm-outdated.json" 2>/dev/null || true
    fi
    
    if [ -f "yarn.lock" ]; then
        echo "    - yarn audit (Yarn dependencies)"
        yarn audit --json > "$REPORT_DIR/yarn-audit-report.json" 2>/dev/null || true
    fi
fi

# === JAVA SCANNERS ===
if [ -f "pom.xml" ] || [ -f "build.gradle" ] || find . -name "*.java" -type f | head -n 1 | grep -q .; then
    echo "  ☕ Java detected"
    
    if command -v dependency-check.sh &> /dev/null; then
        echo "    - OWASP Dependency Check (Java dependencies)"
        dependency-check.sh --scan . --format JSON --out "$REPORT_DIR" --project "scan" 2>/dev/null || true
        mv "$REPORT_DIR/dependency-check-report.json" "$REPORT_DIR/java-dependency-check.json" 2>/dev/null || true
    fi
fi

# === GO SCANNERS ===
if [ -f "go.mod" ] || find . -name "*.go" -type f | head -n 1 | grep -q .; then
    echo "  🔷 Go detected"
    
    if command -v gosec &> /dev/null; then
        echo "    - Gosec (Go security)"
        gosec -fmt json -out "$REPORT_DIR/gosec-report.json" ./... 2>/dev/null || true
    fi
    
    if [ -f "go.sum" ] && command -v nancy &> /dev/null; then
        echo "    - Nancy (Go dependencies)"
        go list -json -m all | nancy sleuth --output json > "$REPORT_DIR/nancy-report.json" 2>/dev/null || true
    fi
fi

# === UNIVERSAL SCANNERS (ALL LANGUAGES) ===
echo "  🔍 Universal scanners"

echo "    - Semgrep (multi-language)"
semgrep --config auto --json --output "$REPORT_DIR/semgrep-report.json" "$SCAN_PATH" 2>/dev/null || true

if command -v trivy &> /dev/null; then
    echo "    - Trivy (vulnerabilities & misconfigurations)"
    trivy fs --format json --output "$REPORT_DIR/trivy-report.json" "$SCAN_PATH" 2>/dev/null || true
fi

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
        
        # Use issues_detailed.json for consistent counts with dashboard
        python /app/src/reporters/pr_commenter.py \
            --report "$REPORT_DIR/issues_detailed.json" \
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
