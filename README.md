# AI Security Scanner 3.0

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AI%20Security%20Scanner-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=github)](https://github.com/marketplace/actions/ai-security-scanner)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Required-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)

**Multi-Language Security Scanner with AI-Powered Analysis**

A comprehensive security scanning tool for Python, JavaScript/Node.js, Java, and Go projects with AI-powered vulnerability summarization, dashboard reporting, and policy enforcement.

## 🚀 Features

### Multi-Language Support
- **Python**: Bandit (security), pip-audit (dependencies), Semgrep
- **JavaScript/Node.js**: npm/yarn audit (dependencies), Semgrep
- **Java**: OWASP Dependency Check, Semgrep
- **Go**: Gosec (security), Nancy (dependencies), Semgrep
- **Universal**: Trivy (vulnerabilities & misconfigurations)

### Intelligent Features
- **Auto Language Detection**: Automatically detects project languages and runs appropriate scanners
- **AI-Powered Analysis**: FLAN-T5 model generates impact statements and fix suggestions
- **Dashboard Reports**: Color-coded console dashboard with severity distribution
- **Policy Enforcement**: Blocks pushes when HIGH severity issues exceed 25% threshold
- **PR Integration**: Comprehensive PR comments with:
  - Dashboard-style severity overview
  - File-by-file vulnerability breakdown
  - Detailed issue descriptions with impact and fixes
  - Policy compliance status

### Security Scanners

| Language | Security Scanner | Dependency Scanner | Coverage |
|----------|-----------------|-------------------|----------|
| Python | Bandit, Semgrep | pip-audit | Static code analysis, known vulnerabilities |
| JavaScript/Node.js | Semgrep | - | Code patterns, security vulnerabilities |
| Java | Semgrep | - | Code patterns, security vulnerabilities |
| Go | Semgrep | - | Code patterns, security vulnerabilities |
| Ruby, PHP, C, C++, etc. | Semgrep | - | Multi-language security patterns |

**Note:** Semgrep's `--config auto` automatically detects and scans 30+ languages without requiring separate language runtimes.

## 📋 Requirements

**For GitHub Actions (Recommended):**
- GitHub token (automatically provided by `${{ secrets.GITHUB_TOKEN }}`)
- No local installation needed!

**For Local Testing (Optional):**
- Docker Desktop (only if you want to test locally)
- GitHub token for PR comment testing

## � Quick Start
### Option 1: One-Click Setup (Recommended)
1. Go to your repository's **Actions** tab
2. Click **"New workflow"**
3. Search for **"Secure AI Scanner"**
4. Click **"Configure"** → **"Start commit"**

### Option 2: Manual SetupAdd this workflow to your repository at `.github/workflows/security.yml`:

```yaml
name: AI Security Scan

permissions:
  contents: write          # For committing reports
  pull-requests: write     # For PR comments
  security-events: write   # For security tab

on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run AI Security Scanner
        uses: Srivatsanalluraya/AI-Security-Scanner3.0@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          enforce_policy: "false"
          google_api_key: ${{ secrets.GOOGLE_API_KEY }}  # Optional: Enable AI enhancements
      
      - name: Commit scan reports
        if: always()
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add security-reports/
          git commit -m "📊 Security scan [skip ci]" || true
          git push || true
```

That's it! Push and the scanner runs automatically.

### Local Testing (Optional - Requires Docker Desktop)

**Note:** You don't need Docker Desktop for normal use! The scanner runs automatically in GitHub Actions.

Only use this if you want to test changes locally:

```bash
docker build -t security-scanner .

docker run --rm \
  -v $(pwd):/workspace \
  -e GITHUB_TOKEN=your_token \
  -e INPUT_ENFORCE_POLICY=true \
  security-scanner . your_token
```

## 📊 Output Formats

### Console Dashboard
```
╔═══════════════════════════════════════╗
║      🔒 SECURITY SCAN SUMMARY         ║
╠═══════════════════════════════════════╣
║  HIGH:    5  ████████░░ (25%)        ║
║  MEDIUM: 11  ██████████░ (55%)       ║
║  LOW:     4  ████░░░░░░ (20%)        ║
╠═══════════════════════════════════════╣
║  Total Issues: 20                     ║
║  Status: ⚠️ WARNING (25% HIGH)        ║
╚═══════════════════════════════════════╝
```

### PR Comments
- **Dashboard Section**: Visual severity distribution
- **Files Section**: Grouped vulnerabilities by affected file
- **Detailed Issues**: 
  - **Pushed by**: Scanner tool (Bandit, Gosec, npm-audit, etc.)
  - **Description**: Vulnerability explanation
  - **Impact**: AI-generated impact assessment
  - **Fix**: Actionable remediation steps
- **Policy Status**: Allow/Block decision with threshold details

### Report Files
- `issues_detailed.json`: Comprehensive issue list with metadata
- `final_report.json`: Merged scanner outputs
- `*-report.json`: Individual scanner reports
- `languages.txt`: Detected languages in workspace

## 🤖 AI Enhancement (Optional)

The scanner includes optional AI-powered analysis using Google Gemini 1.5 Flash:
- **Impact Statements**: Context-aware vulnerability impact analysis
- **Fix Suggestions**: Tailored remediation recommendations

**Without API Key**: Pattern-based analysis (fast, reliable, no setup)
**With API Key**: AI-enhanced insights (more context-aware)

### Enable AI Enhancement
1. Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Add to repository secrets: `Settings` → `Secrets and variables` → `Actions` → `New repository secret`
   - Name: `GOOGLE_API_KEY`
   - Value: Your API key
3. Update workflow:
```yaml
- uses: Srivatsanalluraya/AI-Security-Scanner3.0@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    google_api_key: ${{ secrets.GOOGLE_API_KEY }}  # Add this line
```

**Free Tier Limits**: 15 requests/min, 1500/day, 1M tokens/day

## 🛡️ Security Policy

**Default Threshold**: 25% HIGH severity

- **Above 25% HIGH**: ❌ **BLOCKED** - Push rejected
- **Below 25% HIGH**: ⚠️ **WARNING** - Push allowed with notice
- **No HIGH issues**: ✅ **PASSED** - Clean scan

Customize enforcement:
```yaml
with:
  enforce_policy: "true"  # Blocks on policy violation
  # OR
  enforce_policy: "false" # Warning only (default)
```

## 🧩 Architecture

```
Language Detection → Conditional Scanners → Report Merging → AI Analysis → Display/PR
      ↓                    ↓                     ↓              ↓           ↓
 detector.py          entrypoint.sh       report_builder   summarizer   dashboard
                      (Python: bandit)                                   pr_commenter
                      (Node: npm audit)
                      (Java: dep-check)
                      (Go: gosec)
                      (All: semgrep)
```

## 🔍 Scanner Details

### Python Scanners
- **Bandit**: Detects SQL injection, hardcoded credentials, weak crypto
- **pip-audit**: Scans requirements.txt for CVEs
- **Semgrep**: Custom security rules for Python

### JavaScript/Node.js Scanners
- **npm audit**: Official npm vulnerability scanner
- **yarn audit**: Yarn dependency security
- **Semgrep**: JavaScript/TypeScript security patterns

### Java Scanners
- **OWASP Dependency Check**: CVE scanning for Java dependencies
- **Semgrep**: Java security rules

### Go Scanners
- **Gosec**: Go security checker (hardcoded credentials, weak crypto)
- **Nancy**: go.mod/go.sum vulnerability scanner
- **Semgrep**: Go security patterns

### Universal Scanners
- **Trivy**: Comprehensive vulnerability scanner (OS packages, application dependencies, IaC)
- **Semgrep**: Multi-language security rules (auto-config)

## 📁 Project Structure

```
AI-Security-Scanner3.0/
├── action.yml              # GitHub Action definition
├── Dockerfile              # Multi-language container
├── entrypoint.sh           # Main orchestration script
├── src/
│   ├── language_detector.py    # Auto-detect languages
│   ├── security_policy.py      # Policy enforcement logic
│   ├── output_formatter.py     # Console formatting
│   ├── ai/
│   │   ├── summarizer.py       # AI-powered analysis
│   │   └── prompts/
│   │       └── summary.md      # FLAN-T5 prompts
│   └── reporters/
│       ├── dashboard.py         # Console dashboard
│       ├── pr_commenter.py      # PR comment generator
│       ├── report_builder.py    # Report merger
│       ├── report_display.py    # Download guidance
│       └── sarif_writer.py      # SARIF export
└── rules/
    └── semgrep.yml             # Custom Semgrep rules
```

## 🔐 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub token for API access | Yes (for PR comments) |
| `INPUT_ENFORCE_POLICY` | Enable/disable policy blocking | No (default: false) |
| `GITHUB_REPOSITORY` | Repository name (auto-set by Actions) | Yes (for PR comments) |
| `GITHUB_EVENT_PATH` | Event payload path (auto-set by Actions) | Yes (for PR comments) |

## 🤖 AI-Powered Features

Uses **FLAN-T5-base** model for:

1. **Impact Generation**: Analyzes vulnerability context to generate business impact
2. **Fix Suggestions**: Provides actionable remediation steps
3. **Severity Normalization**: Maps scanner-specific severities to HIGH/MEDIUM/LOW

## 📦 Installation & Dependencies

All dependencies are containerized in the Docker image:

**Base Runtimes**:
- Python 3.12
- Node.js 20.x
- Go 1.21
- Java OpenJDK 17

**Security Tools**:
- bandit, pip-audit, semgrep (Python)
- npm, yarn (JavaScript)
- gosec, nancy (Go)
- trivy (Universal)
- OWASP Dependency Check (Java) [Planned]

**AI/ML**:
- transformers (HuggingFace)
- torch (PyTorch)

## 🛠️ Development

### Local Testing

1. Build container:
```bash
docker build -t security-scanner .
```

2. Run on sample project:
```bash
docker run --rm -v /path/to/project:/workspace security-scanner
```

3. Test specific language:
```bash
# Python project
docker run --rm -v /path/to/python-app:/workspace security-scanner

# Node.js project
docker run --rm -v /path/to/node-app:/workspace security-scanner

# Multi-language project
docker run --rm -v /path/to/polyglot-app:/workspace security-scanner
```

### Adding New Scanners

1. Update `Dockerfile` with scanner installation
2. Add detection logic in `language_detector.py`
3. Add scanner invocation in `entrypoint.sh`
4. Update `summarizer.py` to parse new report format
5. Add report filename to `report_builder.py` KNOWN_JSON_REPORTS

## 📄 License

See [LICENSE](LICENSE) file.

## 🔗 Links

- [Security Policy](SECURITY.md)
- [Action Definition](action.yml)

## 🆘 Troubleshooting

**Issue**: Scanners not running
- Check language detection: `cat reports/languages.txt`
- Verify manifest files exist (requirements.txt, package.json, go.mod, pom.xml)

**Issue**: Policy blocking unexpectedly
- Review HIGH severity count in dashboard
- Check threshold: 25% HIGH triggers block
- Verify `enforce_policy` setting

**Issue**: PR comments not appearing
- Ensure `GITHUB_TOKEN` has write permissions
- Verify PR number extraction from `GITHUB_EVENT_PATH`
- Check runner logs for API errors

**Issue**: Missing dependencies in scan
- Node.js: Run `npm install` before scanning
- Python: Ensure requirements.txt is up-to-date
- Go: Run `go mod tidy` before scanning
- Java: Verify pom.xml or build.gradle exists

## 📈 Version History

- **v3.0**: Multi-language support (Python, JavaScript, Java, Go)
- **v2.5**: Policy enforcement and dashboard reports
- **v2.0**: AI-powered analysis with FLAN-T5
- **v1.0**: Initial Python-only scanner

---

**Built with ❤️ for secure software development**
