# Multi-Language Scanner Testing Guide

## Quick Test Commands

### Build the Container
```bash
docker build -t ai-security-scanner:v3 .
```

### Test with Different Languages

#### Python Project
```bash
docker run --rm \
  -v /path/to/python-project:/workspace \
  -e GITHUB_TOKEN=dummy \
  -e INPUT_ENFORCE_POLICY=false \
  ai-security-scanner:v3
```

#### Node.js Project
```bash
docker run --rm \
  -v /path/to/nodejs-project:/workspace \
  -e GITHUB_TOKEN=dummy \
  -e INPUT_ENFORCE_POLICY=false \
  ai-security-scanner:v3
```

#### Go Project
```bash
docker run --rm \
  -v /path/to/go-project:/workspace \
  -e GITHUB_TOKEN=dummy \
  -e INPUT_ENFORCE_POLICY=false \
  ai-security-scanner:v3
```

#### Java Project
```bash
docker run --rm \
  -v /path/to/java-project:/workspace \
  -e GITHUB_TOKEN=dummy \
  -e INPUT_ENFORCE_POLICY=false \
  ai-security-scanner:v3
```

#### Multi-Language (Polyglot) Project
```bash
docker run --rm \
  -v /path/to/polyglot-project:/workspace \
  -e GITHUB_TOKEN=dummy \
  -e INPUT_ENFORCE_POLICY=true \
  ai-security-scanner:v3
```

## Expected Output Structure

### Console Output
```
🔥 AI Vulnerability Scanner Starting...
🔍 Scanning path: .
🔐 Policy enforcement: false

🔎 Detecting languages...
Python: ✓
JavaScript: ✓
Go: ✗
Java: ✗

▶ Running security scanners...
  🐍 Python detected
    - Bandit (Python security)
    - pip-audit (Python dependencies)
  
  📦 JavaScript/Node.js detected
    - npm audit (Node.js dependencies)
    - npm outdated
  
  🔍 Universal scanners
    - Semgrep (multi-language)
    - Trivy (vulnerabilities & misconfigurations)

▶ Merging reports...
▶ Generating AI summaries...

╔═══════════════════════════════════════╗
║      🔒 SECURITY SCAN SUMMARY         ║
╠═══════════════════════════════════════╣
║  HIGH:    3  ████░░░░░░ (15%)        ║
║  MEDIUM:  8  ████████░░ (40%)        ║
║  LOW:     9  █████████░ (45%)        ║
╠═══════════════════════════════════════╣
║  Total Issues: 20                     ║
║  Status: ⚠️ WARNING                   ║
╚═══════════════════════════════════════╝

▶ Checking security policy...
✅ Policy: PASSED (15% HIGH < 25% threshold)

✅ Scan complete!
```

### Report Files Generated
```
reports/
├── languages.txt                  # Detected languages
├── bandit-report.json            # Python security issues
├── pip-audit-report.json         # Python dependency vulnerabilities
├── npm-audit-report.json         # Node.js dependency vulnerabilities
├── npm-outdated.json             # Outdated npm packages
├── gosec-report.json             # Go security issues (if Go detected)
├── nancy-report.json             # Go dependency vulnerabilities (if Go detected)
├── trivy-report.json             # Universal vulnerability scan
├── semgrep-report.json           # Multi-language security patterns
├── final_report.json             # Merged report
└── issues_detailed.json          # AI-enhanced issue details
```

## Verification Checklist

### ✅ Language Detection
- [ ] Correct languages detected in `reports/languages.txt`
- [ ] Appropriate scanners run for each detected language
- [ ] No errors for missing language tools

### ✅ Scanner Execution
- [ ] Python: Bandit and pip-audit reports generated
- [ ] JavaScript: npm-audit report generated
- [ ] Go: gosec and nancy reports generated (if applicable)
- [ ] Java: dependency-check report generated (if applicable)
- [ ] Universal: Semgrep and Trivy reports generated

### ✅ Report Processing
- [ ] `final_report.json` contains merged results
- [ ] `issues_detailed.json` has AI-generated impacts and fixes
- [ ] Dashboard displays correct issue counts
- [ ] Severity distribution matches actual issues

### ✅ Policy Enforcement
- [ ] Policy calculation shows correct HIGH percentage
- [ ] Exit code 0 when policy passes (< 25% HIGH)
- [ ] Exit code 1 when policy fails (>= 25% HIGH and enforce_policy=true)
- [ ] Warning displayed correctly

### ✅ PR Comments (GitHub Actions only)
- [ ] Dashboard section rendered with emojis
- [ ] Files section groups issues by file
- [ ] Detailed issues show [Pushed by | Description | Impact | Fix]
- [ ] Policy status clearly indicated

## Sample Test Projects

### Minimal Python Test
```bash
mkdir test-python
cd test-python
echo "import os" > app.py
echo "password = 'hardcoded123'" >> app.py
echo "requests" > requirements.txt

docker run --rm -v $(pwd):/workspace ai-security-scanner:v3
```

Expected: Bandit detects hardcoded password

### Minimal Node.js Test
```bash
mkdir test-nodejs
cd test-nodejs
echo '{"dependencies": {"express": "3.0.0"}}' > package.json
npm install

docker run --rm -v $(pwd):/workspace ai-security-scanner:v3
```

Expected: npm audit finds vulnerabilities in old Express version

### Minimal Go Test
```bash
mkdir test-go
cd test-go
go mod init testapp
echo 'package main; import "crypto/md5"; var _ = md5.New()' > main.go

docker run --rm -v $(pwd):/workspace ai-security-scanner:v3
```

Expected: Gosec detects weak crypto (MD5)

## Troubleshooting

### Issue: "Language detection skipped"
**Solution**: Ensure language_detector.py has executable permissions and Python path is correct

### Issue: Scanner not running for detected language
**Solution**: Check scanner is installed in Dockerfile and executable in container

### Issue: Empty reports generated
**Solution**: Verify manifest files exist (requirements.txt, package.json, go.mod) and have valid syntax

### Issue: Policy shows 0% HIGH but issues visible
**Solution**: Check severity normalization in summarizer.py extract_severity_level()

### Issue: Dashboard shows different counts than PR comment
**Solution**: Both should read from issues_detailed.json - verify data source in both files

## Performance Notes

- **Python scanning**: ~10-30 seconds for medium projects
- **Node.js scanning**: ~5-15 seconds (npm audit is fast)
- **Go scanning**: ~20-40 seconds (gosec is thorough)
- **Trivy scanning**: ~30-60 seconds (downloads vulnerability DB first run)
- **AI summarization**: ~10-20 seconds (FLAN-T5 model inference)

## Advanced Testing

### Test Policy Enforcement
```bash
# Create project with many HIGH issues
mkdir test-policy
cd test-policy
echo "eval(input())" > dangerous.py
echo "exec(open('file').read())" >> dangerous.py
echo "password = 'admin123'" >> dangerous.py

docker run --rm \
  -v $(pwd):/workspace \
  -e INPUT_ENFORCE_POLICY=true \
  ai-security-scanner:v3

echo "Exit code: $?"  # Should be 1 (blocked)
```

### Test Multi-Language Detection
```bash
mkdir test-multilang
cd test-multilang

# Python files
echo "import os" > app.py
echo "requests" > requirements.txt

# Node.js files
echo '{"dependencies": {}}' > package.json

# Go files
echo "package main" > main.go
go mod init testapp

docker run --rm -v $(pwd):/workspace ai-security-scanner:v3

# Check detected languages
cat reports/languages.txt
```

Expected output:
```
Python: ✓
JavaScript: ✓
Go: ✓
Java: ✗
```

### Test SARIF Output (Future)
```bash
# SARIF files should be in reports/sarif/
docker run --rm -v $(pwd):/workspace ai-security-scanner:v3
ls -la reports/sarif/
```

## CI/CD Integration Examples

### GitHub Actions
```yaml
- name: Multi-Language Security Scan
  uses: your-username/ai-security-scanner@v3
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    scan_path: "."
    enforce_policy: "true"
```

### GitLab CI
```yaml
security_scan:
  image: your-registry/ai-security-scanner:v3
  script:
    - /app/entrypoint.sh . $CI_JOB_TOKEN
  artifacts:
    paths:
      - reports/
    reports:
      sast: reports/semgrep.sarif
```

### Jenkins
```groovy
stage('Security Scan') {
  steps {
    docker.image('ai-security-scanner:v3').inside {
      sh '/app/entrypoint.sh . $GITHUB_TOKEN'
    }
  }
}
```

## Next Steps

1. ✅ Multi-language detection implemented
2. ✅ Scanner infrastructure in place
3. ✅ Report parsing updated
4. ⏳ Test with real-world projects
5. ⏳ Add Java OWASP Dependency Check integration
6. ⏳ Optimize Trivy caching
7. ⏳ Add custom Semgrep rules per language
8. ⏳ Implement SARIF upload to GitHub Security tab

---

**Happy Scanning! 🔒**
