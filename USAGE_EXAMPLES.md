# Usage Examples - Downloadable Reports

The scanner automatically saves timestamped reports to `security-reports/` directory in your target repository.

## Example 1: Commit Reports to Repository

Create `.github/workflows/security-scan.yml` in your target repository:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    
    permissions:
      contents: write
      pull-requests: write
      security-events: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Run AI Security Scanner
        uses: Srivatsanalluraya/AI-Security-Scanner3.0@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          enforce_policy: "false"
      
      - name: Commit scan reports
        if: always()
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add security-reports/
          git diff --staged --quiet || git commit -m "📊 Security scan reports [skip ci]"
          git push || true
```

**Result:** Reports committed to your repo's `security-reports/` directory.

---

## Example 2: GitHub Actions Artifacts (No Commit)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run AI Security Scanner
        uses: Srivatsanalluraya/AI-Security-Scanner3.0@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload scan artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports-${{ github.run_number }}
          path: security-reports/
          retention-days: 90
```

**Result:** Reports downloadable from Actions → Artifacts tab.

---

## Example 3: Both Options Combined

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    
    permissions:
      contents: write
      pull-requests: write
    
    steps:
      - uses: actions/checkout@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Run Scanner
        uses: Srivatsanalluraya/AI-Security-Scanner3.0@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
      
      # Option 1: Upload to Actions
      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: security-reports/
      
      # Option 2: Commit to repo
      - name: Commit reports
        if: github.event_name == 'push'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add security-reports/
          git commit -m "📊 Security scan [skip ci]" || true
          git push || true
```

**Result:** Reports available in both Actions artifacts AND committed to repo.

---

## Report Files Generated

Each scan creates 3 files with timestamp `YYYYMMDD_HHMMSS`:

1. **`scan-YYYYMMDD_HHMMSS.json`**
   - Detailed issues with AI-generated impacts and fixes
   - Used by PR comments and dashboard

2. **`full-YYYYMMDD_HHMMSS.json`**
   - Complete merged output from all scanners
   - Includes raw data from Bandit, Semgrep, pip-audit, etc.

3. **`summary-YYYYMMDD_HHMMSS.md`**
   - Human-readable summary
   - Includes metadata (timestamp, repo, branch)

---

## Managing Old Reports

### Keep Last 7 Days Only
Add cleanup step before commit:
```yaml
- name: Cleanup old reports
  run: find security-reports/ -type f -mtime +7 -delete
```

### Ignore Reports in Git
Add to `.gitignore`:
```
security-reports/
```

Then use only GitHub Actions artifacts (Example 2).

---

## Accessing Reports

**From Git:**
```bash
git pull
ls security-reports/
cat security-reports/scan-20251210_143527.json
```

**From Actions UI:**
1. Go to Actions tab
2. Click on workflow run
3. Scroll to Artifacts section
4. Download `security-reports` zip

**From API:**
```bash
gh run download <run-id> -n security-reports
```
