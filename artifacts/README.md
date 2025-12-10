# Artifacts Directory Info

The `artifacts/` directory contains timestamped security scan reports.

## Files Generated:
- `security-scan-YYYYMMDD_HHMMSS.json` - Detailed issues with AI analysis
- `full-report-YYYYMMDD_HHMMSS.json` - Complete merged scanner output
- `summary-YYYYMMDD_HHMMSS.md` - Human-readable summary

## Directory Management:

### Option 1: Commit artifacts (Recommended for audit trail)
Keep artifacts in git to maintain a history of security scans:
```bash
# Add to your workflow (already in example-with-artifacts.yml)
git add artifacts/
git commit -m "Security scan artifacts"
git push
```

### Option 2: Ignore artifacts (For cleaner repo)
Add to your `.gitignore`:
```
artifacts/
```
Then use GitHub Actions artifacts instead:
```yaml
- name: Upload scan results
  uses: actions/upload-artifact@v3
  with:
    name: security-scan-results
    path: artifacts/
    retention-days: 90
```

## Cleanup Old Artifacts:

To keep only recent scans (e.g., last 30 days):
```bash
find artifacts/ -type f -mtime +30 -delete
```

Add this to your workflow after the scan step if desired.
