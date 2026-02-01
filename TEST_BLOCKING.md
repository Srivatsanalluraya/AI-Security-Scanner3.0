# Testing Enhanced Merge Blocking

## Setup Instructions

### Step 1: Enable Branch Protection (Required for Blocking)
1. Go to your repository on GitHub
2. Navigate to: **Settings** → **Branches**
3. Click **Add rule** or edit existing rule for `main`
4. Configure:
   ```
   ☑️ Require status checks to pass before merging
      ☑️ Require branches to be up to date before merging
      Search and add: "security-scan" or "AI Security Scan"
   ```
5. Click **Save changes**

**Without branch protection, the workflow will fail but merge button stays enabled.**

---

## Test Case 1: Create Vulnerable Code (HIGH > 25%)

### Create a test branch with vulnerabilities:

```bash
# Create new branch
git checkout -b test-security-block

# Create vulnerable Python file
cat > vulnerable_test.py << 'EOF'
import pickle
import os

# HIGH: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

# HIGH: SQL Injection vulnerability
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return execute_query(query)

# HIGH: Unsafe deserialization
def load_data(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)

# HIGH: Command injection
def run_command(user_input):
    os.system("ping " + user_input)

# HIGH: eval usage
def calculate(expression):
    return eval(expression)

# MEDIUM: Weak hash
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
EOF

# Commit and push
git add vulnerable_test.py
git commit -m "test: Add intentionally vulnerable code for security scan testing"
git push origin test-security-block
```

---

## Test Case 2: Create Pull Request

1. Go to your repository on GitHub
2. Click **Pull requests** → **New pull request**
3. Set base: `main`, compare: `test-security-block`
4. Click **Create pull request**
5. Fill in title: "Test: Security blocking functionality"
6. Click **Create pull request**

---

## Expected Results

### 1. Workflow Execution (30-60 seconds)
GitHub Actions will automatically run the security scanner.

### 2. Console Output
```
====================================================================
❌ WORKFLOW FAILED - MERGE BLOCKED BY SECURITY POLICY
====================================================================

🚨 HIGH severity vulnerabilities exceed 25% threshold
📋 Review security scan results above
🔧 Fix critical issues and push changes to unblock

This PR cannot be merged until security issues are resolved.
====================================================================
```

### 3. PR Status
- **Status Check**: ❌ Red X - "Security Scan — Failed"
- **Merge Button**: 🚫 **Disabled** with message:
  ```
  Merging is blocked
  Required status check "security-scan" is failing
  ```

### 4. PR Comment (Automated)
```markdown
## ⛔ MERGE BLOCKED - CRITICAL SECURITY ISSUES

🚨 75% HIGH severity vulnerabilities detected (6/8 issues)

### Why is this blocked?
Your code changes contain 6 HIGH severity security issues, 
which exceeds the 25% threshold policy.

### What you need to do:
1. Review the HIGH severity issues listed below
2. Fix the critical vulnerabilities (focus on 🔴 items)
3. Push your fixes to this branch
4. Wait for scan to re-run - merge will be unblocked when HIGH < 25%

### Current Status:
- ❌ Merge button is DISABLED
- ❌ This PR cannot be merged until vulnerabilities are fixed
- ✅ Your code is pushed and visible for review

---

## 🔍 Security Scan Details

**Total Issues Found: 8**

### Critical Issues Requiring Immediate Attention
**#1** | HIGH | `vulnerable_test.py:6` | [Bandit] Hardcoded password string
**#2** | HIGH | `vulnerable_test.py:7` | [Bandit] Hardcoded password string
...

[Detailed dashboard and file listings follow]
```

---

## Test Case 3: Fix Vulnerabilities (Unblock Merge)

### Fix the issues:

```bash
# Edit the file to remove vulnerabilities
cat > vulnerable_test.py << 'EOF'
import os
import hashlib
import json

# FIXED: Use environment variables for secrets
API_KEY = os.getenv("API_KEY")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

# FIXED: Use parameterized queries (example)
def get_user(user_id):
    # Use proper ORM or parameterized queries
    query = "SELECT * FROM users WHERE id = ?"
    return execute_query(query, (user_id,))

# FIXED: Use JSON instead of pickle
def load_data(filename):
    with open(filename, 'r') as f:
        return json.load(f)

# FIXED: Use subprocess with shell=False
import subprocess
def run_command(user_input):
    # Validate and sanitize input
    if not user_input.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid input")
    subprocess.run(["ping", "-c", "1", user_input], shell=False)

# FIXED: Use ast.literal_eval or proper parser
import ast
def calculate(expression):
    return ast.literal_eval(expression)

# FIXED: Use bcrypt for passwords
import bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
EOF

# Commit and push fixes
git add vulnerable_test.py
git commit -m "fix: Replace hardcoded secrets with env vars and fix vulnerabilities"
git push origin test-security-block
```

---

## Expected Results After Fix

### 1. Workflow Re-runs Automatically
Scanner detects the new commit and re-scans.

### 2. Console Output
```
====================================================================
✅ SECURITY SCAN COMPLETED SUCCESSFULLY
====================================================================

✓ Security policy check passed
✓ Merge is allowed (review recommended)

🎉 Scan complete!
====================================================================
```

### 3. PR Status
- **Status Check**: ✅ Green checkmark - "Security Scan — Passed"
- **Merge Button**: ✅ **ENABLED**
  ```
  ✅ All checks have passed
  This branch has no conflicts with the base branch
  ```

### 4. Updated PR Comment
```markdown
## ⚠️ Security Review Recommended

0% HIGH severity vulnerabilities detected (0/3 issues)

### Status:
- ✅ Below 25% threshold - merge is allowed
- ⚠️ Security review recommended before production deployment
- 📋 Review the issues listed above and consider fixing before merge
```

---

## Test Case 4: Warning Mode (Default)

To test without blocking (warning only):

```yaml
# In your workflow file
- uses: Srivatsanalluraya/AI-Security-Scanner3.0@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    enforce_policy: "false"  # ← Warning only, no blocking
```

**Result**: 
- Workflow shows ⚠️ yellow status
- Merge button stays enabled
- PR comment shows warnings but doesn't block

---

## Verification Checklist

After testing, verify:

- [ ] Workflow fails when HIGH > 25% and `enforce_policy: "true"`
- [ ] Merge button is disabled (requires branch protection)
- [ ] PR comment clearly shows "MERGE BLOCKED" alert at top
- [ ] Console output shows clear blocking message
- [ ] Workflow succeeds after fixing vulnerabilities
- [ ] Merge button re-enables after fix
- [ ] PR comment updates to show "PASSED" status
- [ ] Warning mode allows merge with yellow status

---

## Cleanup

```bash
# Delete test branch
git checkout main
git branch -D test-security-block
git push origin --delete test-security-block

# Close the test PR on GitHub (if not already merged)
```

---

## Troubleshooting

### Merge button still enabled despite failed check?
- **Check branch protection**: Status checks must be required
- **Check check name**: Must match exactly (case-sensitive)

### Workflow passes but should block?
- **Check enforce_policy**: Must be `"true"` not `true`
- **Check HIGH percentage**: Must be ≥25%

### PR comment not posting?
- **Check token permissions**: `pull-requests: write` required
- **Check GITHUB_TOKEN**: Should be `${{ secrets.GITHUB_TOKEN }}`

### API key errors?
- Scanner works without AI - pattern-based analysis is fallback
- Optional: Add `GROQ_API_KEY` secret for AI enhancement
