#!/usr/bin/env python3
"""
pr_commenter.py - ENHANCED VERSION

Posts an AI-generated summary as a GitHub PR comment with:
1. Dashboard-style report
2. Files with vulnerabilities highlighted
3. Severity-based allow/restrict logic
"""

import argparse
import os
import requests
import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict


def load_issues_from_report(report_path: Path) -> list:
    """Load issues from the detailed issues report (same as dashboard)."""
    if not report_path.exists():
        return []
    
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        
        # Check if this is issues_detailed.json format
        if "detailed_issues" in data:
            # Load from issues_detailed.json (preferred)
            issues = []
            for issue in data.get("detailed_issues", []):
                issues.append({
                    "source": issue.get("source", "Unknown"),
                    "issue": issue.get("description", ""),
                    "severity": issue.get("severity", "MEDIUM").upper(),
                    "path": issue.get("file", "unknown"),
                    "line": issue.get("line", 0),
                    "impact": issue.get("impact", ""),
                    "fix": issue.get("fix", "")
                })
            return issues
        
        # Fallback: Load from final_report.json format
        issues = []
        for report_name, report_data in data.get("reports", {}).items():
            if isinstance(report_data, dict):
                results = report_data.get("results", report_data.get("issues", []))
                if results:
                    for result in results:
                        issues.append({
                            "source": report_name.replace("-report.json", "").title(),
                            "issue": result.get("message", result.get("issue_text", "")),
                            "severity": result.get("severity", result.get("issue_severity", "MEDIUM")).upper(),
                            "path": result.get("path", result.get("filename", "")),
                            "line": result.get("line", result.get("line_number", 0))
                        })
        
        return issues
    except Exception as e:
        print(f"Warning: Could not load issues from report: {e}")
        return []


def group_issues_by_file(issues: List[Dict]) -> Dict[str, List[Dict]]:
    """Group issues by file path for highlighting."""
    grouped = defaultdict(list)
    for issue in issues:
        file_path = issue.get("path", "unknown")
        grouped[file_path].append(issue)
    return grouped


def calculate_severity_proportions(issues: List[Dict]) -> Dict[str, float]:
    """Calculate percentage of each severity level."""
    if not issues:
        return {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    severity_count = defaultdict(int)
    for issue in issues:
        severity = issue.get("severity", "UNKNOWN").upper()
        severity_count[severity] += 1
    
    total = len(issues)
    proportions = {
        "HIGH": round((severity_count.get("HIGH", 0) / total) * 100, 1),
        "MEDIUM": round((severity_count.get("MEDIUM", 0) / total) * 100, 1),
        "LOW": round((severity_count.get("LOW", 0) / total) * 100, 1)
    }
    return proportions


def check_policy_compliance(issues: List[Dict]) -> Tuple[str, str, bool]:
    """
    Check if severity proportions allow pushing.
    
    Returns: (status, message, allow_push)
    - If HIGH >= 25%: BLOCK (return False)
    - Else: ALERT but allow with warning (return True)
    """
    if not issues:
        return "PASS", "✅ No vulnerabilities found", True
    
    proportions = calculate_severity_proportions(issues)
    high_percentage = proportions["HIGH"]
    high_count = sum(1 for i in issues if i.get("severity") == "HIGH")
    total = len(issues)
    
    if high_percentage >= 25:
        msg = f"""## ⛔ MERGE BLOCKED - CRITICAL SECURITY ISSUES

**🚨 {high_percentage}% HIGH severity vulnerabilities detected ({high_count}/{total} issues)**

### Why is this blocked?
Your code changes contain **{high_count} HIGH severity** security issues, which exceeds the 25% threshold policy.

### What you need to do:
1. **Review the HIGH severity issues** listed above
2. **Fix the critical vulnerabilities** (focus on 🔴 items)
3. **Push your fixes** to this branch
4. **Wait for scan to re-run** - merge will be unblocked when HIGH < 25%

### Current Status:
- ❌ **Merge button is DISABLED**
- ❌ **This PR cannot be merged** until vulnerabilities are fixed
- ✅ **Your code is pushed** and visible for review

---
**Policy**: HIGH severity issues must be < 25% of total issues"""
        return "BLOCKED", msg, False
    else:
        msg = f"""## ⚠️ Security Review Recommended

**{high_percentage}% HIGH severity vulnerabilities detected ({high_count}/{total} issues)**

### Status:
- ✅ **Below 25% threshold** - merge is allowed
- ⚠️ **Security review recommended** before production deployment
- 📋 Review the issues listed above and consider fixing before merge

---
**Policy**: Currently passing with {high_percentage}% HIGH severity issues (threshold: 25%)"""
        return "WARNING", msg, True


def build_pie_chart_ascii(proportions: Dict[str, float], counts: Dict[str, int]) -> str:
    """Generate an ASCII pie chart for severity distribution."""
    total = sum(counts.values())
    if total == 0:
        return "No issues detected"
    
    # Calculate segments (use 20 segments for better resolution)
    segments = 20
    high_segments = round((proportions['HIGH'] / 100) * segments)
    med_segments = round((proportions['MEDIUM'] / 100) * segments)
    low_segments = segments - high_segments - med_segments
    
    # Build pie chart using block characters
    chart_lines = []
    chart_lines.append("```")
    chart_lines.append("     ╔═══════════════════════════════════════╗")
    chart_lines.append("     ║     SEVERITY DISTRIBUTION (%)         ║")
    chart_lines.append("     ╠═══════════════════════════════════════╣")
    
    # Create circular representation
    pie_line = "     ║  "
    pie_line += "█" * high_segments if high_segments > 0 else ""
    pie_line += "▓" * med_segments if med_segments > 0 else ""
    pie_line += "░" * low_segments if low_segments > 0 else ""
    pie_line += " " * (20 - len(pie_line) + 11)
    chart_lines.append(pie_line + "║")
    
    chart_lines.append("     ╠═══════════════════════════════════════╣")
    chart_lines.append(f"     ║  █ HIGH:   {proportions['HIGH']:>5}% ({counts['HIGH']:>3} issues) ║")
    chart_lines.append(f"     ║  ▓ MEDIUM: {proportions['MEDIUM']:>5}% ({counts['MEDIUM']:>3} issues) ║")
    chart_lines.append(f"     ║  ░ LOW:    {proportions['LOW']:>5}% ({counts['LOW']:>3} issues) ║")
    chart_lines.append("     ╚═══════════════════════════════════════╝")
    chart_lines.append("```")
    
    return "\n".join(chart_lines)


def build_dashboard_section(issues: List[Dict]) -> str:
    """Build dashboard-style report for PR comment with graphical elements."""
    if not issues:
        return ""
    
    lines = []
    lines.append("\n---\n")
    lines.append("## 📊 Security Dashboard\n")
    
    # Summary box
    proportions = calculate_severity_proportions(issues)
    high_count = sum(1 for i in issues if i.get("severity") == "HIGH")
    med_count = sum(1 for i in issues if i.get("severity") == "MEDIUM")
    low_count = sum(1 for i in issues if i.get("severity") == "LOW")
    
    counts = {"HIGH": high_count, "MEDIUM": med_count, "LOW": low_count}
    
    # Add pie chart
    lines.append("### Severity Distribution")
    lines.append(build_pie_chart_ascii(proportions, counts))
    lines.append("")
    
    # Add bar chart
    lines.append("### Issue Breakdown")
    lines.append("```")
    max_bar_width = 30
    total = len(issues)
    
    # HIGH bar
    high_bar_width = int((high_count / total) * max_bar_width) if total > 0 else 0
    high_bar = "█" * high_bar_width
    lines.append(f"HIGH   │{high_bar:<{max_bar_width}}│ {high_count:>3} ({proportions['HIGH']:>5.1f}%)")
    
    # MEDIUM bar
    med_bar_width = int((med_count / total) * max_bar_width) if total > 0 else 0
    med_bar = "█" * med_bar_width
    lines.append(f"MEDIUM │{med_bar:<{max_bar_width}}│ {med_count:>3} ({proportions['MEDIUM']:>5.1f}%)")
    
    # LOW bar
    low_bar_width = int((low_count / total) * max_bar_width) if total > 0 else 0
    low_bar = "█" * low_bar_width
    lines.append(f"LOW    │{low_bar:<{max_bar_width}}│ {low_count:>3} ({proportions['LOW']:>5.1f}%)")
    lines.append("       └" + "─" * max_bar_width + "┘")
    lines.append(f"       Total: {total} issues detected")
    lines.append("```")
    lines.append("")
    
    # Emoji indicators
    lines.append("### Quick Status")
    if proportions['HIGH'] >= 25:
        lines.append("🔴 **CRITICAL** - Immediate attention required")
    elif proportions['HIGH'] >= 10:
        lines.append("🟠 **WARNING** - Security review recommended")
    else:
        lines.append("🟢 **GOOD** - Low risk level detected")
    lines.append("")
    
    return "\n".join(lines)


def build_files_section(issues: List[Dict]) -> str:
    """Build file-by-file vulnerability listing."""
    if not issues:
        return ""
    
    grouped = group_issues_by_file(issues)
    lines = []
    lines.append("\n---\n")
    lines.append("## 📁 Vulnerable Files\n")
    
    for file_path, file_issues in sorted(grouped.items()):
        if not file_path or file_path == "unknown":
            continue
        
        # Count by severity
        high = sum(1 for i in file_issues if i.get("severity") == "HIGH")
        med = sum(1 for i in file_issues if i.get("severity") == "MEDIUM")
        low = sum(1 for i in file_issues if i.get("severity") == "LOW")
        
        severity_str = ""
        if high > 0:
            severity_str += f" 🔴{high}"
        if med > 0:
            severity_str += f" 🟡{med}"
        if low > 0:
            severity_str += f" 🔵{low}"
        
        lines.append(f"### `{file_path}`{severity_str}")
        
        # List issues in this file
        for idx, issue in enumerate(file_issues, 1):
            severity = issue.get("severity", "UNKNOWN")
            source = issue.get("source", "Unknown")
            line_num = issue.get("line", "?")
            desc = issue.get("issue", "")[:100]
            
            lines.append(f"  {idx}. **{severity}** [{source}] Line {line_num}: {desc}")
        
        lines.append("")
    
    return "\n".join(lines)


def build_comment_body(issues: List[Dict], pushed_by: str = "", allow_push: bool = True) -> str:
    """
    Build comprehensive PR comment with:
    1. Policy status (TOP - most visible)
    2. Structured issue list
    3. Dashboard
    4. Vulnerable files
    """
    if not issues:
        return """## ✅ AI Security Scan - No Issues Found

This automated security scan found **no security issues**.

---
🙌 *Generated by the AI Vulnerability Scanner*
"""
    
    # Get policy status
    status, policy_msg, allow_push = check_policy_compliance(issues)
    
    # Build structured issue list - Show ALL issues
    issue_lines = []
    for idx, issue in enumerate(issues, start=1):  # Show all issues
        severity = issue.get("severity", "UNKNOWN")
        description = issue.get("issue", "No description")[:120]
        path = issue.get("path", "unknown")
        line = issue.get("line", "?")
        source = issue.get("source", "Scanner")
        
        issue_line = f"**#{idx}** | {severity} | `{path}:{line}` | [{source}] {description}"
        issue_lines.append(issue_line)
    
    issues_section = "\n".join(issue_lines)
    
    # Dashboard section
    dashboard = build_dashboard_section(issues)
    
    # Files section (show top HIGH severity files if blocked)
    files = build_files_section(issues)
    
    # Build comment with policy at TOP for visibility
    if not allow_push:
        # BLOCKED: Show policy alert FIRST
        comment = f"""{policy_msg}

---

## 🔍 Security Scan Details

**Total Issues Found: {len(issues)}**

### Critical Issues Requiring Immediate Attention
{issues_section}

{dashboard}

{files}

---

### 📝 How to Unblock This PR:
1. Review HIGH severity issues marked with 🔴
2. Apply fixes based on recommendations
3. Push changes to trigger new scan
4. Merge will be enabled when HIGH < 25%

🙌 *Generated by AI Vulnerability Scanner*
"""
    else:
        # PASSING: Show standard report
        comment = f"""{policy_msg}

---

## 🔍 AI Security Scan Report

**Total Issues: {len(issues)}**

### Detailed Findings
{issues_section}

{dashboard}

{files}

---

### 📝 Notes
- Use the file paths and line numbers to navigate to vulnerabilities
- Each issue shows severity, source scanner, and brief description
- Review recommendations and apply fixes before merging

🙌 *Generated by AI Vulnerability Scanner*
"""
    
    return comment


def set_commit_status(repo: str, sha: str, token: str, state: str, description: str, context: str = "AI Security Scanner"):
    """Set commit status to block/allow PR merge.
    
    Args:
        repo: Repository in format 'owner/repo'
        sha: Commit SHA to set status on
        token: GitHub token
        state: 'success', 'failure', 'error', or 'pending'
        description: Status description
        context: Status check name
    """
    url = f"https://api.github.com/repos/{repo}/statuses/{sha}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    
    payload = {
        "state": state,
        "description": description,
        "context": context
    }
    
    resp = requests.post(url, headers=headers, json=payload)
    
    if resp.status_code >= 300:
        print(f"⚠️ Warning: Could not set commit status: {resp.status_code} {resp.text}")
    else:
        status_emoji = "✅" if state == "success" else "❌"
        print(f"{status_emoji} Set commit status to '{state}': {description}")


def post_comment(repo: str, pr_number: str, token: str, comment: str):
    """Post comment to GitHub PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    resp = requests.post(url, headers=headers, json={"body": comment})
    
    if resp.status_code >= 300:
        raise Exception(f"GitHub API error: {resp.status_code} {resp.text}")
    
    print(f"💬 Successfully posted PR comment on #{pr_number}")


def post_pr_summary(severity: str, issue_count: int):
    """
    Simple alternative: print summary to stdout for GitHub Actions.
    GitHub Actions can capture this and set output variables.
    """
    print(f"::notice::AI Security Scan: {issue_count} issues found (Severity: {severity})")


def enforce_policy(issues: List[Dict]) -> int:
    """
    Enforce security policy based on vulnerability proportions.
    
    Returns:
    - 0: Allow push with warning
    - 1: Block push
    """
    status, message, allow_push = check_policy_compliance(issues)
    
    print("\n" + "="*70)
    print("🔐 SECURITY POLICY ENFORCEMENT")
    print("="*70)
    
    if not allow_push:
        proportions = calculate_severity_proportions(issues)
        high_count = sum(1 for i in issues if i.get("severity") == "HIGH")
        
        print("❌ MERGE BLOCKED - CRITICAL SECURITY ISSUES DETECTED")
        print(f"   └─ {proportions['HIGH']}% HIGH severity ({high_count} issues)")
        print(f"   └─ Threshold: 25% maximum")
        print(f"   └─ Status: EXCEEDS LIMIT")
        print()
        print("🚫 This PR cannot be merged until HIGH severity issues are reduced.")
        print("📋 Review the security scan results and fix critical vulnerabilities.")
        print("="*70 + "\n")
        return 1
    else:
        proportions = calculate_severity_proportions(issues)
        high_count = sum(1 for i in issues if i.get("severity") == "HIGH")
        
        print("✅ SECURITY POLICY CHECK PASSED")
        print(f"   └─ {proportions['HIGH']}% HIGH severity ({high_count} issues)")
        print(f"   └─ Threshold: 25% maximum")
        print(f"   └─ Status: WITHIN LIMITS")
        print()
        print("⚠️  Security review recommended before production deployment.")
        print("="*70 + "\n")
        return 0


# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", help="Path to final report JSON")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--pr", required=True, help="Pull request number")
    parser.add_argument("--token", required=False, help="GitHub token")
    parser.add_argument("--sha", required=False, help="Commit SHA (for blocking merge)")
    parser.add_argument("--pushed-by", default="", help="GitHub username who pushed")
    parser.add_argument("--enforce-policy", action="store_true", help="Enforce push restrictions")

    args = parser.parse_args()

    # GitHub Token (fallback to env)
    token = args.token or os.environ.get("GITHUB_TOKEN")

    if not token:
        raise Exception("❌ GitHub token not provided (set GITHUB_TOKEN or use --token).")

    # Load issues from report if available
    issues = []
    if args.report:
        issues = load_issues_from_report(Path(args.report))

    status, message, allow_push = check_policy_compliance(issues)
    
    # Build and post comment
    comment_body = build_comment_body(issues, pushed_by=args.pushed_by, allow_push=allow_push)
    post_comment(args.repo, args.pr, token, comment_body)
    
    # Set commit status to block/allow merge
    if args.sha:
        proportions = calculate_severity_proportions(issues)
        if proportions["HIGH"] >= 25:
            # Block merge
            set_commit_status(
                repo=args.repo,
                sha=args.sha,
                token=token,
                state="failure",
                description=f"❌ {proportions['HIGH']}% HIGH severity issues (threshold: 25%)",
                context="AI Security Scanner / Merge Policy"
            )
        else:
            # Allow merge
            set_commit_status(
                repo=args.repo,
                sha=args.sha,
                token=token,
                state="success",
                description=f"✅ {proportions['HIGH']}% HIGH severity issues (threshold: 25%)",
                context="AI Security Scanner / Merge Policy"
            )
    
    # Enforce policy if requested
    if args.enforce_policy:
        exit_code = enforce_policy(issues)
        exit(exit_code)


if __name__ == "__main__":
    main()
