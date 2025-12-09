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
    
    if high_percentage >= 25:
        msg = f"❌ CRITICAL: {high_percentage}% HIGH severity issues (≥25% threshold). Push blocked."
        return "BLOCKED", msg, False
    else:
        msg = f"⚠️  WARNING: {high_percentage}% HIGH severity issues detected. Please review before merging."
        return "WARNING", msg, True


def build_dashboard_section(issues: List[Dict]) -> str:
    """Build dashboard-style report for PR comment."""
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
    
    lines.append("### Scan Summary")
    lines.append(f"- **Total Issues**: {len(issues)}")
    lines.append(f"- **HIGH** ({proportions['HIGH']}%): {high_count}")
    lines.append(f"- **MEDIUM** ({proportions['MEDIUM']}%): {med_count}")
    lines.append(f"- **LOW** ({proportions['LOW']}%): {low_count}\n")
    
    # Severity bars
    lines.append("### Issue Distribution")
    high_bar = "🔴" * min(10, max(1, high_count)) if high_count > 0 else ""
    med_bar = "🟡" * min(10, max(1, med_count)) if med_count > 0 else ""
    low_bar = "🔵" * min(10, max(1, low_count)) if low_count > 0 else ""
    if high_bar:
        lines.append(f"HIGH:   {high_bar} ({high_count})")
    if med_bar:
        lines.append(f"MEDIUM: {med_bar} ({med_count})")
    if low_bar:
        lines.append(f"LOW:    {low_bar} ({low_count})")
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
    1. Structured issue list
    2. Dashboard
    3. Vulnerable files
    4. Policy status
    """
    if not issues:
        return """## ✅ AI Security Scan - No Issues Found

This automated security scan found **no security issues**.

---
🙌 *Generated by the AI Vulnerability Scanner*
"""
    
    # Get policy status
    status, policy_msg, _ = check_policy_compliance(issues)
    
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
    
    # Files section
    files = build_files_section(issues)
    
    # Policy status
    policy_section = f"\n---\n\n## 🚨 Policy Status\n\n{policy_msg}\n"
    
    comment = f"""## 🔍 AI Security Scan Report

**Total Issues: {len(issues)}**

### Detailed Findings
{issues_section}

{dashboard}

{files}

{policy_section}

---

### 📝 Notes
- Use the file paths and line numbers to navigate to vulnerabilities
- Each issue shows severity, source scanner, and brief description
- Review recommendations and apply fixes before merging

🙌 *Generated by AI Vulnerability Scanner*
"""
    
    return comment


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
    
    print("\n" + "="*60)
    print("🔐 SECURITY POLICY CHECK")
    print("="*60)
    print(message)
    print("="*60 + "\n")
    
    if not allow_push:
        print("❌ Push denied by security policy")
        return 1
    else:
        print("✅ Push allowed with security review recommended")
        return 0


# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", help="Path to final report JSON")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--pr", required=True, help="Pull request number")
    parser.add_argument("--token", required=False, help="GitHub token")
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
    
    # Enforce policy if requested
    if args.enforce_policy:
        exit_code = enforce_policy(issues)
        exit(exit_code)


if __name__ == "__main__":
    main()
