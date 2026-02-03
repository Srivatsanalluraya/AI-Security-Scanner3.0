#!/usr/bin/env python3
"""
pr_commenter.py - PRODUCTION ENHANCED VERSION

Posts an AI-generated security report to GitHub PRs with:
- Policy status
- Visual dashboard
- AI insights
- File-level grouping
- Merge blocking
"""

import argparse
import os
import requests
import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict


# =================================================
# Load Issues
# =================================================

def load_issues_from_report(report_path: Path) -> List[Dict]:

    if not report_path.exists():
        return []

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))

        # Preferred format
        if "detailed_issues" in data:

            issues = []

            for issue in data["detailed_issues"]:

                issues.append({
                    "source": issue.get("source", "Unknown"),
                    "issue": issue.get("description", ""),
                    "severity": issue.get("severity", "MEDIUM").upper(),
                    "path": issue.get("file", "unknown"),
                    "line": issue.get("line", 0),
                    "impact": issue.get("impact", ""),
                    "fix": issue.get("fix", ""),
                })

            return issues

        return []

    except Exception as e:
        print(f"⚠ Could not parse report: {e}")
        return []


# =================================================
# Grouping + Stats
# =================================================

def group_issues_by_file(issues: List[Dict]) -> Dict[str, List[Dict]]:

    grouped = defaultdict(list)

    for issue in issues:
        grouped[issue.get("path", "unknown")].append(issue)

    return grouped


def calculate_severity_proportions(issues: List[Dict]) -> Dict[str, float]:

    counts = defaultdict(int)

    for i in issues:
        counts[i.get("severity", "MEDIUM")] += 1

    total = len(issues)

    if total == 0:
        return {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    return {
        "HIGH": round(counts["HIGH"] / total * 100, 1),
        "MEDIUM": round(counts["MEDIUM"] / total * 100, 1),
        "LOW": round(counts["LOW"] / total * 100, 1),
    }


# =================================================
# Policy
# =================================================

def check_policy(issues: List[Dict]) -> Tuple[str, bool]:

    if not issues:
        return "PASS", True

    p = calculate_severity_proportions(issues)

    if p["HIGH"] >= 25:
        return "BLOCKED", False

    return "WARNING", True


# =================================================
# Dashboard
# =================================================

def build_dashboard(issues: List[Dict]) -> str:

    p = calculate_severity_proportions(issues)

    high = sum(i["severity"] == "HIGH" for i in issues)
    med = sum(i["severity"] == "MEDIUM" for i in issues)
    low = sum(i["severity"] == "LOW" for i in issues)

    total = len(issues)

    lines = []

    lines.append("## 📊 Security Dashboard\n")

    lines.append("```")
    lines.append(f"HIGH   │{'█'*high:<20}│ {high:>2} ({p['HIGH']:>4}%)")
    lines.append(f"MEDIUM │{'█'*med:<20}│ {med:>2} ({p['MEDIUM']:>4}%)")
    lines.append(f"LOW    │{'█'*low:<20}│ {low:>2} ({p['LOW']:>4}%)")
    lines.append("       └" + "─"*20 + "┘")
    lines.append(f"Total Issues: {total}")
    lines.append("```")

    return "\n".join(lines)


# =================================================
# Files
# =================================================

def build_files_section(issues: List[Dict]) -> str:

    grouped = group_issues_by_file(issues)

    lines = []
    lines.append("## 📁 Affected Files\n")

    for path, items in sorted(grouped.items()):

        high = sum(i["severity"] == "HIGH" for i in items)
        med = sum(i["severity"] == "MEDIUM" for i in items)
        low = sum(i["severity"] == "LOW" for i in items)

        badge = ""
        if high: badge += f" 🔴{high}"
        if med: badge += f" 🟡{med}"
        if low: badge += f" 🔵{low}"

        lines.append(f"### `{path}`{badge}")

        for i, issue in enumerate(items, 1):

            lines.append(
                f"- **{issue['severity']}** "
                f"(Line {issue['line']}) "
                f"[{issue['source']}] {issue['issue'][:100]}"
            )

        lines.append("")

    return "\n".join(lines)


# =================================================
# Issue List (With AI)
# =================================================

def build_issue_section(issues: List[Dict]) -> str:

    lines = []
    lines.append("## ⚠️ Detailed Findings\n")

    for i, issue in enumerate(issues[:10], 1):

        lines.append(f"### {i}. {issue['issue'][:80]}")
        lines.append(f"📁 `{issue['path']}:{issue['line']}`")
        lines.append(f"**Severity:** {issue['severity']}")

        if issue["impact"]:
            lines.append(f"\n🤖 **AI Impact**\n> {issue['impact']}")

        if issue["fix"]:
            lines.append(f"\n🛠 **AI Fix**\n> {issue['fix']}")

        lines.append("\n---\n")

    if len(issues) > 10:
        lines.append(f"_Showing top 10 of {len(issues)} issues_\n")

    return "\n".join(lines)


# =================================================
# Comment Builder
# =================================================

def build_comment(issues: List[Dict]) -> str:

    status, allow = check_policy(issues)

    header = ["## 🔐 AI Security Scan Report\n"]

    if status == "BLOCKED":
        header.append("🚨 **Status: MERGE BLOCKED (High Risk)**\n")
    elif status == "WARNING":
        header.append("⚠️ **Status: Review Recommended**\n")
    else:
        header.append("✅ **Status: Clean**\n")


    header.append(f"Total Issues: **{len(issues)}**\n")


    if not issues:

        return (
            "## ✅ AI Security Scan\n\n"
            "No vulnerabilities detected.\n\n"
            "_Generated by AI Security Scanner_"
        )


    parts = [
        "\n".join(header),
        build_dashboard(issues),
        build_issue_section(issues),
        build_files_section(issues),
        "### ✅ Next Steps\n"
        "- Fix HIGH severity issues first\n"
        "- Re-run scan\n"
        "- Merge after status = PASSED\n",
        "_Generated by AI Security Scanner_"
    ]


    return "\n\n".join(parts)


# =================================================
# GitHub API
# =================================================

def post_comment(repo, pr, token, body):

    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    r = requests.post(url, headers=headers, json={"body": body})

    if r.status_code >= 300:
        raise Exception(r.text)

    print("💬 PR comment posted")


def set_status(repo, sha, token, state, desc):

    url = f"https://api.github.com/repos/{repo}/statuses/{sha}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    payload = {
        "state": state,
        "description": desc,
        "context": "AI Security Scanner"
    }

    requests.post(url, headers=headers, json=payload)


# =================================================
# Main
# =================================================

def main():

    p = argparse.ArgumentParser()

    p.add_argument("--report")
    p.add_argument("--repo", required=True)
    p.add_argument("--pr", required=True)
    p.add_argument("--token")
    p.add_argument("--sha")

    args = p.parse_args()

    token = args.token or os.getenv("GITHUB_TOKEN")

    if not token:
        raise Exception("Missing GitHub token")


    issues = []

    if args.report:
        issues = load_issues_from_report(Path(args.report))


    body = build_comment(issues)

    post_comment(args.repo, args.pr, token, body)


    # Commit Status
    if args.sha:

        pcts = calculate_severity_proportions(issues)

        if pcts["HIGH"] >= 25:
            set_status(
                args.repo, args.sha, token,
                "failure",
                f"{pcts['HIGH']}% HIGH severity issues"
            )
        else:
            set_status(
                args.repo, args.sha, token,
                "success",
                f"{pcts['HIGH']}% HIGH severity issues"
            )


if __name__ == "__main__":
    main()
