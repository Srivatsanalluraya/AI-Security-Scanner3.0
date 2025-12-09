#!/usr/bin/env python3
"""
output_formatter.py

Provides concise, summarized console output for scanner operations.
Replaces verbose detailed output with clean summary statistics.
"""

import sys
from typing import Optional, List, Dict


class OutputFormatter:
    """Handles concise, non-verbose output for scanner operations."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def print_section_start(self, title: str):
        """Print section header."""
        print(f"\n{'='*50}")
        print(f"  {title}")
        print(f"{'='*50}")
    
    def print_scan_summary(self, scanner_name: str, issue_count: int, severity: Optional[str] = None):
        """Print concise scan result summary."""
        severity_str = f" | Severity: {severity.upper()}" if severity else ""
        print(f"✓ {scanner_name}: {issue_count} issue(s) found{severity_str}")
    
    def print_summary_line(self, label: str, value: str):
        """Print a key-value summary line."""
        print(f"  • {label}: {value}")
    
    def print_issue_summary(self, issue_num: int, issue: Dict):
        """Print a concise issue summary (one-liner or brief)."""
        source = issue.get("source", "Unknown")
        severity = issue.get("severity", "Unknown")
        path = issue.get("file", issue.get("path", "Unknown"))
        line = issue.get("line", "?")
        
        # Extract brief message/description
        desc = issue.get("issue", issue.get("message", "No description"))
        if isinstance(desc, str) and len(desc) > 80:
            desc = desc[:77] + "..."
        
        print(f"  {issue_num}. [{source}] {severity}: {desc} ({path}:{line})")
    
    def print_report_header(self):
        """Print report header."""
        self.print_section_start("📊 SECURITY SCAN SUMMARY REPORT")
    
    def print_report_footer(self):
        """Print report footer with download info."""
        self.print_section_start("📥 REPORT DOWNLOAD")
        print("The following reports have been generated:")
        print("  • reports/final_report.json - Complete merged report")
        print("  • reports/summary.txt - AI-generated summary")
        print("  • reports/bandit/ - Python security analysis")
        print("  • reports/semgrep/ - Code pattern analysis")
        print("  • reports/pip_audit.json - Dependency vulnerabilities")
        print("\nTo download reports in CI/CD:")
        print("  • Configure artifact upload in your workflow")
        print("  • Reports are located in the 'reports/' directory")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"❌ ERROR: {message}", file=sys.stderr)
    
    def print_warning(self, message: str):
        """Print warning message."""
        print(f"⚠️  WARNING: {message}")
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"ℹ️  {message}")
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"✅ {message}")
    
    def print_detailed(self, message: str):
        """Print detailed message only if verbose mode enabled."""
        if self.verbose:
            print(f"   {message}")


def format_issue_for_pr(issue: Dict, pushed_by: str = "") -> str:
    """
    Format a single issue in the required PR comment format:
    Issue_count: [Pushed by, Issue Description, Issue Potential Impact, Issue Potential Fix]
    """
    parts = []
    
    # Pushed by
    parts.append(f"Pushed by: {pushed_by}" if pushed_by else "Pushed by: [Unknown]")
    
    # Issue Description
    description = issue.get("ai_summary") or issue.get("issue") or issue.get("message", "No description")
    if isinstance(description, str) and len(description) > 200:
        description = description[:197] + "..."
    parts.append(f"Description: {description}")
    
    # Potential Impact
    severity = issue.get("severity", "UNKNOWN")
    source = issue.get("source", "Unknown")
    impact = f"Security issue detected by {source} with severity: {severity}"
    if "vulnerability" in str(issue).lower():
        impact += ". Potential unauthorized access or data exposure."
    elif "injection" in str(issue).lower():
        impact += ". Possible code injection attack vector."
    elif "hardcoded" in str(issue).lower():
        impact += ". Exposed credentials or sensitive data."
    parts.append(f"Potential Impact: {impact}")
    
    # Potential Fix
    fix = issue.get("ai_fix") or issue.get("fix") or "Review the code location and apply recommended security best practices."
    if isinstance(fix, str) and len(fix) > 150:
        fix = fix[:147] + "..."
    parts.append(f"Potential Fix: {fix}")
    
    return " | ".join(parts)


def format_final_report(issues: List[Dict], total_findings: int, overall_severity: str) -> str:
    """
    Format the complete final report with all issues in structured format.
    """
    lines = []
    lines.append("=" * 70)
    lines.append("AI SECURITY SCANNER - FINAL REPORT")
    lines.append("=" * 70)
    lines.append("")
    
    # Summary metrics
    lines.append("SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Total Issues Found: {total_findings}")
    lines.append(f"Overall Severity: {overall_severity.upper()}")
    lines.append("")
    
    # Group issues by severity
    severity_order = {"high": 3, "medium": 2, "low": 1, "note": 0}
    sorted_issues = sorted(
        issues,
        key=lambda x: severity_order.get(x.get("severity", "note").lower(), -1),
        reverse=True
    )
    
    # Count by severity
    severity_counts = {}
    for issue in sorted_issues:
        sev = issue.get("severity", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    lines.append("Issues by Severity:")
    for sev, count in sorted(severity_counts.items(), 
                            key=lambda x: severity_order.get(x[0].lower(), -1), reverse=True):
        lines.append(f"  • {sev}: {count}")
    lines.append("")
    
    # Detailed issues
    lines.append("DETAILED FINDINGS")
    lines.append("-" * 70)
    
    for idx, issue in enumerate(sorted_issues, start=1):
        lines.append(f"\nIssue #{idx}")
        lines.append(f"  Source: {issue.get('source', 'Unknown')}")
        lines.append(f"  File: {issue.get('file', issue.get('path', 'Unknown'))}")
        lines.append(f"  Line: {issue.get('line', '?')}")
        lines.append(f"  Severity: {issue.get('severity', 'UNKNOWN')}")
        
        desc = issue.get("ai_summary") or issue.get("issue") or issue.get("message", "No description")
        lines.append(f"  Description: {desc}")
        
        fix = issue.get("ai_fix") or issue.get("fix", "N/A")
        lines.append(f"  Suggested Fix: {fix}")
    
    lines.append("")
    lines.append("=" * 70)
    lines.append("Report generated by AI Security Scanner")
    lines.append("=" * 70)
    
    return "\n".join(lines)
