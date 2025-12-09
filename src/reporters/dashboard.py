#!/usr/bin/env python3
"""
dashboard.py

Generates a beautiful dashboard-style report using ANSI colors and formatting.
Displays scan results in a visually appealing format.
"""

import json
from pathlib import Path
from typing import Dict, List


class DashboardReport:
    """Creates a colorful dashboard report."""
    
    # ANSI Color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_CYAN = "\033[96m"
    
    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = Path(report_dir)
    
    def load_detailed_report(self) -> Dict:
        """Load the detailed issues report."""
        detail_file = self.report_dir / "issues_detailed.json"
        if not detail_file.exists():
            return {"total_issues": 0, "severity_counts": {}, "issues_by_source": {}, "detailed_issues": []}
        
        try:
            return json.loads(detail_file.read_text(encoding="utf-8"))
        except:
            return {"total_issues": 0, "severity_counts": {}, "issues_by_source": {}, "detailed_issues": []}
    
    def severity_color(self, severity: str) -> str:
        """Return color code for severity level."""
        sev = severity.upper()
        if sev == "HIGH":
            return self.BRIGHT_RED
        elif sev == "MEDIUM":
            return self.BRIGHT_YELLOW
        elif sev == "LOW":
            return self.CYAN
        else:
            return self.WHITE
    
    def box_line(self, char: str = "═", width: int = 80) -> str:
        """Create a box line."""
        return char * width
    
    def print_header(self):
        """Print dashboard header."""
        print(f"\n{self.BRIGHT_CYAN}{self.box_line()}{self.RESET}")
        print(f"{self.BRIGHT_CYAN}║{self.RESET} " +
              f"{self.BRIGHT_CYAN}{self.BOLD}  🔐 AI SECURITY SCANNER DASHBOARD{self.RESET}" +
              f" {self.BRIGHT_CYAN}║{self.RESET}")
        print(f"{self.BRIGHT_CYAN}{self.box_line()}{self.RESET}\n")
    
    def print_summary_box(self, total_issues: int, severity_counts: Dict):
        """Print summary statistics box."""
        print(f"{self.BRIGHT_BLUE}┌──────────────────────────────────────────────────────────┐{self.RESET}")
        print(f"{self.BRIGHT_BLUE}│{self.RESET} {self.BOLD}SCAN SUMMARY{self.RESET}")
        print(f"{self.BRIGHT_BLUE}├──────────────────────────────────────────────────────────┤{self.RESET}")
        
        # Total issues
        if total_issues == 0:
            print(f"{self.BRIGHT_BLUE}│{self.RESET}  {self.BRIGHT_GREEN}✓ Total Issues: {total_issues}{self.RESET:.<50}")
        else:
            print(f"{self.BRIGHT_BLUE}│{self.RESET}  {self.BRIGHT_RED}⚠ Total Issues: {total_issues}{self.RESET:.<50}")
        
        # Severity breakdown
        print(f"{self.BRIGHT_BLUE}│{self.RESET}")
        print(f"{self.BRIGHT_BLUE}│{self.RESET}  {self.BOLD}Issues by Severity:{self.RESET}")
        
        severity_order = ["HIGH", "MEDIUM", "LOW"]
        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            color = self.severity_color(severity)
            bar_length = int(count * 1.5) if count > 0 else 0
            bar = "█" * min(bar_length, 20)
            print(f"{self.BRIGHT_BLUE}│{self.RESET}    {color}{severity:.<10}{self.RESET} {bar} {color}{count:>3}{self.RESET}")
        
        print(f"{self.BRIGHT_BLUE}└──────────────────────────────────────────────────────────┘{self.RESET}\n")
    
    def print_source_breakdown(self, issues_by_source: Dict):
        """Print breakdown by source scanner."""
        if not issues_by_source:
            return
        
        print(f"{self.MAGENTA}┌──────────────────────────────────────────────────────────┐{self.RESET}")
        print(f"{self.MAGENTA}│{self.RESET} {self.BOLD}SCANNER BREAKDOWN{self.RESET}")
        print(f"{self.MAGENTA}├──────────────────────────────────────────────────────────┤{self.RESET}")
        
        for source, count in sorted(issues_by_source.items(), key=lambda x: x[1], reverse=True):
            bar_length = int(count * 2)
            bar = "▓" * min(bar_length, 20)
            print(f"{self.MAGENTA}│{self.RESET}  {source:.<20} {bar} {self.YELLOW}{count:>3} issues{self.RESET}")
        
        print(f"{self.MAGENTA}└──────────────────────────────────────────────────────────┘{self.RESET}\n")
    
    def print_top_issues(self, detailed_issues: List[Dict], limit: int = 5):
        """Print top issues by severity."""
        if not detailed_issues:
            print(f"{self.GREEN}✓ No security issues found!{self.RESET}\n")
            return
        
        # Sort by severity
        severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_issues = sorted(
            detailed_issues,
            key=lambda x: severity_rank.get(x.get("severity", "LOW"), 0),
            reverse=True
        )
        
        print(f"{self.YELLOW}┌──────────────────────────────────────────────────────────┐{self.RESET}")
        print(f"{self.YELLOW}│{self.RESET} {self.BOLD}TOP ISSUES{self.RESET}")
        print(f"{self.YELLOW}├──────────────────────────────────────────────────────────┤{self.RESET}")
        
        for idx, issue in enumerate(sorted_issues[:limit], 1):
            severity = issue.get("severity", "UNKNOWN")
            source = issue.get("source", "Unknown")
            desc = issue.get("description", "No description")[:45]
            
            color = self.severity_color(severity)
            print(f"{self.YELLOW}│{self.RESET}")
            print(f"{self.YELLOW}│{self.RESET}  {idx}. {color}{severity}{self.RESET} | {source}")
            print(f"{self.YELLOW}│{self.RESET}     {desc}{'...' if len(issue.get('description', '')) > 45 else ''}")
            print(f"{self.YELLOW}│{self.RESET}     {self.DIM}▶ Fix: {issue.get('fix', 'N/A')[:50]}...{self.RESET}")
        
        if len(sorted_issues) > limit:
            remaining = len(sorted_issues) - limit
            print(f"{self.YELLOW}│{self.RESET}")
            print(f"{self.YELLOW}│{self.RESET}  {self.DIM}... and {remaining} more issue(s){self.RESET}")
        
        print(f"{self.YELLOW}└──────────────────────────────────────────────────────────┘{self.RESET}\n")
    
    def print_status_bar(self, total_issues: int):
        """Print status bar at bottom with policy enforcement."""
        # Calculate severity proportions
        severity_counts = {}
        for issue in self.load_detailed_report().get("detailed_issues", []):
            sev = issue.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        high_pct = 0
        if total_issues > 0:
            high_pct = round((severity_counts.get("HIGH", 0) / total_issues) * 100, 1)
        
        # Determine status based on policy
        if total_issues == 0:
            status = f"{self.BRIGHT_GREEN}{self.BOLD}✓ PASS{self.RESET}"
            message = "No security issues detected"
        elif high_pct >= 25:
            status = f"{self.BRIGHT_RED}{self.BOLD}✗ BLOCKED{self.RESET}"
            message = f"CRITICAL: {high_pct}% HIGH severity (≥25% threshold) - Push blocked"
        elif total_issues <= 2:
            status = f"{self.BRIGHT_YELLOW}{self.BOLD}⚠ WARNING{self.RESET}"
            message = f"Minor security issues found ({high_pct}% HIGH) - Review recommended"
        else:
            status = f"{self.BRIGHT_YELLOW}{self.BOLD}⚠ WARNING{self.RESET}"
            message = f"Security issues detected ({high_pct}% HIGH) - Review before merging"
        
        print(f"{self.BRIGHT_CYAN}{self.box_line()}{self.RESET}")
        print(f"{self.BRIGHT_CYAN}║{self.RESET} Status: {status}  |  {message}")
        print(f"{self.BRIGHT_CYAN}{self.box_line()}{self.RESET}\n")
    
    def print_footer(self):
        """Print dashboard footer."""
        print(f"{self.DIM}All reports available in: reports/{self.RESET}")
        print(f"{self.DIM}Download: final_report.json, summary.txt, issues_detailed.json{self.RESET}\n")
    
    def generate(self):
        """Generate the full dashboard."""
        data = self.load_detailed_report()
        
        self.print_header()
        self.print_summary_box(
            data.get("total_issues", 0),
            data.get("severity_counts", {})
        )
        self.print_source_breakdown(data.get("issues_by_source", {}))
        self.print_top_issues(data.get("detailed_issues", []))
        self.print_status_bar(data.get("total_issues", 0))
        self.print_footer()


def main():
    """Standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Display security scan dashboard")
    parser.add_argument("--report-dir", default="reports", help="Directory containing reports")
    
    args = parser.parse_args()
    
    dashboard = DashboardReport(report_dir=args.report_dir)
    dashboard.generate()


if __name__ == "__main__":
    main()
