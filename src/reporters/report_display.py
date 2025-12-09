#!/usr/bin/env python3
"""
report_display.py

Handles displaying summarized reports and providing download options
for all generated scanner reports.
"""

import json
import os
from pathlib import Path
from typing import Dict, List


class ReportDisplay:
    """Displays scan results and provides download information."""
    
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)
    
    def display_summary_report(self):
        """Display the summarized report from summary.txt."""
        summary_file = self.report_dir / "summary.txt"
        
        print("\n" + "=" * 80)
        print("📊 AI SECURITY SCAN SUMMARY")
        print("=" * 80 + "\n")
        
        if summary_file.exists():
            content = summary_file.read_text(encoding="utf-8")
            print(content)
        else:
            print("✅ No security issues detected.")
        
        print("\n" + "=" * 80)
    
    def display_detailed_report(self):
        """Display the detailed issues report."""
        detail_file = self.report_dir / "issues_detailed.json"
        
        if not detail_file.exists():
            return
        
        print("\n" + "=" * 80)
        print("📋 DETAILED FINDINGS")
        print("=" * 80 + "\n")
        
        try:
            data = json.loads(detail_file.read_text(encoding="utf-8"))
            
            # Summary metrics
            print(f"Total Issues: {data.get('total_issues', 0)}")
            print("\nIssues by Severity:")
            for severity, count in data.get("severity_counts", {}).items():
                print(f"  • {severity}: {count}")
            
            print("\nIssues by Source:")
            for source, count in data.get("issues_by_source", {}).items():
                print(f"  • {source}: {count}")
            
            # Brief issue list
            print("\nTop Issues:")
            for issue in data.get("detailed_issues", [])[:5]:
                print(f"  {issue['number']}. [{issue['source']}] {issue['severity']}: {issue['description'][:60]}...")
            
            if len(data.get("detailed_issues", [])) > 5:
                print(f"  ... and {len(data['detailed_issues']) - 5} more issues")
        
        except Exception as e:
            print(f"⚠️ Could not parse detailed report: {e}")
        
        print("\n" + "=" * 80)
    
    def display_download_options(self):
        """Display available reports and download instructions."""
        print("\n" + "=" * 80)
        print("📥 AVAILABLE REPORTS FOR DOWNLOAD")
        print("=" * 80 + "\n")
        
        reports = self._collect_reports()
        
        if not reports:
            print("No reports generated.")
            return
        
        for idx, (name, path, size) in enumerate(reports, 1):
            size_str = self._format_size(size)
            print(f"{idx}. {name}")
            print(f"   Path: {path}")
            print(f"   Size: {size_str}")
            print()
        
        # Instructions
        print("Download Instructions:")
        print("─" * 80)
        print("\n🐙 GitHub Actions Workflow:")
        print("""
  - name: Upload security reports
    uses: actions/upload-artifact@v3
    if: always()
    with:
      name: security-reports
      path: reports/
      retention-days: 30
""")
        
        print("📦 Local Download:")
        print("  1. Check the 'Artifacts' section in your GitHub Actions run")
        print("  2. Download 'security-reports' artifact")
        print("  3. Extract to view all report files")
        
        print("\n🔍 Viewing Reports Locally:")
        print(f"  • JSON reports: Open with any text editor or JSON viewer")
        print(f"  • Summary: View 'summary.txt' in a text editor")
        print(f"  • SARIF: Use VS Code or other SARIF-compatible tools")
        
        print("\n" + "=" * 80 + "\n")
    
    def _collect_reports(self) -> List[tuple]:
        """Collect all generated report files."""
        reports = []
        
        # Expected report files/directories
        report_patterns = [
            ("Final Merged Report", "final_report.json"),
            ("Summary (Text)", "summary.txt"),
            ("Detailed Issues", "issues_detailed.json"),
            ("Bandit Report", "bandit/bandit.json"),
            ("Semgrep Report", "sarif/semgrep.sarif"),
            ("Pip-Audit Report", "pip_audit.json"),
        ]
        
        for name, rel_path in report_patterns:
            full_path = self.report_dir / rel_path
            if full_path.exists():
                size = full_path.stat().st_size
                reports.append((name, str(rel_path), size))
        
        return reports
    
    def _format_size(self, bytes_size: int) -> str:
        """Format bytes to human-readable size."""
        for unit in ['B', 'KB', 'MB']:
            if bytes_size < 1024:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024
        return f"{bytes_size:.1f} GB"
    
    def display_all(self):
        """Display all reports in sequence."""
        self.display_summary_report()
        self.display_detailed_report()
        self.display_download_options()


def main():
    """Main function for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Display security scan reports")
    parser.add_argument("--report-dir", default="reports", help="Directory containing reports")
    parser.add_argument("--summary-only", action="store_true", help="Only show summary")
    parser.add_argument("--downloads-only", action="store_true", help="Only show download info")
    
    args = parser.parse_args()
    
    display = ReportDisplay(report_dir=args.report_dir)
    
    if args.summary_only:
        display.display_summary_report()
    elif args.downloads_only:
        display.display_download_options()
    else:
        display.display_all()


if __name__ == "__main__":
    main()
