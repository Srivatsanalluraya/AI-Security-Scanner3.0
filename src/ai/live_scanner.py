#!/usr/bin/env python3

import subprocess
import json
import os
from typing import List, Dict

from summarizer import (
    generate_impact_statement,
    generate_fix_suggestion
)


# ----------------------------
# Run Commands in Memory
# ----------------------------
def run_json(cmd: List[str]) -> Dict:
    """Run tool and capture JSON output"""

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if p.returncode != 0:
            print("⚠ Tool failed:", " ".join(cmd))
            print(p.stderr[:500])

        return json.loads(p.stdout) if p.stdout else {}

    except Exception as e:
        print("⚠ Execution failed:", e)
        return {}


# ----------------------------
# Collect All Issues
# ----------------------------
def collect_issues(scan_path=".") -> List[Dict]:

    issues = []

    # Bandit
    print("▶ Bandit")
    bandit = run_json([
        "bandit", "-r", scan_path, "-f", "json"
    ])

    for r in bandit.get("results", []):
        issues.append({
            "source": "Bandit",
            "issue": r.get("issue_text"),
            "file": r.get("filename"),
            "line": r.get("line_number"),
            "severity": r.get("issue_severity")
        })

    # Semgrep
    print("▶ Semgrep")
    semgrep = run_json([
        "semgrep", "--config", "auto", "--json", scan_path
    ])

    for r in semgrep.get("results", []):
        issues.append({
            "source": "Semgrep",
            "issue": r.get("extra", {}).get("message"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "severity": r.get("extra", {}).get("severity")
        })

    # Pip-audit
    print("▶ Pip-audit")
    pip_audit = run_json([
        "pip-audit", "-f", "json"
    ])

    deps = pip_audit if isinstance(pip_audit, list) else pip_audit.get("dependencies", [])

    for dep in deps:
        for v in dep.get("vulns", []):
            issues.append({
                "source": "pip-audit",
                "issue": v.get("description"),
                "file": "requirements.txt",
                "line": 0,
                "severity": "MEDIUM"
            })

    return issues


# ----------------------------
# Main
# ----------------------------
def main():

    scan_path = os.getenv("SCAN_PATH", ".")

    print("🔍 Scanning:", scan_path)

    issues = collect_issues(scan_path)

    if not issues:
        print("✅ No issues found")
        return

    print(f"⚠ Found {len(issues)} issues")

    report = []

    for i, issue in enumerate(issues, 1):

        impact = generate_impact_statement(issue)
        fix = generate_fix_suggestion(issue)

        report.append({
            "id": i,
            "source": issue["source"],
            "file": issue["file"],
            "line": issue["line"],
            "issue": issue["issue"],
            "impact": impact,
            "fix": fix
        })

    # Export
    os.makedirs("security-reports", exist_ok=True)

    with open("security-reports/live_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("✅ Live AI report saved")


if __name__ == "__main__":
    main()
