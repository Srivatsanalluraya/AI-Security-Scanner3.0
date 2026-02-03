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
    """Run tool and capture JSON output safely"""

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Warn only if tool produced NO usable output
        if p.returncode != 0 and not p.stdout:
            print("⚠ Tool execution failed:", " ".join(cmd))
            print(p.stderr[:500])

        if not p.stdout:
            return {}

        return json.loads(p.stdout)

    except Exception as e:
        print("⚠ Execution failed:", e)
        return {}


# ----------------------------
# Collect All Issues
# ----------------------------
def collect_issues(scan_path=".") -> List[Dict]:

    issues = []

    # ---------------- Bandit ----------------
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


    # ---------------- Semgrep ----------------
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


    # ---------------- Pip-audit ----------------
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


    # ---------------- Build AI Report ----------------
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


    # ---------------- Export ----------------

    # Ensure dirs exist
    os.makedirs("security-reports", exist_ok=True)
    os.makedirs("reports", exist_ok=True)


    # 1️⃣ Live report
    live_file = "security-reports/live_report.json"

    with open(live_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


    # 2️⃣ Legacy detailed report
    detailed = {
        "total_issues": len(report),
        "detailed_issues": []
    }

    for item in report:
        detailed["detailed_issues"].append({
            "number": item["id"],
            "source": item["source"],
            "severity": "MEDIUM",
            "file": item["file"],
            "line": item["line"],
            "description": item["issue"],
            "impact": item["impact"],
            "fix": item["fix"]
        })


    issues_file = "reports/issues_detailed.json"

    with open(issues_file, "w", encoding="utf-8") as f:
        json.dump(detailed, f, indent=2)


    # 3️⃣ Final merged report
    final_file = "reports/final_report.json"

    with open(final_file, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "total_issues": len(report)
            },
            "issues": report
        }, f, indent=2)


    print("✅ Reports generated:")
    print("  →", live_file)
    print("  →", issues_file)
    print("  →", final_file)




if __name__ == "__main__":
    main()
