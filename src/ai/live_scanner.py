#!/usr/bin/env python3

import subprocess
import json
import os
from typing import List, Dict

from summarizer import (
    batch_ai_analysis,
    fallback_impact,
    fallback_fix,
    extract_severity_level
)


# =================================================
# Collect All Scannable Source Files
# =================================================
def collect_all_files(scan_path="."):

    exts = (
        ".py",
        ".js", ".jsx", ".ts", ".tsx",
        ".java",
        ".go",
        ".php",
        ".rb",
        ".c", ".cpp",
        ".cs"
    )

    scanned = []

    for root, _, files in os.walk(scan_path):

        if any(x in root for x in [".git", "node_modules", ".venv", "dist", "build"]):
            continue

        for f in files:

            if f.lower().endswith(exts):

                full = os.path.join(root, f)
                scanned.append(full.replace(scan_path, "").lstrip("/"))

    return sorted(scanned)


# =================================================
# Helpers
# =================================================
def has_python_project(path="."):

    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".py"):
                return True

    if os.path.exists("requirements.txt"):
        return True

    if os.path.exists("pyproject.toml"):
        return True

    return False


def has_node_project():
    return os.path.exists("package.json")


# =================================================
# Run external tools safely
# =================================================
def run_json(cmd: List[str]) -> Dict:

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if p.returncode != 0 and not p.stdout:
            print("⚠ Tool failed:", " ".join(cmd))
            print(p.stderr[:400])

        if not p.stdout:
            return {}

        return json.loads(p.stdout)

    except Exception as e:
        print("⚠ Execution failed:", e)
        return {}


# =================================================
# Collect Vulnerabilities
# =================================================
def collect_issues(scan_path=".") -> List[Dict]:

    issues = []


    # ---------------- Bandit (Python) ----------------
    if has_python_project(scan_path):

        print("▶ Bandit (Python)")

        bandit = run_json([
            "bandit", "-r", scan_path, "-f", "json"
        ])

        for r in bandit.get("results", []):

            issues.append({
                "source": "Bandit",
                "issue": r.get("issue_text"),
                "file": r.get("filename"),
                "line": r.get("line_number"),
                "severity": extract_severity_level(
                    r.get("issue_severity", "MEDIUM")
                )
            })

    else:
        print("⏭ Skipping Bandit (no Python found)")


    # ---------------- Semgrep (Multi-Lang) ----------------
    print("▶ Semgrep (JS / TS / Java / Go / Python / Secrets)")

    semgrep = run_json([

        "semgrep",

        "--disable-version-check",
        "--metrics=off",

        "--config", "p/javascript.security",
        "--config", "p/javascript.lang.correctness",
        "--config", "p/typescript.security",
        "--config", "p/python.security",
        "--config", "p/java.security",
        "--config", "p/golang.security",
        "--config", "p/generic.secrets",

        "--json",
        scan_path
    ])


    for r in semgrep.get("results", []):

        sev = r.get("extra", {}).get("severity", "MEDIUM")

        issues.append({
            "source": "Semgrep",
            "issue": r.get("extra", {}).get("message"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "severity": extract_severity_level(sev)
        })


    # ---------------- pip-audit (Python deps) ----------------
    if has_python_project(scan_path):

        print("▶ Pip-audit (Python deps)")

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
                    "severity": "HIGH"
                })

    else:
        print("⏭ Skipping pip-audit (no Python deps)")


    # ---------------- npm audit (Node deps) ----------------
    if has_node_project():

        print("▶ npm audit (JS deps)")

        npm_audit = run_json([
            "npm", "audit", "--json"
        ])

        vulns = npm_audit.get("vulnerabilities", {})

        for name, data in vulns.items():

            severity = data.get("severity", "medium").upper()

            issues.append({
                "source": "npm-audit",
                "issue": data.get("title", "Dependency vulnerability"),
                "file": "package.json",
                "line": 0,
                "severity": extract_severity_level(severity)
            })

    else:
        print("⏭ Skipping npm audit (no package.json)")


    # ---------------- RetireJS ----------------
    if has_node_project():

        print("▶ RetireJS (JS libraries)")

        retire = run_json([
            "retire",
            "--js",
            "--outputformat", "json"
        ])

        if isinstance(retire, list):

            for result in retire:

                for r in result.get("results", []):

                    for vuln in r.get("vulnerabilities", []):

                        issues.append({
                            "source": "RetireJS",
                            "issue": vuln.get("info", ["Outdated library"])[0],
                            "file": result.get("file", "JS"),
                            "line": 0,
                            "severity": extract_severity_level(
                                vuln.get("severity", "medium")
                            )
                        })

    else:
        print("⏭ Skipping RetireJS (no Node project)")


    return issues


# =================================================
# Main Pipeline
# =================================================
def main():

    scan_path = os.getenv("SCAN_PATH", ".")

    print("🔍 Scanning:", scan_path)
    print("📁 Collecting scannable files...")

    all_files = collect_all_files(scan_path)

    print(f"📊 Total files scanned: {len(all_files)}")

    for f in all_files:
        print("   •", f)


    # ---------- Collect Issues ----------
    issues = collect_issues(scan_path)

    if not issues:
        print("✅ No issues found")


    print(f"⚠ Found {len(issues)} issues")


    # ---------- Batch AI ----------
    print("🤖 Running batched AI analysis...")

    ai_map = batch_ai_analysis(issues)


    # ---------- Build Report ----------
    report = []

    for i, issue in enumerate(issues, 1):

        ai = ai_map.get(str(i), {})

        impact = ai.get("impact") or fallback_impact(issue)
        fix = ai.get("fix") or fallback_fix(issue)

        report.append({
            "id": i,
            "source": issue["source"],
            "severity": issue.get("severity", "MEDIUM"),
            "file": issue["file"],
            "line": issue["line"],
            "issue": issue["issue"],
            "impact": impact,
            "fix": fix
        })


    # ---------- Analytics ----------
    severity_counts = {}
    issues_by_source = {}

    for item in report:

        sev = item.get("severity", "MEDIUM")
        src = item.get("source", "Unknown")

        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        issues_by_source[src] = issues_by_source.get(src, 0) + 1


    # ---------- Output ----------
    os.makedirs("security-reports", exist_ok=True)
    os.makedirs("reports", exist_ok=True)


    # Save scanned files
    with open("reports/scanned_files.txt", "w", encoding="utf-8") as f:
        for file in all_files:
            f.write(file + "\n")


    # Live report
    live_file = "security-reports/live_report.json"

    with open(live_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


    # Detailed report
    detailed = {
        "total_issues": len(report),
        "severity_counts": severity_counts,
        "issues_by_source": issues_by_source,
        "detailed_issues": []
    }


    for item in report:

        detailed["detailed_issues"].append({
            "number": item["id"],
            "source": item["source"],
            "severity": item.get("severity", "MEDIUM"),
            "file": item["file"],
            "line": item["line"],
            "description": item["issue"],
            "impact": item["impact"],
            "fix": item["fix"]
        })


    issues_file = "reports/issues_detailed.json"

    with open(issues_file, "w", encoding="utf-8") as f:
        json.dump(detailed, f, indent=2)


    # Final report
    final_file = "reports/final_report.json"

    with open(final_file, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "total_issues": len(report),
                "severity_counts": severity_counts,
                "issues_by_source": issues_by_source
            },
            "issues": report
        }, f, indent=2)


    # ---------- Status ----------
    print("✅ Reports generated successfully:")
    print("  →", live_file)
    print("  →", issues_file)
    print("  →", final_file)


# =================================================
# Entry
# =================================================
if __name__ == "__main__":
    main()
