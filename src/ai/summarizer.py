#!/usr/bin/env python3
"""
Structured AI summarizer for Bandit, Semgrep, pip-audit results.
- Extracts each issue
- Uses secure backend AI
- Generates summary + detailed reports
"""

import json
import os
import requests
from pathlib import Path
from typing import Dict, List, Optional


# ===============================
# Backend Configuration
# ===============================

BACKEND_URL = os.getenv(
    "AI_BACKEND_URL",
    "https://ai-security-backend.onrender.com/analyze"  # ✅ FIXED (no space)
)

AI_ENABLED = True

# Connection tuning
TIMEOUT = 25
RETRIES = 2


# ===============================
# AI Backend Call
# ===============================

def _ai_generate(prompt: str) -> Optional[str]:
    """Send prompt to secure backend with retry"""

    if not AI_ENABLED:
        return None

    for attempt in range(RETRIES):

        try:
            r = requests.post(
                BACKEND_URL,
                json={"prompt": prompt},
                timeout=TIMEOUT
            )

            if r.status_code != 200:
                print("⚠ AI backend HTTP error:", r.status_code, r.text[:200])
                continue

            data = r.json()

            # ✅ Correct Groq format
            if "choices" in data and data["choices"]:
                return data["choices"][0]["message"]["content"].strip()

            print("⚠ AI backend returned unexpected format:", data)
            return None

        except requests.exceptions.Timeout:
            print(f"⚠ AI backend timeout (attempt {attempt+1}/{RETRIES})")

        except Exception as e:
            print("⚠ AI backend failed:", e)

    print("⚠ AI backend unavailable, falling back to rules")
    return None


# ===============================
# Utilities
# ===============================

def load_json(path):
    if not Path(path).exists():
        return None

    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def extract_severity_level(severity_str: str) -> str:

    if not severity_str:
        return "MEDIUM"

    sev = severity_str.upper()

    if any(x in sev for x in ["HIGH", "CRITICAL", "ERROR"]):
        return "HIGH"
    elif any(x in sev for x in ["MEDIUM", "WARNING"]):
        return "MEDIUM"
    else:
        return "LOW"


# ===============================
# AI / Pattern Logic
# ===============================

def generate_impact_statement(issue: Dict) -> str:

    source = issue.get("source", "Unknown")
    severity = extract_severity_level(issue.get("severity", "MEDIUM"))
    issue_text = str(issue.get("issue", ""))

    # ---- Try AI ----
    prompt = f"""
Analyze this security issue in 1 sentence (max 100 chars):

Issue: {issue_text[:200]}
Severity: {severity}
Source: {source}

Format:
[{severity}] Brief impact - consequence
"""

    response = _ai_generate(prompt)

    if response:
        return response[:200]

    # ---- Fallback ----
    issue_lower = issue_text.lower()

    if any(x in issue_lower for x in ["sql", "injection", "command"]):
        return f"[{severity}] Injection risk - Code execution possible"

    elif any(x in issue_lower for x in ["hardcoded", "password", "secret", "key", "token"]):
        return f"[{severity}] Credential exposure - Sensitive data leak"

    elif any(x in issue_lower for x in ["pickle", "deserial"]):
        return f"[{severity}] Unsafe deserialization - RCE possible"

    elif any(x in issue_lower for x in ["eval", "exec"]):
        return f"[{severity}] Unsafe code execution"

    elif any(x in issue_lower for x in ["authentication", "authorization"]):
        return f"[{severity}] Access control weakness"

    elif any(x in issue_lower for x in ["crypto", "encryption", "hash"]):
        return f"[{severity}] Weak cryptography"

    elif "cve" in issue_lower:
        return f"[{severity}] Known vulnerability"

    else:
        return f"[{severity}] Security issue from {source}"


def generate_fix_suggestion(issue: Dict) -> str:

    issue_text = str(issue.get("issue", ""))
    source = issue.get("source", "Unknown")

    # ---- Try AI ----
    prompt = f"""
Suggest 1 specific fix (max 100 chars):

Issue: {issue_text[:200]}
Source: {source}
"""

    response = _ai_generate(prompt)

    if response:
        return response[:250]

    # ---- Fallback ----
    issue_lower = issue_text.lower()

    if "sql" in issue_lower:
        return "Use prepared statements"

    elif "hardcoded" in issue_lower:
        return "Move secrets to env variables"

    elif "pickle" in issue_lower:
        return "Use safe serialization"

    elif "eval" in issue_lower:
        return "Avoid eval/exec"

    elif "crypto" in issue_lower:
        return "Use modern algorithms"

    elif source == "pip-audit":
        return issue.get("fix", "Update dependency")

    else:
        return "Follow secure coding practices"


# ===============================
# Extract Issues
# ===============================

def extract_all_issues(report_dir) -> List[Dict]:

    issues = []

    # -------- Bandit --------
    bandit = load_json(f"{report_dir}/bandit-report.json")

    if bandit and "results" in bandit:
        for r in bandit["results"]:
            issues.append({
                "source": "Bandit",
                "file": r.get("filename"),
                "line": r.get("line_number"),
                "issue": r.get("issue_text"),
                "severity": extract_severity_level(r.get("issue_severity")),
                "confidence": r.get("issue_confidence")
            })

    # -------- Semgrep --------
    semgrep = load_json(f"{report_dir}/semgrep-report.json")

    if semgrep and "results" in semgrep:
        for r in semgrep["results"]:
            issues.append({
                "source": "Semgrep",
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "issue": r.get("extra", {}).get("message"),
                "severity": extract_severity_level(
                    r.get("extra", {}).get("severity")
                ),
            })

    # -------- pip-audit --------
    pip_audit = load_json(f"{report_dir}/pip-audit-report.json")

    if pip_audit:

        deps = pip_audit if isinstance(pip_audit, list) else pip_audit.get("dependencies", [])

        for dep in deps:
            for vuln in dep.get("vulns", []):

                issues.append({
                    "source": "pip-audit",
                    "package": dep.get("name"),
                    "version": dep.get("version"),
                    "file": "requirements.txt",
                    "line": 0,
                    "issue": f"{vuln.get('id')} - {vuln.get('description')}",
                    "severity": "MEDIUM",
                    "fix": f"Update {dep.get('name')}"
                })

    return issues


# ===============================
# Reports
# ===============================

def generate_final_summary(issues: List[Dict]) -> str:

    if not issues:
        return "⚠️ No issues extracted\n"

    lines = []

    lines.append("📊 SECURITY SCAN RESULTS")
    lines.append(f"Found {len(issues)} issue(s)\n")

    for i, issue in enumerate(issues, 1):

        lines.append(f"Issue #{i}:")

        desc = issue.get("issue", "No description")

        if len(desc) > 100:
            desc = desc[:97] + "..."

        lines.append(f"  Description: {desc}")
        lines.append(f"  Impact: {generate_impact_statement(issue)}")
        lines.append(f"  Fix: {issue.get('fix') or generate_fix_suggestion(issue)}\n")

    return "\n".join(lines)


def generate_detailed_report(issues: List[Dict]) -> Dict:

    report = {
        "total_issues": len(issues),
        "detailed_issues": []
    }

    for i, issue in enumerate(issues, 1):

        report["detailed_issues"].append({
            "number": i,
            "source": issue.get("source"),
            "severity": issue.get("severity"),
            "file": issue.get("file"),
            "line": issue.get("line"),
            "description": issue.get("issue"),
            "impact": generate_impact_statement(issue),
            "fix": issue.get("fix") or generate_fix_suggestion(issue)
        })

    return report


# ===============================
# Main
# ===============================

def main():

    report_dir = "reports"

    print("📂 Reading reports from:", report_dir)
    print("📄 Files:", list(Path(report_dir).glob("*")))

    issues = extract_all_issues(report_dir)

    if not issues:

        print("⚠️ No issues found in reports")

        Path(f"{report_dir}/summary.txt").write_text(
            "⚠️ No issues extracted.\n"
        )

        Path(f"{report_dir}/issues_detailed.json").write_text(
            json.dumps({"total_issues": 0}, indent=2)
        )

        return


    summary = generate_final_summary(issues)

    Path(f"{report_dir}/summary.txt").write_text(
        summary,
        encoding="utf-8"
    )


    detailed = generate_detailed_report(issues)

    Path(f"{report_dir}/issues_detailed.json").write_text(
        json.dumps(detailed, indent=2),
        encoding="utf-8"
    )


    print("✅ Summary written to reports/summary.txt")
    print("✅ Detailed report written to reports/issues_detailed.json")


if __name__ == "__main__":
    main()
