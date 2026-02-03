#!/usr/bin/env python3
"""
Structured AI summarizer for Bandit, Semgrep, pip-audit results.
- Extracts each issue
- Summarizes issue, consequence, fix separately
- Produces consistent PR-ready output
- Optional Groq AI enhancement
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

# Global variables
GROQ_AVAILABLE = False
client = None
API_KEY = None


# -------------------------------
# Initialize Groq Client
# -------------------------------
def _init_groq_client():
    """Initialize Groq client if available."""
    global GROQ_AVAILABLE, client, API_KEY

    GROQ_AVAILABLE = False
    client = None
    API_KEY = os.getenv("GROQ_API_KEY")

    if not API_KEY:
        print("ℹ️ GROQ_API_KEY not found, using pattern-based analysis")
        return False, None

    try:
        from groq import Groq

        client = Groq(api_key=API_KEY)
        GROQ_AVAILABLE = True

        print("✓ Groq AI enabled")
        return True, client

    except Exception as e:
        print(f"⚠ Groq AI not available: {e}")
        return False, None


# Initialize on load
_init_groq_client()


# -------------------------------
# Groq Generation
# -------------------------------
def _groq_generate(prompt: str) -> Optional[str]:
    """Generate text using Groq Chat API."""

    if not GROQ_AVAILABLE or client is None:
        return None

    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",  # ✅ Correct model
            messages=[
                {"role": "system", "content": "You are a security analysis assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=200
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        print(f"⚠ Groq API call failed, using patterns: {e}")
        return None


# -------------------------------
# Utilities
# -------------------------------
def load_json(path):
    if not Path(path).exists():
        return None

    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def extract_severity_level(severity_str: str) -> str:
    """Normalize severity levels."""

    if not severity_str:
        return "MEDIUM"

    sev = severity_str.upper()

    if any(x in sev for x in ["HIGH", "CRITICAL", "ERROR"]):
        return "HIGH"
    elif any(x in sev for x in ["MEDIUM", "WARNING"]):
        return "MEDIUM"
    else:
        return "LOW"


# -------------------------------
# AI / Pattern Logic
# -------------------------------
def generate_impact_statement(issue: Dict) -> str:
    """Generate impact statement."""

    source = issue.get("source", "Unknown")
    severity = extract_severity_level(issue.get("severity", "MEDIUM"))
    issue_text = str(issue.get("issue", ""))

    # Try AI first
    if GROQ_AVAILABLE and API_KEY:
        try:
            prompt = f"""
Analyze this security issue in 1 sentence (max 100 chars):

Issue: {issue_text[:200]}
Severity: {severity}
Source: {source}

Format:
[{severity}] Brief impact - consequence
"""

            response_text = _groq_generate(prompt)

            if response_text:
                return response_text[:200]

        except Exception as e:
            print(f"⚠ Groq failed, fallback: {e}")

    # Fallback rules
    issue_lower = issue_text.lower()

    if any(x in issue_lower for x in ["sql", "injection", "command"]):
        return f"[{severity}] Injection risk - Arbitrary code execution possible"

    elif any(x in issue_lower for x in ["hardcoded", "password", "secret", "key", "token"]):
        return f"[{severity}] Credential exposure - Sensitive data leak"

    elif any(x in issue_lower for x in ["pickle", "deserial"]):
        return f"[{severity}] Unsafe deserialization - RCE possible"

    elif any(x in issue_lower for x in ["eval", "exec"]):
        return f"[{severity}] Unsafe code execution - Arbitrary execution"

    elif any(x in issue_lower for x in ["authentication", "authorization"]):
        return f"[{severity}] Access control issue - Unauthorized access"

    elif any(x in issue_lower for x in ["crypto", "encryption", "hash"]):
        return f"[{severity}] Weak cryptography - Data exposure"

    elif "cve" in issue_lower:
        return f"[{severity}] Known vulnerability - Patch required"

    else:
        return f"[{severity}] Security issue detected by {source}"


def generate_fix_suggestion(issue: Dict) -> str:
    """Generate fix suggestion."""

    issue_text = str(issue.get("issue", ""))
    source = issue.get("source", "Unknown")

    # Try AI first
    if GROQ_AVAILABLE and API_KEY:
        try:
            prompt = f"""
Suggest 1 fix (max 100 chars):

Issue: {issue_text[:200]}
Source: {source}
"""

            response_text = _groq_generate(prompt)

            if response_text:
                return response_text[:250]

        except Exception as e:
            print(f"⚠ Groq failed, fallback: {e}")

    # Fallback rules
    issue_lower = issue_text.lower()

    if "sql" in issue_lower:
        return "Use parameterized queries"

    elif "hardcoded" in issue_lower:
        return "Move secrets to environment variables"

    elif "pickle" in issue_lower:
        return "Use safe serialization formats"

    elif "eval" in issue_lower:
        return "Avoid eval/exec"

    elif "crypto" in issue_lower:
        return "Use modern cryptography"

    elif source == "pip-audit":
        return issue.get("fix", "Update dependency")

    else:
        return "Follow security best practices"


# -------------------------------
# Extract Issues
# -------------------------------
def extract_all_issues(report_dir) -> List[Dict]:

    issues = []

    # Bandit
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

    # Semgrep
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

    # Pip-audit
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


# -------------------------------
# Reports
# -------------------------------
def generate_final_summary(issues: List[Dict]) -> str:

    if not issues:
        return "⚠️ No issues extracted. Check scanner reports.\n"

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


# -------------------------------
# Main
# -------------------------------
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
