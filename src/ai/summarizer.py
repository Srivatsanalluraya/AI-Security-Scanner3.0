#!/usr/bin/env python3
"""
Structured AI summarizer for Bandit, Semgrep, pip-audit results.
- Extracts each issue
- Summarizes issue, consequence, fix separately
- Produces consistent PR-ready output with Impact and Fix suggestions
"""

import json
from pathlib import Path
from typing import Dict, List, Optional


MODEL_NAME = "google/flan-t5-small"


def load_json(path):
    if not Path(path).exists():
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except:
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


def generate_impact_statement(issue: Dict) -> str:
    """Generate a concise impact statement for the issue."""
    source = issue.get("source", "Unknown")
    severity = extract_severity_level(issue.get("severity", "MEDIUM"))
    
    issue_text = str(issue.get("issue", "")).lower()
    
    # Determine impact based on common vulnerability patterns
    if any(x in issue_text for x in ["sql", "injection", "command"]):
        return f"[{severity}] Code/SQL injection risk - Attacker could execute arbitrary code or queries"
    elif any(x in issue_text for x in ["hardcoded", "password", "secret", "key", "token"]):
        return f"[{severity}] Credential exposure - Hardcoded sensitive data could be compromised"
    elif any(x in issue_text for x in ["pickle", "deserial"]):
        return f"[{severity}] Unsafe deserialization - Could lead to arbitrary code execution"
    elif any(x in issue_text for x in ["eval", "exec"]):
        return f"[{severity}] Dynamic code execution - Unsafe evaluation of untrusted input"
    elif any(x in issue_text for x in ["authentication", "authorization", "permission"]):
        return f"[{severity}] Access control issue - Unauthorized access possible"
    elif any(x in issue_text for x in ["crypto", "encryption", "hash"]):
        return f"[{severity}] Weak cryptography - Insufficient security for sensitive operations"
    elif "vulnerability" in issue_text or "cve" in issue_text:
        return f"[{severity}] Known vulnerability - Update dependency to patched version"
    else:
        return f"[{severity}] Security issue detected by {source}"


def generate_fix_suggestion(issue: Dict) -> str:
    """Generate a concise fix suggestion."""
    issue_text = str(issue.get("issue", "")).lower()
    source = issue.get("source", "Unknown")
    
    # Provide specific fixes based on issue type
    if any(x in issue_text for x in ["sql", "injection"]):
        return "Use parameterized queries or prepared statements; never concatenate user input into SQL"
    elif any(x in issue_text for x in ["hardcoded", "password", "secret", "key"]):
        return "Move credentials to environment variables or secure vaults (e.g., .env, AWS Secrets Manager)"
    elif any(x in issue_text for x in ["pickle"]):
        return "Replace pickle with JSON, Protocol Buffers, or other safe serialization formats"
    elif any(x in issue_text for x in ["eval", "exec"]):
        return "Avoid eval/exec; use ast.literal_eval or dedicated parsing libraries for specific data types"
    elif any(x in issue_text for x in ["authentication", "authorization"]):
        return "Implement proper access control checks; validate user permissions before operations"
    elif any(x in issue_text for x in ["crypto", "encryption", "md5", "sha1"]):
        return "Use modern algorithms (bcrypt for passwords, SHA-256+ for hashing, AES for encryption)"
    elif source == "pip-audit":
        return issue.get("fix", "Update dependency to latest patched version")
    else:
        return f"Review security best practices for {source}; check official documentation"


def extract_all_issues(report_dir) -> List[Dict]:
    issues = []

    # -----------------------
    # BANDIT extraction (Python)
    # -----------------------
    bandit = load_json(f"{report_dir}/bandit-report.json")
    if bandit and "results" in bandit:
        for r in bandit["results"]:
            issues.append({
                "source": "Bandit",
                "file": r.get("filename"),
                "line": r.get("line_number"),
                "issue": r.get("issue_text"),
                "severity": extract_severity_level(r.get("issue_severity", "MEDIUM")),
                "confidence": r.get("issue_confidence", "UNKNOWN")
            })

    # -----------------------
    # SEMGREP extraction (Multi-language)
    # -----------------------
    semgrep = load_json(f"{report_dir}/semgrep-report.json")
    if semgrep and "results" in semgrep:
        for r in semgrep["results"]:
            issues.append({
                "source": "Semgrep",
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "issue": r.get("extra", {}).get("message", ""),
                "severity": extract_severity_level(r.get("extra", {}).get("severity", "MEDIUM")),
            })

    # -----------------------
    # PIP-AUDIT extraction (Python dependencies)
    # -----------------------
    pip_audit = load_json(f"{report_dir}/pip-audit-report.json")
    if pip_audit:
        deps = pip_audit if isinstance(pip_audit, list) else pip_audit.get("dependencies", [])
        for dep in deps:
            for vuln in dep.get("vulns", []):
                issues.append({
                    "source": "pip-audit",
                    "package": dep.get("name", "unknown"),
                    "version": dep.get("version", "?"),
                    "file": "requirements.txt",
                    "line": 0,
                    "issue": f"{vuln.get('id', 'CVE')} - {vuln.get('description', 'Dependency vulnerability')}",
                    "severity": "MEDIUM",
                    "fix": f"Update {dep.get('name')} to {vuln.get('fix_versions', 'latest version')}"
                })

    # -----------------------
    # NPM AUDIT extraction (Node.js dependencies)
    # -----------------------
    npm_audit = load_json(f"{report_dir}/npm-audit-report.json")
    if npm_audit and "vulnerabilities" in npm_audit:
        for pkg_name, vuln_data in npm_audit.get("vulnerabilities", {}).items():
            if isinstance(vuln_data, dict):
                issues.append({
                    "source": "npm-audit",
                    "package": pkg_name,
                    "file": "package.json",
                    "line": 0,
                    "issue": vuln_data.get("title", "Dependency vulnerability"),
                    "severity": extract_severity_level(vuln_data.get("severity", "MEDIUM")),
                    "fix": f"Update to version {vuln_data.get('fixAvailable', {}).get('version', 'latest')}"
                })

    # -----------------------
    # GOSEC extraction (Go security)
    # -----------------------
    gosec = load_json(f"{report_dir}/gosec-report.json")
    if gosec and "Issues" in gosec:
        for r in gosec["Issues"]:
            issues.append({
                "source": "Gosec",
                "file": r.get("file"),
                "line": r.get("line"),
                "issue": r.get("details"),
                "severity": extract_severity_level(r.get("severity", "MEDIUM")),
            })

    # -----------------------
    # NANCY extraction (Go dependencies)
    # -----------------------
    nancy = load_json(f"{report_dir}/nancy-report.json")
    if nancy and isinstance(nancy, list):
        for vuln in nancy:
            if isinstance(vuln, dict):
                issues.append({
                    "source": "Nancy",
                    "package": vuln.get("Coordinates", "unknown"),
                    "file": "go.sum",
                    "line": 0,
                    "issue": vuln.get("Title", "Go dependency vulnerability"),
                    "severity": "HIGH",
                    "fix": "Update Go dependencies"
                })

    # -----------------------
    # TRIVY extraction (Universal)
    # -----------------------
    trivy = load_json(f"{report_dir}/trivy-report.json")
    if trivy and "Results" in trivy:
        for result in trivy["Results"]:
            for vuln in result.get("Vulnerabilities", []):
                issues.append({
                    "source": "Trivy",
                    "package": vuln.get("PkgName", "unknown"),
                    "file": result.get("Target", "dependencies"),
                    "line": 0,
                    "issue": vuln.get("Title", vuln.get("VulnerabilityID", "Vulnerability")),
                    "severity": extract_severity_level(vuln.get("Severity", "MEDIUM")),
                    "fix": f"Update to {vuln.get('FixedVersion', 'latest version')}"
                })

    # -----------------------
    # JAVA DEPENDENCY CHECK extraction
    # -----------------------
    java_dep = load_json(f"{report_dir}/java-dependency-check.json")
    if java_dep and "dependencies" in java_dep:
        for dep in java_dep["dependencies"]:
            for vuln in dep.get("vulnerabilities", []):
                issues.append({
                    "source": "OWASP-DepCheck",
                    "package": dep.get("fileName", "unknown"),
                    "file": "pom.xml",
                    "line": 0,
                    "issue": vuln.get("name", "Java dependency vulnerability"),
                    "severity": extract_severity_level(vuln.get("severity", "MEDIUM")),
                    "fix": "Update Java dependencies"
                })

    return issues


def generate_final_summary(issues: List[Dict], pushed_by: str = "") -> str:
    """Format issues into structured PR comment format."""
    if not issues:
        return "✅ No security issues detected.\n"

    lines = []
    lines.append(f"📊 SECURITY SCAN RESULTS")
    lines.append(f"Found {len(issues)} issue(s)")
    lines.append("")

    for idx, issue in enumerate(issues, start=1):
        lines.append(f"Issue #{idx}:")
        
        pushed = pushed_by or "Unknown"
        lines.append(f"  Pushed by: {pushed}")
        
        description = issue.get("issue", "No description")
        if len(description) > 100:
            description = description[:97] + "..."
        lines.append(f"  Description: {description}")
        
        impact = generate_impact_statement(issue)
        lines.append(f"  Impact: {impact}")
        
        fix = issue.get("fix") or generate_fix_suggestion(issue)
        if len(fix) > 120:
            fix = fix[:117] + "..."
        lines.append(f"  Fix: {fix}")
        
        lines.append("")

    return "\n".join(lines)


def generate_detailed_report(issues: List[Dict]) -> Dict:
    """Generate a structured report with all issue details."""
    report = {
        "total_issues": len(issues),
        "severity_counts": {},
        "issues_by_source": {},
        "detailed_issues": []
    }
    
    # Count by severity
    for issue in issues:
        sev = issue.get("severity", "MEDIUM")
        report["severity_counts"][sev] = report["severity_counts"].get(sev, 0) + 1
        
        # Group by source
        source = issue.get("source", "Unknown")
        if source not in report["issues_by_source"]:
            report["issues_by_source"][source] = 0
        report["issues_by_source"][source] += 1
    
    # Detailed issues with all fields
    for idx, issue in enumerate(issues, start=1):
        detailed = {
            "number": idx,
            "source": issue.get("source", "Unknown"),
            "severity": issue.get("severity", "MEDIUM"),
            "file": issue.get("file", issue.get("package", "Unknown")),
            "line": issue.get("line", 0),
            "description": issue.get("issue", ""),
            "impact": generate_impact_statement(issue),
            "fix": issue.get("fix") or generate_fix_suggestion(issue)
        }
        report["detailed_issues"].append(detailed)
    
    return report


def main():
    report_dir = "reports"

    issues = extract_all_issues(report_dir)
    
    if not issues:
        Path(f"{report_dir}/summary.txt").write_text("✅ No security issues detected.\n")
        Path(f"{report_dir}/issues_detailed.json").write_text(json.dumps({"total_issues": 0}, indent=2))
        return

    # Generate text summary
    summary_text = generate_final_summary(issues)
    Path(f"{report_dir}/summary.txt").write_text(summary_text, encoding="utf-8")
    
    # Generate detailed JSON report
    detailed_report = generate_detailed_report(issues)
    Path(f"{report_dir}/issues_detailed.json").write_text(
        json.dumps(detailed_report, indent=2),
        encoding="utf-8"
    )
    
    print(f"✅ Summary written to reports/summary.txt")
    print(f"✅ Detailed report written to reports/issues_detailed.json")


if __name__ == "__main__":
    main()
