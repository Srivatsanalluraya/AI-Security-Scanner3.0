````python
#!/usr/bin/env python3

"""
Structured AI summarizer (Improved Descriptions + Batched AI)
"""

import json
import os
import requests
from pathlib import Path
from typing import Dict, List, Optional
import re

# ===============================
# Backend Configuration
# ===============================

BACKEND_URL = os.getenv(
    "AI_BACKEND_URL",
    "https://ai-security-backend.onrender.com/analyze"
)

AI_ENABLED = True

TIMEOUT = 90
RETRIES = 3

MAX_AI_ISSUES = int(os.getenv("AI_MAX_ISSUES", 30))


# ===============================
# Utilities
# ===============================

def clean_text(text: str) -> str:

    if not text:
        return ""

    text = text.replace("\n", " ")
    text = text.replace("\r", " ")

    # Remove markdown headings
    text = re.sub(r'#+\s*', '', text)

    # Normalize spaces
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


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

    sev = str(severity_str).upper()

    if any(x in sev for x in ["HIGH", "CRITICAL", "ERROR"]):
        return "HIGH"

    elif any(x in sev for x in ["MEDIUM", "WARNING"]):
        return "MEDIUM"

    return "LOW"


def extract_pip_severity(vuln: Dict) -> str:

    text = (
        str(vuln.get("description", "")) +
        " " +
        str(vuln.get("id", ""))
    ).upper()

    if any(x in text for x in ["CRITICAL", "CVSS:9", "CVSS 9"]):
        return "HIGH"

    if any(x in text for x in ["HIGH", "CVSS:7", "CVSS 7"]):
        return "HIGH"

    if any(x in text for x in ["MEDIUM", "MODERATE", "CVSS:4"]):
        return "MEDIUM"

    return "LOW"


# ===============================
# AI Backend
# ===============================

def _ai_generate(prompt: str) -> Optional[str]:

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
                print("⚠ AI backend HTTP error:", r.status_code)
                continue

            data = r.json()

            if "choices" in data and data["choices"]:
                return data["choices"][0]["message"]["content"].strip()

            if "response" in data:
                return str(data["response"]).strip()

            if "content" in data:
                return str(data["content"]).strip()

            print("⚠ AI backend returned unexpected format")
            return None

        except requests.exceptions.Timeout:
            print(f"⚠ AI timeout ({attempt+1}/{RETRIES})")

        except Exception as e:
            print("⚠ AI backend failed:", e)

    print("⚠ AI backend unavailable")
    return None


# ===============================
# JSON Extractor
# ===============================

def _safe_json_extract(text: str):

    if not text:
        return None

    text = text.replace("```json", "")
    text = text.replace("```", "")
    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r'\{[\s\S]*\}', text)

    if not match:
        return None

    try:
        return json.loads(match.group(0))
    except Exception:
        return None


# ===============================
# Batch AI
# ===============================

def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]


def batch_ai_analysis(issues: List[Dict]) -> Dict:

    if not AI_ENABLED or not issues:
        return {}

    final_results = {}

    CHUNK_SIZE = 5

    issues = issues[:15]

    issue_index = 1

    for chunk in chunked(issues, CHUNK_SIZE):

        prompt = """
You are a security engineer.

For each issue return:
- impact
- specific fix

Use concise actionable fixes.
Return ONLY valid JSON.

Format:
{
  "1": {"impact": "...", "fix": "..."}
}

Issues:
"""

        for issue in chunk:

            prompt += f"""
{issue_index}.
Source: {issue.get('source')}
Severity: {issue.get('severity')}
File: {issue.get('file')}
Line: {issue.get('line')}
Issue: {issue.get('issue')}
"""

            snippet = clean_text(issue.get("snippet", ""))[:300]

            if snippet:
                prompt += f"Snippet: {snippet}\n"

            issue_index += 1

        response = _ai_generate(prompt)

        if not response:
            continue

        data = _safe_json_extract(response)

        if not data:
            continue

        final_results.update(data)

    return final_results


# ===============================
# Fallback Logic
# ===============================

def fallback_impact(issue: Dict) -> str:

    sev = extract_severity_level(issue.get("severity"))
    txt = str(issue.get("issue", "")).lower()

    if "sql" in txt:
        return f"[{sev}] SQL injection risk"

    if "password" in txt or "secret" in txt:
        return f"[{sev}] Credential exposure"

    if "eval" in txt or "exec" in txt:
        return f"[{sev}] Arbitrary code execution"

    if "crypto" in txt or "hash" in txt:
        return f"[{sev}] Weak cryptography"

    if "dependency" in txt or "vulnerability" in txt:
        return f"[{sev}] Vulnerable dependency may expose application to known exploits"

    return f"[{sev}] Security issue detected"


def fallback_fix(issue: Dict) -> str:

    txt = str(issue.get("issue", "")).lower()

    if "sql" in txt:
        return "Use prepared statements"

    if "password" in txt:
        return "Move secrets to environment variables"

    if "eval" in txt or "exec" in txt:
        return "Avoid eval/exec and use safer alternatives"

    if "crypto" in txt or "hash" in txt:
        return "Use modern secure cryptographic algorithms"

    if "dependency" in txt or "vulnerability" in txt:
        return "Update vulnerable dependency to latest secure version"

    return "Follow secure coding practices"


# ===============================
# Extract Issues
# ===============================

def extract_all_issues(report_dir) -> List[Dict]:

    issues = []

    # ==========================
    # Bandit
    # ==========================

    bandit = load_json(f"{report_dir}/bandit-report.json")

    if bandit and "results" in bandit:

        for r in bandit["results"]:

            issue_text = clean_text(r.get("issue_text", ""))

            if r.get("more_info"):
                issue_text += f" More Info: {clean_text(r.get('more_info'))}"

            issues.append({
                "source": "Bandit",
                "file": r.get("filename"),
                "line": r.get("line_number"),
                "issue": issue_text,
                "severity": extract_severity_level(
                    r.get("issue_severity")
                ),
                "rule_id": r.get("test_id"),
                "snippet": clean_text(r.get("code", "")),
            })

    # ==========================
    # Semgrep
    # ==========================

    semgrep = load_json(f"{report_dir}/semgrep-report.json")

    if semgrep and "results" in semgrep:

        for r in semgrep["results"]:

            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})

            issue_text = clean_text(extra.get("message", ""))

            if metadata.get("cwe"):
                issue_text += f" | CWE: {metadata.get('cwe')}"

            if metadata.get("owasp"):
                issue_text += f" | OWASP: {metadata.get('owasp')}"

            issues.append({
                "source": "Semgrep",
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "issue": issue_text,
                "severity": extract_severity_level(
                    extra.get("severity")
                ),
                "rule_id": r.get("check_id"),
                "snippet": clean_text(extra.get("lines", "")),
            })

    # ==========================
    # pip-audit
    # ==========================

    pip_audit = load_json(f"{report_dir}/pip-audit-report.json")

    if pip_audit:

        deps = (
            pip_audit
            if isinstance(pip_audit, list)
            else pip_audit.get("dependencies", [])
        )

        for dep in deps:

            for v in dep.get("vulns", []):

                desc = clean_text(v.get("description", ""))

                issue_text = f"{v.get('id')} - {desc}"

                issues.append({
                    "source": "pip-audit",
                    "file": "requirements.txt",
                    "line": 0,
                    "issue": issue_text,
                    "severity": extract_pip_severity(v),
                    "fix": f"Update {dep.get('name')}",
                    "package": dep.get("name"),
                    "fixed_version": v.get("fix_versions"),
                })

    return issues


# ===============================
# Reports
# ===============================

def generate_detailed_report(issues: List[Dict], ai_map: Dict) -> Dict:

    report = {
        "total_issues": len(issues),
        "detailed_issues": []
    }

    for i, issue in enumerate(issues, 1):

        ai = ai_map.get(str(i), {})

        impact = ai.get("impact") or fallback_impact(issue)
        fix = ai.get("fix") or fallback_fix(issue)

        report["detailed_issues"].append({
            "number": i,
            "source": issue.get("source"),
            "severity": issue.get("severity"),
            "file": issue.get("file"),
            "line": issue.get("line"),
            "description": clean_text(issue.get("issue", "")),
            "impact": impact,
            "fix": fix
        })

    return report


def generate_summary(issues: List[Dict], ai_map: Dict) -> str:

    if not issues:
        return "⚠️ No issues extracted\n"

    lines = []

    lines.append("📊 SECURITY SCAN RESULTS")
    lines.append(f"Found {len(issues)} issue(s)\n")

    for i, issue in enumerate(issues, 1):

        ai = ai_map.get(str(i), {})

        impact = ai.get("impact") or fallback_impact(issue)
        fix = ai.get("fix") or fallback_fix(issue)

        desc = clean_text(issue.get("issue", ""))

        lines.append(f"Issue #{i}:")
        lines.append(f"  Description: {desc}")
        lines.append(f"  Impact: {impact}")
        lines.append(f"  Fix: {fix}\n")

    return "\n".join(lines)


# ===============================
# Main
# ===============================

def main():

    report_dir = "reports"

    print("📂 Reading reports from:", report_dir)

    issues = extract_all_issues(report_dir)

    if not issues:

        print("⚠ No issues found")

        Path(f"{report_dir}/summary.txt").write_text("No issues\n")

        Path(f"{report_dir}/issues_detailed.json").write_text(
            json.dumps({"total_issues": 0}, indent=2)
        )

        return

    print(f"🤖 Running batch AI on {min(len(issues), MAX_AI_ISSUES)} issues...")

    ai_map = batch_ai_analysis(issues)

    summary = generate_summary(issues, ai_map)

    detailed = generate_detailed_report(issues, ai_map)

    Path(f"{report_dir}/summary.txt").write_text(summary)

    Path(f"{report_dir}/issues_detailed.json").write_text(
        json.dumps(detailed, indent=2)
    )

    print("✅ Summary written")
    print("✅ Detailed report written")


if __name__ == "__main__":
    main()
````
