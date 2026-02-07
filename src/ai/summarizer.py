#!/usr/bin/env python3
"""
Structured AI summarizer (Optimized + Batched)
- Extracts issues
- Uses secure backend AI
- Batches AI calls to avoid rate limits
- Generates summary + detailed reports
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

TIMEOUT = 25
RETRIES = 2

# Limit batch size (prevents token overflow)
MAX_AI_ISSUES = int(os.getenv("AI_MAX_ISSUES", 30))


# ===============================
# AI Backend Call
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

            print("⚠ AI backend returned unexpected format")
            return None

        except requests.exceptions.Timeout:
            print(f"⚠ AI timeout ({attempt+1}/{RETRIES})")

        except Exception as e:
            print("⚠ AI backend failed:", e)

    print("⚠ AI backend unavailable, fallback mode")
    return None


# ===============================
# Batch AI Analyzer (NEW)
# ===============================
def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]



def _safe_json_extract(text: str):
    """
    Extract valid JSON object from AI response safely
    """

    if not text:
        return None

    # Remove markdown ``` blocks
    text = re.sub(r"```.*?```", "", text, flags=re.S)

    # Find first {...} block
    match = re.search(r"\{.*\}", text, re.S)

    if not match:
        return None

    json_text = match.group(0)

    try:
        return json.loads(json_text)
    except Exception:
        return None

def batch_ai_analysis(issues: List[Dict]) -> Dict:
    """
    Chunked batch AI analysis (production safe)
    """

    if not AI_ENABLED or not issues:
        return {}

    final_results = {}
    CHUNK_SIZE = 5   # 🔴 critical: keep small

    issue_index = 1

    for chunk in chunked(issues, CHUNK_SIZE):

        prompt = """
You are a security analysis assistant.

For each issue below, generate:
- impact: 1 sentence (max 100 chars)
- fix: 1 sentence (max 100 chars)

Return ONLY valid JSON in this format:

{
  "1": {"impact": "...", "fix": "..."},
  "2": {"impact": "...", "fix": "..."}
}

Issues:
"""

        local_map = {}

        for issue in chunk:
            local_map[str(issue_index)] = issue
            prompt += f"""
{issue_index}.
Source: {issue.get('source')}
Severity: {issue.get('severity')}
File: {issue.get('file')}
Issue: {issue.get('issue')}
"""
            issue_index += 1

        response = _ai_generate(prompt)

        if not response:
            print("⚠ AI returned empty chunk, skipping")
            continue

        data = _safe_json_extract(response)

        if not data:
            print("⚠ Batch AI parse failed for chunk")
            continue

        # Merge chunk results
        for k, v in data.items():
            final_results[k] = v

    if final_results:
        print(f"✓ AI batch processed {len(final_results)} issues")
    else:
        print("⚠ AI unavailable, using rule-based analysis")

    return final_results


# ===============================
# Utilities
# ===============================

def load_json(path):

    if not Path(path).exists():
        return None

    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except:
        return None


def extract_severity_level(severity_str: str) -> str:

    if not severity_str:
        return "MEDIUM"

    sev = severity_str.upper()

    if any(x in sev for x in ["HIGH", "CRITICAL", "ERROR"]):
        return "HIGH"

    elif any(x in sev for x in ["MEDIUM", "WARNING"]):
        return "MEDIUM"

    return "LOW"


# ===============================
# Fallback Rules
# ===============================

def fallback_impact(issue: Dict) -> str:

    sev = extract_severity_level(issue.get("severity"))
    txt = str(issue.get("issue", "")).lower()

    if "sql" in txt:
        return f"[{sev}] SQL injection risk"

    if "password" in txt or "secret" in txt:
        return f"[{sev}] Credential exposure"

    if "eval" in txt:
        return f"[{sev}] Arbitrary code execution"

    if "crypto" in txt:
        return f"[{sev}] Weak cryptography"

    return f"[{sev}] Security issue detected"


def fallback_fix(issue: Dict) -> str:

    txt = str(issue.get("issue", "")).lower()

    if "sql" in txt:
        return "Use prepared statements"

    if "password" in txt:
        return "Move secrets to env vars"

    if "eval" in txt:
        return "Remove eval/exec"

    if "crypto" in txt:
        return "Use modern crypto"

    return "Follow secure coding practices"


# ===============================
# Extract Issues
# ===============================

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
                "severity": extract_severity_level(
                    r.get("issue_severity")
                )
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
                )
            })


    # pip-audit
    pip_audit = load_json(f"{report_dir}/pip-audit-report.json")

    if pip_audit:

        deps = pip_audit if isinstance(pip_audit, list) else pip_audit.get("dependencies", [])

        for dep in deps:

            for v in dep.get("vulns", []):

                issues.append({
                    "source": "pip-audit",
                    "file": "requirements.txt",
                    "line": 0,
                    "issue": f"{v.get('id')} - {v.get('description')}",
                    "severity": "MEDIUM",
                    "fix": f"Update {dep.get('name')}"
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
            "description": issue.get("issue"),
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

        desc = issue.get("issue", "")[:100]

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


    # ---------------------------
    # Batch AI (KEY CHANGE)
    # ---------------------------

    print(f"🤖 Running batch AI on {min(len(issues), MAX_AI_ISSUES)} issues...")

    ai_map = batch_ai_analysis(issues)


    # ---------------------------
    # Generate Reports
    # ---------------------------

    summary = generate_summary(issues, ai_map)

    detailed = generate_detailed_report(issues, ai_map)


    Path(f"{report_dir}/summary.txt").write_text(summary)

    Path(f"{report_dir}/issues_detailed.json").write_text(
        json.dumps(detailed, indent=2)
    )


    print("✅ Summary written")
    print("✅ Detailed report written")
    print("🚀 AI calls used: 1 (batched)")


if __name__ == "__main__":
    main()
