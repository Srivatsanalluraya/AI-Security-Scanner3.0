#!/usr/bin/env python3
"""
Structured AI summarizer for Bandit, Semgrep, pip-audit results.
- Extracts each issue
- Summarizes issue, consequence, fix separately
- Produces consistent PR-ready output
"""

import json
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM


MODEL_NAME = "google/flan-t5-small"


def load_json(path):
    if not Path(path).exists():
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except:
        return None


def short_ai_summary(text, tokenizer, model, max_len=120):
    """Use FLAN-T5 to summarize *small chunks only*."""
    prompt = (
        "Summarize the following security issue in 2–3 sentences. "
        "Explain the risk and a safe fix.\n\n" + text
    )

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=512
    )

    outputs = model.generate(
        inputs["input_ids"],
        max_length=max_len,
        num_beams=4,
        early_stopping=True
    )

    return tokenizer.decode(outputs[0], skip_special_tokens=True)


def extract_all_issues(report_dir):
    issues = []

    # -----------------------
    # BANDIT extraction
    # -----------------------
    bandit = load_json(f"{report_dir}/bandit-report.json")
    if bandit and "results" in bandit:
        for r in bandit["results"]:
            issues.append({
                "source": "Bandit",
                "file": r.get("filename"),
                "line": r.get("line_number"),
                "issue": r.get("issue_text"),
                "severity": r.get("issue_severity", "UNKNOWN"),
                "confidence": r.get("issue_confidence", "UNKNOWN")
            })

    # -----------------------
    # SEMGREP extraction
    # -----------------------
    semgrep = load_json(f"{report_dir}/semgrep-report.json")
    if semgrep and "results" in semgrep:
        for r in semgrep["results"]:
            issues.append({
                "source": "Semgrep",
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "issue": r["extra"]["message"],
                "severity": r["extra"].get("severity", "UNKNOWN"),
            })

    # -----------------------
    # PIP-AUDIT extraction
    # -----------------------
    pip_audit = load_json(f"{report_dir}/pip-audit-report.json")
    if pip_audit and "dependencies" in pip_audit:
        for dep in pip_audit["dependencies"]:
            for vuln in dep.get("vulns", []):
                issues.append({
                    "source": "pip-audit",
                    "package": dep["name"],
                    "version": dep["version"],
                    "issue": vuln.get("id") or vuln.get("aliases"),
                    "fix": vuln.get("fix_versions")
                })

    return issues


def generate_final_summary(issues, pushed_by):
    """Format issues into the exact PR comment format you want."""

    lines = []
    lines.append(f"Pushed by: {pushed_by}")
    lines.append(f"Issues Found: {len(issues)}")
    lines.append("")

    for idx, issue in enumerate(issues, start=1):
        lines.append(f"Issue {idx}:")
        lines.append(f"  • Source: {issue.get('source')}")
        lines.append(f"  • File: {issue.get('file')}")
        lines.append(f"  • Line: {issue.get('line')}")
        lines.append(f"  • Description: {issue['ai_summary']}")
        lines.append("")

    return "\n".join(lines)


def main():
    report_dir = "reports"

    issues = extract_all_issues(report_dir)
    if not issues:
        Path(f"{report_dir}/summary.txt").write_text("No issues detected.")
        return

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME)

    # run short summarization for each issue
    for issue in issues:
        raw_text = f"{issue}"
        issue["ai_summary"] = short_ai_summary(raw_text, tokenizer, model)

    pushed_by = ""  # pr_commenter will fill this later
    final_text = generate_final_summary(issues, pushed_by)

    Path(f"{report_dir}/summary.txt").write_text(final_text, encoding="utf-8")
    print("Summary written to reports/summary.txt")


if __name__ == "__main__":
    main()
