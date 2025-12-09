#!/usr/bin/env python3
"""
Better Security Summarizer
Outputs REAL issues + real fixes, not generic statements.
"""

import os
import json
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import argparse


def load_report(path: Path):
    """Load JSON report or fallback to raw text."""
    if not path.exists():
        raise FileNotFoundError(f"Missing report: {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return path.read_text()


def build_strict_prompt(report_text: str) -> str:
    """
    Creates a STRICT template forcing the model to produce:
    - Issue description
    - Severity
    - Why it is dangerous
    - EXACT recommended fix
    """

    return f"""
You are a senior application security engineer.
Analyze the following Bandit + Semgrep + pip-audit report and produce a *developer-ready* summary.

STRICT OUTPUT FORMAT (do NOT deviate):

### 🔥 Critical / High Issues
For each issue:
- **Issue:** <short description of vulnerability>
- **File:** <filename + line number>
- **Severity:** <LOW/MEDIUM/HIGH/CRITICAL>
- **Why it matters:** <1–2 sentences explaining the risk>
- **Recommended Fix:** <EXACT fix or safe alternative>

### 🟡 Medium Issues
(Same format)

### 🟢 Low Issues
(Same format)

### 📦 Dependency Vulnerabilities (pip-audit)
- <package> <version>: <vulnerability + fix>

DO NOT add disclaimers.
DO NOT say “this is AI-generated.”
DO NOT invent references.
Only summarize what is IN the report.

--- BEGIN REPORT ---
{report_text}
--- END REPORT ---
"""


def generate_summary(model_name: str, report_text: str, max_len=400):
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    prompt = build_strict_prompt(report_text)

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=1024
    )

    summary_ids = model.generate(
        inputs["input_ids"],
        max_length=max_len,
        min_length=120,
        num_beams=4,
        early_stopping=True
    )

    return tokenizer.decode(summary_ids[0], skip_special_tokens=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/final_report.json")
    parser.add_argument("--output", default="reports/summary.txt")
    parser.add_argument("--model", default="google/flan-t5-large")
    args = parser.parse_args()

    report_data = load_report(Path(args.input))

    if isinstance(report_data, dict):
        report_text = json.dumps(report_data, indent=2)
    else:
        report_text = str(report_data)

    if len(report_text) > 20000:
        report_text = report_text[:20000]

    summary = generate_summary(args.model, report_text)

    Path(args.output).write_text(summary)
    print("\n===== AI SUMMARY =====\n")
    print(summary)


if __name__ == "__main__":
    main()
