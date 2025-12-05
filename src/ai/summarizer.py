#!/usr/bin/env python3
"""
summarizer.py

Produces a structured, accurate summary from final_report.json
using FLAN-T5, WITHOUT hallucinations or generic filler text.
"""

import os
import json
from pathlib import Path
import argparse
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM


def load_report(path: Path):
    """Load JSON report or raw text."""
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")

    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return path.read_text()


def build_strict_prompt(report_text: str) -> str:
    """
    Creates a strict, structured summarization instruction.
    FLAN-T5 will follow this EXACT format.
    """

    return f"""
You are an AI security assistant. Summarize ONLY using the information inside the report below.
Do NOT invent text, URLs, tools, references, or vulnerabilities.

Your summary MUST follow this EXACT format:

======================
🔐 SECURITY SUMMARY
======================

### HIGH Severity Issues
- File: <file> | Line: <line>  
  Issue: <issue text>  
  Risk: <risk explanation>  
  Fix: <short recommended fix>

### MEDIUM Severity Issues
- File: <file> | Line: <line>  
  Issue: <issue text>  
  Risk: <risk explanation>  
  Fix: <short recommended fix>

### LOW Severity Issues
- File: <file> | Line: <line>  
  Issue: <issue text>  
  Risk: <risk explanation>  
  Fix: <short recommended fix>

### ❗ Dependency Vulnerabilities (pip-audit)
- Package: <name> <version>  
  Vulnerability: <ID>  
  Fix: <upgrade version>

### Final Notes
- Summarize pattern trends (only what is present in the report).
- No hallucinations. No assumptions.

======================
SCAN REPORT BEGINS BELOW
======================

{report_text}
"""


def generate_summary(model_name: str, report_text: str):
    print(f"📦 Loading model: {model_name}")

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    prompt = build_strict_prompt(report_text)

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=1024
    )

    print("🤖 Generating strict structured summary...")
    output_ids = model.generate(
        inputs["input_ids"],
        max_length=512,
        min_length=150,
        num_beams=5,
        early_stopping=True
    )

    return tokenizer.decode(output_ids[0], skip_special_tokens=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/final_report.json")
    parser.add_argument("--output", default="reports/summary.txt")
    parser.add_argument("--model", default="google/flan-t5-small")
    args = parser.parse_args()

    report_data = load_report(Path(args.input))

    # Convert to readable text
    report_text = json.dumps(report_data, indent=2) if isinstance(report_data, dict) else str(report_data)

    # Trim very large reports
    if len(report_text) > 20000:
        report_text = report_text[:20000]

    summary = generate_summary(args.model, report_text)

    Path(args.output).write_text(summary, encoding="utf-8")
    print("✅ Summary written to", args.output)


if __name__ == "__main__":
    main()
