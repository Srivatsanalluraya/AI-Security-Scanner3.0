#!/usr/bin/env python3
"""
summarizer.py

Reads final_report.json and generates a concise vulnerability summary
using a Hugging Face Seq2Seq model (FLAN-T5 recommended).
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


def prepare_prompt(report_text: str) -> str:
    return (
        "You are an AI that summarizes security scan results.\n"
        "Produce a clean, structured, concise summary with:\n"
        "- High severity issues\n"
        "- Medium severity issues\n"
        "- Low severity issues\n"
        "- Recommended fixes\n"
        "- Anything suspicious\n\n"
        "Here is the scan report:\n\n"
        f"{report_text}"
    )


def generate_summary(model_name: str, content: str):
    print(f"📦 Loading model: {model_name}")

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    prompt = prepare_prompt(content)

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=1024
    )

    print("🤖 Generating summary...")
    output_ids = model.generate(
        inputs["input_ids"],
        max_length=350,
        min_length=100,
        num_beams=4,
        early_stopping=True
    )

    return tokenizer.decode(output_ids[0], skip_special_tokens=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/final_report.json")
    parser.add_argument("--output", default="reports/summary.txt")
    parser.add_argument("--model", default="google/flan-t5-small")
    args = parser.parse_args()

    # Load merged report
    report_data = load_report(Path(args.input))
    report_text = json.dumps(report_data, indent=2) if isinstance(report_data, dict) else str(report_data)

    # Truncate large report
    if len(report_text) > 20000:
        report_text = report_text[:20000]

    # Generate summary
    summary = generate_summary(args.model, report_text)

    # Save output
    Path(args.output).write_text(summary, encoding="utf-8")
    print("✅ Summary written to", args.output)


if __name__ == "__main__":
    main()
