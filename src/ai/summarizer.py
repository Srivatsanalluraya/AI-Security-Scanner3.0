
#!/usr/bin/env python3
"""
summarizer.py

Reads final_report.json created by report_builder.py,
summarizes it using a Hugging Face model, and writes summary.txt.

Default model: google/flan-t5-small
"""

import os
import json
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import argparse


def load_report(report_path: Path):
    if not report_path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # fallback: treat file as raw text
        return report_path.read_text(encoding="utf-8")


def generate_summary(model_name: str, content: str, max_length=300):
    print(f"📦 Loading model: {model_name} ...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    # Prepare the input prompt
    input_text = (
        "Summarize the following security scan report for developers. "
        "Highlight vulnerabilities, risks, severity, and recommended fixes.\n\n"
        + content
    )

    print("🔍 Tokenizing input...")
    inputs = tokenizer.encode(
        input_text,
        return_tensors="pt",
        truncation=True,
        max_length=1024
    )

    print("🤖 Generating summary...")
    summary_ids = model.generate(
        inputs,
        max_length=max_length,
        min_length=80,
        num_beams=4,
        length_penalty=2.0,
        early_stopping=True
    )

    return tokenizer.decode(summary_ids[0], skip_special_tokens=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="reports/final_report.json",
        help="Path to merged scan report"
    )
    parser.add_argument(
        "--output",
        default="reports/summary.txt",
        help="Where to write the summary"
    )
    parser.add_argument(
        "--model",
        default="google/flan-t5-small",
        help="Hugging Face model name"
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    print(f"📄 Reading report: {input_path}")
    report_data = load_report(input_path)

    # Convert report to text
    if isinstance(report_data, dict):
        report_text = json.dumps(report_data, indent=2)
    else:
        report_text = str(report_data)

    # Limit size to avoid GPU/CPU overload
    if len(report_text) > 20000:
        print("⚠️ Report too long — truncating for summary...")
        report_text = report_text[:20000]

    # Generate summary
    summary = generate_summary(args.model, report_text)

    # Write output
    print(f"📝 Writing summary to: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(summary, encoding="utf-8")

    print("✅ Summary generation completed!")


if __name__ == "__main__":
    main()
