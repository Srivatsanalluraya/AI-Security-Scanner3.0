#!/usr/bin/env python3
"""
summarizer.py (FIXED)

Uses a stronger Hugging Face summarization model instead of flan-t5-small.
Adds chunking to prevent empty/garbage summaries.
"""

import os
import json
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch
import argparse


# Strong, stable summarization model that works well in GitHub Actions
DEFAULT_MODEL = "sshleifer/distilbart-cnn-12-6"


def load_report(report_path: Path):
    """Loads JSON or raw text report"""
    if not report_path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")

    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return report_path.read_text(encoding="utf-8")


def chunk_text(text, chunk_size=3000):
    """Splits large reports into smaller chunks for better summarization"""
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def generate_chunk_summary(model, tokenizer, chunk):
    """Summarizes a single chunk"""
    prompt = (
        "Summarize the following section of a security scan report. "
        "Highlight vulnerabilities and recommended fixes:\n\n" + chunk
    )

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=1024,
    )

    summary_ids = model.generate(
        inputs["input_ids"],
        max_length=250,
        min_length=60,
        num_beams=4,
        early_stopping=True,
    )

    return tokenizer.decode(summary_ids[0], skip_special_tokens=True)


def summarize_text(full_text, model_name):
    """Main summarization routine"""
    print(f"📦 Loading model: {model_name} ...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    chunks = chunk_text(full_text)
    print(f"🧩 Splitting report into {len(chunks)} chunks...")

    summaries = []
    for i, chunk in enumerate(chunks, start=1):
        print(f"🤖 Summarizing chunk {i}/{len(chunks)}...")
        summaries.append(generate_chunk_summary(model, tokenizer, chunk))

    # Final combined summary
    final_prompt = (
        "Combine the following partial summaries into one clean, concise "
        "security report for developers:\n\n" + "\n\n".join(summaries)
    )

    print("📦 Finalizing global summary...")
    inputs = tokenizer(final_prompt, return_tensors="pt", truncation=True, max_length=1024)

    final_ids = model.generate(
        inputs["input_ids"],
        max_length=300,
        min_length=100,
        num_beams=4,
        early_stopping=True,
    )

    return tokenizer.decode(final_ids[0], skip_special_tokens=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/final_report.json")
    parser.add_argument("--output", default="reports/summary.txt")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    print(f"📄 Reading report: {input_path}")
    report_data = load_report(input_path)

    report_text = json.dumps(report_data, indent=2) if isinstance(report_data, dict) else str(report_data)

    # Limit extreme sizes
    report_text = report_text[:50000]

    summary = summarize_text(report_text, args.model)

    print(f"📝 Writing summary to: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(summary, encoding="utf-8")

    print("✅ Summary generation completed!")


if __name__ == "__main__":
    main()
