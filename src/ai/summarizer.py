#!/usr/bin/env python3
"""
summarizer.py

Reads final_report.json (merged report),
summarizes it using a Hugging Face model (Mistral-7B),
and writes summary.txt.

This version:
- Uses a structured, anti-hallucination prompt
- Produces stable, clean, severity-grouped summaries
- Only prints the summary AFTER model execution
"""

import os
import json
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import argparse


# -----------------------------
# Load and Validate Report
# -----------------------------
def load_report(report_path: Path):
    if not report_path.exists():
        raise FileNotFoundError(f"❌ Report not found: {report_path}")

    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return report_path.read_text(encoding="utf-8")


# -----------------------------
# Build Anti-Hallucination Prompt
# -----------------------------
def build_prompt(report_text: str):
    return f"""
You are an AI Security Assistant.

Your job is to summarize the following merged vulnerability scan report
STRICTLY using the data provided.

⚠️ IMPORTANT ANTI-HALLUCINATION RULES:
- Do NOT invent websites, people, editions, or tools.
- Use ONLY information found inside the report.
- Do NOT guess details.
- Keep the summary clear, concise, and technical.

📌 STRUCTURE YOUR SUMMARY EXACTLY LIKE THIS:
1. HIGH severity issues (filename, line number, description)
2. MEDIUM severity issues
3. LOW severity issues
4. Dependency vulnerabilities (from pip-audit)
5. Semgrep findings (summarized)
6. Recommended fixes (short bullet points)
7. Final overall risk rating (High / Medium / Low)

Here is the scan report (JSON):
--------------------------------
{report_text}
--------------------------------

Generate the structured summary now:
    """


# -----------------------------
# Generate Summary (Mistral-7B)
# -----------------------------
def generate_summary(model_name: str, content: str, max_new_tokens=600):
    print(f"📦 Loading summarization model: {model_name} ...")

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float32,
        device_map="auto"
    )

    prompt = build_prompt(content)

    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=4096)

    print("🤖 Running summarizer model...")
    output = model.generate(
        inputs["input_ids"],
        max_new_tokens=max_new_tokens,
        temperature=0.2,
        top_p=0.95,
        repetition_penalty=1.1
    )

    summary = tokenizer.decode(output[0], skip_special_tokens=True)

    # Return ONLY the generated portion after the prompt
    return summary[len(prompt):].strip()


# -----------------------------
# Main Function
# -----------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/final_report.json")
    parser.add_argument("--output", default="reports/summary.txt")
    parser.add_argument("--model", default="mistralai/Mistral-7B-Instruct-v0.3")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    print(f"📄 Reading merged report: {input_path}")
    report_data = load_report(input_path)

    # Convert report to text
    if isinstance(report_data, dict):
        report_text = json.dumps(report_data, indent=2)
    else:
        report_text = str(report_data)

    # Truncate if extremely large
    if len(report_text) > 40000:
        print("⚠️ Report too large — truncating safely...")
        report_text = report_text[:40000]

    # Summarize
    summary = generate_summary(args.model, report_text)

    # Save output
    print(f"📝 Writing final AI summary to: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(summary, encoding="utf-8")

    print("✅ AI Summary Completed Successfully!")
    print("➡ Summary will now print in the console at the END of scanning.\n")


if __name__ == "__main__":
    main()
