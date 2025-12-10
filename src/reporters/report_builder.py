#!/usr/bin/env python3
"""
report_builder.py

Merge scanner outputs (Bandit, Semgrep, pip-audit, Safety text, etc.)
into a single JSON file suitable for summarization or further processing.

Usage:
  python scripts/report_builder.py --reports-dir reports --out reports/final_report.json
"""
import argparse
import json
from pathlib import Path
from datetime import datetime

KNOWN_JSON_REPORTS = [
    "bandit-report.json",
    "semgrep-report.json",
    "pip-audit-report.json",
    "safety-report.json",
    "npm-audit-report.json",
    "retire-report.json",
    "static_report.json",   # alternate name used earlier
    "merged_scan.json",
]

def load_json_safe(p: Path):
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Warning: failed to parse JSON {p}: {e}")
        return None

def load_text_safe(p: Path):
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8")
    except Exception as e:
        print(f"Warning: failed to read text {p}: {e}")
        return None

def collect_reports(reports_dir: Path):
    collected = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "reports": {},
        "metrics": {}
    }

    # load known json reports
    for name in KNOWN_JSON_REPORTS:
        p = reports_dir / name
        data = load_json_safe(p)
        if data is not None:
            collected["reports"][name] = data
            # simple metric: lines of JSON text
            try:
                collected["metrics"][name] = {
                    "size_bytes": p.stat().st_size
                }
            except Exception:
                pass

    # detect other files in reports_dir
    for p in sorted(reports_dir.iterdir()):
        if p.name in collected["reports"]:
            continue
        if p.suffix.lower() in [".json", ".txt", ".md"]:
            if p.suffix.lower() == ".json":
                data = load_json_safe(p)
                if data is not None:
                    collected["reports"][p.name] = data
                else:
                    collected["reports"][p.name] = {"raw_text": load_text_safe(p)}
            else:
                collected["reports"][p.name] = {"raw_text": load_text_safe(p)}

    return collected

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", default="reports", help="Directory containing scanner reports")
    parser.add_argument("--out", default="reports/final_report.json", help="Output merged report JSON")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    out_path = Path(args.out)
    if not reports_dir.exists():
        print(f"Reports directory not found: {reports_dir}")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({"error": "reports dir missing"}, indent=2))
        return 1

    merged = collect_reports(reports_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(f"Wrote merged report to {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
