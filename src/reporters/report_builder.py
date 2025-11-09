import os
import datetime
import json

def build_report(findings, outdir="out"):
    ts = datetime.datetime.utcnow().isoformat()
    report_md = os.path.join(outdir, "report", "report.md")
    os.makedirs(os.path.dirname(report_md), exist_ok=True)

    with open(report_md, "w", encoding="utf-8") as f:
        f.write(f"# Vulnerability Report\n\nGenerated: {ts}\n\n")
        f.write(f"## Findings ({len(findings)})\n")
        for fnd in findings:
            f.write(f"- `{fnd['level'].upper()}` — `{fnd['path']}:{fnd['line']}` — {fnd['message']}\n")

    return report_md

