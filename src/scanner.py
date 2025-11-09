from src.policy import decide_outcome
from src.reporters.pr_commenter import post_pr_summary
from src.reporters.report_builder import build_report

import argparse
import os
import json
import subprocess
import sys
import pathlib


def run(cmd, cwd=None):
    """Run a subprocess command and return stdout/stderr/exitcode."""
    print(f"[run] {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result


def run_semgrep(workspace, outdir):
    """Run Semgrep on workspace and export SARIF report."""
    sarif_out = os.path.join(outdir, "sarif", "semgrep.sarif")
    pathlib.Path(os.path.join(outdir, "sarif")).mkdir(parents=True, exist_ok=True)

    # Use Python-specific Semgrep ruleset:
    cmd = [
        "semgrep", "--config", "p/python-security", "--sarif", "--output", sarif_out, workspace
    ]

    result = run(cmd)
    return sarif_out, result.returncode


def determine_severity(sarif_file):
    """Parse SARIF and return highest severity."""
    if not os.path.exists(sarif_file):
        return "none"

    with open(sarif_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    severity_rank = {"error": 3, "warning": 2, "note": 1}
    max_severity = 0

    for run in data.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "note")
            max_severity = max(max_severity, severity_rank.get(level, 0))

    return {0: "none", 1: "low", 2: "medium", 3: "high"}[max_severity]


def extract_findings(sarif_file):
    """Parse SARIF for simple findings list."""
    if not os.path.exists(sarif_file):
        return []

    with open(sarif_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            loc = result.get("locations", [{}])[0]
            findings.append({
                "level": result.get("level", "note"),
                "message": result.get("message", {}).get("text", ""),
                "path": loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                "line": loc.get("physicalLocation", {}).get("region", {}).get("startLine", 1)
            })
    return findings


def write_outputs(outdir, severity):
    """Write severity summary to outputs."""
    pathlib.Path(outdir).mkdir(exist_ok=True)
    with open(os.path.join(outdir, "severity.txt"), "w") as f:
        f.write(severity)
    print(f"Overall severity: {severity}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default=os.getenv("GITHUB_WORKSPACE", "/github/workspace"))
    parser.add_argument("--outdir", default="/app/out")
    args = parser.parse_args()

    print(f"Scanning workspace: {args.workspace}")

    # Diagnostic: See which files are being scanned
    print("Files being scanned:")
    for root, dirs, files in os.walk(args.workspace):
        for file in files:
            print(os.path.join(root, file))

    # Run semgrep scan
    sarif_file, _ = run_semgrep(args.workspace, args.outdir)

    # Process results
    severity = determine_severity(sarif_file)
    write_outputs(args.outdir, severity)
    findings = extract_findings(sarif_file)

    # Create human-friendly report
    report = build_report(findings, args.outdir)

    # Post PR summary (if applicable)
    post_pr_summary(severity, len(findings))

    # Apply policy
    outcome = decide_outcome(severity, policy=os.getenv("INPUT_SEVERITY_POLICY", "default"))
    print(f"Outcome: {outcome}")

    # Exit codes
    if outcome == "block":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
