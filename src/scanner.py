import sys
import traceback
import argparse
import os
import json
import subprocess
import pathlib

from src.policy import decide_outcome
from src.reporters.pr_commenter import post_pr_summary
from src.reporters.report_builder import build_report
from src.output_formatter import OutputFormatter


# --- Global crash hook for visibility ---
sys.excepthook = lambda et, ev, tb: (
    print("⚠️ Python Exception:", ''.join(traceback.format_exception(et, ev, tb))),
    sys.exit(1)
)
print("✅ scanner.py loaded successfully")

# Initialize formatter
formatter = OutputFormatter(verbose=False)


# --- Utility to run shell commands (silent mode) ---
def run(cmd, cwd=None):
    """Run a subprocess command with suppressed output."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return result


# --- SEMGREP ---
def run_semgrep(workspace, outdir, include_pattern=None):
    """Run Semgrep on workspace and export SARIF report."""
    sarif_out = os.path.join(outdir, "sarif", "semgrep.sarif")
    pathlib.Path(os.path.join(outdir, "sarif")).mkdir(parents=True, exist_ok=True)

    cmd = [
        "semgrep",
        "--config", "p/python-security",
        "--exclude", "**/.git/**",
        "--exclude", "**/.github/**",
        "--sarif",
        "--output", sarif_out,
    ]

    # Restrict scope if pattern provided
    if include_pattern and include_pattern != ".":
        if not any(ch in include_pattern for ch in ["*", "?"]):
            include_glob = f"**/{include_pattern}"
        else:
            include_glob = include_pattern
        cmd += ["--include", include_glob]

    cmd.append(workspace)
    result = run(cmd)
    return sarif_out, result.returncode


# --- BANDIT ---
def run_bandit(workspace, outdir, include_pattern=None):
    """Run Bandit scan and export JSON report."""
    json_out = os.path.join(outdir, "bandit", "bandit.json")
    pathlib.Path(os.path.join(outdir, "bandit")).mkdir(parents=True, exist_ok=True)

    target = workspace if not include_pattern or include_pattern == "." else include_pattern
    cmd = ["bandit", "-r", target, "-f", "json", "-o", json_out]
    result = run(cmd)
    return json_out, result.returncode


# --- PIP-AUDIT ---
def run_pip_audit(workspace, outdir):
    """Run pip-audit to detect known dependency vulnerabilities."""
    json_out = os.path.join(outdir, "pip_audit.json")
    result = run(["pip-audit", "-r", f"{workspace}/requirements.txt", "-f", "json", "-o", json_out])
    return json_out, result.returncode


# --- Parse SARIF ---
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


# --- MAIN FUNCTION ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default=os.getenv("GITHUB_WORKSPACE", "/github/workspace"))
    parser.add_argument("--outdir", default="/app/out")
    parser.add_argument("--scan-path", default=".")
    args = parser.parse_args()

    workspace = args.workspace
    outdir = args.outdir
    scan_path = args.scan_path

    formatter.print_section_start("🔍 SECURITY SCANNING")
    print(f"Workspace: {workspace}")
    print(f"Target path: {scan_path}")
    print()

    # --- SEMGREP ---
    print("▶ Running Semgrep...")
    sarif_file, _ = run_semgrep(workspace, outdir, include_pattern=scan_path)
    severity = determine_severity(sarif_file)
    findings = extract_findings(sarif_file)
    formatter.print_scan_summary("Semgrep", len(findings), severity)

    # --- BANDIT ---
    print("▶ Running Bandit...")
    try:
        bandit_file, _ = run_bandit(workspace, outdir, include_pattern=scan_path)
        with open(bandit_file, "r", encoding="utf-8") as f:
            bandit_data = json.load(f)
            bandit_findings = []
            for issue in bandit_data.get("results", []):
                bandit_findings.append({
                    "level": issue.get("issue_severity", "LOW").lower(),
                    "message": issue.get("issue_text", ""),
                    "path": issue.get("filename", ""),
                    "line": issue.get("line_number", 0)
                })
            formatter.print_scan_summary("Bandit", len(bandit_findings))
            findings.extend(bandit_findings)
    except Exception as e:
        formatter.print_warning(f"Bandit scan failed: {e}")

    # --- DEPENDENCY AUDIT ---
    if os.path.exists(os.path.join(workspace, "requirements.txt")):
        print("▶ Running pip-audit...")
        try:
            pip_audit_file, _ = run_pip_audit(workspace, outdir)
            with open(pip_audit_file, "r", encoding="utf-8") as f:
                deps = json.load(f)
                dep_findings = []
                for pkg in deps:
                    for vuln in pkg.get("vulns", []):
                        dep_findings.append({
                            "level": "medium",
                            "message": f"{pkg['name']} {pkg['version']} - {vuln['id']}",
                            "path": "requirements.txt",
                            "line": 0
                        })
                formatter.print_scan_summary("pip-audit", len(dep_findings))
                findings.extend(dep_findings)
        except Exception as e:
            formatter.print_warning(f"Dependency scan failed: {e}")
    else:
        print("ℹ️  No requirements.txt — skipping dependency scan")

    # --- COMBINE & DETERMINE OVERALL SEVERITY ---
    combined_severity = "none"
    if any(f["level"] in ["error", "high"] for f in findings):
        combined_severity = "high"
    elif any(f["level"] in ["warning", "medium"] for f in findings):
        combined_severity = "medium"
    elif any(f["level"] in ["note", "low"] for f in findings):
        combined_severity = "low"

    write_outputs(outdir, combined_severity)

    # --- REPORT ---
    print("\n▶ Generating reports...")
    report = build_report(findings, outdir)
    formatter.print_success(f"Reports generated in {outdir}")

    # --- PR Summary ---
    post_pr_summary(combined_severity, len(findings))

    # --- Policy Decision ---
    outcome = decide_outcome(combined_severity, policy=os.getenv("INPUT_SEVERITY_POLICY", "default"))
    
    formatter.print_section_start("SCAN COMPLETE")
    print(f"Total issues found: {len(findings)}")
    print(f"Overall severity: {combined_severity.upper()}")
    print(f"Policy decision: {outcome.upper()}")
    print()

    # --- Exit Handling ---
    if outcome == "block":
        formatter.print_error("Build blocked due to high severity findings")
        sys.exit(1)

    formatter.print_success("Scan complete — no blocking issues")
    sys.exit(0)


if __name__ == "__main__":
    main()
