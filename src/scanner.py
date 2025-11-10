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


# --- Global crash hook for visibility ---
sys.excepthook = lambda et, ev, tb: (
    print("⚠️ Python Exception:", ''.join(traceback.format_exception(et, ev, tb))),
    sys.exit(1)
)
print("✅ scanner.py loaded successfully")


# --- Utility to run shell commands ---
def run(cmd, cwd=None):
    """Run a subprocess command and return CompletedProcess."""
    print(f"[run] {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
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

    print(f"🔍 Scanning workspace: {workspace}")
    print(f"🎯 Target path (include pattern): {scan_path}")

    # Diagnostic listing
    print("📂 Files present in workspace:")
    for root, dirs, files in os.walk(workspace):
        for file in files:
            print(os.path.join(root, file))

    # --- SEMGREP ---
    print("\n🚀 Running Semgrep scan...")
    sarif_file, _ = run_semgrep(workspace, outdir, include_pattern=scan_path)
    severity = determine_severity(sarif_file)
    findings = extract_findings(sarif_file)
    print(f"✅ Semgrep findings: {len(findings)} | Highest severity: {severity.upper()}")

    # --- BANDIT ---
    print("\n🔎 Running Bandit scan (Python security analyzer)...")
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
            print(f"✅ Bandit findings: {len(bandit_findings)}")
            findings.extend(bandit_findings)
    except Exception as e:
        print(f"⚠️ Bandit scan failed or no findings: {e}")

    # --- DEPENDENCY AUDIT ---
    if os.path.exists(os.path.join(workspace, "requirements.txt")):
        print("\n📦 Running dependency audit (pip-audit)...")
        try:
            pip_audit_file, _ = run_pip_audit(workspace, outdir)
            with open(pip_audit_file, "r", encoding="utf-8") as f:
                deps = json.load(f)
                dep_findings = []
                for pkg in deps:
                    for vuln in pkg.get("vulns", []):
                        dep_findings.append({
                            "level": "medium",
                            "message": f"Package {pkg['name']} {pkg['version']} - {vuln['id']} ({vuln['fix_versions']})",
                            "path": "requirements.txt",
                            "line": 0
                        })
                print(f"✅ Dependency vulnerabilities: {len(dep_findings)}")
                findings.extend(dep_findings)
        except Exception as e:
            print(f"⚠️ Dependency scan failed or skipped: {e}")
    else:
        print("📦 No requirements.txt found — skipping dependency scan.")

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
    print("\n🧾 Generating final report...")
    report = build_report(findings, outdir)
    print(f"📄 Report generated at: {report}")

    # --- PR Summary ---
    post_pr_summary(combined_severity, len(findings))

    # --- Policy Decision ---
    outcome = decide_outcome(combined_severity, policy=os.getenv("INPUT_SEVERITY_POLICY", "default"))
    print(f"\n⚖️ Policy outcome: {outcome.upper()}")

    # --- Exit Handling ---
    if outcome == "block":
        print("❌ Build blocked due to high severity findings.")
        sys.exit(1)

    print("✅ Scan complete — no blocking issues.")
    sys.exit(0)


if __name__ == "__main__":
    main()
