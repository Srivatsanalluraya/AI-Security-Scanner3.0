#!/usr/bin/env python3
"""
sarif_writer.py

Convert merged report produced by report_builder.py into a minimal SARIF file.

Usage:
  python scripts/sarif_writer.py --input reports/final_report.json --out reports/report.sarif
"""
import argparse
import json
from pathlib import Path

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur

def build_tool(driver_name):
    return {
        "driver": {
            "name": driver_name,
            "informationUri": "https://github.com",
            "rules": []
        }
    }

def bandit_to_sarif_entries(bandit_json):
    results = []
    rules = {}
    for r in bandit_json.get("results", []):
        filename = safe_get(r, "location", "filename") or r.get("filename", "unknown")
        lineno = safe_get(r, "location", "line_number") or r.get("line_number")
        rule_id = r.get("test_id") or r.get("test_name") or r.get("issue_confidence", "BND")
        message = r.get("issue_text") or r.get("test_name") or "Bandit finding"
        severity = r.get("issue_severity", "UNSPECIFIED")
        key = rule_id

        # add rule once
        if key not in rules:
            rules[key] = {
                "id": key,
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": message}
            }

        res = {
            "ruleId": key,
            "level": "error" if severity.lower() in ("high", "error") else "warning",
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": filename},
                        "region": {"startLine": int(lineno) if lineno else 1}
                    }
                }
            ]
        }
        results.append(res)
    return rules, results

def semgrep_to_sarif_entries(semgrep_json):
    results = []
    rules = {}
    for r in semgrep_json.get("results", []):
        check_id = r.get("check_id") or r.get("rule_id") or r.get("id") or "semgrep"
        # semgrep path usually under r["path"] or r["extra"]["lines"]
        path = r.get("path") or safe_get(r, "extra", "metadata", "filename") or safe_get(r, "extra", "filename") or r.get("metdata", {}).get("filename")
        message = r.get("message") or safe_get(r, "extra", "message") or "Semgrep finding"
        start = safe_get(r, "start", "line") or safe_get(r, "path", "start") or safe_get(r, "extra", "start", "line") or 1

        if isinstance(path, dict):
            path = path.get("name") or path.get("filename") or "unknown"

        key = check_id
        if key not in rules:
            rules[key] = {
                "id": key,
                "shortDescription": {"text": key},
                "fullDescription": {"text": message}
            }
        res = {
            "ruleId": key,
            "level": "warning",
            "message": {"text": message},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": path or "unknown"}, "region": {"startLine": int(start) if start else 1}}}
            ]
        }
        results.append(res)
    return rules, results

def pip_audit_to_sarif_entries(pip_audit_json):
    results = []
    rules = {}
    deps = pip_audit_json.get("dependencies", []) if isinstance(pip_audit_json, dict) else []
    for dep in deps:
        name = dep.get("name") or "unknown"
        ver = dep.get("version") or ""
        vulns = dep.get("vulns") or []
        for v in vulns:
            vid = v.get("id") or (v.get("aliases") and ", ".join(v.get("aliases"))) or "pip-audit"
            desc = v.get("description") or v.get("details") or vid
            key = f"{name}:{vid}"
            rules[key] = {
                "id": key,
                "shortDescription": {"text": f"{name} {ver}"},
                "fullDescription": {"text": desc}
            }
            res = {
                "ruleId": key,
                "level": "error",
                "message": {"text": f"{name} {ver} - {vid}"},
                "properties": {"package": name, "version": ver}
            }
            results.append(res)
    return rules, results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/final_report.json", help="Merged report JSON")
    parser.add_argument("--out", default="reports/report.sarif", help="Output SARIF path")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.out)
    if not in_path.exists():
        print(f"Input merged report not found: {in_path}")
        return 2

    merged = json.loads(in_path.read_text(encoding="utf-8"))
    reports = merged.get("reports", {})

    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": []
    }

    tool_rules = {}
    all_results = []

    # Bandit
    if "bandit-report.json" in reports:
        rules, results = bandit_to_sarif_entries(reports["bandit-report.json"])
        tool_rules.update(rules)
        all_results.extend(results)

    # semgrep
    if "semgrep-report.json" in reports:
        rules, results = semgrep_to_sarif_entries(reports["semgrep-report.json"])
        tool_rules.update(rules)
        all_results.extend(results)

    # pip-audit
    if "pip-audit-report.json" in reports:
        rules, results = pip_audit_to_sarif_entries(reports["pip-audit-report.json"])
        tool_rules.update(rules)
        all_results.extend(results)

    # Build a single run with aggregated tool info
    run = {
        "tool": {
            "driver": {
                "name": "AI-Powered Security Scanner",
                "informationUri": "https://github.com",
                "rules": list(tool_rules.values())
            }
        },
        "results": all_results
    }
    sarif["runs"].append(run)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"Wrote SARIF to {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

