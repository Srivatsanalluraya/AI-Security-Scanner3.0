#!/usr/bin/env python3
"""
pr_commenter.py

Post a text summary as a GitHub Pull Request comment.

Usage:
  python scripts/pr_commenter.py --summary reports/summary.txt --repo owner/repo --pr 123 --token $GITHUB_TOKEN

If run in GitHub Actions, you can omit --repo and --pr if the workflow provides the environment variables:
  GITHUB_REPOSITORY (owner/repo) and GITHUB_REF or PR number via github.event.pull_request.number.

The script prefers explicit arguments, then environment variables.
"""
import argparse
import json
import os
import requests
from pathlib import Path

GITHUB_API = "https://api.github.com"

def load_text(p: Path):
    if not p.exists():
        raise FileNotFoundError(f"Summary file not found: {p}")
    return p.read_text(encoding="utf-8")

def post_pr_comment(token, repo, pr_number, body_text):
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }
    payload = {"body": body_text}
    resp = requests.post(url, headers=headers, json=payload)
    if resp.status_code not in (200, 201):
        print("Failed to post PR comment:", resp.status_code, resp.text)
        resp.raise_for_status()
    return resp.json()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", default="reports/summary.txt", help="Path to summary text to post")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY"), help="owner/repo")
    parser.add_argument("--pr", type=int, default=None, help="Pull Request number")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token with repo:status or repo scope")
    args = parser.parse_args()

    if not args.token:
        raise SystemExit("Error: GitHub token not provided (set GITHUB_TOKEN or use --token).")

    summary_path = Path(args.summary)
    try:
        text = load_text(summary_path)
    except FileNotFoundError as e:
        print(e)
        raise SystemExit(2)

    repo = args.repo
    if not repo:
        raise SystemExit("Error: repository not provided (use --repo or set GITHUB_REPOSITORY).")

    pr_number = args.pr
    # attempt to discover PR number from environment (GitHub Actions)
    if pr_number is None:
        # GitHub Actions exposes GITHUB_EVENT_PATH with event payload
        event_path = os.getenv("GITHUB_EVENT_PATH")
        if event_path and Path(event_path).exists():
            try:
                event = json.loads(Path(event_path).read_text(encoding="utf-8"))
                pr_number = event.get("pull_request", {}).get("number")
            except Exception:
                pass
    if pr_number is None:
        raise SystemExit("Error: PR number not provided (use --pr) and couldn't find it in environment.")

    print(f"Posting summary to {repo} PR #{pr_number} ...")
    resp = post_pr_comment(args.token, repo, pr_number, text)
    print("Posted comment id:", resp.get("id"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
