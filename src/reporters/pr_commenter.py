#!/usr/bin/env python3

import argparse
import requests
import os

def post_comment(repo, pr_number, token, body):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    response = requests.post(url, headers=headers, json={"body": body})

    if response.status_code >= 300:
        raise Exception(f"GitHub API error: {response.status_code} {response.text}")

    print("✅ PR comment posted successfully!")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True)
    parser.add_argument("--token", required=False)

    args = parser.parse_args()

    token = args.token or os.getenv("GITHUB_TOKEN")

    if not token:
        raise ValueError("GitHub token not provided (set GITHUB_TOKEN or use --token).")

    with open(args.summary, "r") as f:
        summary_text = f.read().strip()

    comment_body = (
        "## 🔒 AI Security Scan Summary\n"
        "Here is the automated vulnerability summary:\n\n"
        f"{summary_text}"
    )

    post_comment(args.repo, args.pr, token, comment_body)


if __name__ == "__main__":
    main()
