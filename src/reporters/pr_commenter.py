import os
import requests

def post_pr_summary(severity: str, findings_count: int):
    repo = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("GITHUB_REF", "").split("/")[-1]
    token = os.getenv("GITHUB_TOKEN", "")

    if "pull" not in os.getenv("GITHUB_REF", ""):
        print("Not a pull request, skipping PR comment.")
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {"Authorization": f"token {token}"}

    body = f"""
### 🔍 AI Vulnerability Scanner Report

- **Overall severity:** {severity.upper()}
- **Total findings:** {findings_count}

_See detailed scan report in workflow artifacts._
"""
    response = requests.post(url, headers=headers, json={"body": body})
    print(f"Posted PR summary: {response.status_code}")

