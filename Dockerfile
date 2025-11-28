FROM python:3.12-slim

# -----------------------------------------
# 1. System Setup
# -----------------------------------------
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

# Install system-level dependencies needed by Semgrep + Transformers
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev jq\
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------
# 2. Install Required Python Tools
# -----------------------------------------
RUN pip install --no-cache-dir \
    semgrep==1.80.0 \
    bandit==1.7.9 \
    pip-audit==2.7.3 \
    transformers \
    torch \
    requests

# -----------------------------------------
# 3. Copy Source Code
# -----------------------------------------
# These are from YOUR repo
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# -----------------------------------------
# 4. Entrypoint
# -----------------------------------------
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
