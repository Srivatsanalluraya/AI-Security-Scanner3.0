FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev jq wget \
    openjdk-17-jre-headless \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Node LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y nodejs

# JS tools
RUN npm install -g eslint retire @microsoft/eslint-formatter-sarif || true

# Security tools
RUN pip install --no-cache-dir \
    semgrep \
    bandit==1.7.9 \
    pip-audit==2.7.3 \
    safety \
    requests \
    pytest

# Copy files
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
