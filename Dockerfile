FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"
ARG CACHE_BUST=1

# Install system dependencies + Node.js
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev jq wget \
    nodejs npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install JavaScript security tools
RUN npm install -g eslint retire @microsoft/eslint-formatter-sarif 2>/dev/null || true

# Install Python security tools (including semgrep which supports multiple languages)
RUN pip install --no-cache-dir \
    semgrep==1.80.0 \
    bandit==1.7.9 \
    pip-audit==2.7.3 \
    safety \
    requests \
    && pip install --no-cache-dir --upgrade groq pytest

# Copy source files
ARG CACHE_BUST
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
