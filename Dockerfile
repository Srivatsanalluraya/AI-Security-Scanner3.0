FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN pip install --no-cache-dir \
    semgrep==1.80.0 \
    bandit==1.7.9 \
    pip-audit==2.7.3

# Install AI summarization tools + utilities
RUN pip install --no-cache-dir \
    transformers \
    torch \
    requests

# Copy your scripts
COPY scripts/ ./scripts/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
