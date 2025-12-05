FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    semgrep==1.80.0 \
    bandit==1.7.9 \
    pip-audit==2.7.3 \
    transformers \
    torch \
    requests \
    sentencepeice \
    

# Copy repo files
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
