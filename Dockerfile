FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Make sure /app is discoverable by Python
ENV PYTHONPATH="/app"

# Install essential system dependencies for Semgrep
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep and any other Python dependencies
RUN pip install --no-cache-dir semgrep==1.80.0

# Copy action files
COPY src/ ./src/
COPY rules/ ./rules/
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
