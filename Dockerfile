FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy all source files into /app/
COPY src/ ./src/
COPY rules/ ./rules/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && pip install --no-cache-dir semgrep==1.80.0

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
