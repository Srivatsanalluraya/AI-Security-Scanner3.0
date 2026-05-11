# Stable base (important — prevents Debian package breakage)
FROM python:3.11-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

# ------------------------------------------------
# Install system dependencies
# ------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    build-essential \
    libyaml-dev \
    jq \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*


# ------------------------------------------------
# Install NodeJS LTS (modern npm required)
# ------------------------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get update \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*


# ------------------------------------------------
# Install JavaScript security tools
# ------------------------------------------------
RUN npm install -g \
    eslint \
    retire \
    @microsoft/eslint-formatter-sarif \
    || true


# ------------------------------------------------
# Install Python security tools
# ------------------------------------------------
RUN pip install --no-cache-dir \
    "semgrep<1.80" \
    bandit==1.7.9 \
    pip-audit==2.7.3 \
    safety \
    requests \
    pytest

#-------------------------------------------------
# Install GitLeaks
#------------------------------------------------
RUN wget -qO /tmp/gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

# ------------------------------------------------
# Copy source files
# ------------------------------------------------
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY entrypoint.sh /app/entrypoint.sh


# ------------------------------------------------
# Make entrypoint executable
# ------------------------------------------------
RUN chmod +x /app/entrypoint.sh


# ------------------------------------------------
# Entrypoint
# ------------------------------------------------
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
