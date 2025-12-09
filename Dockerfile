FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"
ARG CACHE_BUST=1

# Install system dependencies (including Node.js, Java, Go)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential libyaml-dev jq \
    wget gnupg software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20.x
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest

# Install Go 1.21
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Java (OpenJDK 17)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install --no-cache-dir \
    semgrep==1.80.0 \
    bandit==1.7.9 \
    pip-audit==2.7.3 \
    transformers==4.37.2 \
    torch \
    requests \
    sentencepiece \
    safetensors \
    accelerate

# Install Go security tools
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest \
    && go install github.com/sonatype-nexus-community/nancy@latest

# Install Trivy (universal scanner)
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy source files
ARG CACHE_BUST
COPY src/ /app/src/
COPY rules/ /app/rules/
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
