FROM python:3.12-slim
WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && adduser --disabled-password --gecos "" runner && chown -R runner:runner /app
USER runner
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
