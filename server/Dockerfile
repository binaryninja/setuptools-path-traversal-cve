FROM python:3.12-slim

WORKDIR /app

# Install openssh-client for SSH validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY malicious_server.py .

EXPOSE 8080

CMD ["python", "malicious_server.py"]
