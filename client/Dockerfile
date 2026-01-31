FROM python:3.12-slim

WORKDIR /app

# Install vulnerable setuptools version and openssh-server for SSH validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

RUN pip install --no-cache-dir setuptools==78.1.0

COPY victim_client.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]
