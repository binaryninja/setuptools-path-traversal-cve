FROM python:3.12-slim

WORKDIR /app

# Install vulnerable setuptools version
RUN pip install --no-cache-dir setuptools==78.1.0

COPY victim_client.py .

CMD ["python", "victim_client.py"]
