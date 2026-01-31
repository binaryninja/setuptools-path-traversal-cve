FROM python:3.12-slim

WORKDIR /research

# Install exact vulnerable version of setuptools
RUN pip install setuptools==78.1.0 pytest

# Copy research files
COPY . .

# Run the proof of concept
CMD ["python", "poc_direct_download.py"]
