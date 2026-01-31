FROM python:3.12-slim

WORKDIR /research

# Install exact vulnerable version of setuptools and pytest
RUN pip install --no-cache-dir setuptools==78.1.0 pytest

# Copy research files
COPY *.py ./
COPY *.md ./

# Run the scenario demonstrations by default
CMD ["python", "demo_scenarios.py"]
