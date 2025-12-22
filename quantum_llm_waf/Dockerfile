# Dockerfile for Quantum LLM WAF Secure Chatbot
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY requirements-web.txt .
COPY secure_agent/requirements.txt ./secure_agent/requirements.txt

# Copy PurpleLlama requirements files that are referenced in requirements.txt
COPY PurpleLlama/CybersecurityBenchmarks/requirements.txt ./PurpleLlama/CybersecurityBenchmarks/requirements.txt
COPY PurpleLlama/CybersecurityBenchmarks/benchmark/infrastructure/requirements.txt ./PurpleLlama/CybersecurityBenchmarks/benchmark/infrastructure/requirements.txt
COPY PurpleLlama/CybersecurityBenchmarks/benchmark/llms/community_contribution/requirements.txt ./PurpleLlama/CybersecurityBenchmarks/benchmark/llms/community_contribution/requirements.txt
COPY PurpleLlama/SensitiveDocClassification/requirements.txt ./PurpleLlama/SensitiveDocClassification/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r secure_agent/requirements.txt && \
    pip install --no-cache-dir -r requirements-web.txt

# Copy application code
COPY . .

# Set Python path
ENV PYTHONPATH=/app:/app/PurpleLlama

# Expose port
EXPOSE 8080

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "120", "secure_agent.web_app:flask_app"]

