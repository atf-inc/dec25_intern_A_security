
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for ML libraries (if needed example: libgomp1 for XGBoost)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# We assume the build context contains quantumshield/requirements.txt
COPY quantumshield/requirements.txt ./requirements.txt
# If ml-classifier has requirements, merge them. For now, assume quantumshield's reqs cover it or we perform a second install.
COPY ml-classifier/requirements.txt ./ml_requirements.txt

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r ml_requirements.txt

# Copy application code
# Expects build context to be the project root
COPY quantumshield/ /app/quantumshield/
COPY ml-classifier/ /app/ml-classifier/

WORKDIR /app/quantumshield

# Expose port
EXPOSE 8000
EXPOSE 8081

# Start
CMD ["python", "full_run.py"]
