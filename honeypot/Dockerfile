
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies if any (usually none for basic python)
# RUN apt-get update && apt-get install -y --no-install-recommends ...

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose port
EXPOSE 8001

# Start
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
