# ============================================================================
# Honeypot Firewall - Dockerfile
# Multi-stage build with CPU-only PyTorch for smaller image size
# ============================================================================

# Stage 1: Builder - Install dependencies
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install CPU-only PyTorch first (significantly smaller than GPU version)
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Stage 2: Runtime - Lean production image
# ============================================================================
FROM python:3.11-slim as runtime

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=appuser:appgroup . .

# Remove unnecessary files from final image
RUN rm -rf myenv/ __pycache__/ .git/ *.log .env tests/ *.md

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/debug/trap-status || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

