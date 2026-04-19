# ---------------------------------------------------------------------------
# AI Sentinel — Container Image
# ---------------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for scanner tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

# Copy application code
COPY scripts/prioritize_vulnerabilities.py /app/scripts/
COPY api/app.py /app/api/

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run the API
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
