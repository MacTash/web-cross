# Web-Cross Vulnerability Scanner v3.0
# Multi-stage build for optimized container

# Stage 1: Build dependencies
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Create non-root user
RUN groupadd --gid 1000 webcross && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home webcross

WORKDIR /app

# Install runtime dependencies for WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels and install
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application
COPY --chown=webcross:webcross . .

# Create data directories
RUN mkdir -p /app/data/scans /app/data/reports /app/data/states && \
    chown -R webcross:webcross /app/data

# Switch to non-root user
USER webcross

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WEBCROSS_LOG_LEVEL=INFO \
    WEBCROSS_DATABASE__URL=sqlite:///data/webcross.db

# Expose port for web UI
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Entry point
ENTRYPOINT ["python"]
CMD ["web-cross.py"]
