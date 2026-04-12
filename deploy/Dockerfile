# ═══════════════════════════════════════════════════
# LLMPot — Docker Configuration
# Multi-stage build for minimal image size
# ═══════════════════════════════════════════════════

FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Runtime Stage ────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="LLMPot Project"
LABEL description="AI-Driven SSH Honeypot System"

# Security: run as non-root
RUN groupadd -r honeypot && useradd -r -g honeypot -d /app -s /bin/bash honeypot

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy application
COPY --chown=honeypot:honeypot . .

# Create data directories
RUN mkdir -p data logs models keys && \
    chown -R honeypot:honeypot /app

USER honeypot

# Generate host key on first run
RUN python generate_key.py 2>/dev/null || true

# Expose ports
# 2222 = SSH honeypot
# 8501 = Streamlit dashboard
EXPOSE 2222
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 2222)); s.close()" || exit 1

# Default: run honeypot
CMD ["python", "main.py"]
