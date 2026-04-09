# ─────────────────────────────────────────────────────────────────────────────
# Secure Data Anonymization Pipeline – Container Image
# Base: python:3.9-slim  (minimal attack surface, no unnecessary OS packages)
# Default command: run the full Pytest suite
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.9-slim

# ── Metadata ──────────────────────────────────────────────────────────────────
LABEL maintainer="DAP Team"
LABEL description="Secure Data Anonymization Pipeline - test & runtime image"
LABEL version="1.0.0"

# ── OS hardening: run as a non-root user ──────────────────────────────────────
RUN useradd --create-home --shell /bin/bash appuser

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Install Python dependencies ───────────────────────────────────────────────
# Copy requirements first to maximise Docker layer-cache efficiency:
# dependencies are re-installed only when requirements.txt changes.
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# ── Copy application source ───────────────────────────────────────────────────
# Secrets (.env) are intentionally excluded via .dockerignore (never baked in).
COPY anonymizer.py .
COPY test_anonymizer.py .

# ── Switch to non-root user ───────────────────────────────────────────────────
USER appuser

# ── Default command: run the Pytest suite ────────────────────────────────────
# The HASH_SALT secret is injected at runtime via --env / GitHub Secrets;
# it is never embedded in the image.
CMD ["pytest", "test_anonymizer.py", "-v", "--tb=short"]
