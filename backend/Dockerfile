FROM python:3.12-slim AS base

# Security: don't run as root
RUN groupadd -r netra && useradd -r -g netra -d /app -s /sbin/nologin netra

WORKDIR /app

# Install system deps for WeasyPrint and spaCy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libcairo2 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]" \
    && python -m spacy download en_core_web_sm

COPY backend/ ./backend/
COPY datagen/ ./datagen/

# Security: drop to non-root user
USER netra

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
