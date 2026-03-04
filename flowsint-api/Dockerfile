FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    POETRY_HOME="/opt/poetry"

ENV PATH="$POETRY_HOME/bin:$PATH"

WORKDIR /app

# build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    pkg-config \
    libcairo2-dev \
    && rm -rf /var/lib/apt/lists/*

# poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

COPY hudhud-core/pyproject.toml hudhud-core/poetry.lock* ./hudhud-core/
COPY hudhud-types/pyproject.toml hudhud-types/poetry.lock* ./hudhud-types/
COPY hudhud-enrichers/pyproject.toml hudhud-enrichers/poetry.lock* ./hudhud-enrichers/
COPY hudhud-api/pyproject.toml hudhud-api/poetry.lock* ./hudhud-api/

COPY hudhud-core ./hudhud-core
COPY hudhud-types ./hudhud-types
COPY hudhud-enrichers ./hudhud-enrichers
COPY hudhud-api ./hudhud-api

WORKDIR /app/hudhud-api
RUN poetry install --no-root

# DEV
FROM python:3.12-slim AS dev

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=development \
    PATH="/app/hudhud-api/.venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libcairo2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/hudhud-api/.venv ./hudhud-api/.venv

# Copy application code
COPY hudhud-core ./hudhud-core
COPY hudhud-types ./hudhud-types
COPY hudhud-enrichers ./hudhud-enrichers
COPY hudhud-api ./hudhud-api

WORKDIR /app/hudhud-api

# Make entrypoint executable
RUN chmod +x entrypoint.sh

EXPOSE 5001

ENTRYPOINT ["./entrypoint.sh"]

# Dev command with hot-reload
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001", "--reload"]

# PROD
FROM python:3.12-slim AS production

LABEL org.opencontainers.image.source="https://github.com/reconurge/hudhud"
LABEL org.opencontainers.image.description="Hudhud API & Worker"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production \
    PATH="/app/hudhud-api/.venv/bin:$PATH"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libcairo2 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -g 1001 hudhud && \
    useradd -u 1001 -g hudhud -s /bin/bash -m hudhud

WORKDIR /app

# Copy virtual environment from builder (production deps only would require separate install)
COPY --from=builder --chown=hudhud:hudhud /app/hudhud-api/.venv ./hudhud-api/.venv

# Copy application code
COPY --chown=hudhud:hudhud hudhud-core ./hudhud-core
COPY --chown=hudhud:hudhud hudhud-types ./hudhud-types
COPY --chown=hudhud:hudhud hudhud-enrichers ./hudhud-enrichers
COPY --chown=hudhud:hudhud hudhud-api ./hudhud-api

WORKDIR /app/hudhud-api

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Switch to non-root user
# USER hudhud

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

ENTRYPOINT ["./entrypoint.sh"]

# Production command (no reload)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]
