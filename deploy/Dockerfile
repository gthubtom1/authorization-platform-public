ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --disable-pip-version-check -r requirements.lock

COPY manage.py ./manage.py
COPY src ./src
COPY protocol ./protocol
COPY 接入说明 ./接入说明
COPY docs/API-CONTRACT.md ./docs/API-CONTRACT.md

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin authorization-platform \
    && mkdir -p /app/storage \
    && chown -R authorization-platform:authorization-platform /app

USER authorization-platform

EXPOSE 8000
CMD ["gunicorn", "authorization_platform.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "60", "--max-requests", "1000", "--max-requests-jitter", "100"]
