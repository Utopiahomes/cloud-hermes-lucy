FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN groupadd --system --gid 10001 lucy \
    && useradd --system --uid 10001 --gid lucy --home-dir /nonexistent lucy

WORKDIR /app
COPY pyproject.toml ./
COPY deploy/render/requirements.lock ./deploy/render/requirements.lock
COPY alembic.ini hermes.lock ./
COPY migrations ./migrations
COPY src ./src
RUN pip install --no-cache-dir --require-hashes -r deploy/render/requirements.lock

USER 10001:10001
CMD ["python", "-m", "lucy.runtime"]
