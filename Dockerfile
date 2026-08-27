FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN groupadd --system --gid 10001 lucy \
    && useradd --system --uid 10001 --gid lucy --home-dir /nonexistent lucy

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

USER 10001:10001
CMD ["uvicorn", "lucy.api:app", "--host", "0.0.0.0", "--port", "8080"]
