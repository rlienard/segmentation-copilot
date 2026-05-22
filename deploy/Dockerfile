# Multi-stage build — one image, one role per replica.
#
# The image installs ALL optional extras so the same artifact can serve
# every role (api / worker / scheduler / threat-daemon / webex-bot /
# mcp-http / streamlit-ui). Pick the role with the container CMD or
# pod spec. Keeps the registry footprint to one tag per release.

ARG PYTHON_VERSION=3.11

# --- builder ---------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/
COPY services/ services/
COPY alembic.ini ./
COPY alembic/ alembic/
COPY app.py ./

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install ".[api,worker,webex,mcp,cli,ui,sources,otel,postgres]"

# --- runtime ---------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Run as non-root. UID 10001 matches the K8s PSP-style baseline.
RUN groupadd --system --gid 10001 scopilot && \
    useradd --system --uid 10001 --gid scopilot --home /app --shell /usr/sbin/nologin scopilot

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build /app

USER 10001:10001

# Default to the API; override the CMD per replica.
EXPOSE 8000
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
