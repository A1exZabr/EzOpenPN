# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE_REPOSITORY=docker.io/library/python
ARG PYTHON_BASE_DIGEST=sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49

FROM ${PYTHON_BASE_REPOSITORY}@${PYTHON_BASE_DIGEST} AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app

RUN python -m pip install --no-cache-dir uv==0.12.7

COPY pyproject.toml uv.lock README.md ./
COPY control/src ./control/src
RUN uv sync --frozen --no-dev --no-editable

FROM ${PYTHON_BASE_REPOSITORY}@${PYTHON_BASE_DIGEST} AS runtime

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EZOPENPN_CONFIG_PATH=/etc/ezopenpn/control.toml \
    EZOPENPN_CONTROL_ROOT=/app/control

RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ezopenpn \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin ezopenpn \
    && install --directory --owner=10001 --group=10001 --mode=0700 \
        /var/lib/ezopenpn /run/ezopenpn-xray

WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 control/alembic.ini /app/control/alembic.ini
COPY --chown=10001:10001 control/migrations /app/control/migrations
COPY --chown=10001:10001 --chmod=0555 control/docker-entrypoint.sh /app/control/docker-entrypoint.sh

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).read()"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/control/docker-entrypoint.sh"]
CMD ["uvicorn", "ezopenpn.web.app:create_runtime_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
