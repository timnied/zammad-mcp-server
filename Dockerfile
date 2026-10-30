# Zammad MCP Server - hardened image for running behind a gateway.
#
# Reproducible: dependencies come from uv.lock (uv sync --frozen), not from whatever
# is newest on PyPI. Runs as an unprivileged user. Default transport is Streamable HTTP
# on :8000/mcp. Do NOT publish the port: attach the container to the gateway's internal
# Docker network only (see deploy/compose.agentgateway.yaml).

FROM python:3.13-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install uv==0.11.32
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim

LABEL org.opencontainers.image.title="zammad-mcp-server" \
      org.opencontainers.image.description="MCP server for Zammad (profiles, on-behalf-of identity, internal-note enforcement)"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    MCP_TRANSPORT=http \
    MCP_SERVER_HOST=0.0.0.0 \
    MCP_SERVER_PORT=8000 \
    MCP_SERVER_PATH=/mcp

COPY --from=builder /app/.venv /app/.venv

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp
USER 10001

EXPOSE 8000

# TCP listen check - the MCP endpoint has no /health route and needs a session.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 2).close()"]

CMD ["zammad-mcp-server"]
