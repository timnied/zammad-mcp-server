# Changelog

## Unreleased

Hardened gateway deployment (see `docs/GATEWAY_DEPLOYMENT.md`).

- **Security fix:** `MCP_DENIED_TOOLS` did not block tool calls (`can_read`/`can_write`/`can_admin` ignored the deny list). Denied tools are now refused and removed from `tools/list`.
- New `MCP_PROFILE` (`readonly`, `helpdesk`, `full`) and `MCP_ALLOWED_TOOLS` allow-list. **Default is now `helpdesk`**: no delete, merge or user/organization/group changes. Set `MCP_PROFILE=full` for the previous behaviour.
- New `MCP_ARTICLE_POLICY=internal_only` (default except in profile `full`): articles are always internal notes.
- Zammad `X-On-Behalf-Of` per request (`MCP_OBO_SOURCE=header|jwt`), fail closed, per-user caches and rate limit, user in the audit log.
- `*_FILE` variants for `ZAMMAD_HTTP_TOKEN`, `ZAMMAD_OAUTH2_TOKEN`, `ZAMMAD_PASSWORD`, `MCP_OBO_PROXY_SECRET`.
- Audit log lines were silently dropped at the default log level; `MCP_LOG_LEVEL` (default `INFO`) now applies.
- Dockerfile: reproducible (`uv.lock`), non-root, path `/mcp`; `deploy/` has a compose file and a gateway snippet.

- Dev stack defaults to Zammad **7.2.2** (`7.2.2-0024`): Memcached, scheduler, websocket, PostgreSQL 17, Redis 8, and Elasticsearch 9. Zammad 7.1 stays a supported tag.

## 0.2.0

- CLI: `--transport stdio|http|sse` with `MCP_TRANSPORT`, host, port, and path.
- Docker default is Streamable HTTP on port 8000; SSE remains a legacy override.
- Healthcheck uses a TCP listen probe (FastMCP has no `/health` route).
- Access control lists only registered tools (no ghost search tools).
- Tags, attachments, ticket links/merge, and `summarize_ticket`.
- Write-scope enforcement for `MCP_ALLOWED_GROUPS` / `MCP_ALLOWED_ORGANIZATIONS`.
- `MCP_DEFAULT_PERMISSION=read_only`, rate limits, JSON audit log on stderr/file.
- HTML-to-plain article bodies (`MCP_STRIP_HTML`, default on).
- Extra MCP prompts and resources.

## 0.1.1

- Production-ready MCP tools for Zammad 6.0+ / 7.x (tested on 7.1).
- PyPI (`uvx zammad-mcp-server`) and GHCR Docker publish.
