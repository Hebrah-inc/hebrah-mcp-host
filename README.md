# while-mcp-host

Hosted While MCP server (Streamable HTTP). Point Cursor, Claude Code, or other MCP clients at `/mcp` with a universal `wh_pat_*` token.

## Local dev

```bash
cd while-mcp-host
cp .env.example .env
pnpm install
pnpm dev
```

Requires while-app on **http://localhost:3000** with `MCP_INTERNAL_SECRET` matching this service.

## Environment

| Variable | Default |
|----------|---------|
| `PORT` | `3021` |
| `WHILE_DASHBOARD_URL` | `http://localhost:3000` |
| `WHILE_API_URL` | `http://localhost:8000` |
| `WHILE_SANDBOX_API_KEY` | (required for `trigger_test_webhook`, `get_sandbox_catalog`) |
| `MCP_INTERNAL_SECRET` | `dev-mcp-internal-secret` |

## Cursor config

See while-app **Settings → MCP** or `GET /api/mcp/cursor-config`.
