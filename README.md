# hebrah-mcp-host

Hosted hebrah MCP server (Streamable HTTP). Point Cursor, Claude Code, or other MCP clients at `/mcp` with a universal `hb_pat_*` token.

## Local dev

```bash
cd hebrah-mcp-host
cp .env.example .env
pnpm install
pnpm dev
```

Requires hebrah-app on **http://localhost:3000** with `MCP_INTERNAL_SECRET` matching this service.

Health check: `curl -s http://localhost:3021/health | jq .`

## Environment

| Variable | Default (local) | Purpose |
|----------|-----------------|---------|
| `PORT` | `3021` | HTTP listen port |
| `HEBRAH_DASHBOARD_URL` | `http://localhost:3000` | PAT validation + dashboard API proxy |
| `HEBRAH_API_URL` | `http://localhost:8000` | Control plane for catalog + webhook trigger |
| `HEBRAH_SANDBOX_API_KEY` | *(required for some tools)* | Org `hb_test_*` from onboarding — **not** the PAT |
| `MCP_INTERNAL_SECRET` | (from `generate-local-secrets.sh`) | Must match hebrah-app |

Copy `.env.example` and fill in `HEBRAH_SANDBOX_API_KEY` from hebrah onboarding **Step 2**. Run `bash ../scripts/generate-local-secrets.sh` and `bash ../scripts/merge-local-secrets.sh` for `MCP_INTERNAL_SECRET` (must match hebrah-app). Set `NUXT_PUBLIC_MCP_URL=http://localhost:3021` in hebrah-app `.env`.

The dev server loads `hebrah-mcp-host/.env` automatically at startup.

### Credential types

| Credential | Used for |
|------------|----------|
| `hb_pat_*` | MCP session auth — dashboard reads/writes via PAT-scoped API |
| `hb_test_*` (`HEBRAH_SANDBOX_API_KEY`) | Direct hebrah-api calls from the MCP host |

`HEBRAH_SANDBOX_API_KEY` is required for hebrah-api sandbox tools (`get_sandbox_catalog`, `trigger_test_webhook`, `list_sandbox_domains`, `run_sandbox_scenario`, etc.). Without it, those tools error; PAT-only tools still work.

## All 21 tools

| # | Tool | Purpose |
|---|------|---------|
| 1 | `set_active_connection` | Set sandbox `connectionId` context for subsequent tools |
| 2 | `get_account_status` | Org status, keys, connections summary |
| 3 | `list_connections` | All dashboard connections (including hidden system row) |
| 4 | `get_connection_mapping` | Read HL7→FHIR mappings (sandbox) |
| 5 | `update_connection_mapping` | Write mappings (sandbox only) |
| 6 | `list_config_versions` | Immutable version history per sandbox connection |
| 7 | `create_config_version` | Snapshot current sandbox config as new version |
| 8 | `create_promotion` | Open promotion PR to sync version to Live |
| 9 | `get_promotion` | Promotion detail and diff summary |
| 10 | `confirm_action` | Issue short-lived token before `approve_promotion` |
| 11 | `approve_promotion` | Approve and sync to Live (guarded) |
| 12 | `reject_promotion` | Reject open promotion |
| 13 | `get_live_deployment` | Read-only: active version on Live connection |
| 14 | `get_sandbox_catalog` | hebrah-api catalog (`HEBRAH_SANDBOX_API_KEY`) |
| 15 | `trigger_test_webhook` | Queue mock event; supports `scenario_id` |
| 16 | `list_sandbox_domains` | Discover sandbox domains |
| 17 | `get_sandbox_domain` | Events + scenarios for one domain |
| 18 | `get_synthetic_resource` | Synthetic FHIR fixture |
| 19 | `run_sandbox_scenario` | Multi-step workflow runner |
| 20 | `get_payer_rules` | Prior-auth payer stub |
| 21 | `list_sandbox_events` | Event groups from catalog |

Implementation: [src/tools.ts](./src/tools.ts).

## Sandbox-only policy

| Rule | Detail |
|------|--------|
| Writes | `update_connection_mapping`, `create_config_version` apply to **Sandbox** connections only |
| Live | Read-only until an approved promotion deploys config |
| Context | Call `set_active_connection` before mapping or promotion tools |

## Promotion guardrails (`confirm_action` → `approve_promotion`)

Live sync requires a deliberate two-step confirmation. Skipping `confirm_action` or omitting `humanIntentMessage` causes `approve_promotion` to fail.

**Required sequence:**

```
create_promotion → confirm_action → approve_promotion
```

| Step | Tool | Notes |
|------|------|-------|
| 1 | `create_config_version` | Snapshot current sandbox mappings |
| 2 | `create_promotion` | Pass `toVersionId`, optional `title` / `description` |
| 3 | `get_promotion` | Review diff before approving |
| 4 | `confirm_action` | Issues `confirmationToken` (~5 min TTL) for `promotionId` |
| 5 | `approve_promotion` | Requires `confirmationToken`, `promotionId`, `humanIntentMessage` |
| — | `reject_promotion` | Close without deploying |

Guardrails in [src/guardrails.ts](./src/guardrails.ts): rate limits per tool, max 10 promotion approves per org per day, confirmation tokens expire after 5 minutes.

## Cursor config

See hebrah-app **Settings → MCP** or `GET /api/mcp/cursor-config`:

```json
{
  "mcpServers": {
    "hebrah": {
      "url": "http://localhost:3021/mcp",
      "headers": {
        "Authorization": "Bearer hb_pat_YOUR_TOKEN"
      }
    }
  }
}
```

## Related docs

- [documentation/hosted-mcp.md](../documentation/hosted-mcp.md) — full hosted MCP reference
- [documentation/agent-quickstart.md](../documentation/agent-quickstart.md) — 15-minute local setup
- [hebrah-examples/admit-monitor-demo/](../hebrah-examples/admit-monitor-demo/) — MCP + webhook census demo
