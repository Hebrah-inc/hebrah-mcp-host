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

### Blast radius (multi-tenant hosted MCP)

`HEBRAH_SANDBOX_API_KEY` is **org-wide** sandbox API access — not scoped by PAT. Never share one key across tenants on a shared MCP host. Prefer one host per org until per-PAT sandbox key injection ships. See [documentation/hosted-mcp.md](../documentation/hosted-mcp.md#blast-radius-sec-009).

## All 51 tools

Canonical numbered list: [documentation/hosted-mcp.md](../documentation/hosted-mcp.md#all-51-tools).

| # | Tool | Purpose |
|---|------|---------|
| 1–21 | *(baseline + Phases 1–2)* | Connection mapping, promotions, domains, scenarios, HL7, sidecar |
| 22–33 | *(Phase 3 + reliability)* | Webhook deliveries, replay, reliability profile/scenarios |
| 34–35 | SMART | `register_smart_client`, `start_smart_launch` (PAT `connections:write`) |
| 36–41 | Interop domains | MPI, credentialing, aggregator |
| 42–46 | Synthetic EHR / BYOM | Profile, base models, reset, developer doc, propose custom model |
| 47–51 | Credentials | Mint/list/revoke `hb_test_*`; set webhook URL; rotate `hbsec_*` |
| — | `get_connection_credentials` | Read credentials metadata + Docker URL hints for local demos |
| — | `get_sdk_reference` | Official `@hebrah/sdk` (Node) reference — install, API, MCP-to-SDK mapping |

**Local demos:** after `create_connection`, each credential write requires `confirm_action` first, then the write tool with `confirmationToken` + `humanIntentMessage`:

```
confirm_action(action=create_sandbox_api_key, connectionId) → create_sandbox_api_key(...)
confirm_action(action=set_connection_webhook_url, connectionId) → set_connection_webhook_url(...)
confirm_action(action=rotate_connection_webhook_secret, connectionId) → rotate_connection_webhook_secret(...)
```

Write plaintext once into the demo `.env`. Multiple active keys per connection are supported; plaintext is never re-fetched.

## Credential write guardrails (`confirm_action` → credential tools)

Credential writes that return or affect secrets require the same two-step confirmation as `remove_connection`:

| Write tool | `confirm_action` action | Notes |
|------------|-------------------------|-------|
| `create_sandbox_api_key` | `create_sandbox_api_key` | Returns plaintext `hb_test_*` once |
| `set_connection_webhook_url` | `set_connection_webhook_url` | Redirects webhook delivery; supports `localAppUrl` / `port` + `deliveryTarget` for Docker demos |
| `rotate_connection_webhook_secret` | `rotate_connection_webhook_secret` | Returns plaintext `hbsec_*` once |
| `revoke_sandbox_api_key` | `revoke_sandbox_api_key` | Requires `keyId` on both steps |

`list_sandbox_api_keys` and `get_connection_credentials` are metadata-only (no gate). Tokens expire after ~5 minutes and are single-use.

Implementation: [src/tools.ts](./src/tools.ts).

### SDK reference sync

`pnpm predev` / `pnpm prebuild` runs [scripts/sync-sdk-reference.mjs](./scripts/sync-sdk-reference.mjs), which embeds [hebrah-sdk-node/README.md](../hebrah-sdk-node/README.md) into `src/generated/nodeSdkReference.ts`. Agents should call `get_sdk_reference` instead of web-searching npm.

## Sandbox-only policy

| Rule | Detail |
|------|--------|
| Writes | `update_connection_mapping`, `create_config_version` apply to **Sandbox** connections only |
| Live | Read-only until an approved **Pro-plan** promotion deploys config |
| Promotions | **Pro plan only** — `get_account_status.canPromoteToLive` must be true |
| Context | Call `set_active_connection` before mapping; promotion tools require Pro |

## Promotion guardrails (Pro plan — `confirm_action` → `approve_promotion`)

Promotion MCP tools and dashboard **Promote to Live** require a **Pro plan**. The MCP host checks `canPromoteToLive` on `/api/org/status` before `create_promotion`, `get_promotion`, `confirm_action`, `approve_promotion`, or `reject_promotion`.

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
