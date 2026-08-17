# hebrah-mcp-host

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node 22+](https://img.shields.io/badge/node-%3E%3D22-blueviolet)](./package.json)

Open-source **[Model Context Protocol](https://modelcontextprotocol.io/)** server for the [Hebrah](https://hebrah.com) platform. Bridges MCP clients (Cursor, Claude Code, etc.) to a Hebrah dashboard + control plane over Streamable HTTP, using a per-user Personal Access Token (`hb_pat_*`).

- **Source:** https://github.com/Hebrah-inc/hebrah-mcp-host
- **License:** [MIT](./LICENSE)
- **Security:** [SECURITY.md](./SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)

> The MCP server is **one piece of the Hebrah platform.** You will also need a running [hebrah-app](https://github.com/Hebrah-inc/hebrah-app) dashboard (port 3000) and [hebrah-api](https://github.com/Hebrah-inc/hebrah-api) control plane (port 8000). For application code, prefer the official SDKs: [`@hebrah/sdk`](https://www.npmjs.com/package/@hebrah/sdk) (Node) and [`hebrah`](https://pypi.org/project/hebrah/) (Python).

---

## What it does

`hebrah-mcp-host` exposes ~50 tools that let an agent:

| Category | Examples |
|---|---|
| **Connection lifecycle** | `list_connections`, `create_connection`, `pause_connection`, `remove_connection` |
| **Sandbox exploration** | `get_sandbox_catalog`, `list_sandbox_domains`, `run_sandbox_scenario` |
| **HL7 / sidecar** | `inject_hl7`, `run_hl7_flight_check`, `sidecar_writeback` |
| **Webhook reliability** | `list_webhook_deliveries`, `replay_webhook_delivery`, `run_webhook_reliability_scenario` |
| **SMART on FHIR** | `register_smart_client`, `start_smart_launch` |
| **Interop** | `run_mpi_match`, `run_mpi_scenario`, `get_practitioner_credentialing`, `run_aggregator_query` |
| **Synthetic EHR / BYOM** | `get_synthetic_ehr_profile`, `list_ehr_base_models`, `reset_synthetic_ehr_data`, `propose_custom_ehr_model` |
| **Research Packs** | `list_research_packs`, `get_research_pack`, `apply_research_pack`, `compare_research_pack` |
| **PTB-XL ECG** | `list_ptbxl_ecg_records`, `get_ptbxl_ecg_record`, `attach_ptbxl_ecg_exemplar` |
| **Credentials (gated)** | `create_sandbox_api_key`, `revoke_sandbox_api_key`, `set_connection_webhook_url`, `rotate_connection_webhook_secret` |
| **SDK reference** | `get_sdk_reference` (embedded `@hebrah/sdk` README + MCP-to-SDK mapping) |

The full numbered list and tool descriptions are returned by `tools/list` once the server is connected.

---

## Install

```bash
git clone https://github.com/Hebrah-inc/hebrah-mcp-host.git
cd hebrah-mcp-host
pnpm install
cp .env.example .env
# Fill HEBRAH_SANDBOX_API_KEY from hebrah onboarding Step 2
# Generate MCP_INTERNAL_SECRET: openssl rand -hex 32 (must match hebrah-app)
pnpm dev
```

Health check: `curl -s http://localhost:3021/health | jq .`

### Production build

```bash
pnpm build
node dist/index.js
```

Or with Docker:

```bash
docker build -t hebrah-mcp-host .
docker run --rm -p 3021:3021 --env-file .env hebrah-mcp-host
```

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3021` | HTTP listen port |
| `HEBRAH_DASHBOARD_URL` | `http://localhost:3000` | PAT validation + dashboard API proxy |
| `HEBRAH_API_URL` | `http://localhost:8000` | Control plane for catalog + webhook trigger |
| `HEBRAH_SANDBOX_API_KEY` | *(required)* | Org `hb_test_*` from onboarding Step 2 — **not** the PAT |
| `MCP_INTERNAL_SECRET` | *(required, ≥ 32 chars)* | Shared with hebrah-app for audit log + MCP ACL lookup |
| `REDIS_URL` | *(optional)* | Optional Redis for shared rate-limit counters |
| `ORCHESTRATOR_URL` | `http://localhost:8090` | HL7 flight checks |
| `ORCHestratorSECRET` | *(empty)* | Orchestrator auth |
| `INTEGRATION_AGENT_URL` | `http://localhost:3050` | BYOM agent |

`MCP_INTERNAL_SECRET` must be at least 32 characters. The server refuses to start otherwise.

---

## Connecting a client

Point your MCP client at `/mcp` with a Bearer `hb_pat_*` token. In Cursor:

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

Or use `GET /api/mcp/cursor-config` on hebrah-app to mint a Cursor snippet for your org.

---

## Credential types

| Credential | Used for |
|---|---|
| `hb_pat_*` (per-user PAT) | MCP session auth — dashboard reads/writes via PAT-scoped API |
| `hb_test_*` (`HEBRAH_SANDBOX_API_KEY`) | Direct hebrah-api calls from the MCP host (catalog, mock webhook trigger) |
| `hbsec_*` | Per-connection webhook signing secret (held by hebrah-app) |

`HEBRAH_SANDBOX_API_KEY` is **org-wide** — not scoped by PAT. For multi-tenant hosted deployments, run one MCP host per organization until per-PAT sandbox key injection ships.

---

## Credential write guardrails

Mutating tools that return or affect secrets require a two-step `confirm_action` flow with a single-use token (5-minute TTL):

| Tool | `confirm_action` action |
|---|---|
| `create_sandbox_api_key` | `create_sandbox_api_key` |
| `set_connection_webhook_url` | `set_connection_webhook_url` |
| `rotate_connection_webhook_secret` | `rotate_connection_webhook_secret` |
| `revoke_sandbox_api_key` | `revoke_sandbox_api_key` (requires `keyId` on both steps) |
| `approve_promotion` | `approve_promotion` |
| `remove_connection` | `remove_connection` |

The token is action- and target-scoped, expires after 5 minutes, and can only be consumed once. Plaintext keys are returned once on the write step.

Implementation: [`src/guardrails.ts`](./src/guardrails.ts).

---

## Sandbox-only policy

| Rule | Detail |
|---|---|
| Writes | `update_connection_mapping`, `create_config_version` apply to **Sandbox** connections only |
| Live | Read-only until an approved promotion deploys the new sandbox version |
| Promotions | Require Pro plan — `get_account_status.canPromoteToLive` must be `true` |
| Context | Call `set_active_connection` before mapping; promotion tools require Pro |

---

## Promotion flow

Live sync requires a deliberate two-step confirmation. Skipping `confirm_action` or omitting `humanIntentMessage` causes `approve_promotion` to fail.

```
create_config_version
  → create_promotion
  → get_promotion        (review diff)
  → confirm_action       (issues confirmationToken, ~5 min TTL)
  → approve_promotion    (requires confirmationToken + humanIntentMessage)
```

Rate-limited to 10 promotion approves per org per day (in-memory; shared via Redis if configured).

---

## Architecture

```
MCP client (Cursor / Claude Code / ...)
        │  Authorization: Bearer hb_pat_*
        ▼
┌────────────────────────────────────┐
│  hebrah-mcp-host  (this repo)      │  Streamable HTTP / SSE
│                                    │  • PAT validation  → hebrah-app
│  • tool dispatcher                 │  • audit log       → hebrah-app (internal)
│  • confirmation tokens             │  • sandbox calls   → hebrah-api
│  • rate limiting (in-memory + Redis)│
│  • ACL gates (per-org)             │
└────────────────────────────────────┘
        │                  │              │
        ▼                  ▼              ▼
   hebrah-app        hebrah-api    Redis (optional)
   (PAT / audit)     (sandbox)     (rate limits)
```

Threat model, deployment guidance, and credential handling: [`SECURITY.md`](./SECURITY.md).

Key files: [`src/index.ts`](./src/index.ts) (Hono app), [`src/tools.ts`](./src/tools.ts) (tool dispatch), [`src/guardrails.ts`](./src/guardrails.ts) (tokens + rate limits), [`src/connectionPolicyGate.ts`](./src/connectionPolicyGate.ts) (ACL), [`src/promotionGate.ts`](./src/promotionGate.ts) (plan gate).

---

## Testing

```bash
pnpm test
```

Tests run with the Node test runner (`node --test`). They cover:

- `connectionPolicyGate` — ACL defaults, partial overrides, tool filtering
- `guardrails` — rate limits, confirmation token lifecycle
- `credentialConfirmGate` — two-step `confirm_action` for credential writes
- `credentialTools` — webhook URL builder edge cases
- `promotionGate` — Pro-plan gate
- `sdkReference` — embedded SDK reference shape
- `sseKeepalive` — keepalive wrapper

Tests are self-contained and do not require network access.

---

## License

[MIT](./LICENSE) — Copyright (c) 2026 Hebrah, Inc.

## Related

- [`@hebrah/sdk`](https://github.com/Hebrah-inc/hebrah-sdk-node) — Node SDK (MIT)
- [`hebrah`](https://github.com/Hebrah-inc/hebrah-sdk-python) — Python SDK (MIT)
- [hebrah-app](https://github.com/Hebrah-inc/hebrah-app) — operator dashboard
- [hebrah-api](https://github.com/Hebrah-inc/hebrah-api) — control plane + sandbox