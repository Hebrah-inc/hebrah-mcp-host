# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` | Yes       |

## Reporting a vulnerability

Please report security issues privately to **security@hebrah.com**.

Include:

- A description of the issue and potential impact
- Steps to reproduce
- Affected version(s)

We aim to acknowledge reports within 2 business days. Do not open public GitHub issues for undisclosed vulnerabilities.

## Threat model

`hebrah-mcp-host` is a Streamable HTTP MCP server that bridges MCP clients (Cursor, Claude Code, autonomous agents, etc.) to a Hebrah dashboard (`hebrah-app`) and control plane (`hebrah-api`). It does not persist data; all state lives in the dashboard / control plane / optional Redis for rate-limit counters.

| Concern | Owner |
|---|---|
| Identity (`hb_pat_*` PAT validation, `hb_conn_*` agent keys, org binding) | `hebrah-app` / `hebrah-api` |
| Token / key storage, billing, audit log | `hebrah-app` / `hebrah-api` |
| Isolated Health Environments, synthetic EHR, credential-blind SQL, webhook signing | `hebrah-api` |
| Rate limiting, org-bound confirmation tokens, ACL gates, SSRF protection | this service |
| TLS termination | deployer |

## Integrator guidance

- **Never commit `.env`**, `MCP_INTERNAL_SECRET`, or any `hb_pat_*` / `hb_conn_*` / `hb_test_*` / `hbsec_*` credential. `.env` is git-ignored; keep it that way.
- `MCP_INTERNAL_SECRET` must be **≥ 32 chars** (`openssl rand -hex 32`) and match the value configured in `hebrah-app`. Rotate both at the same time.
- `HEBRAH_SANDBOX_API_KEY` is **org-wide** sandbox access — not scoped by PAT. For multi-tenant hosted deployments, prefer `hb_conn_*` agent keys or run one MCP host per organization.
- Deploy behind TLS. The MCP host listens on plain HTTP and assumes a TLS-terminating proxy in front.
- Treat the session header as bearer material. `Mcp-Session-Id` is automatically redacted in server logs (`first 8 chars…`) and bound to the caller's `orgId`.
- Restrict network egress to the dashboard and control plane only. `sidecar_writeback` enforces strict SSRF protection against cloud metadata (`169.254.169.254`, `metadata.google.internal`) and private/loopback addresses on hosted deployments.

## Credential write guardrails

Mutating tools that return or affect secrets require a two-step `confirm_action` flow with a single-use, org-bound token (5-minute TTL):

- `create_sandbox_api_key`
- `rotate_connection_webhook_secret`
- `revoke_sandbox_api_key`
- `set_connection_webhook_url`
- `connect_to_data_source`
- `revoke_data_source_connection`
- `remove_connection`
- `approve_promotion`

See `src/guardrails.ts` for the implementation. The token is bound to `(orgId, action, targetId)` and can only be consumed once.