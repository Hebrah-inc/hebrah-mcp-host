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

`hebrah-mcp-host` is a Streamable HTTP MCP server that bridges MCP clients (Cursor, Claude Code, etc.) to a Hebrah dashboard (hebrah-app) and control plane (hebrah-api). It does not persist data; all state lives in the dashboard / control plane / optional Redis for rate-limit counters.

| Concern | Owner |
|---|---|
| Identity (PAT validation, org binding) | hebrah-app |
| Token / key storage, billing, audit log | hebrah-app |
| Synthetic FHIR, webhook signing, replay | hebrah-api |
| Rate limiting, confirmation tokens, ACL gates | this service |
| TLS termination | deployer |

## Integrator guidance

- **Never commit `.env`**, `MCP_INTERNAL_SECRET`, or any `hb_pat_*` / `hb_test_*` / `hbsec_*` credential. `.env` is git-ignored; keep it that way.
- `MCP_INTERNAL_SECRET` must be **≥ 32 chars** and match the value configured in hebrah-app. Rotate both at the same time.
- `HEBRAH_SANDBOX_API_KEY` is **org-wide** sandbox access — not scoped by PAT. For multi-tenant hosted deployments, run one MCP host per organization until per-PAT sandbox key injection ships.
- Deploy behind TLS. The MCP host listens on plain HTTP and assumes a TLS-terminating proxy in front.
- Treat the session header as bearer material. Restrict `Mcp-Session-Id` exposure (don't log it; don't echo it in URLs).
- Restrict network egress to the dashboard and control plane only. The host does not need internet access.

## Credential write guardrails

Mutating tools that return or affect secrets require a two-step `confirm_action` flow with a single-use token (5-minute TTL):

- `create_sandbox_api_key`
- `rotate_connection_webhook_secret`
- `revoke_sandbox_api_key`
- `set_connection_webhook_url`

See `src/guardrails.ts` for the implementation. The token is action- and target-scoped (e.g. `connectionId` + `keyId` for revoke).