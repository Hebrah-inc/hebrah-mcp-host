# Contributing

Thanks for your interest in `hebrah-mcp-host`! This is an open-source MCP server that bridges MCP clients to the Hebrah dashboard and control plane.

## Development setup

Requirements: Node.js 22+, pnpm 11+, a running [hebrah-app](https://github.com/Hebrah-inc/hebrah-app) on port 3000, and a running [hebrah-api](https://github.com/Hebrah-inc/hebrah-api) on port 8000.

```bash
git clone https://github.com/Hebrah-inc/hebrah-mcp-host.git
cd hebrah-mcp-host
cp .env.example .env
# Fill HEBRAH_SANDBOX_API_KEY from hebrah onboarding Step 2
# Generate MCP_INTERNAL_SECRET: openssl rand -hex 32 (must match hebrah-app)
pnpm install
pnpm dev
```

Health check: `curl -s http://localhost:3021/health | jq .`

## Scripts

| Command | Purpose |
|---|---|
| `pnpm dev` | Watch-mode TypeScript via `tsx` |
| `pnpm build` | Compile to `dist/` |
| `pnpm start` | Run compiled `dist/index.js` |
| `pnpm test` | `node --test` against `test/*.test.ts` |
| `pnpm predev` / `prebuild` | Regenerate embedded SDK reference (optional — see below) |

## Optional: SDK reference sync

`src/generated/nodeSdkReference.ts` is **committed** and embeds the latest published `@hebrah/sdk` README plus the MCP-to-SDK method mapping table. To regenerate against a sibling checkout of [`hebrah-sdk-node`](https://github.com/Hebrah-inc/hebrah-sdk-node):

```bash
# Expected layout: ../hebrah-sdk-node (sibling directory)
pnpm predev
```

If the sibling repo is absent the script logs a warning and exits 0 — the embedded reference is left untouched.

## Tests

Tests run with the Node test runner — no extra framework:

```bash
pnpm test
```

Add a test next to the file you are changing (`test/<module>.test.ts`). Tests must not require network access; stub external services.

## Pull request process

1. Fork the repository and create a feature branch.
2. Run `pnpm test` — all tests must pass.
3. Run `pnpm build` — TypeScript must compile cleanly.
4. Open a PR describing the change and the test coverage.
5. Wait for CI and a maintainer review.

## Coding style

- TypeScript strict mode (`tsconfig.json`).
- ESM (`"type": "module"`).
- No external test runner; use `node:test` + `node:assert/strict`.
- No client-side dependencies. This server runs Node only.
- Prefer named exports. Keep tool definitions and schemas in `src/tools.ts` and `src/toolSchemas.ts`.

## Adding a tool

1. Add the tool definition to `toolDefinitions` in `src/tools.ts`.
2. Add the `case` branch in `callTool()`.
3. Add a JSON Schema in `listToolInputSchema()` in `src/toolSchemas.ts` (keep payloads small).
4. Add tests covering the gate, ACL, and rate-limit interaction.
5. If the tool returns or affects secrets, add a `ConfirmationAction` entry in `src/guardrails.ts` and a corresponding `confirm_action` gate in `src/tools.ts`.
6. Update the README tool list.

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md). Do not open a public issue for security reports.

## License

By contributing, you agree that your contributions will be licensed under the MIT License. See [`LICENSE`](./LICENSE).