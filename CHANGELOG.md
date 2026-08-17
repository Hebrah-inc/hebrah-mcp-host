# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- README env-var table typo: `ORCHestratorSECRET` → `ORCHESTRATOR_SECRET` (matches `src/config.ts`).
- `.env.example` now includes `ORCHESTRATOR_URL`, `ORCHESTRATOR_SECRET`, `INTEGRATION_AGENT_URL`, and `REDIS_URL` so the documented config table is reproducible from the example file.

### Added

- GitHub Actions CI: install, type-check, build, test on Node 22.
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1).
- Issue templates (bug report, feature request, docs) and PR template under `.github/`.
- OSS discovery badges in README (License, MCP protocol, Node 22+, GitHub stars + issues).

## [0.1.0] — 2026-06-08

### Added

- Initial open-source release of the Streamable HTTP MCP host.
- ~50 tools across connection lifecycle, sandbox exploration, HL7/sidecar, webhook reliability, SMART on FHIR, MPI / aggregator, synthetic EHR / BYOM, Research Packs, and PTB-XL ECG.
- Two-step `confirm_action` guardrail for credential-mutating tools.
- Connection policy gate with per-org ACL.
- In-memory rate limiting with optional Redis backend.

[Unreleased]: https://github.com/Hebrah-inc/hebrah-mcp-host/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Hebrah-inc/hebrah-mcp-host/releases/tag/v0.1.0