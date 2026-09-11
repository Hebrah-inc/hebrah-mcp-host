import { config } from './config.js'
import {
  type McpAcl,
  assertMcpConnectionActionAllowed,
  normalizeMcpAcl
} from './connectionPolicyGate.js'
import {
  type ConfirmationAction,
  checkPromotionApproveLimit,
  checkRateLimit,
  consumeConfirmationToken,
  issueConfirmationToken
} from './guardrails.js'
import { assertCanPromoteToLive } from './promotionGate.js'
import { buildSdkReference } from './sdkReference.js'
import {
  parseLocalAppUrlFromArgs,
  resolveWebhookUrlFromSetArgs,
  suggestedWebhookUrls
} from './webhookUrl.js'

export type McpAuth = {
  mode: 'pat' | 'agent'
  /** PAT mode: dashboard PAT. Agent mode: the agent's hb_conn_* key. */
  pat: string
  agentKey?: string
  orgId: string
  tokenId: string
  mcpAcl: McpAcl
  bootstrap?: boolean
}

const sessions = new Map<string, { activeConnectionId?: string, connectApiKey?: string, connectAccountId?: string, connectConnectionId?: string }>()

export function getSession(sessionId: string) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {})
  }
  return sessions.get(sessionId)!
}

async function connectFetch<T>(
  auth: McpAuth,
  session: { connectApiKey?: string, connectAccountId?: string },
  path: string,
  init?: RequestInit
): Promise<T> {
  let key = config.connectApiKey
  if (!key) {
    if (!session.connectApiKey) {
      const response = await fetch(`${config.connectUrl}/v1/account`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: `mcp-agent:${auth.orgId}` }),
        signal: AbortSignal.timeout(15_000)
      })
      if (!response.ok) {
        throw new Error(`Hebrah Connect account creation failed (${response.status}): ${await response.text()}`)
      }
      const account = await response.json() as { account_id: string, api_key: string }
      session.connectApiKey = account.api_key
      session.connectAccountId = account.account_id
    }
    key = session.connectApiKey ?? ''
  }
  const response = await fetch(`${config.connectUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`,
      ...(init?.headers ?? {})
    },
    signal: init?.signal ?? AbortSignal.timeout(30_000)
  })
  if (!response.ok) {
    throw new Error(`Hebrah Connect ${path} failed (${response.status}): ${await response.text()}`)
  }
  return response.json() as Promise<T>
}

async function ultraFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const key = config.sandboxApiKey
  if (!key.startsWith('hb_test_')) {
    throw new Error('HEBRAH_SANDBOX_API_KEY must be set on hebrah-mcp-host for hebrah-api tools')
  }
  const res = await fetch(`${config.hebrahApiUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`,
      ...(init?.headers ?? {})
    }
  })
  if (!res.ok) {
    throw new Error(`hebrah-api ${path} failed (${res.status}): ${await res.text()}`)
  }
  return res.json() as Promise<T>
}


/**
 * Agent-surface fetch: forwards the caller's hb_conn_* agent key to the
 * merged hebrah-api control plane. Scopes, metering, and audit attribute
 * to the agent's org.
 */
async function agentApiFetch<T>(
  auth: McpAuth,
  path: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(`${config.hebrahApiUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${auth.agentKey}`,
      ...(init?.headers ?? {})
    },
    signal: AbortSignal.timeout(30_000)
  })
  if (!res.ok) {
    let message = `agent API ${path} failed (${res.status})`
    try {
      const body = await res.json() as { detail?: { message?: string } | string }
      if (typeof body.detail === 'object' && body.detail?.message) message = body.detail.message
      else if (typeof body.detail === 'string') message = body.detail
    } catch {
      // non-JSON error body — keep the default message
    }
    throw new Error(message)
  }
  return res.json() as Promise<T>
}

/** Tools available in agent-key (hb_conn_*) sessions. */
export const AGENT_TOOL_NAMES = [
  'discover_data_sources',
  'connect_to_data_source',
  'query_data_source',
  'get_data_source_audit',
  'get_connect_usage',
  'revoke_data_source_connection',
  'get_wallet_status',
  'set_auto_reload',
  'create_topup',
  'get_usage_forecast'
] as const

export const agentToolDefinitions = [
  { name: 'discover_data_sources', description: 'List every connector target (12 demo targets across 6 packs + live Stripe) with required scopes, tiers, and health' },
  { name: 'connect_to_data_source', description: 'Open a scoped, TTL-bound connection to a target (target_id + scopes from discovery); the agent never receives the source credential' },
  { name: 'query_data_source', description: 'Run one read-only, scope-enforced query; returns rows, cost_cents, bytes_egressed, and audit_event_id' },
  { name: 'get_data_source_audit', description: 'Read the hash-chained audit events for a connection' },
  { name: 'get_connect_usage', description: 'Read trial quota, remaining queries/egress, and wallet balance' },
  { name: 'get_wallet_status', description: 'Read wallet balance, auto-reload config, 30-day burn rate, and projected runway', inputSchema: { type: 'object', properties: {}, required: [] } },
  { name: 'set_auto_reload', description: 'Enable or disable auto-reload and set the threshold ($1-$10,000) and reload amount ($5-$10,000). Defaults: $5 threshold / $20 reload. Call get_wallet_status first to see current state.', inputSchema: { type: 'object', properties: { auto_reload_enabled: { type: 'boolean', description: 'true = enable auto-reload' }, auto_reload_threshold_cents: { type: 'number', description: 'Trigger when balance drops below this (cents; min 100, max 1,000,000)' }, auto_reload_amount_cents: { type: 'number', description: 'Reload amount per trigger (cents; min 500, max 1,000,000)' } }, required: ['auto_reload_enabled'] } },
  { name: 'create_topup', description: 'Create a Stripe Checkout session for a one-time credit purchase', inputSchema: { type: 'object', properties: { amount_cents: { type: 'number', description: 'Amount in cents (min 100 = $1, max 1,000,000 = $10,000)' } }, required: ['amount_cents'] } },
  { name: 'get_usage_forecast', description: '30-day burn rate + projected days to empty (auto-reload on = no runway needed)', inputSchema: { type: 'object', properties: {}, required: [] } },
  { name: 'revoke_data_source_connection', description: 'Revoke a connection instantly — one call, audited; the audit trail stays verifiable' }
] as const

async function assertPromoteToLiveAllowed(pat: string): Promise<void> {
  const status = await dashboardFetch<{ canPromoteToLive?: boolean }>(pat, '/api/org/status')
  assertCanPromoteToLive(status.canPromoteToLive)
}

const CREDENTIAL_CONFIRM_ACTIONS = new Set<ConfirmationAction>([
  'create_sandbox_api_key',
  'rotate_connection_webhook_secret',
  'revoke_sandbox_api_key',
  'set_connection_webhook_url',
  'connect_to_data_source',
  'revoke_data_source_connection'
])
function revokeConfirmationTarget(connectionId: string, keyId: string): string {
  return `${connectionId}:${keyId}`
}

function consumeCredentialConfirmation(
  args: Record<string, unknown>,
  action: ConfirmationAction,
  targetId: string
): void {
  const intent = String(args.humanIntentMessage ?? '')
  if (!intent.trim()) {
    throw new Error(`humanIntentMessage required for ${action}`)
  }
  consumeConfirmationToken(String(args.confirmationToken ?? ''), action, targetId)
}

async function dashboardFetch<T>(pat: string, path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${config.dashboardUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${pat}`,
      ...(init?.headers ?? {})
    }
  })
  if (!res.ok) {
    throw new Error(`Dashboard ${path} failed (${res.status}): ${await res.text()}`)
  }
  return res.json() as Promise<T>
}

export const bootstrapToolDefinitions = [
  { name: 'create_account', description: 'Create a Hebrah agent account headlessly — $1 trial credit, 100 queries, 5 MB egress, 7 days, no card. Available only when ALLOW_HEADLESS_SIGNUP=true' }
]

export const toolDefinitions = [
  { name: 'set_active_connection', description: 'Set the sandbox connection context for subsequent tools' },
  { name: 'get_account_status', description: 'Org status and connections summary' },
  { name: 'list_connections', description: 'List dashboard connections' },
  { name: 'create_connection', description: 'Create a sandbox + live connection pair (requires name and ehrVendor: Epic|Cerner|Athena; use list_ehr_base_models for catalog)' },
  { name: 'pause_connection', description: 'Pause a connection (blocks dashboard writes until resumed)' },
  { name: 'resume_connection', description: 'Resume a paused connection' },
  { name: 'remove_connection', description: 'Remove a deletable connection pair (requires confirm_action token)' },
  { name: 'get_connection_mapping', description: 'Get HL7→FHIR mappings (sandbox only)' },
  { name: 'update_connection_mapping', description: 'Update mappings on sandbox connection only' },
  { name: 'list_config_versions', description: 'List sandbox config versions' },
  { name: 'create_config_version', description: 'Snapshot current sandbox config as a new version' },
  { name: 'create_promotion', description: 'Pro plan: open a promotion (PR) to sync sandbox version to Live' },
  { name: 'get_promotion', description: 'Pro plan: promotion detail and diff summary' },
  { name: 'confirm_action', description: 'Issue a confirmation token before credential writes, approve_promotion, or remove_connection' },
  { name: 'approve_promotion', description: 'Pro plan: approve & sync to Live (requires confirm_action token)' },
  { name: 'reject_promotion', description: 'Pro plan: reject an open promotion' },
  { name: 'get_live_deployment', description: 'Read-only: what version is deployed on Live' },
  { name: 'get_sandbox_catalog', description: 'hebrah-api sandbox catalog (optional connection_id). For app code use @hebrah/sdk — see get_sdk_reference.' },
  { name: 'trigger_test_webhook', description: 'Trigger mock webhook (sandbox); supports event, scenario_id, connection_id. For app code use @hebrah/sdk — see get_sdk_reference.' },
  { name: 'list_sandbox_domains', description: 'List sandbox domain definitions (clinical, documents, prior_auth, etc.)' },
  { name: 'get_sandbox_domain', description: 'Get one sandbox domain with events, resources, and scenarios' },
  { name: 'get_synthetic_resource', description: 'Fetch synthetic FHIR resource by type and id. For app code use @hebrah/sdk — see get_sdk_reference.' },
  { name: 'run_sandbox_scenario', description: 'Run multi-step sandbox workflow scenario (e.g. prior_auth_happy_path). For app code use @hebrah/sdk — see get_sdk_reference.' },
  { name: 'get_payer_rules', description: 'Synthetic prior-auth payer rules stub' },
  { name: 'list_sandbox_events', description: 'List webhook events grouped by sandbox domain' },
  { name: 'list_hl7_templates', description: 'List injectable HL7 sandbox templates' },
  { name: 'inject_hl7', description: 'Inject synthetic HL7 message or template; fires mapped webhook' },
  { name: 'sidecar_writeback', description: 'POST synthetic EHR write-back action to local sidecar URL' },
  { name: 'run_hl7_flight_check', description: 'Run orchestrator HL7 ACK probe for a provisioned VM' },
  { name: 'list_webhook_deliveries', description: 'List outbound webhook delivery records with retry status' },
  { name: 'replay_webhook_delivery', description: 'Replay a stored webhook envelope by delivery id' },
  { name: 'configure_webhook_reliability', description: 'Set sandbox webhook reliability/chaos profile' },
  { name: 'run_webhook_reliability_scenario', description: 'Configure profile and run webhook reliability scenario' },
  { name: 'register_smart_client', description: 'Register SMART OAuth client (client_id, redirect_uris) for sandbox launch' },
  { name: 'start_smart_launch', description: 'Create SMART launch context for a sandbox patient (returns launch token + authorize URL)' },
  { name: 'run_mpi_match', description: 'Run synthetic MPI patient match (returns Parameters + duplicate pair)' },
  { name: 'run_mpi_scenario', description: 'Run MPI sandbox scenario (e.g. mpi_merge_workflow)' },
  { name: 'get_practitioner_credentialing', description: 'Fetch Practitioner + role + VerificationResult fixture bundle' },
  { name: 'run_credentialing_scenario', description: 'Run credentialing sandbox scenario (e.g. credentialing_happy_path)' },
  { name: 'run_aggregator_query', description: 'Submit synthetic aggregator/HIE query; returns consolidated Bundle' },
  { name: 'run_aggregator_scenario', description: 'Run aggregator sandbox scenario (e.g. aggregator_pull_happy_path)' },
  { name: 'get_synthetic_ehr_profile', description: 'Vendor model + endpoints for active connection synthetic EHR' },
  { name: 'list_ehr_base_models', description: 'List Epic/Cerner/Athena base EHR model packs' },
  { name: 'reset_synthetic_ehr_data', description: 'Re-seed VM synthetic EHR store from model pack' },
  { name: 'list_research_packs', description: 'List Research Packs (e.g. medicare_utilization_v1 CMS claims calibration, ptbxl_ecg_v1 ECG cohort)' },
  { name: 'get_research_pack', description: 'Get Research Pack metadata + CMS benchmark snapshot or PTB-XL attribution' },
  { name: 'apply_research_pack', description: 'Apply a Research Pack to the active sandbox connection and remount seed (Medicare only; not PTB-XL)' },
  { name: 'get_research_pack_kpis', description: 'Sandbox claim KPIs for a Research Pack (DRG mix, denial rate, Medicare share)' },
  { name: 'compare_research_pack', description: 'Compare sandbox KPIs to vendored CMS open-data benchmark for a Research Pack' },
  { name: 'list_ptbxl_ecg_records', description: 'List PTB-XL open-data ECG records (superclass filter: NORM/MI/STTC/CD/HYP)' },
  { name: 'get_ptbxl_ecg_record', description: 'Get PTB-XL ECG metadata + suggested conditions (no full waveform samples)' },
  { name: 'get_ptbxl_ecg_waveform_meta', description: 'PTB-XL waveform metadata + truncated lead preview (avoid huge MCP payloads)' },
  { name: 'attach_ptbxl_ecg_exemplar', description: 'Attach a PTB-XL ECG exemplar to a sandbox cardiology patient (research label only)' },
  { name: 'get_connection_developer_doc', description: 'Rendered markdown integration reference for active connection' },
  { name: 'propose_custom_ehr_model', description: 'Ingest doc text/URL and generate a BYOM draft model pack (apply via dashboard review gate)' },
  { name: 'get_connection_credentials', description: 'Read sandbox credentials metadata (webhook URL, secret configured, Docker URL hints). Pass localAppUrl or port for demo-app suggestions.' },
  { name: 'create_sandbox_api_key', description: 'Mint an additional connection-scoped hb_test_* key (requires confirm_action token; plaintext once)' },
  { name: 'list_sandbox_api_keys', description: 'List active sandbox API key metadata for a connection (no plaintext)' },
  { name: 'revoke_sandbox_api_key', description: 'Revoke one sandbox API key by id (requires confirm_action token; blocked if last unless allowLast)' },
  { name: 'set_connection_webhook_url', description: 'Set per-connection webhook URL override for local demo receiver (requires confirm_action token)' },
  { name: 'rotate_connection_webhook_secret', description: 'Rotate connection hbsec_* webhook secret (requires confirm_action token; plaintext once)' },
  { name: 'get_sdk_reference', description: 'Official @hebrah/sdk (Node) reference — install, API surface, MCP-to-SDK mapping. Do not web-search npm.' }
]

export async function callTool(
  auth: McpAuth,
  sessionId: string,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  if (!auth.bootstrap) await checkRateLimit(auth.orgId, name)
  const session = getSession(sessionId)

  // Agent-key (hb_conn_*) sessions: the connection surface only. These
  // forward the agent key to the merged hebrah-api — scopes, metering, and
  // audit attribute to the agent's org.
  if (auth.mode === 'agent') {
    if (!(AGENT_TOOL_NAMES as readonly string[]).includes(name)) {
      throw new Error(
        `${name} requires a dashboard PAT session (hb_pat_*). Agent-key sessions expose the connection tools only: ${AGENT_TOOL_NAMES.join(', ')}`
      )
    }
    switch (name) {
      case 'discover_data_sources':
        return agentApiFetch(auth, '/v1/connections/targets')
      case 'connect_to_data_source': {
        const target = String(args.target_id ?? args.target ?? '').trim()
        if (!target) throw new Error('target_id is required; call discover_data_sources first')
        const rawScopes = args.scopes
        if (!Array.isArray(rawScopes) || rawScopes.length === 0 || rawScopes.some(scope => typeof scope !== 'string')) {
          throw new Error('scopes must be a non-empty string array from the target discovery metadata')
        }
        const result = await agentApiFetch<{ connectionId: string, audit_genesis_hash?: string }>(
          auth,
          '/v1/connections',
          {
            method: 'POST',
            body: JSON.stringify({
              target_id: target,
              scopes: rawScopes,
              tier: args.tier ?? 'container',
              ttl_seconds: args.ttlSeconds ?? args.ttl_seconds ?? 3600
            })
          }
        )
        session.connectConnectionId = result.connectionId
        return {
          ...result,
          note: 'Connection is scoped, TTL-bound, read-only, and audited. Every query appends to the hash-chained audit trail.'
        }
      }
      case 'query_data_source': {
        const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
        const sql = String(args.sql ?? '')
        if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
        if (!sql.trim()) throw new Error('sql is required')
        return agentApiFetch(auth, `/v1/connections/${encodeURIComponent(connectionId)}/query`, {
          method: 'POST',
          body: JSON.stringify({ sql })
        })
      }
      case 'get_data_source_audit': {
        const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
        if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
        return agentApiFetch(auth, `/v1/connections/${encodeURIComponent(connectionId)}/audit`)
      }
      case 'get_connect_usage':
        return agentApiFetch(auth, '/v1/agent/account/usage')
      case 'get_wallet_status':
        return agentApiFetch(auth, '/v1/agent/wallet')
      case 'set_auto_reload': {
        const enabled = Boolean(args.autoReloadEnabled)
        const body: Record<string, unknown> = { auto_reload_enabled: enabled }
        if (args.autoReloadThresholdCents !== undefined) body.auto_reload_threshold_cents = args.autoReloadThresholdCents
        if (args.autoReloadAmountCents !== undefined) body.auto_reload_amount_cents = args.auto_reload_amount_cents ?? args.autoReloadAmountCents
        return agentApiFetch(auth, '/v1/agent/wallet/config', { method: 'POST', body: JSON.stringify(body) })
      }
      case 'create_topup': {
        const amountCents = Number(args.amount_cents ?? 2000)
        if (!amountCents || amountCents < 100) throw new Error('amount_cents must be >= 100 ($1)')
        if (amountCents > 1_000_000) throw new Error('amount_cents must be <= 1,000,000 ($10,000)')
        return agentApiFetch(auth, '/v1/agent/topup', { method: 'POST', body: JSON.stringify({ amount_cents: amountCents }) })
      }
      case 'get_usage_forecast':
        return agentApiFetch(auth, '/v1/agent/wallet')
      case 'revoke_data_source_connection': {
        const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
        if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
        const result = await agentApiFetch<{ connectionId: string, status: string }>(
          auth,
          `/v1/connections/${encodeURIComponent(connectionId)}/revoke`,
          { method: 'POST' }
        )
        if (session.connectConnectionId === connectionId) {
          delete session.connectConnectionId
        }
        return {
          ...result,
          note: 'Connection revoked instantly. Its audit trail remains verifiable.'
        }
      }
      default:
        throw new Error(`Unknown agent tool: ${name}`)
    }
  }

  switch (name) {
    case 'create_account': {
      if (!auth.bootstrap || !config.allowHeadlessSignup) {
        throw new Error('Headless account creation is not currently available on this MCP host.')
      }
      const orgName = String(args.orgName ?? '').trim()
      if (!orgName) throw new Error('orgName is required for create_account')
      const inviteEmail = String(args.inviteEmail ?? '').trim()
      if (inviteEmail && !inviteEmail.includes('@')) {
        throw new Error('inviteEmail must be a valid email if provided')
      }
      const body: Record<string, unknown> = { orgName, headless: true }
      if (args.agentName) body.agentName = String(args.agentName)
      if (inviteEmail) body.inviteEmail = inviteEmail

      const result = await fetch(`${config.hebrahApiUrl}/v1/agent/account`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30_000)
      })
      if (!result.ok) {
        throw new Error(`Agent signup failed (${result.status}): ${await result.text()}`)
      }
      const data = await result.json() as {
        orgId: string
        apiKey: string
        keyPrefix: string
        mcpEndpointUrl: string
        trial: { credits: { queries: number, egressBytes: number }, expires_at: string }
      }
      return {
        orgId: data.orgId,
        apiKey: data.apiKey,
        keyPrefix: data.keyPrefix,
        mcpEndpointUrl: data.mcpEndpointUrl,
        trial: data.trial,
        note: `Agent account created — $1 trial credit (100 queries, 5 MB egress, 7 days). ` +
          `Save the apiKey (${data.keyPrefix}…) now — it is shown once. ` +
          'Reconnect to this MCP server with "Authorization: Bearer <apiKey>" to use the connection tools, or call the agent API directly.'
      }
    }
    case 'discover_data_sources':
      return connectFetch(auth, session, '/v1/targets')
    case 'connect_to_data_source': {
      const target = String(args.target ?? '').trim()
      if (!target) throw new Error('target is required; call discover_data_sources first')
      const rawScopes = args.scopes
      if (!Array.isArray(rawScopes) || rawScopes.length === 0 || rawScopes.some(scope => typeof scope !== 'string')) {
        throw new Error('scopes must be a non-empty string array from the target discovery metadata')
      }
      consumeCredentialConfirmation(args, 'connect_to_data_source', target)
      const result = await connectFetch<{ connection_id: string, target: string, scopes: string[], tier: string, expires_at: string }>(
        auth,
        session,
        '/v1/connections',
        {
          method: 'POST',
          body: JSON.stringify({
            target,
            scopes: rawScopes,
            tier: args.tier ?? 'container',
            ttl_seconds: args.ttlSeconds ?? args.ttl_seconds ?? 3600
          })
        }
      )
      session.connectConnectionId = result.connection_id
      return {
        ...result,
        connectAccountId: session.connectAccountId,
        note: 'Connection is scoped, TTL-bound, read-only in this milestone, and source credentials remain in the relay.'
      }
    }
    case 'query_data_source': {
      const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
      const sql = String(args.sql ?? '')
      if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
      if (!sql.trim()) throw new Error('sql is required')
      return connectFetch(auth, session, `/v1/connections/${encodeURIComponent(connectionId)}/query`, {
        method: 'POST',
        body: JSON.stringify({ sql })
      })
    }
    case 'get_data_source_audit': {
      const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
      if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
      return connectFetch(auth, session, `/v1/connections/${encodeURIComponent(connectionId)}/audit`)
    }
    case 'get_connect_usage':
      return connectFetch(auth, session, '/v1/account/usage')
    case 'revoke_data_source_connection': {
      const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
      if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
      consumeCredentialConfirmation(args, 'revoke_data_source_connection', connectionId)
      const result = await connectFetch<{ connection_id: string, status: string }>(
        auth,
        session,
        `/v1/connections/${encodeURIComponent(connectionId)}/revoke`,
        { method: 'POST' }
      )
      if (session.connectConnectionId === connectionId) session.connectConnectionId = undefined
      return result
    }
    case 'set_active_connection': {
      session.activeConnectionId = String(args.connectionId)
      const list = await dashboardFetch<{ connections: Array<{ id: string, environment: string, name: string }> }>(
        auth.pat,
        '/api/connections?includeHidden=true'
      )
      const conn = list.connections.find(c => c.id === session.activeConnectionId)
      return {
        activeConnectionId: session.activeConnectionId,
        connection: conn,
        note: 'All edits apply to Sandbox. Promote-to-Live (create_promotion) requires a Pro plan; get_account_status returns canPromoteToLive.'
      }
    }
    case 'get_account_status':
      return dashboardFetch(auth.pat, '/api/org/status')
    case 'list_connections':
      return dashboardFetch(auth.pat, '/api/connections?includeHidden=true')
    case 'create_connection': {
      assertMcpConnectionActionAllowed(auth.mcpAcl, 'creation')
      const name = String(args.name ?? '').trim()
      if (!name) {
        throw new Error('name is required for create_connection')
      }
      const ehrVendor = String(args.ehrVendor ?? args.ehr_vendor ?? '').trim()
      if (!ehrVendor) {
        throw new Error('ehrVendor is required for create_connection (Epic, Cerner, or Athena). Call list_ehr_base_models for the catalog.')
      }
      const allowed = ['Epic', 'Cerner', 'Athena']
      const normalized = allowed.find(v => v.toLowerCase() === ehrVendor.toLowerCase())
      if (!normalized) {
        throw new Error(`ehrVendor must be one of: ${allowed.join(', ')}`)
      }
      const body: Record<string, unknown> = { name, ehrVendor: normalized }
      if (args.dataFormat) body.dataFormat = args.dataFormat
      if (args.resourceTypes) body.resourceTypes = args.resourceTypes
      const result = await dashboardFetch<{
        sandboxConnectionId: string
        liveConnectionId: string
        provisioningUrl: string
      }>(auth.pat, '/api/connections/sandbox', {
        method: 'POST',
        body: JSON.stringify(body)
      })
      session.activeConnectionId = result.sandboxConnectionId
      return {
        ...result,
        activeConnectionId: result.sandboxConnectionId,
        note: 'Sandbox connection set as active context. Edits apply to Sandbox only.'
      }
    }
    case 'pause_connection': {
      assertMcpConnectionActionAllowed(auth.mcpAcl, 'pause')
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      if (!id) {
        throw new Error('connectionId is required for pause_connection')
      }
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/pause`, {
        method: 'PATCH'
      })
    }
    case 'resume_connection': {
      assertMcpConnectionActionAllowed(auth.mcpAcl, 'pause')
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      if (!id) {
        throw new Error('connectionId is required for resume_connection')
      }
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/resume`, {
        method: 'PATCH'
      })
    }
    case 'remove_connection': {
      assertMcpConnectionActionAllowed(auth.mcpAcl, 'removal')
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      if (!id) {
        throw new Error('connectionId is required for remove_connection')
      }
      const token = String(args.confirmationToken ?? '')
      const intent = String(args.humanIntentMessage ?? '')
      if (!intent.trim()) {
        throw new Error('humanIntentMessage required to remove a connection')
      }
      consumeConfirmationToken(token, 'remove_connection', id)
      const result = await dashboardFetch<{ removedConnectionIds: string[] }>(
        auth.pat,
        `/api/connections/${encodeURIComponent(id)}`,
        { method: 'DELETE' }
      )
      if (session.activeConnectionId && result.removedConnectionIds.includes(session.activeConnectionId)) {
        session.activeConnectionId = undefined
      }
      return result
    }
    case 'get_connection_mapping': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/mapping`)
    }
    case 'update_connection_mapping': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/mapping`, {
        method: 'PUT',
        body: JSON.stringify({ mappings: args.mappings })
      })
    }
    case 'list_config_versions': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/versions`)
    }
    case 'create_config_version': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/versions`, {
        method: 'POST',
        body: JSON.stringify({ source: 'mcp' })
      })
    }
    case 'create_promotion': {
      await assertPromoteToLiveAllowed(auth.pat)
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/promotions`, {
        method: 'POST',
        body: JSON.stringify({
          toVersionId: args.toVersionId,
          title: args.title,
          description: args.description,
          submit: args.submit ?? true
        })
      })
    }
    case 'get_promotion': {
      await assertPromoteToLiveAllowed(auth.pat)
      const connId = String(args.connectionId ?? session.activeConnectionId ?? '')
      const prId = String(args.promotionId ?? '')
      return dashboardFetch(
        auth.pat,
        `/api/connections/${encodeURIComponent(connId)}/promotions/${encodeURIComponent(prId)}`
      )
    }
    case 'confirm_action': {
      const action = String(args.action ?? (args.promotionId ? 'approve_promotion' : args.connectionId ? 'remove_connection' : ''))

      if (CREDENTIAL_CONFIRM_ACTIONS.has(action as ConfirmationAction)) {
        const credentialAction = action as ConfirmationAction
        const connectionId = String(args.connectionId ?? session.activeConnectionId ?? '')
        if (!connectionId && credentialAction !== 'connect_to_data_source') {
          throw new Error(`connectionId required for confirm_action(${credentialAction})`)
        }

        let targetId = connectionId
        if (credentialAction === 'connect_to_data_source') {
          targetId = String(args.target ?? '')
          if (!targetId) throw new Error('target required for confirm_action(connect_to_data_source)')
        }
        let keyId: string | undefined
        if (credentialAction === 'revoke_sandbox_api_key') {
          keyId = String(args.keyId ?? args.key_id ?? '')
          if (!keyId) {
            throw new Error('keyId required for confirm_action(revoke_sandbox_api_key)')
          }
          targetId = revokeConfirmationTarget(connectionId, keyId)
        }

        const token = issueConfirmationToken(credentialAction, targetId)
        return {
          confirmationToken: token,
          expiresInSeconds: 300,
          action: credentialAction,
          ...(connectionId ? { connectionId } : {}),
          ...(credentialAction === 'connect_to_data_source' ? { target: targetId } : {}),
          ...(keyId ? { keyId } : {}),
          message: `Pass confirmationToken and humanIntentMessage to ${credentialAction}.`
        }
      }

      if (action === 'remove_connection') {
        assertMcpConnectionActionAllowed(auth.mcpAcl, 'removal')
        const connectionId = String(args.connectionId ?? session.activeConnectionId ?? '')
        if (!connectionId) {
          throw new Error('connectionId required for confirm_action(remove_connection)')
        }
        const token = issueConfirmationToken('remove_connection', connectionId)
        return {
          confirmationToken: token,
          expiresInSeconds: 300,
          action: 'remove_connection',
          connectionId,
          message: 'Pass confirmationToken and humanIntentMessage to remove_connection.'
        }
      }

      await assertPromoteToLiveAllowed(auth.pat)
      const promotionId = String(args.promotionId ?? '')
      if (!promotionId) {
        throw new Error(
          'promotionId required for confirm_action(approve_promotion), or pass action with connectionId for credential writes or remove_connection'
        )
      }
      const token = issueConfirmationToken('approve_promotion', promotionId)
      return {
        confirmationToken: token,
        expiresInSeconds: 300,
        action: 'approve_promotion',
        promotionId,
        message: 'Pass confirmationToken to approve_promotion with human-intent acknowledgment.'
      }
    }
    case 'approve_promotion': {
      await assertPromoteToLiveAllowed(auth.pat)
      const connId = String(args.connectionId ?? session.activeConnectionId ?? '')
      const prId = String(args.promotionId ?? '')
      const token = String(args.confirmationToken ?? '')
      const intent = String(args.humanIntentMessage ?? '')
      if (!intent.trim()) {
        throw new Error('humanIntentMessage required to approve a Live promotion')
      }
      consumeConfirmationToken(token, 'approve_promotion', prId)
      await checkPromotionApproveLimit(auth.orgId)
      return dashboardFetch(
        auth.pat,
        `/api/connections/${encodeURIComponent(connId)}/promotions/${encodeURIComponent(prId)}/approve`,
        { method: 'POST', body: JSON.stringify({ humanIntentMessage: intent }) }
      )
    }
    case 'reject_promotion': {
      await assertPromoteToLiveAllowed(auth.pat)
      const connId = String(args.connectionId ?? session.activeConnectionId ?? '')
      const prId = String(args.promotionId ?? '')
      return dashboardFetch(
        auth.pat,
        `/api/connections/${encodeURIComponent(connId)}/promotions/${encodeURIComponent(prId)}/reject`,
        { method: 'POST', body: JSON.stringify({ comment: args.comment }) }
      )
    }
    case 'get_live_deployment': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/deployment`)
    }
    case 'get_sandbox_catalog': {
      const connectionId = args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/catalog${q}`)
    }
    case 'trigger_test_webhook': {
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const body: Record<string, unknown> = {
        event: args.event ?? 'patient.admitted',
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      if (connectionId) {
        body.connection_id = connectionId
      }
      if (args.scenario_id ?? args.scenarioId) {
        body.scenario_id = args.scenario_id ?? args.scenarioId
      }
      if (args.domain_id ?? args.domainId) {
        body.domain_id = args.domain_id ?? args.domainId
      }
      return ultraFetch('/v1/webhooks/trigger-mock-event', {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'list_sandbox_domains':
      return ultraFetch('/v1/sandbox/domains')
    case 'get_sandbox_domain':
      return ultraFetch(`/v1/sandbox/domains/${encodeURIComponent(String(args.domainId ?? args.domain_id ?? ''))}`)
    case 'get_synthetic_resource': {
      const resourceType = String(args.resourceType ?? args.resource_type ?? '')
      const resourceId = String(args.resourceId ?? args.resource_id ?? '')
      const patientId = args.patientId ?? args.patient_id
      const q = patientId ? `?patient_id=${encodeURIComponent(String(patientId))}` : ''
      return ultraFetch(
        `/v1/sandbox/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}${q}`
      )
    }
    case 'run_sandbox_scenario': {
      const scenarioId = String(args.scenarioId ?? args.scenario_id ?? '')
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) {
        body.connection_id = connectionId
      }
      if (args.delay_seconds !== undefined || args.delaySeconds !== undefined) {
        body.delay_seconds = args.delay_seconds ?? args.delaySeconds
      }
      return ultraFetch(`/v1/sandbox/scenarios/${encodeURIComponent(scenarioId)}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'get_payer_rules':
      return ultraFetch(`/v1/sandbox/payer-rules/${encodeURIComponent(String(args.payerId ?? args.payer_id ?? 'payer_aetna'))}`)
    case 'list_sandbox_events': {
      const catalog = await ultraFetch<{ event_groups?: Record<string, string[]> }>('/v1/sandbox/catalog')
      return catalog.event_groups ?? {}
    }
    case 'list_hl7_templates':
      return ultraFetch('/v1/sandbox/hl7/templates')
    case 'inject_hl7': {
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01',
        deliver: args.deliver ?? true
      }
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) {
        body.connection_id = connectionId
      }
      if (args.template_id ?? args.templateId) {
        body.template_id = args.template_id ?? args.templateId
      }
      if (args.message) {
        body.message = args.message
      }
      if (args.event) {
        body.event = args.event
      }
      return ultraFetch('/v1/sandbox/hl7/inject', {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'sidecar_writeback': {
      const url = String(args.url ?? process.env.SIDECAR_WRITEBACK_URL ?? '')
      if (!url) {
        throw new Error('url argument or SIDECAR_WRITEBACK_URL env required for sidecar_writeback')
      }
      const action = String(args.action ?? 'chart-note')
      const endpoint = `${url.replace(/\/$/, '')}/v1/writeback/${action}`
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01',
          ...(typeof args.body === 'object' && args.body ? args.body : {})
        })
      })
      if (!res.ok) {
        throw new Error(`sidecar write-back failed (${res.status}): ${await res.text()}`)
      }
      return res.json()
    }
    case 'run_hl7_flight_check': {
      const vmId = String(args.vmId ?? args.vm_id ?? '')
      if (!vmId) {
        throw new Error('vmId required for run_hl7_flight_check')
      }
      const config = await import('./config.js').then(m => m.config)
      const secret = config.orchestratorSecret || process.env.ORCHESTRATOR_SECRET
      if (!secret) {
        throw new Error('ORCHESTRATOR_SECRET required on hebrah-mcp-host for run_hl7_flight_check')
      }
      const orchUrl = config.orchestratorUrl
      const res = await fetch(`${orchUrl}/v1/vms/${encodeURIComponent(vmId)}/hl7-probe`, {
        method: 'POST',
        headers: { 'X-Orchestrator-Secret': secret }
      })
      if (!res.ok) {
        throw new Error(`hl7-probe failed (${res.status}): ${await res.text()}`)
      }
      return res.json()
    }
    case 'list_webhook_deliveries': {
      const params = new URLSearchParams()
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) params.set('connection_id', String(connectionId))
      if (args.status) params.set('status', String(args.status))
      if (args.limit) params.set('limit', String(args.limit))
      const q = params.toString() ? `?${params.toString()}` : ''
      return ultraFetch(`/v1/webhooks/deliveries${q}`)
    }
    case 'replay_webhook_delivery': {
      const deliveryId = String(args.delivery_id ?? args.deliveryId ?? '')
      if (!deliveryId) throw new Error('deliveryId required')
      return ultraFetch(`/v1/webhooks/deliveries/${encodeURIComponent(deliveryId)}/replay`, {
        method: 'POST'
      })
    }
    case 'configure_webhook_reliability': {
      return ultraFetch('/v1/sandbox/webhook-reliability', {
        method: 'PATCH',
        body: JSON.stringify({
          mode: args.mode ?? 'healthy',
          fail_rate: args.fail_rate ?? args.failRate ?? 0,
          latency_ms: args.latency_ms ?? args.latencyMs ?? 0,
          status_code: args.status_code ?? args.statusCode ?? null
        })
      })
    }
    case 'run_webhook_reliability_scenario': {
      const scenarioId = String(args.scenario_id ?? args.scenarioId ?? 'webhook_transient_recovery')
      const profileMode = args.mode ?? 'transient_503'
      await ultraFetch('/v1/sandbox/webhook-reliability', {
        method: 'PATCH',
        body: JSON.stringify({ mode: profileMode, fail_rate: 0.8 })
      })
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      if (connectionId) body.connection_id = connectionId
      return ultraFetch(`/v1/sandbox/scenarios/${encodeURIComponent(scenarioId)}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'register_smart_client':
      return dashboardFetch(auth.pat, '/api/smart/clients', {
        method: 'POST',
        body: JSON.stringify({
          client_id: args.client_id ?? args.clientId,
          name: args.name ?? 'MCP SMART client',
          redirect_uris: args.redirect_uris ?? args.redirectUris ?? []
        })
      })
    case 'start_smart_launch':
      return dashboardFetch(auth.pat, '/api/smart/launch', {
        method: 'POST',
        body: JSON.stringify({
          patient_id: args.patient_id ?? args.patientId,
          encounter_id: args.encounter_id ?? args.encounterId ?? null,
          smart_app_url: args.smart_app_url ?? args.smartAppUrl ?? null
        })
      })
    case 'run_mpi_match':
      return ultraFetch('/v1/sandbox/mpi/match', {
        method: 'POST',
        body: JSON.stringify({
          first_name: args.first_name ?? args.firstName,
          last_name: args.last_name ?? args.lastName,
          birth_date: args.birth_date ?? args.birthDate,
          identifier: args.identifier
        })
      })
    case 'run_mpi_scenario': {
      const scenarioId = String(args.scenarioId ?? args.scenario_id ?? 'mpi_duplicate_resolution')
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) body.connection_id = connectionId
      return ultraFetch(`/v1/sandbox/scenarios/${encodeURIComponent(scenarioId)}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'get_practitioner_credentialing': {
      const practitionerId = String(args.practitioner_id ?? args.practitionerId ?? 'prac_01')
      const params = new URLSearchParams()
      if (args.include_role === false) params.set('include_role', 'false')
      if (args.include_verification === false) params.set('include_verification', 'false')
      const q = params.toString() ? `?${params.toString()}` : ''
      return ultraFetch(`/v1/sandbox/credentialing/practitioners/${encodeURIComponent(practitionerId)}${q}`)
    }
    case 'run_credentialing_scenario': {
      const scenarioId = String(args.scenarioId ?? args.scenario_id ?? 'credentialing_verify_practitioner')
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) body.connection_id = connectionId
      return ultraFetch(`/v1/sandbox/scenarios/${encodeURIComponent(scenarioId)}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'run_aggregator_query':
      return ultraFetch('/v1/sandbox/aggregator/query', {
        method: 'POST',
        body: JSON.stringify({
          patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01',
          include_consent: args.include_consent ?? args.includeConsent ?? true,
          include_provenance: args.include_provenance ?? args.includeProvenance ?? true
        })
      })
    case 'run_aggregator_scenario': {
      const scenarioId = String(args.scenarioId ?? args.scenario_id ?? 'aggregator_query_bundle')
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) body.connection_id = connectionId
      return ultraFetch(`/v1/sandbox/scenarios/${encodeURIComponent(scenarioId)}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'get_synthetic_ehr_profile': {
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/synthetic-ehr/profile${q}`)
    }
    case 'list_ehr_base_models':
      return ultraFetch('/v1/sandbox/ehr-models')
    case 'reset_synthetic_ehr_data': {
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/synthetic-ehr/reset${q}`, { method: 'POST' })
    }
    case 'list_research_packs':
      return ultraFetch('/v1/sandbox/research-packs')
    case 'get_research_pack': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      return ultraFetch(`/v1/sandbox/research-packs/${encodeURIComponent(packId)}`)
    }
    case 'apply_research_pack': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/research-packs/${encodeURIComponent(packId)}/apply${q}`, {
        method: 'POST'
      })
    }
    case 'get_research_pack_kpis': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/research-packs/${encodeURIComponent(packId)}/kpis${q}`)
    }
    case 'compare_research_pack': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/research-packs/${encodeURIComponent(packId)}/compare${q}`)
    }
    case 'list_ptbxl_ecg_records': {
      const params = new URLSearchParams()
      const superclass = args.superclass ?? args.superClass
      if (superclass) params.set('superclass', String(superclass))
      if (args.sex != null) params.set('sex', String(args.sex))
      if (args.fold != null) params.set('fold', String(args.fold))
      if (args.limit != null) params.set('limit', String(args.limit))
      if (args.offset != null) params.set('offset', String(args.offset))
      const qs = params.toString()
      return ultraFetch(`/v1/sandbox/research-packs/ptbxl_ecg_v1/records${qs ? `?${qs}` : ''}`)
    }
    case 'get_ptbxl_ecg_record': {
      const ecgId = args.ecg_id ?? args.ecgId
      if (ecgId == null) throw new Error('ecg_id required for get_ptbxl_ecg_record')
      return ultraFetch(`/v1/sandbox/research-packs/ptbxl_ecg_v1/records/${encodeURIComponent(String(ecgId))}`)
    }
    case 'get_ptbxl_ecg_waveform_meta': {
      const ecgId = args.ecg_id ?? args.ecgId
      if (ecgId == null) throw new Error('ecg_id required for get_ptbxl_ecg_waveform_meta')
      const wave = await ultraFetch<{
        ecg_id?: number
        fs?: number
        duration_s?: number
        lead_order?: string[]
        leads?: Record<string, number[]>
        disclaimer?: string
        attribution?: string
      }>(`/v1/sandbox/research-packs/ptbxl_ecg_v1/records/${encodeURIComponent(String(ecgId))}/waveform`)
      const preview: Record<string, number[]> = {}
      for (const [lead, samples] of Object.entries(wave.leads || {})) {
        preview[lead] = Array.isArray(samples) ? samples.slice(0, 8) : []
      }
      return {
        pack_id: 'ptbxl_ecg_v1',
        ecg_id: wave.ecg_id,
        fs: wave.fs,
        duration_s: wave.duration_s,
        lead_order: wave.lead_order,
        lead_sample_counts: Object.fromEntries(
          Object.entries(wave.leads || {}).map(([k, v]) => [k, Array.isArray(v) ? v.length : 0])
        ),
        lead_preview_first_8: preview,
        waveform_path: `/v1/sandbox/research-packs/ptbxl_ecg_v1/records/${encodeURIComponent(String(ecgId))}/waveform`,
        disclaimer: wave.disclaimer,
        attribution: wave.attribution,
        note: 'Full samples omitted for MCP payload size. Use waveform_path via API/UI viewer.'
      }
    }
    case 'attach_ptbxl_ecg_exemplar': {
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const patientId = args.patient_id ?? args.patientId
      const ecgId = args.ecg_id ?? args.ecgId
      if (!patientId || ecgId == null) {
        throw new Error('patient_id and ecg_id required for attach_ptbxl_ecg_exemplar')
      }
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(`/v1/sandbox/research-packs/ptbxl_ecg_v1/attach${q}`, {
        method: 'POST',
        body: JSON.stringify({
          patient_id: String(patientId),
          ecg_id: ecgId,
          connection_id: connectionId ? String(connectionId) : undefined
        })
      })
    }
    case 'get_connection_developer_doc': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!id) throw new Error('connectionId required for get_connection_developer_doc')
      return dashboardFetch(auth.pat, `/api/connections/${encodeURIComponent(id)}/developer-doc`)
    }
    case 'get_connection_credentials': {
      const connectionId = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!connectionId) {
        throw new Error('connectionId required for get_connection_credentials')
      }

      const localAppUrl = String(args.localAppUrl ?? args.local_app_url ?? '').trim()
      const query = localAppUrl
        ? `?localAppUrl=${encodeURIComponent(localAppUrl)}`
        : ''

      const credentials = await dashboardFetch<Record<string, unknown>>(
        auth.pat,
        `/api/connections/${encodeURIComponent(connectionId)}/credentials${query}`
      )

      const urlInput = parseLocalAppUrlFromArgs(args)
      const suggestions = Object.keys(urlInput).length > 0
        ? suggestedWebhookUrls(urlInput)
        : undefined

      const note = credentials.webhookUrlNeedsDockerFix
        ? 'hebrah-api in Docker cannot POST to localhost on the host. Use suggestedWebhookUrls.docker or set deliveryTarget=docker when calling set_connection_webhook_url.'
        : undefined

      return {
        ...credentials,
        ...(suggestions ? { suggestedWebhookUrls: suggestions } : {}),
        ...(note ? { note } : {})
      }
    }
    case 'set_connection_webhook_url': {
      const connectionId = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!connectionId) {
        throw new Error('connectionId required for set_connection_webhook_url')
      }

      consumeCredentialConfirmation(args, 'set_connection_webhook_url', connectionId)

      const body: Record<string, unknown> = {}
      if (args.inheritDefault === true || args.inherit_default === true) {
        body.inheritDefault = true
      } else {
        body.inheritDefault = false
        body.webhookUrl = resolveWebhookUrlFromSetArgs(args)
      }

      const result = await dashboardFetch<{
        effective?: { webhookUrl?: string | null }
      }>(auth.pat, `/api/connections/${encodeURIComponent(connectionId)}/webhook`, {
        method: 'POST',
        body: JSON.stringify(body)
      })

      return {
        connectionId,
        webhookUrl: body.webhookUrl,
        effectiveWebhookUrl: result.effective?.webhookUrl ?? body.webhookUrl,
        note: 'Connection webhook override saved. Use trigger_test_webhook to verify delivery to your local receiver.'
      }
    }
    case 'get_sdk_reference': {
      const connectionId = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '').trim()
      return buildSdkReference(connectionId || undefined)
    }
    case 'propose_custom_ehr_model': {
      const connectionId = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!connectionId) throw new Error('connectionId required for propose_custom_ehr_model')
      const ingestBody: Record<string, unknown> = {}
      if (args.url) ingestBody.url = String(args.url)
      if (args.text) ingestBody.text = String(args.text)
      if (!ingestBody.url && !ingestBody.text) {
        throw new Error('text or url required for propose_custom_ehr_model')
      }
      const ingestJson = await dashboardFetch<{ chunk_id: string }>(
        auth.pat,
        `/api/connections/${encodeURIComponent(connectionId)}/byom/ingest`,
        { method: 'POST', body: JSON.stringify(ingestBody) }
      )
      const generated = await dashboardFetch<Record<string, unknown>>(
        auth.pat,
        `/api/connections/${encodeURIComponent(connectionId)}/byom/generate`,
        {
          method: 'POST',
          body: JSON.stringify({ docChunkIds: [ingestJson.chunk_id] })
        }
      )
      return {
        ...generated,
        note: 'Draft only. Apply via dashboard Developer Docs BYOM panel with confirm token.'
      }
    }
    case 'create_sandbox_api_key': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!id) throw new Error('connectionId required for create_sandbox_api_key')
      consumeCredentialConfirmation(args, 'create_sandbox_api_key', id)
      const body: Record<string, unknown> = {}
      if (args.label !== undefined) body.label = args.label
      const result = await dashboardFetch<{
        sandboxApiKey: string
        key: { id: string, keyPrefix: string, environment: string, createdAt: string, label: string | null }
        note?: string
      }>(auth.pat, `/api/connections/${encodeURIComponent(id)}/credentials/keys`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
      return {
        ...result,
        connectionId: id,
        note: result.note
          ?? 'Plaintext is shown once — write HEBRAH_SANDBOX_API_KEY to your local demo .env immediately.'
      }
    }
    case 'list_sandbox_api_keys': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!id) throw new Error('connectionId required for list_sandbox_api_keys')
      const creds = await dashboardFetch<{
        connectionId: string
        activeKeys?: Array<{ id: string, keyPrefix: string, environment: string, createdAt: string, label?: string | null }>
        activeKey: { id: string, keyPrefix: string, environment: string, createdAt: string, label?: string | null } | null
        webhookUrl: string | null
        webhookSecretConfigured: boolean
        webhookSecretMasked: string | null
      }>(auth.pat, `/api/connections/${encodeURIComponent(id)}/credentials`)
      return {
        connectionId: creds.connectionId,
        activeKeys: creds.activeKeys ?? (creds.activeKey ? [creds.activeKey] : []),
        webhookUrl: creds.webhookUrl,
        webhookSecretConfigured: creds.webhookSecretConfigured,
        webhookSecretMasked: creds.webhookSecretMasked,
        note: 'Metadata only — plaintext keys are never re-fetched.'
      }
    }
    case 'revoke_sandbox_api_key': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      const keyId = String(args.keyId ?? args.key_id ?? '')
      if (!id) throw new Error('connectionId required for revoke_sandbox_api_key')
      if (!keyId) throw new Error('keyId required for revoke_sandbox_api_key')
      consumeCredentialConfirmation(args, 'revoke_sandbox_api_key', revokeConfirmationTarget(id, keyId))
      const body: Record<string, unknown> = {}
      if (args.allowLast === true || args.allow_last === true) body.allowLast = true
      return dashboardFetch(
        auth.pat,
        `/api/connections/${encodeURIComponent(id)}/credentials/keys/${encodeURIComponent(keyId)}/revoke`,
        { method: 'POST', body: JSON.stringify(body) }
      )
    }
    case 'rotate_connection_webhook_secret': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!id) throw new Error('connectionId required for rotate_connection_webhook_secret')
      consumeCredentialConfirmation(args, 'rotate_connection_webhook_secret', id)
      const result = await dashboardFetch<{
        webhookSecret: string
        note?: string
        effective?: { webhookUrl: string | null }
      }>(auth.pat, `/api/connections/${encodeURIComponent(id)}/webhook/rotate-secret`, {
        method: 'POST'
      })
      return {
        ...result,
        connectionId: id,
        note: result.note
          ?? 'Plaintext is shown once — write HEBRAH_WEBHOOK_SECRET to your local demo .env immediately.'
      }
    }
    default:
      throw new Error(`Unknown tool: ${name}`)
  }
}

const PAT_VALIDATE_TIMEOUT_MS = 10_000

export async function validatePat(pat: string) {
  let res: Response
  try {
    res = await fetch(`${config.dashboardUrl}/api/internal/mcp/validate-pat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-hebrah-mcp-internal-secret': config.mcpInternalSecret
      },
      body: JSON.stringify({ token: pat }),
      signal: AbortSignal.timeout(PAT_VALIDATE_TIMEOUT_MS)
    })
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    console.error(`[hebrah-mcp-host] PAT validation unreachable (${config.dashboardUrl}):`, detail)
    throw new Error(
      `Dashboard unreachable at ${config.dashboardUrl}. Start hebrah-app (pnpm dev in hebrah-app/) and reload MCP in Cursor.`
    )
  }

  if (!res.ok) return null
  const data = await res.json() as { orgId: string, tokenId: string, scopes: string[], mcpAcl?: Partial<McpAcl> }
  return {
    orgId: data.orgId,
    tokenId: data.tokenId,
    scopes: data.scopes,
    mcpAcl: normalizeMcpAcl(data.mcpAcl)
  }
}