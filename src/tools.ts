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
import { listToolInputSchema } from './toolSchemas.js'
import {
  assertSafeWebhookOrCallbackUrl,
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

const MAX_SESSIONS = 1_000

const sessions = new Map<string, {
  activeConnectionId?: string
  connectApiKey?: string
  connectAccountId?: string
  connectConnectionId?: string
  activeEnvironmentId?: string
}>()

export function getSession(sessionId: string) {
  let existing = sessions.get(sessionId)
  if (!existing) {
    while (sessions.size >= MAX_SESSIONS) {
      const oldest = sessions.keys().next().value
      if (!oldest) break
      sessions.delete(oldest)
    }
    existing = {}
    sessions.set(sessionId, existing)
  }
  return existing
}

export function deleteSession(sessionId: string) {
  sessions.delete(sessionId)
}

const SAFE_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/

/**
 * Validate path-segment identifiers to prevent path traversal (`..`, `/`),
 * query injection, or empty path segments (`//`).
 */
export function safeId(value: unknown, fieldName: string): string {
  const trimmed = String(value ?? '').trim()
  if (!trimmed) {
    throw new Error(`${fieldName} is required`)
  }
  if (!SAFE_ID_RE.test(trimmed) || trimmed.includes('..')) {
    throw new Error(`Invalid ${fieldName}: must match [A-Za-z0-9._:-]{1,128}`)
  }
  return encodeURIComponent(trimmed)
}

function isPrivateOrMetadataHost(hostname: string): { isMetadata: boolean, isPrivateOrLoopback: boolean } {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const isMetadata =
    lower === 'metadata.google.internal' ||
    lower === 'metadata' ||
    lower === '169.254.169.254' ||
    lower.startsWith('169.254.') ||
    lower.startsWith('fe80:') ||
    lower === '0.0.0.0'

  const isLoopback =
    lower === 'localhost' ||
    lower === '127.0.0.1' ||
    lower.startsWith('127.') ||
    lower === '::1' ||
    lower === '0:0:0:0:0:0:0:1'

  let isRfc1918 = false
  const ipv4Match = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (ipv4Match) {
    const a = Number(ipv4Match[1])
    const b = Number(ipv4Match[2])
    if (a === 10) isRfc1918 = true
    else if (a === 172 && b >= 16 && b <= 31) isRfc1918 = true
    else if (a === 192 && b === 168) isRfc1918 = true
    else if (a === 100 && b >= 64 && b <= 127) isRfc1918 = true
  }
  if (
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.local')
  ) {
    isRfc1918 = true
  }

  return { isMetadata, isPrivateOrLoopback: isLoopback || isRfc1918 }
}

/**
 * Guard `sidecar_writeback` URLs against Server-Side Request Forgery (SSRF)
 * targeting cloud metadata endpoints or internal VPC services.
 */
export function assertSafeSidecarUrl(rawUrl: string): string {
  let parsed: URL
  try {
    parsed = new URL(rawUrl.trim())
  } catch {
    throw new Error('Invalid sidecar URL')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Sidecar URL must use http:// or https://')
  }
  if (parsed.username || parsed.password) {
    throw new Error('Sidecar URL must not contain embedded credentials')
  }
  const { isMetadata, isPrivateOrLoopback } = isPrivateOrMetadataHost(parsed.hostname)
  if (isMetadata) {
    throw new Error('Sidecar URL blocked: cloud metadata and link-local addresses are prohibited')
  }
  const isHostedCloud = Boolean(process.env.K_SERVICE || process.env.NODE_ENV === 'production')
  const configuredSidecar = (process.env.SIDECAR_WRITEBACK_URL ?? '').trim().replace(/\/$/, '')
  const normalizedOriginPath = parsed.origin + parsed.pathname.replace(/\/$/, '')
  if (isHostedCloud && isPrivateOrLoopback && (!configuredSidecar || normalizedOriginPath !== configuredSidecar)) {
    throw new Error('Sidecar URL blocked: private or loopback addresses are not allowed on hosted MCP')
  }
  return normalizedOriginPath
}

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\bhb_(?:live|test|pat|conn|claim)_[A-Za-z0-9_-]+/g, 'hb_[REDACTED]'],
  [/\bhbsec_[A-Za-z0-9_-]+/g, 'hbsec_[REDACTED]'],
  [/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]+/g, 'sk_[REDACTED]'],
  [/\bwhsec_[A-Za-z0-9]+/g, 'whsec_[REDACTED]'],
  [/\benc:v1:[A-Za-z0-9+/=_:-]+/g, 'enc:v1:[REDACTED]'],
  [/(Authorization\s*:\s*Bearer\s+)[^\s"',;]+/gi, '$1[REDACTED]'],
  [/(Bearer\s+)(?:hb_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/gi, '$1[REDACTED]'],
  [/(PrivateKey\s*=\s*)[^\s\r\n]+/gi, '$1[REDACTED]']
]

export function redactSecrets(text: string): string {
  let out = text
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement)
  }
  if (config.mcpInternalSecret && config.mcpInternalSecret.length >= 8 && out.includes(config.mcpInternalSecret)) {
    out = out.split(config.mcpInternalSecret).join('[REDACTED_INTERNAL_SECRET]')
  }
  if (config.orchestratorSecret && config.orchestratorSecret.length >= 8 && out.includes(config.orchestratorSecret)) {
    out = out.split(config.orchestratorSecret).join('[REDACTED_ORCHESTRATOR_SECRET]')
  }
  return out
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
        throw new Error(redactSecrets(`Hebrah Connect account creation failed (${response.status}): ${await response.text()}`))
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
    throw new Error(redactSecrets(`Hebrah Connect ${path} failed (${response.status}): ${await response.text()}`))
  }
  return response.json() as Promise<T>
}

async function ultraFetch<T>(orgId: string, path: string, init?: RequestInit): Promise<T> {
  const key = config.sandboxApiKey
  if (!key.startsWith('hb_test_')) {
    throw new Error('HEBRAH_SANDBOX_API_KEY must be set on hebrah-mcp-host for hebrah-api tools')
  }
  const res = await fetch(`${config.hebrahApiUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`,
      ...(orgId ? { 'X-Hebrah-Org-Id': orgId } : {}),
      ...(init?.headers ?? {})
    },
    signal: init?.signal ?? AbortSignal.timeout(30_000)
  })
  if (!res.ok) {
    throw new Error(redactSecrets(`hebrah-api ${path} failed (${res.status}): ${await res.text()}`))
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
    throw new Error(redactSecrets(message))
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
  'get_usage_forecast',
  'env_list',
  'env_create',
  'env_consult_architect',
  'hebrah_consult_architect',
  'env_admit_patients',
  'env_connect',
  'env_get',
  'env_list_tables',
  'env_query_db',
  'env_record_outcome',
  'env_trigger_scenario',
  'env_list_patients',
  'env_get_patient_chart',
  'env_get_logs',
  'env_pause',
  'env_resume',
  'env_consult_studio',
  'env_search_clinical_evidence'
] as const

export const agentToolDefinitions = [
  { name: 'discover_data_sources', description: 'List every connector target with required scopes, tiers, and health', inputSchema: listToolInputSchema('discover_data_sources') },
  {
    name: 'connect_to_data_source',
    description: 'Open a scoped, TTL-bound connection to a target (target_id + scopes from discovery); the agent never receives the source credential',
    inputSchema: {
      type: 'object',
      required: ['target_id', 'scopes'],
      properties: {
        target_id: { type: 'string', description: 'Target id from discover_data_sources' },
        scopes: { type: 'array', items: { type: 'string' }, description: 'Exact required scopes from discovery' },
        tier: { type: 'string', enum: ['container', 'vm'] },
        ttl_seconds: { type: 'number', minimum: 60, maximum: 86400 }
      }
    }
  },
  {
    name: 'query_data_source',
    description: 'Run one read-only, scope-enforced query; returns rows, cost_cents, bytes_egressed, and audit_event_id',
    inputSchema: listToolInputSchema('query_data_source')
  },
  { name: 'get_data_source_audit', description: 'Read the hash-chained audit events for a connection', inputSchema: listToolInputSchema('get_data_source_audit') },
  { name: 'get_connect_usage', description: 'Read trial quota, remaining queries/egress, and wallet balance', inputSchema: listToolInputSchema('get_connect_usage') },
  { name: 'get_wallet_status', description: 'Read wallet balance, auto-reload config, 30-day burn rate, and projected runway', inputSchema: listToolInputSchema('get_wallet_status') },
  {
    name: 'set_auto_reload',
    description: 'Enable or disable auto-reload and set the threshold ($1-$10,000) and reload amount ($5-$10,000). Defaults: $5 threshold / $20 reload. Call get_wallet_status first to see current state.',
    inputSchema: listToolInputSchema('set_auto_reload')
  },
  {
    name: 'create_topup',
    description: 'Create a Stripe Checkout session for a one-time credit purchase',
    inputSchema: listToolInputSchema('create_topup')
  },
  { name: 'get_usage_forecast', description: '30-day burn rate + projected days to empty (auto-reload on = no runway needed)', inputSchema: listToolInputSchema('get_usage_forecast') },
  {
    name: 'revoke_data_source_connection',
    description: 'Revoke a connection instantly — one call, audited; the audit trail stays verifiable',
    inputSchema: {
      type: 'object',
      properties: {
        connectionId: { type: 'string', description: 'Connection ID to revoke (optional; defaults to the current session connection)' }
      }
    }
  },
  {
    name: 'env_list',
    description: 'List isolated health environments for this organization',
    inputSchema: listToolInputSchema('env_list')
  },
  {
    name: 'env_create',
    description: 'Provision a new isolated clinic health environment with synthetic EHR, diversified hospital departments/pathways, 6 base clinical capability packs, and attachable database modules',
    inputSchema: listToolInputSchema('env_create')
  },
  {
    name: 'env_consult_architect',
    description: 'Consult the per-organization isolated Conversational Environment Architect Agent to design a custom hospital simulation blueprint from natural language requirements, or auto-provision it in one call',
    inputSchema: listToolInputSchema('env_consult_architect')
  },
  {
    name: 'hebrah_consult_architect',
    description: 'Alias for env_consult_architect — consult the isolated Conversational Environment Architect Agent to map out synthetic hospital departments, clinical packs, and database add-ons',
    inputSchema: listToolInputSchema('hebrah_consult_architect')
  },
  {
    name: 'env_admit_patients',
    description: 'Dynamically admit and generate a new diversified synthetic patient cohort in an active environment by department, diagnosis pathway, treatment modality, or acuity',
    inputSchema: listToolInputSchema('env_admit_patients')
  },
  {
    name: 'env_connect',
    description: 'Connect this AI agent session to an existing isolated health environment, register in Connected Agents, and set active session context',
    inputSchema: listToolInputSchema('env_connect')
  },
  {
    name: 'env_get',
    description: 'Get details, connection endpoints, and database module status for an isolated environment',
    inputSchema: listToolInputSchema('env_get')
  },
  {
    name: 'env_list_tables',
    description: 'Inspect all database tables, live row counts, and column schemas in the environment isolated database',
    inputSchema: listToolInputSchema('env_list_tables')
  },
  {
    name: 'env_query_db',
    description: 'Execute a read-only SQL query against an environment database module via credential-blind proxy',
    inputSchema: listToolInputSchema('env_query_db')
  },
  {
    name: 'env_record_outcome',
    description: 'Persist a structured AI agent clinical finding or outcome into the environment app_outcomes table (protected by inbound DLP filter)',
    inputSchema: listToolInputSchema('env_record_outcome')
  },
  {
    name: 'env_trigger_scenario',
    description: 'Trigger a synthetic clinical workflow scenario (e.g. er_arrival, lab_critical, discharge, code_blue, icu_sepsis_deterioration, ventilator_desaturation_alarm) with live HL7 WebSocket alerts',
    inputSchema: listToolInputSchema('env_trigger_scenario')
  },
  {
    name: 'env_list_patients',
    description: 'List synthetic patients in the environment EHR with multi-facet filtering by department, diagnosis pathway, treatment modality, or acuity',
    inputSchema: listToolInputSchema('env_list_patients')
  },
  {
    name: 'env_get_patient_chart',
    description: 'Retrieve a complete synthetic patient chart (demographics, conditions, medications, vitals, lab results, encounters, imaging studies, genomics, SDOH, external C-CDA documents)',
    inputSchema: listToolInputSchema('env_get_patient_chart')
  },
  {
    name: 'env_get_logs',
    description: 'Retrieve tamper-evident activity and audit logs for the isolated health environment',
    inputSchema: listToolInputSchema('env_get_logs')
  },
  {
    name: 'env_pause',
    description: 'Pause an environment to suspend compute and reduce hourly rate to $0.00/hr (data preserved)',
    inputSchema: listToolInputSchema('env_pause')
  },
  {
    name: 'env_resume',
    description: 'Resume a paused environment and restore compute services',
    inputSchema: listToolInputSchema('env_resume')
  },
  {
    name: 'env_consult_studio',
    description: 'Consult the Per-Environment Isolated GCP AI Studio to explore synthetic cohorts, open-data clinical vignettes/guidelines/calculators/PrimeKG pathways, or execute read-only SQL/FHIR/DICOM/CDS checks (strictly locked to the environment; external skill/tool installation requests are blocked)',
    inputSchema: listToolInputSchema('env_consult_studio')
  },
  {
    name: 'env_search_clinical_evidence',
    description: 'Search the Open-Data Clinical Knowledge & Evidence Enrichment Pack (clinical_knowledge_v1 + dicom_imaging_v1: vignettes, clinical guidelines, PrimeKG biomedical graph pathways, calculators, and de-identified DICOM exemplars)',
    inputSchema: listToolInputSchema('env_search_clinical_evidence')
  }
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
  targetId: string,
  orgId = ''
): void {
  const intent = String(args.humanIntentMessage ?? '')
  if (!intent.trim()) {
    throw new Error(`humanIntentMessage required for ${action}`)
  }
  consumeConfirmationToken(String(args.confirmationToken ?? ''), action, targetId, orgId)
}

async function dashboardFetch<T>(pat: string, path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${config.dashboardUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${pat}`,
      ...(init?.headers ?? {})
    },
    signal: init?.signal ?? AbortSignal.timeout(30_000)
  })
  if (!res.ok) {
    throw new Error(redactSecrets(`Dashboard ${path} failed (${res.status}): ${await res.text()}`))
  }
  return res.json() as Promise<T>
}

export const bootstrapToolDefinitions = [
  { name: 'create_account', description: 'Create a Hebrah agent account headlessly — $5.00 free credit, 1,000 queries, 50 MB egress, 14 days, no card. Available only when ALLOW_HEADLESS_SIGNUP=true' }
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
  { name: 'list_research_packs', description: 'List Research Packs (e.g. medicare_utilization_v1 CMS claims calibration, ptbxl_ecg_v1 ECG cohort, dicom_imaging_v1 Open DICOM medical imaging, clinical_knowledge_v1 Open-Data Clinical Knowledge & Evidence)' },
  { name: 'get_research_pack', description: 'Get Research Pack metadata + CMS benchmark snapshot, PTB-XL attribution, Open DICOM imaging attribution, or Open-Data Clinical Knowledge pack' },
  { name: 'apply_research_pack', description: 'Apply a Research Pack to the active sandbox connection and remount seed (Medicare only; not PTB-XL)' },
  { name: 'get_research_pack_kpis', description: 'Sandbox claim KPIs for a Research Pack (DRG mix, denial rate, Medicare share)' },
  { name: 'compare_research_pack', description: 'Compare sandbox KPIs to vendored CMS open-data benchmark for a Research Pack' },
  { name: 'list_ptbxl_ecg_records', description: 'List PTB-XL open-data ECG records (superclass filter: NORM/MI/STTC/CD/HYP)' },
  { name: 'get_ptbxl_ecg_record', description: 'Get PTB-XL ECG metadata + suggested conditions (no full waveform samples)' },
  { name: 'get_ptbxl_ecg_waveform_meta', description: 'PTB-XL waveform metadata + truncated lead preview (avoid huge MCP payloads)' },
  { name: 'attach_ptbxl_ecg_exemplar', description: 'Attach a PTB-XL ECG exemplar to a sandbox cardiology patient (research label only)' },
  { name: 'list_dicom_imaging_records', description: 'List open-licensed de-identified DICOM medical imaging exemplars from dicom_imaging_v1 (modalities: DX, CT, MR, XA, US, MG, PT) with CC BY / CC0 citations and PS3.15 de-identification metadata' },
  { name: 'get_dicom_imaging_record', description: 'Get full metadata, Window/Level presets, and open-data citation for a dicom_imaging_v1 exemplar' },
  { name: 'attach_dicom_imaging_exemplar', description: 'Attach a de-identified open-data DICOM imaging exemplar to a patient in an isolated health environment via STOW-RS' },
  { name: 'get_connection_developer_doc', description: 'Rendered markdown integration reference for active connection' },
  { name: 'propose_custom_ehr_model', description: 'Ingest doc text/URL and generate a BYOM draft model pack (apply via dashboard review gate)' },
  { name: 'get_connection_credentials', description: 'Read sandbox credentials metadata (webhook URL, secret configured, Docker URL hints). Pass localAppUrl or port for demo-app suggestions.' },
  { name: 'create_sandbox_api_key', description: 'Mint an additional connection-scoped hb_test_* key (requires confirm_action token; plaintext once)' },
  { name: 'list_sandbox_api_keys', description: 'List active sandbox API key metadata for a connection (no plaintext)' },
  { name: 'revoke_sandbox_api_key', description: 'Revoke one sandbox API key by id (requires confirm_action token; blocked if last unless allowLast)' },
  { name: 'set_connection_webhook_url', description: 'Set per-connection webhook URL override for local demo receiver (requires confirm_action token)' },
  { name: 'rotate_connection_webhook_secret', description: 'Rotate connection hbsec_* webhook secret (requires confirm_action token; plaintext once)' },
  { name: 'get_sdk_reference', description: 'Official @hebrah/sdk (Node) reference — install, API surface, MCP-to-SDK mapping. Do not web-search npm.' },
  { name: 'env_list', description: 'List isolated health environments for this organization' },
  { name: 'env_create', description: 'Provision a new isolated clinic health environment with synthetic EHR, diversified hospital departments/pathways, 6 base clinical capability packs, and attachable database modules' },
  { name: 'env_consult_architect', description: 'Consult the per-organization isolated Conversational Environment Architect Agent to design a custom hospital simulation blueprint from natural language requirements, or auto-provision it in one call' },
  { name: 'hebrah_consult_architect', description: 'Alias for env_consult_architect — consult the isolated Conversational Environment Architect Agent to map out synthetic hospital departments, clinical packs, and database add-ons' },
  { name: 'env_admit_patients', description: 'Dynamically admit and generate a new diversified synthetic patient cohort in an active environment by department, diagnosis pathway, treatment modality, or acuity' },
  { name: 'env_connect', description: 'Connect this session to an existing isolated health environment and set active environment context' },
  { name: 'env_get', description: 'Get details, connection endpoints, and database module status for an isolated environment' },
  { name: 'env_list_tables', description: 'Inspect all database tables, live row counts, and column schemas in the environment isolated database' },
  { name: 'env_query_db', description: 'Execute a read-only SQL query against an environment database module via credential-blind proxy' },
  { name: 'env_record_outcome', description: 'Persist a structured clinical finding or outcome into the environment app_outcomes table (protected by inbound DLP filter)' },
  { name: 'env_trigger_scenario', description: 'Trigger a synthetic clinical workflow scenario with live HL7 WebSocket alerts' },
  { name: 'env_list_patients', description: 'List synthetic patients in the environment EHR with multi-facet filtering by department, diagnosis pathway, treatment modality, or acuity' },
  { name: 'env_get_patient_chart', description: 'Retrieve a complete synthetic patient chart' },
  { name: 'env_get_logs', description: 'Retrieve tamper-evident activity and audit logs for the isolated health environment' },
  { name: 'env_pause', description: 'Pause an environment to suspend compute and reduce hourly rate to $0.00/hr' },
  { name: 'env_resume', description: 'Resume a paused environment and restore compute services' },
  { name: 'env_consult_studio', description: 'Consult the Per-Environment Isolated GCP AI Studio to explore synthetic cohorts, open-data clinical vignettes/guidelines/calculators/PrimeKG pathways, or execute read-only SQL/FHIR/DICOM/CDS checks (strictly locked to the environment; external skill/tool installation requests are blocked)' },
  { name: 'env_search_clinical_evidence', description: 'Search the Open-Data Clinical Knowledge & Evidence Enrichment Pack (clinical_knowledge_v1 + dicom_imaging_v1: vignettes, clinical guidelines, PrimeKG biomedical graph pathways, calculators, and de-identified DICOM exemplars)' }
]

export function filterClinicalEvidenceCatalog(
  catalog: Record<string, unknown>,
  query: string,
  subpack: string,
  specialty: string
): Record<string, unknown> {
  const q = query.trim().toLowerCase()
  const sp = specialty.trim().toLowerCase()
  const sub = subpack.trim().toLowerCase() || 'all'
  if (!q && !sp && sub === 'all') {
    return {
      ...catalog,
      filter_applied: { query: null, subpack: sub, specialty: null }
    }
  }

  const matchesItem = (item: unknown): boolean => {
    if (!item || typeof item !== 'object') return true
    const rec = item as Record<string, unknown>
    if (sp) {
      const itemSpec = String(rec.specialty ?? rec.archetype_id ?? rec.department ?? '').toLowerCase()
      if (itemSpec && !itemSpec.includes(sp)) return false
    }
    if (q) {
      const text = JSON.stringify(rec).toLowerCase()
      if (!text.includes(q)) return false
    }
    return true
  }

  const out: Record<string, unknown> = { ...catalog }
  const sectionKeys = ['vignettes', 'guidelines', 'primekg_pathways', 'calculators', 'imaging_exemplars']
  for (const key of sectionKeys) {
    if (sub !== 'all' && key !== sub) {
      continue
    }
    if (Array.isArray(out[key])) {
      out[key] = (out[key] as unknown[]).filter(matchesItem)
    }
  }

  return {
    ...out,
    filter_applied: { query: q || null, subpack: sub, specialty: sp || null }
  }
}

async function executeEnvironmentTool(
  auth: McpAuth,
  session: ReturnType<typeof getSession>,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  const isAgent = auth.mode === 'agent'
  const envPrefix = isAgent ? '/v1/environments' : '/api/environments'

  const envFetch = <T>(path: string, init?: RequestInit): Promise<T> => {
    if (auth.mode === 'agent') {
      return agentApiFetch<T>(auth, path, init)
    }
    return dashboardFetch<T>(auth.pat, path, init)
  }

  const resolveEnvId = (requireExplicit = false): { rawEnvId: string, encodedEnvId: string } => {
    const rawEnvId = String(
      args.environment_id ?? args.environmentId ?? (requireExplicit && isAgent ? '' : session.activeEnvironmentId) ?? ''
    ).trim()
    if (!rawEnvId) {
      throw new Error(
        requireExplicit
          ? 'environment_id is required for env_connect'
          : 'environment_id is required; call env_connect, env_create, or env_list first'
      )
    }
    return { rawEnvId, encodedEnvId: safeId(rawEnvId, 'environment_id') }
  }

  switch (name) {
    case 'env_list': {
      const includeDestroyed = Boolean(args.include_destroyed ?? args.includeDestroyed)
      return envFetch(`${envPrefix}?include_destroyed=${includeDestroyed}`)
    }
    case 'env_create': {
      const envName = String(args.name ?? '').trim()
      if (!envName) throw new Error('name is required for env_create')
      const addons = (args.addons ?? args.database_packs ?? args.databasePacks ?? ['postgres']) as string[]
      const body: Record<string, unknown> = {
        name: envName,
        clinic_type: args.clinic_type ?? args.clinicType ?? 'ambulatory',
        patient_cohort: args.patient_cohort ?? args.patientCohort ?? 'geriatric',
        addons
      }
      if (Array.isArray(args.departments)) body.departments = args.departments
      if (Array.isArray(args.diagnosis_pathways ?? args.diagnosisPathways)) body.diagnosis_pathways = args.diagnosis_pathways ?? args.diagnosisPathways
      if (Array.isArray(args.treatment_modalities ?? args.treatmentModalities)) body.treatment_modalities = args.treatment_modalities ?? args.treatmentModalities
      if (Array.isArray(args.acuity_levels ?? args.acuityLevels)) body.acuity_levels = args.acuity_levels ?? args.acuityLevels
      if (Array.isArray(args.capability_packs ?? args.capabilityPacks)) body.capability_packs = args.capability_packs ?? args.capabilityPacks
      if (args.patient_count ?? args.patientCount) body.patient_count = Number(args.patient_count ?? args.patientCount)
      if (args.bed_count ?? args.bedCount) body.bed_count = Number(args.bed_count ?? args.bedCount)
      const result = await envFetch<{ id: string }>(envPrefix, {
        method: 'POST',
        body: JSON.stringify(body)
      })
      if (result?.id) {
        session.activeEnvironmentId = result.id
      }
      return result
    }
    case 'env_consult_architect':
    case 'hebrah_consult_architect': {
      const message = String(args.message ?? '').trim()
      if (!message) throw new Error('message is required for env_consult_architect')
      const body: Record<string, unknown> = {
        message,
        channel: 'agent_mcp',
        auto_provision: Boolean(args.auto_provision ?? args.autoProvision)
      }
      if (args.session_id ?? args.sessionId) {
        body.session_id = safeId(String(args.session_id ?? args.sessionId).trim(), 'session_id')
      }
      const result = await envFetch<{ provisioned_environment?: { id?: string } }>(
        `${envPrefix}/architect/chat`,
        {
          method: 'POST',
          body: JSON.stringify(body)
        }
      )
      if (result?.provisioned_environment?.id) {
        session.activeEnvironmentId = result.provisioned_environment.id
      }
      return result
    }
    case 'env_admit_patients': {
      const { encodedEnvId } = resolveEnvId()
      const body: Record<string, unknown> = {
        count: Number(args.count ?? 10)
      }
      if (Array.isArray(args.departments)) body.departments = args.departments
      if (Array.isArray(args.diagnosis_pathways ?? args.diagnosisPathways)) body.diagnosis_pathways = args.diagnosis_pathways ?? args.diagnosisPathways
      if (Array.isArray(args.treatment_modalities ?? args.treatmentModalities)) body.treatment_modalities = args.treatment_modalities ?? args.treatmentModalities
      if (Array.isArray(args.acuity_levels ?? args.acuityLevels)) body.acuity_levels = args.acuity_levels ?? args.acuityLevels
      return envFetch(`${envPrefix}/${encodedEnvId}/ehr/patients/generate`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'env_connect': {
      const { rawEnvId, encodedEnvId } = resolveEnvId(true)
      if (isAgent) {
        const body: Record<string, unknown> = {
          client: String(args.client ?? 'hebrah-mcp-host').trim() || 'hebrah-mcp-host'
        }
        if (args.agent_name ?? args.agentName) {
          body.agent_name = String(args.agent_name ?? args.agentName).trim()
        }
        const result = await envFetch<Record<string, unknown>>(
          `${envPrefix}/${encodedEnvId}/agents/connect`,
          {
            method: 'POST',
            body: JSON.stringify(body)
          }
        )
        session.activeEnvironmentId = rawEnvId
        return {
          ...result,
          activeEnvironmentId: rawEnvId,
          note: 'Agent session connected and registered in Connected Agents. Subsequent env_* tools will default to this environment.'
        }
      }
      const env = await envFetch<Record<string, unknown>>(`${envPrefix}/${encodedEnvId}`)
      session.activeEnvironmentId = rawEnvId
      return {
        ...env,
        activeEnvironmentId: rawEnvId,
        note: 'Active environment set for this session. Subsequent env_* tools will default to this environment.'
      }
    }
    case 'env_get': {
      const { rawEnvId, encodedEnvId } = resolveEnvId()
      if (!session.activeEnvironmentId) {
        session.activeEnvironmentId = rawEnvId
      }
      return envFetch(`${envPrefix}/${encodedEnvId}`)
    }
    case 'env_list_tables': {
      const { encodedEnvId } = resolveEnvId()
      return envFetch(`${envPrefix}/${encodedEnvId}/db/tables`)
    }
    case 'env_query_db': {
      const { encodedEnvId } = resolveEnvId()
      const sql = String(args.sql ?? args.query ?? '').trim()
      if (!sql) throw new Error('sql is required')
      const addon = String(args.addon ?? args.pack ?? 'postgres').trim()
      return envFetch(`${envPrefix}/${encodedEnvId}/db/query`, {
        method: 'POST',
        body: JSON.stringify({ sql, addon, actor_type: 'agent' })
      })
    }
    case 'env_record_outcome': {
      const { encodedEnvId } = resolveEnvId()
      const outcomeType = String(args.outcome_type ?? args.outcomeType ?? '').trim()
      if (!outcomeType) throw new Error('outcome_type is required')
      const summary = String(args.summary ?? '').trim()
      if (!summary) throw new Error('summary is required')
      const body: Record<string, unknown> = {
        outcome_type: outcomeType,
        summary
      }
      if (args.patient_id ?? args.patientId) body.patient_id = safeId(String(args.patient_id ?? args.patientId).trim(), 'patient_id')
      if (args.score !== undefined || args.risk_score !== undefined) {
        body.score = Number(args.score ?? args.risk_score)
      }
      if (args.source_agent ?? args.sourceAgent) {
        body.source_agent = String(args.source_agent ?? args.sourceAgent).trim()
      }
      if (args.payload && typeof args.payload === 'object') {
        body.payload = args.payload
      }
      return envFetch(`${envPrefix}/${encodedEnvId}/db/outcomes`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'env_trigger_scenario': {
      const { encodedEnvId } = resolveEnvId()
      const scenario = String(args.scenario ?? args.scenario_id ?? args.scenarioId ?? '').trim()
      if (!scenario) throw new Error('scenario is required (e.g. er_arrival, lab_critical, discharge, code_blue)')
      const body: Record<string, unknown> = { scenario }
      if (args.patient_id ?? args.patientId) body.patient_id = safeId(String(args.patient_id ?? args.patientId).trim(), 'patient_id')
      if (args.notes) body.notes = String(args.notes)
      return envFetch(`${envPrefix}/${encodedEnvId}/ehr/scenarios/trigger`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'env_list_patients': {
      const { encodedEnvId } = resolveEnvId()
      const params = new URLSearchParams()
      if (args.department) params.set('department', String(args.department).trim())
      if (args.diagnosis) params.set('diagnosis', String(args.diagnosis).trim())
      if (args.treatment_modality ?? args.treatmentModality) params.set('treatment_modality', String(args.treatment_modality ?? args.treatmentModality).trim())
      if (args.acuity_level ?? args.acuityLevel) params.set('acuity_level', String(args.acuity_level ?? args.acuityLevel).trim())
      if (args.limit != null) params.set('limit', String(Number(args.limit)))
      const qs = params.toString() ? `?${params.toString()}` : ''
      return envFetch(`${envPrefix}/${encodedEnvId}/ehr/patients${qs}`)
    }
    case 'env_get_patient_chart': {
      const { encodedEnvId } = resolveEnvId()
      const rawPatientId = String(args.patient_id ?? args.patientId ?? '').trim()
      if (!rawPatientId) throw new Error('patient_id is required (e.g. pat_001)')
      const encodedPatientId = safeId(rawPatientId, 'patient_id')
      return envFetch(`${envPrefix}/${encodedEnvId}/ehr/patients/${encodedPatientId}`)
    }
    case 'env_get_logs': {
      const { encodedEnvId } = resolveEnvId()
      const params = new URLSearchParams()
      if (args.limit != null) params.set('limit', String(Number(args.limit)))
      if (args.event_type ?? args.eventType) params.set('event_type', String(args.event_type ?? args.eventType).trim())
      const qs = params.toString() ? `?${params.toString()}` : ''
      return envFetch(`${envPrefix}/${encodedEnvId}/logs${qs}`)
    }
    case 'env_pause': {
      const { encodedEnvId } = resolveEnvId()
      return envFetch(`${envPrefix}/${encodedEnvId}/pause`, {
        method: 'POST'
      })
    }
    case 'env_resume': {
      const { encodedEnvId } = resolveEnvId()
      return envFetch(`${envPrefix}/${encodedEnvId}/resume`, {
        method: 'POST'
      })
    }
    case 'env_consult_studio': {
      const { encodedEnvId } = resolveEnvId()
      const message = String(args.message ?? '').trim()
      if (!message) throw new Error('message is required for env_consult_studio')
      const body: Record<string, unknown> = {
        message,
        channel: 'agent_mcp'
      }
      if (args.session_id ?? args.sessionId) {
        body.session_id = safeId(String(args.session_id ?? args.sessionId).trim(), 'session_id')
      }
      return envFetch(`${envPrefix}/${encodedEnvId}/studio/chat`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'env_search_clinical_evidence': {
      const rawEnvId = String(args.environment_id ?? args.environmentId ?? session.activeEnvironmentId ?? '').trim()
      const query = String(args.query ?? '')
      const subpack = String(args.subpack ?? 'all')
      const specialty = String(args.specialty ?? '')
      let catalog: Record<string, unknown>
      if (rawEnvId) {
        const encodedEnvId = safeId(rawEnvId, 'environment_id')
        catalog = auth.mode === 'agent'
          ? await agentApiFetch<Record<string, unknown>>(auth, `/v1/environments/${encodedEnvId}/open-data/catalog`)
          : await dashboardFetch<Record<string, unknown>>(auth.pat, `/api/environments/${encodedEnvId}/open-data`)
      } else {
        catalog = auth.mode === 'agent'
          ? await agentApiFetch<Record<string, unknown>>(auth, '/v1/sandbox/research-packs/clinical_knowledge_v1')
          : await ultraFetch<Record<string, unknown>>(auth.orgId, '/v1/sandbox/research-packs/clinical_knowledge_v1')
      }
      return filterClinicalEvidenceCatalog(catalog, query, subpack, specialty)
    }
    default:
      throw new Error(`Unknown environment tool: ${name}`)
  }
}

export async function callTool(
  auth: McpAuth,
  sessionId: string,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  if (!auth.bootstrap) await checkRateLimit(auth.orgId, name)
  const session = getSession(sessionId)

  // Agent-key (hb_conn_* / hb_live_* / hb_test_*) sessions: the connection and
  // isolated environment surfaces. Forward the agent key to hebrah-api — scopes,
  // metering, and audit attribute to the agent's org.
  if (auth.mode === 'agent') {
    if (!(AGENT_TOOL_NAMES as readonly string[]).includes(name)) {
      throw new Error(
        `${name} requires a dashboard PAT session (hb_pat_*). Agent-key sessions expose the connection tools only: ${AGENT_TOOL_NAMES.join(', ')}`
      )
    }
    if (name.startsWith('env_') || name === 'hebrah_consult_architect') {
      return executeEnvironmentTool(auth, session, name, args)
    }
    switch (name) {
      case 'discover_data_sources':
        return agentApiFetch(auth, '/v1/connections/targets')
      case 'connect_to_data_source': {
        const target = String(args.target_id ?? args.target ?? '').trim()
        if (!target) throw new Error('target_id is required; call discover_data_sources first')
        safeId(target, 'target_id')
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
        const rawId = String(args.connectionId ?? session.connectConnectionId ?? '').trim()
        if (!rawId) throw new Error('connectionId is required; call connect_to_data_source first')
        const connectionId = safeId(rawId, 'connectionId')
        const sql = String(args.sql ?? '')
        if (!sql.trim()) throw new Error('sql is required')
        return agentApiFetch(auth, `/v1/connections/${connectionId}/query`, {
          method: 'POST',
          body: JSON.stringify({ sql })
        })
      }
      case 'get_data_source_audit': {
        const rawId = String(args.connectionId ?? session.connectConnectionId ?? '').trim()
        if (!rawId) throw new Error('connectionId is required; call connect_to_data_source first')
        const connectionId = safeId(rawId, 'connectionId')
        return agentApiFetch(auth, `/v1/connections/${connectionId}/audit`)
      }
      case 'get_connect_usage':
        return agentApiFetch(auth, '/v1/agent/account/usage')
      case 'get_wallet_status':
        return agentApiFetch(auth, '/v1/agent/wallet')
      case 'set_auto_reload': {
        const rawEnabled = args.auto_reload_enabled ?? args.autoReloadEnabled
        const enabled = Boolean(rawEnabled)
        const threshold = args.auto_reload_threshold_cents ?? args.autoReloadThresholdCents
        const amount = args.auto_reload_amount_cents ?? args.autoReloadAmountCents
        const body: Record<string, unknown> = { auto_reload_enabled: enabled }
        if (threshold !== undefined) body.auto_reload_threshold_cents = Number(threshold)
        if (amount !== undefined) body.auto_reload_amount_cents = Number(amount)
        return agentApiFetch(auth, '/v1/agent/wallet/config', { method: 'POST', body: JSON.stringify(body) })
      }
      case 'create_topup': {
        const amountCents = Number(args.amount_cents ?? args.amountCents ?? 2000)
        if (!amountCents || amountCents < 100) throw new Error('amount_cents must be >= 100 ($1)')
        if (amountCents > 1_000_000) throw new Error('amount_cents must be <= 1,000,000 ($10,000)')
        return agentApiFetch(auth, '/v1/agent/topup', { method: 'POST', body: JSON.stringify({ amount_cents: amountCents }) })
      }
      case 'get_usage_forecast':
        return agentApiFetch(auth, '/v1/agent/wallet')
      case 'revoke_data_source_connection': {
        const rawId = String(args.connectionId ?? session.connectConnectionId ?? '').trim()
        if (!rawId) throw new Error('connectionId is required; call connect_to_data_source first')
        const encodedId = safeId(rawId, 'connectionId')
        const result = await agentApiFetch<{ connectionId: string, status: string }>(
          auth,
          `/v1/connections/${encodedId}/revoke`,
          { method: 'POST' }
        )
        if (session.connectConnectionId === rawId) {
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

  if (!auth.bootstrap && (name.startsWith('env_') || name === 'hebrah_consult_architect')) {
    return executeEnvironmentTool(auth, session, name, args)
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
        throw new Error(redactSecrets(`Agent signup failed (${result.status}): ${await result.text()}`))
      }
      const data = await result.json() as {
        orgId: string
        apiKey: string
        keyPrefix: string
        mcpEndpointUrl: string
        trial: { credits: { queries: number, egressBytes: number }, expires_at: string }
        claimUrl?: string | null
        inviteEmail?: string | null
      }

      const claimUrl = data.claimUrl
      const invite = data.inviteEmail || inviteEmail
      const hasClaim = Boolean(claimUrl && invite && !invite.endsWith('@agent.local'))

      let markdown = `### 🎉 Hebrah Account Created for **${orgName}**\n\n` +
        `Your workspace is provisioned with **$5.00 free credit** (1,000 queries, 50 MB egress, 14 days).\n\n` +
        `- **API Key:** \`${data.apiKey}\` *(save this key now — it is shown once)*\n` +
        `- **MCP Endpoint:** \`${data.mcpEndpointUrl}\`\n\n`

      if (hasClaim) {
        markdown += `#### 👤 Human Ownership & Claim Link\n` +
          `An invitation has been dispatched to **${invite}**.\n\n` +
          `👉 **[Claim ${orgName} on Hebrah](${claimUrl})**\n\n` +
          `*To keep your agent running uninterrupted after the trial quota ends, click the link above to claim the organization and add a payment method.*`
      } else {
        markdown += `Reconnect to this MCP server with \`Authorization: Bearer ${data.apiKey}\` to start querying data sources.`
      }

      return {
        orgId: data.orgId,
        apiKey: data.apiKey,
        keyPrefix: data.keyPrefix,
        mcpEndpointUrl: data.mcpEndpointUrl,
        claimUrl: claimUrl ?? null,
        inviteEmail: hasClaim ? invite : null,
        trial: data.trial,
        markdown,
        note: `Agent account created — $5.00 free credit (1,000 queries, 50 MB egress, 14 days). ` +
          `Save the apiKey (${data.keyPrefix}…) now — it is shown once. ` +
          (hasClaim ? `Claim the organization at ${claimUrl} to attach billing. ` : '') +
          'Reconnect to this MCP server with "Authorization: Bearer <apiKey>" to use the connection tools, or call the agent API directly.'
      }
    }
    case 'discover_data_sources':
      return connectFetch(auth, session, '/v1/targets')
    case 'connect_to_data_source': {
      const target = String(args.target ?? '').trim()
      if (!target) throw new Error('target is required; call discover_data_sources first')
      if (target.length > 256 || /[\r\n\0]/.test(target) || target.includes('..')) {
        throw new Error('Invalid target')
      }
      const rawScopes = args.scopes
      if (!Array.isArray(rawScopes) || rawScopes.length === 0 || rawScopes.some(scope => typeof scope !== 'string')) {
        throw new Error('scopes must be a non-empty string array from the target discovery metadata')
      }
      consumeCredentialConfirmation(args, 'connect_to_data_source', target, auth.orgId)
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
      return connectFetch(auth, session, `/v1/connections/${safeId(connectionId, 'connectionId')}/query`, {
        method: 'POST',
        body: JSON.stringify({ sql })
      })
    }
    case 'get_data_source_audit': {
      const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
      if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
      return connectFetch(auth, session, `/v1/connections/${safeId(connectionId, 'connectionId')}/audit`)
    }
    case 'get_connect_usage':
      return connectFetch(auth, session, '/v1/account/usage')
    case 'revoke_data_source_connection': {
      const connectionId = String(args.connectionId ?? session.connectConnectionId ?? '')
      if (!connectionId) throw new Error('connectionId is required; call connect_to_data_source first')
      consumeCredentialConfirmation(args, 'revoke_data_source_connection', connectionId, auth.orgId)
      const result = await connectFetch<{ connection_id: string, status: string }>(
        auth,
        session,
        `/v1/connections/${safeId(connectionId, 'connectionId')}/revoke`,
        { method: 'POST' }
      )
      if (session.connectConnectionId === connectionId) session.connectConnectionId = undefined
      return result
    }
    case 'set_active_connection': {
      const rawConnId = String(args.connectionId ?? '').trim()
      if (!rawConnId) throw new Error('connectionId is required for set_active_connection')
      safeId(rawConnId, 'connectionId')
      session.activeConnectionId = rawConnId
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
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/pause`, {
        method: 'PATCH'
      })
    }
    case 'resume_connection': {
      assertMcpConnectionActionAllowed(auth.mcpAcl, 'pause')
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      if (!id) {
        throw new Error('connectionId is required for resume_connection')
      }
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/resume`, {
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
      consumeConfirmationToken(token, 'remove_connection', id, auth.orgId)
      const result = await dashboardFetch<{ removedConnectionIds: string[] }>(
        auth.pat,
        `/api/connections/${safeId(id, 'connectionId')}`,
        { method: 'DELETE' }
      )
      if (session.activeConnectionId && result.removedConnectionIds.includes(session.activeConnectionId)) {
        session.activeConnectionId = undefined
      }
      return result
    }
    case 'get_connection_mapping': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/mapping`)
    }
    case 'update_connection_mapping': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/mapping`, {
        method: 'PUT',
        body: JSON.stringify({ mappings: args.mappings })
      })
    }
    case 'list_config_versions': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/versions`)
    }
    case 'create_config_version': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/versions`, {
        method: 'POST',
        body: JSON.stringify({ source: 'mcp' })
      })
    }
    case 'create_promotion': {
      await assertPromoteToLiveAllowed(auth.pat)
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/promotions`, {
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
        `/api/connections/${safeId(connId, 'connectionId')}/promotions/${safeId(prId, 'promotionId')}`
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

        const token = issueConfirmationToken(credentialAction, targetId, auth.orgId)
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
        const token = issueConfirmationToken('remove_connection', connectionId, auth.orgId)
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
      const token = issueConfirmationToken('approve_promotion', promotionId, auth.orgId)
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
      consumeConfirmationToken(token, 'approve_promotion', prId, auth.orgId)
      await checkPromotionApproveLimit(auth.orgId)
      return dashboardFetch(
        auth.pat,
        `/api/connections/${safeId(connId, 'connectionId')}/promotions/${safeId(prId, 'promotionId')}/approve`,
        { method: 'POST', body: JSON.stringify({ humanIntentMessage: intent }) }
      )
    }
    case 'reject_promotion': {
      await assertPromoteToLiveAllowed(auth.pat)
      const connId = String(args.connectionId ?? session.activeConnectionId ?? '')
      const prId = String(args.promotionId ?? '')
      return dashboardFetch(
        auth.pat,
        `/api/connections/${safeId(connId, 'connectionId')}/promotions/${safeId(prId, 'promotionId')}/reject`,
        { method: 'POST', body: JSON.stringify({ comment: args.comment }) }
      )
    }
    case 'get_live_deployment': {
      const id = String(args.connectionId ?? session.activeConnectionId ?? '')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/deployment`)
    }
    case 'get_sandbox_catalog': {
      const connectionId = args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(auth.orgId, `/v1/sandbox/catalog${q}`)
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
      return ultraFetch(auth.orgId, '/v1/webhooks/trigger-mock-event', {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'list_sandbox_domains':
      return ultraFetch(auth.orgId, '/v1/sandbox/domains')
    case 'get_sandbox_domain':
      return ultraFetch(auth.orgId, `/v1/sandbox/domains/${safeId(String(args.domainId ?? args.domain_id ?? ''), 'domainId')}`)
    case 'get_synthetic_resource': {
      const resourceType = String(args.resourceType ?? args.resource_type ?? '')
      const resourceId = String(args.resourceId ?? args.resource_id ?? '')
      const patientId = args.patientId ?? args.patient_id
      const q = patientId ? `?patient_id=${encodeURIComponent(String(patientId))}` : ''
      return ultraFetch(
        auth.orgId,
        `/v1/sandbox/resources/${safeId(resourceType, 'resourceType')}/${safeId(resourceId, 'resourceId')}${q}`
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
      return ultraFetch(auth.orgId, `/v1/sandbox/scenarios/${safeId(scenarioId, 'scenarioId')}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'get_payer_rules':
      return ultraFetch(auth.orgId, `/v1/sandbox/payer-rules/${safeId(String(args.payerId ?? args.payer_id ?? 'payer_aetna'), 'payerId')}`)
    case 'list_sandbox_events': {
      const catalog = await ultraFetch<{ event_groups?: Record<string, string[]> }>(auth.orgId, '/v1/sandbox/catalog')
      return catalog.event_groups ?? {}
    }
    case 'list_hl7_templates':
      return ultraFetch(auth.orgId, '/v1/sandbox/hl7/templates')
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
      return ultraFetch(auth.orgId, '/v1/sandbox/hl7/inject', {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'sidecar_writeback': {
      const url = String(args.url ?? process.env.SIDECAR_WRITEBACK_URL ?? '')
      if (!url) {
        throw new Error('url argument or SIDECAR_WRITEBACK_URL env required for sidecar_writeback')
      }
      const safeBaseUrl = assertSafeSidecarUrl(url)
      const action = safeId(String(args.action ?? 'chart-note'), 'action')
      const endpoint = `${safeBaseUrl}/v1/writeback/${action}`
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
        body: JSON.stringify({
          patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01',
          ...(typeof args.body === 'object' && args.body ? args.body : {})
        })
      })
      if (!res.ok) {
        throw new Error(redactSecrets(`sidecar write-back failed (${res.status}): ${await res.text()}`))
      }
      return res.json()
    }
    case 'run_hl7_flight_check': {
      const vmId = String(args.vmId ?? args.vm_id ?? '')
      if (!vmId) {
        throw new Error('vmId required for run_hl7_flight_check')
      }
      const secret = config.orchestratorSecret || process.env.ORCHESTRATOR_SECRET
      if (!secret) {
        throw new Error('ORCHESTRATOR_SECRET required on hebrah-mcp-host for run_hl7_flight_check')
      }
      const orchUrl = config.orchestratorUrl
      const res = await fetch(`${orchUrl}/v1/vms/${safeId(vmId, 'vmId')}/hl7-probe`, {
        method: 'POST',
        headers: { 'X-Orchestrator-Secret': secret },
        signal: AbortSignal.timeout(15_000)
      })
      if (!res.ok) {
        throw new Error(redactSecrets(`hl7-probe failed (${res.status}): ${await res.text()}`))
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
      return ultraFetch(auth.orgId, `/v1/webhooks/deliveries${q}`)
    }
    case 'replay_webhook_delivery': {
      const deliveryId = String(args.delivery_id ?? args.deliveryId ?? '')
      if (!deliveryId) throw new Error('deliveryId required')
      return ultraFetch(auth.orgId, `/v1/webhooks/deliveries/${safeId(deliveryId, 'deliveryId')}/replay`, {
        method: 'POST'
      })
    }
    case 'configure_webhook_reliability': {
      return ultraFetch(auth.orgId, '/v1/sandbox/webhook-reliability', {
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
      await ultraFetch(auth.orgId, '/v1/sandbox/webhook-reliability', {
        method: 'PATCH',
        body: JSON.stringify({ mode: profileMode, fail_rate: 0.8 })
      })
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      if (connectionId) body.connection_id = connectionId
      return ultraFetch(auth.orgId, `/v1/sandbox/scenarios/${safeId(scenarioId, 'scenarioId')}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'register_smart_client': {
      const rawRedirectUris = args.redirect_uris ?? args.redirectUris ?? []
      if (!Array.isArray(rawRedirectUris)) {
        throw new Error('redirect_uris must be an array of URLs')
      }
      const validatedRedirectUris = rawRedirectUris.map(u =>
        assertSafeWebhookOrCallbackUrl(String(u), 'redirect_uris')
      )
      return dashboardFetch(auth.pat, '/api/smart/clients', {
        method: 'POST',
        body: JSON.stringify({
          client_id: args.client_id ?? args.clientId,
          name: args.name ?? 'MCP SMART client',
          redirect_uris: validatedRedirectUris
        })
      })
    }
    case 'start_smart_launch': {
      const rawSmartUrl = args.smart_app_url ?? args.smartAppUrl ?? null
      const validatedSmartUrl = rawSmartUrl
        ? assertSafeWebhookOrCallbackUrl(String(rawSmartUrl), 'smart_app_url')
        : null
      return dashboardFetch(auth.pat, '/api/smart/launch', {
        method: 'POST',
        body: JSON.stringify({
          patient_id: args.patient_id ?? args.patientId,
          encounter_id: args.encounter_id ?? args.encounterId ?? null,
          smart_app_url: validatedSmartUrl
        })
      })
    }
    case 'run_mpi_match':
      return ultraFetch(auth.orgId, '/v1/sandbox/mpi/match', {
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
      return ultraFetch(auth.orgId, `/v1/sandbox/scenarios/${safeId(scenarioId, 'scenarioId')}/run`, {
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
      return ultraFetch(auth.orgId, `/v1/sandbox/credentialing/practitioners/${safeId(practitionerId, 'practitionerId')}${q}`)
    }
    case 'run_credentialing_scenario': {
      const scenarioId = String(args.scenarioId ?? args.scenario_id ?? 'credentialing_verify_practitioner')
      const body: Record<string, unknown> = {
        patient_id: args.patient_id ?? args.patientId ?? 'pat_00000000_01'
      }
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      if (connectionId) body.connection_id = connectionId
      return ultraFetch(auth.orgId, `/v1/sandbox/scenarios/${safeId(scenarioId, 'scenarioId')}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'run_aggregator_query':
      return ultraFetch(auth.orgId, '/v1/sandbox/aggregator/query', {
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
      return ultraFetch(auth.orgId, `/v1/sandbox/scenarios/${safeId(scenarioId, 'scenarioId')}/run`, {
        method: 'POST',
        body: JSON.stringify(body)
      })
    }
    case 'get_synthetic_ehr_profile': {
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(auth.orgId, `/v1/sandbox/synthetic-ehr/profile${q}`)
    }
    case 'list_ehr_base_models':
      return ultraFetch(auth.orgId, '/v1/sandbox/ehr-models')
    case 'reset_synthetic_ehr_data': {
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(auth.orgId, `/v1/sandbox/synthetic-ehr/reset${q}`, { method: 'POST' })
    }
    case 'list_research_packs':
      return ultraFetch(auth.orgId, '/v1/sandbox/research-packs')
    case 'get_research_pack': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/${safeId(packId, 'packId')}`)
    }
    case 'apply_research_pack': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/${safeId(packId, 'packId')}/apply${q}`, {
        method: 'POST'
      })
    }
    case 'get_research_pack_kpis': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/${safeId(packId, 'packId')}/kpis${q}`)
    }
    case 'compare_research_pack': {
      const packId = String(args.pack_id ?? args.packId ?? 'medicare_utilization_v1')
      const connectionId = args.connection_id ?? args.connectionId ?? session.activeConnectionId
      const q = connectionId ? `?connection_id=${encodeURIComponent(String(connectionId))}` : ''
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/${safeId(packId, 'packId')}/compare${q}`)
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
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/ptbxl_ecg_v1/records${qs ? `?${qs}` : ''}`)
    }
    case 'get_ptbxl_ecg_record': {
      const ecgId = args.ecg_id ?? args.ecgId
      if (ecgId == null) throw new Error('ecg_id required for get_ptbxl_ecg_record')
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/ptbxl_ecg_v1/records/${safeId(String(ecgId), 'ecg_id')}`)
    }
    case 'get_ptbxl_ecg_waveform_meta': {
      const ecgId = args.ecg_id ?? args.ecgId
      if (ecgId == null) throw new Error('ecg_id required for get_ptbxl_ecg_waveform_meta')
      const encodedEcgId = safeId(String(ecgId), 'ecg_id')
      const wave = await ultraFetch<{
        ecg_id?: number
        fs?: number
        duration_s?: number
        lead_order?: string[]
        leads?: Record<string, number[]>
        disclaimer?: string
        attribution?: string
      }>(auth.orgId, `/v1/sandbox/research-packs/ptbxl_ecg_v1/records/${encodedEcgId}/waveform`)
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
        waveform_path: `/v1/sandbox/research-packs/ptbxl_ecg_v1/records/${encodedEcgId}/waveform`,
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
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/ptbxl_ecg_v1/attach${q}`, {
        method: 'POST',
        body: JSON.stringify({
          patient_id: String(patientId),
          ecg_id: ecgId,
          connection_id: connectionId ? String(connectionId) : undefined
        })
      })
    }
    case 'list_dicom_imaging_records': {
      const params = new URLSearchParams()
      if (args.modality) params.set('modality', String(args.modality))
      if (args.archetype_id ?? args.archetypeId) params.set('archetype_id', String(args.archetype_id ?? args.archetypeId))
      if (args.limit != null) params.set('limit', String(args.limit))
      if (args.offset != null) params.set('offset', String(args.offset))
      const qs = params.toString()
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/dicom_imaging_v1/records${qs ? `?${qs}` : ''}`)
    }
    case 'get_dicom_imaging_record': {
      const exemplarId = args.exemplar_id ?? args.exemplarId
      if (!exemplarId) throw new Error('exemplar_id required for get_dicom_imaging_record')
      return ultraFetch(auth.orgId, `/v1/sandbox/research-packs/dicom_imaging_v1/records/${safeId(String(exemplarId), 'exemplar_id')}`)
    }
    case 'attach_dicom_imaging_exemplar': {
      const envId = args.environment_id ?? args.environmentId
      const patientId = args.patient_id ?? args.patientId
      const exemplarId = args.exemplar_id ?? args.exemplarId
      const modality = args.modality
      if (!envId || !patientId) {
        throw new Error('environment_id and patient_id required for attach_dicom_imaging_exemplar')
      }
      return ultraFetch(auth.orgId, `/v1/environments/${safeId(String(envId), 'environment_id')}/dicomweb/studies`, {
        method: 'POST',
        body: JSON.stringify({
          patient_id: safeId(String(patientId), 'patient_id'),
          exemplar_id: exemplarId ? safeId(String(exemplarId), 'exemplar_id') : undefined,
          modality: modality ? String(modality) : 'CT'
        })
      })
    }
    case 'get_connection_developer_doc': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!id) throw new Error('connectionId required for get_connection_developer_doc')
      return dashboardFetch(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/developer-doc`)
    }
    case 'get_connection_credentials': {
      const connectionId = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!connectionId) {
        throw new Error('connectionId required for get_connection_credentials')
      }

      const urlInput = parseLocalAppUrlFromArgs(args)
      const localAppUrl = urlInput.localAppUrl ?? ''
      const query = localAppUrl
        ? `?localAppUrl=${encodeURIComponent(localAppUrl)}`
        : ''

      const credentials = await dashboardFetch<Record<string, unknown>>(
        auth.pat,
        `/api/connections/${safeId(connectionId, 'connectionId')}/credentials${query}`
      )

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

      consumeCredentialConfirmation(args, 'set_connection_webhook_url', connectionId, auth.orgId)

      const body: Record<string, unknown> = {}
      if (args.inheritDefault === true || args.inherit_default === true) {
        body.inheritDefault = true
      } else {
        body.inheritDefault = false
        body.webhookUrl = resolveWebhookUrlFromSetArgs(args)
      }

      const result = await dashboardFetch<{
        effective?: { webhookUrl?: string | null }
      }>(auth.pat, `/api/connections/${safeId(connectionId, 'connectionId')}/webhook`, {
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
      const encodedConnId = safeId(connectionId, 'connectionId')
      const ingestBody: Record<string, unknown> = {}
      if (args.url) {
        ingestBody.url = assertSafeWebhookOrCallbackUrl(String(args.url), 'url', { disallowLoopback: true })
      }
      if (args.text) ingestBody.text = String(args.text)
      if (!ingestBody.url && !ingestBody.text) {
        throw new Error('text or url required for propose_custom_ehr_model')
      }
      const ingestJson = await dashboardFetch<{ chunk_id: string }>(
        auth.pat,
        `/api/connections/${encodedConnId}/byom/ingest`,
        { method: 'POST', body: JSON.stringify(ingestBody) }
      )
      const generated = await dashboardFetch<Record<string, unknown>>(
        auth.pat,
        `/api/connections/${encodedConnId}/byom/generate`,
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
      consumeCredentialConfirmation(args, 'create_sandbox_api_key', id, auth.orgId)
      const body: Record<string, unknown> = {}
      if (args.label !== undefined) body.label = args.label
      const result = await dashboardFetch<{
        sandboxApiKey: string
        key: { id: string, keyPrefix: string, environment: string, createdAt: string, label: string | null }
        note?: string
      }>(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/credentials/keys`, {
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
      }>(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/credentials`)
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
      consumeCredentialConfirmation(args, 'revoke_sandbox_api_key', revokeConfirmationTarget(id, keyId), auth.orgId)
      const body: Record<string, unknown> = {}
      if (args.allowLast === true || args.allow_last === true) body.allowLast = true
      return dashboardFetch(
        auth.pat,
        `/api/connections/${safeId(id, 'connectionId')}/credentials/keys/${safeId(keyId, 'keyId')}/revoke`,
        { method: 'POST', body: JSON.stringify(body) }
      )
    }
    case 'rotate_connection_webhook_secret': {
      const id = String(args.connectionId ?? args.connection_id ?? session.activeConnectionId ?? '')
      if (!id) throw new Error('connectionId required for rotate_connection_webhook_secret')
      consumeCredentialConfirmation(args, 'rotate_connection_webhook_secret', id, auth.orgId)
      const result = await dashboardFetch<{
        webhookSecret: string
        note?: string
        effective?: { webhookUrl: string | null }
      }>(auth.pat, `/api/connections/${safeId(id, 'connectionId')}/webhook/rotate-secret`, {
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
    console.error(`[hebrah-mcp-host] PAT validation unreachable (${config.dashboardUrl}):`, redactSecrets(detail))
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