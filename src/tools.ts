import { config } from './config.js'
import {
  checkPromotionApproveLimit,
  checkRateLimit,
  consumeConfirmationToken,
  issueConfirmationToken
} from './guardrails.js'

export type McpAuth = {
  pat: string
  orgId: string
  tokenId: string
}

const sessions = new Map<string, { activeConnectionId?: string }>()

export function getSession(sessionId: string) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {})
  }
  return sessions.get(sessionId)!
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

export const toolDefinitions = [
  { name: 'set_active_connection', description: 'Set the sandbox connection context for subsequent tools' },
  { name: 'get_account_status', description: 'Org status and connections summary' },
  { name: 'list_connections', description: 'List dashboard connections' },
  { name: 'get_connection_mapping', description: 'Get HL7→FHIR mappings (sandbox only)' },
  { name: 'update_connection_mapping', description: 'Update mappings on sandbox connection only' },
  { name: 'list_config_versions', description: 'List sandbox config versions' },
  { name: 'create_config_version', description: 'Snapshot current sandbox config as a new version' },
  { name: 'create_promotion', description: 'Open a promotion (PR) to sync sandbox version to Live' },
  { name: 'get_promotion', description: 'Promotion detail and diff summary' },
  { name: 'confirm_action', description: 'Issue a confirmation token before approve_promotion' },
  { name: 'approve_promotion', description: 'Approve & sync to Live (requires confirm_action token)' },
  { name: 'reject_promotion', description: 'Reject an open promotion' },
  { name: 'get_live_deployment', description: 'Read-only: what version is deployed on Live' },
  { name: 'get_sandbox_catalog', description: 'hebrah-api sandbox catalog (optional connection_id)' },
  { name: 'trigger_test_webhook', description: 'Trigger mock webhook (sandbox); supports event, scenario_id, connection_id' },
  { name: 'list_sandbox_domains', description: 'List sandbox domain definitions (clinical, documents, prior_auth, etc.)' },
  { name: 'get_sandbox_domain', description: 'Get one sandbox domain with events, resources, and scenarios' },
  { name: 'get_synthetic_resource', description: 'Fetch synthetic FHIR resource by type and id' },
  { name: 'run_sandbox_scenario', description: 'Run multi-step sandbox workflow scenario (e.g. prior_auth_happy_path)' },
  { name: 'get_payer_rules', description: 'Synthetic prior-auth payer rules stub' },
  { name: 'list_sandbox_events', description: 'List webhook events grouped by sandbox domain' },
  { name: 'list_hl7_templates', description: 'List injectable HL7 sandbox templates' },
  { name: 'inject_hl7', description: 'Inject synthetic HL7 message or template; fires mapped webhook' },
  { name: 'sidecar_writeback', description: 'POST synthetic EHR write-back action to local sidecar URL' },
  { name: 'run_hl7_flight_check', description: 'Run orchestrator HL7 ACK probe for a provisioned VM' },
  { name: 'list_webhook_deliveries', description: 'List outbound webhook delivery records with retry status' },
  { name: 'replay_webhook_delivery', description: 'Replay a stored webhook envelope by delivery id' },
  { name: 'configure_webhook_reliability', description: 'Set sandbox webhook reliability/chaos profile' },
  { name: 'run_webhook_reliability_scenario', description: 'Configure profile and run webhook reliability scenario' }
]

export async function callTool(
  auth: McpAuth,
  sessionId: string,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  checkRateLimit(auth.orgId, name)
  const session = getSession(sessionId)

  switch (name) {
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
        note: 'All edits apply to Sandbox. Use create_promotion to sync Live (read-only until promoted).'
      }
    }
    case 'get_account_status':
      return dashboardFetch(auth.pat, '/api/org/status')
    case 'list_connections':
      return dashboardFetch(auth.pat, '/api/connections?includeHidden=true')
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
      const connId = String(args.connectionId ?? session.activeConnectionId ?? '')
      const prId = String(args.promotionId ?? '')
      return dashboardFetch(
        auth.pat,
        `/api/connections/${encodeURIComponent(connId)}/promotions/${encodeURIComponent(prId)}`
      )
    }
    case 'confirm_action': {
      const promotionId = String(args.promotionId ?? '')
      if (!promotionId) {
        throw new Error('promotionId required for confirm_action')
      }
      const token = issueConfirmationToken(promotionId)
      return {
        confirmationToken: token,
        expiresInSeconds: 300,
        message: 'Pass confirmationToken to approve_promotion with human-intent acknowledgment.'
      }
    }
    case 'approve_promotion': {
      const connId = String(args.connectionId ?? session.activeConnectionId ?? '')
      const prId = String(args.promotionId ?? '')
      const token = String(args.confirmationToken ?? '')
      const intent = String(args.humanIntentMessage ?? '')
      if (!intent.trim()) {
        throw new Error('humanIntentMessage required to approve a Live promotion')
      }
      consumeConfirmationToken(token, prId)
      checkPromotionApproveLimit(auth.orgId)
      return dashboardFetch(
        auth.pat,
        `/api/connections/${encodeURIComponent(connId)}/promotions/${encodeURIComponent(prId)}/approve`,
        { method: 'POST', body: JSON.stringify({ humanIntentMessage: intent }) }
      )
    }
    case 'reject_promotion': {
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
    default:
      throw new Error(`Unknown tool: ${name}`)
  }
}

export async function validatePat(pat: string) {
  const res = await fetch(`${config.dashboardUrl}/api/internal/mcp/validate-pat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-hebrah-mcp-internal-secret': config.mcpInternalSecret
    },
    body: JSON.stringify({ token: pat })
  })
  if (!res.ok) return null
  return res.json() as Promise<{ orgId: string, tokenId: string, scopes: string[] }>
}