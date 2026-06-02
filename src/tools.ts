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
  if (!key.startsWith('wh_test_')) {
    throw new Error('WHILE_SANDBOX_API_KEY must be set on while-mcp-host for ultra-a tools')
  }
  const res = await fetch(`${config.whileApiUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`,
      ...(init?.headers ?? {})
    }
  })
  if (!res.ok) {
    throw new Error(`ultra-a ${path} failed (${res.status}): ${await res.text()}`)
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
  { name: 'get_sandbox_catalog', description: 'ultra-a sandbox catalog (optional)' },
  { name: 'trigger_test_webhook', description: 'Trigger mock webhook (sandbox)' }
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
      return ultraFetch('/v1/webhooks/trigger-mock-event', {
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
      'x-while-mcp-internal-secret': config.mcpInternalSecret
    },
    body: JSON.stringify({ token: pat })
  })
  if (!res.ok) return null
  return res.json() as Promise<{ orgId: string, tokenId: string, scopes: string[] }>
}
