#!/usr/bin/env node
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import {
  CallToolRequestSchema,
  isInitializeRequest,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js'
import { config } from './config.js'
import { logMcpAudit } from './audit.js'
import { wrapSseResponseWithKeepalive } from './sseKeepalive.js'
import { filterToolsForAcl, normalizeMcpAcl } from './connectionPolicyGate.js'
import { listToolInputSchema } from './toolSchemas.js'
import { createHash } from 'node:crypto'
import {
  callTool,
  deleteSession,
  bootstrapToolDefinitions,
  toolDefinitions,
  agentToolDefinitions,
  AGENT_TOOL_NAMES,
  validatePat,
  type McpAuth
} from './tools.js'

const PAT_TOKEN_RE = /^hb_pat_[A-Za-z0-9_-]{6,128}$/
const AGENT_TOKEN_RE = /^hb_conn_[A-Za-z0-9_-]{6,128}$/
const MAX_MCP_SESSIONS = 1_000
const MAX_BODY_BYTES = 1_048_576

export function extractBearerToken(authHeader: string | undefined): { token: string, kind: 'pat' | 'agent' } | null {
  if (!authHeader?.startsWith('Bearer ')) return null
  const token = authHeader.slice(7).trim()
  if (PAT_TOKEN_RE.test(token)) return { token, kind: 'pat' }
  if (AGENT_TOKEN_RE.test(token)) return { token, kind: 'agent' }
  return null
}

function policyDecisionFromError(message: string): string {
  if (message.includes('read-only')) return 'deny_live_write'
  if (message.includes('disabled for this organization')) return 'deny_mcp_acl'
  if (message.includes('humanIntentMessage') || message.includes('confirm_action')) return 'deny_confirm_required'
  return 'error'
}

function describeMcpBody(body: unknown): string {
  if (Array.isArray(body)) {
    return body.map((m) => describeMcpMessage(m)).join(', ')
  }
  return describeMcpMessage(body)
}

function describeMcpMessage(message: unknown): string {
  if (!message || typeof message !== 'object') return 'unknown'
  const m = message as { method?: string, id?: unknown }
  if (m.method) return m.method
  if ('result' in m || 'error' in m) return 'response'
  return 'message'
}

function bodyHasInitialize(body: unknown): boolean {
  if (Array.isArray(body)) {
    return body.some(m => isInitializeRequest(m))
  }
  return isInitializeRequest(body)
}

const MCP_SERVER_INSTRUCTIONS = [
  'Hebrah hosted MCP: use Isolated Health Environment tools (env_list, env_connect, env_create, env_get, env_list_tables, env_query_db, env_record_outcome, env_trigger_scenario, env_list_patients, env_get_patient_chart, env_get_logs, env_pause, env_resume) for clinic sandbox environments, credential-blind SQL queries, synthetic EHR charts, and clinical scenarios.',
  'For private enterprise data connectors, use discover_data_sources → confirm_action → connect_to_data_source → query_data_source; connections are scoped, read-only, TTL-bound, and auditable.',
  'For application integration code, use the official Node SDK @hebrah/sdk (npm install @hebrah/sdk).',
  'Call get_sdk_reference for full SDK docs, API surface, and MCP-to-SDK mapping — do not web-search npm.',
  'Agents authenticate with hb_conn_* keys (from POST /v1/agent/account, hebrah login, or create_account); dashboard integrators use hb_pat_* tokens.'
].join(' ')

function createMcpServer(auth: McpAuth, sessionId: string) {
  const server = new Server(
    { name: 'hebrah-hosted', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      instructions: MCP_SERVER_INSTRUCTIONS
    }
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: (auth.bootstrap
      ? bootstrapToolDefinitions
      : auth.mode === 'agent'
        ? agentToolDefinitions
        : filterToolsForAcl(toolDefinitions, auth.mcpAcl)
    ).map(t => ({
      ...t,
      inputSchema: ('inputSchema' in t && t.inputSchema) ? t.inputSchema : listToolInputSchema(t.name)
    }))
  }))

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name
    const args = (request.params.arguments ?? {}) as Record<string, unknown>
    try {
      const result = await callTool(auth, sessionId, name, args)
      if (!auth.bootstrap) {
        await logMcpAudit({
          orgId: auth.orgId,
          tokenId: auth.tokenId,
          sessionId,
          toolName: name,
          connectionId: typeof args.connectionId === 'string' ? args.connectionId : undefined,
          policyDecision: 'allow',
          outcome: 'ok'
        })
      }
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (!auth.bootstrap) {
        await logMcpAudit({
          orgId: auth.orgId,
          tokenId: auth.tokenId,
          sessionId,
          toolName: name,
          connectionId: typeof args.connectionId === 'string' ? args.connectionId : undefined,
          policyDecision: policyDecisionFromError(message),
          outcome: 'error'
        })
      }
      return { content: [{ type: 'text', text: message }], isError: true }
    }
  })

  return server
}

interface McpSession {
  transport: WebStandardStreamableHTTPServerTransport
  server: Server
  auth: McpAuth
}

const mcpSessions = new Map<string, McpSession>()

function sessionNotFoundResponse(): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Session not found' },
      id: null
    }),
    { status: 404, headers: { 'Content-Type': 'application/json' } }
  )
}

function sessionRequiredResponse(): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Mcp-Session-Id header is required' },
      id: null
    }),
    { status: 400, headers: { 'Content-Type': 'application/json' } }
  )
}

async function createMcpSession(auth: McpAuth): Promise<McpSession> {
  const sessionId = crypto.randomUUID()
  const server = createMcpServer(auth, sessionId)
  let sessionRef: McpSession | null = null

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    enableJsonResponse: true,
    onsessioninitialized: (sid) => {
      if (sessionRef) {
        if (mcpSessions.size >= MAX_MCP_SESSIONS) {
          const oldest = mcpSessions.keys().next().value
          if (oldest) {
            mcpSessions.delete(oldest)
            deleteSession(oldest)
          }
        }
        mcpSessions.set(sid, sessionRef)
      }
    },
    onsessionclosed: (sid) => {
      mcpSessions.delete(sid)
      deleteSession(sid)
    }
  })

  transport.onclose = () => {
    const sid = transport.sessionId
    if (sid) {
      mcpSessions.delete(sid)
      deleteSession(sid)
    }
  }

  sessionRef = { transport, server, auth }
  await server.connect(transport)
  return sessionRef
}

const app = new Hono()

app.use('*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'DENY')
  c.header('Cache-Control', 'no-store')
})

app.get('/health', c => c.json({ ok: true }))

app.all('/mcp', async (c) => {
  const contentLength = Number(c.req.header('content-length') ?? '0')
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return c.json({ error: 'Payload too large' }, 413)
  }

  const sessionHeader = c.req.header('mcp-session-id')
  const bearer = extractBearerToken(c.req.header('authorization'))
  const existingSession = sessionHeader ? mcpSessions.get(sessionHeader) : undefined

  let auth: McpAuth
  if (bearer?.kind === 'agent') {
    // Agent-key session (hb_conn_*): the key is validated by the merged
    // hebrah-api on every call — no dashboard lookup needed. The hashed key
    // acts as the session-org discriminator.
    const agent = bearer.token
    auth = {
      mode: 'agent',
      pat: '',
      agentKey: agent,
      orgId: `agent:${createHash('sha256').update(agent).digest('hex').slice(0, 16)}`,
      tokenId: 'agent-key',
      mcpAcl: normalizeMcpAcl()
    }
  } else if (bearer) {
    const pat = bearer.token
    let validated
    try {
      validated = await validatePat(pat)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Dashboard unreachable'
      return c.json({ error: message }, 503)
    }
    if (!validated) {
      console.warn('[mcp] rejected: invalid or expired PAT')
      return c.json({ error: 'Invalid or expired token' }, 401)
    }
    auth = {
      mode: 'pat',
      pat,
      orgId: validated.orgId,
      tokenId: validated.tokenId,
      mcpAcl: validated.mcpAcl
    }
  } else if (existingSession?.auth.bootstrap) {
    // Bootstrap sessions are deliberately limited to create_account and do
    // not need a PAT on follow-up MCP requests.
    auth = existingSession.auth
  } else if (config.allowHeadlessSignup && !sessionHeader) {
    // A PAT cannot be required for the very tool that creates the first PAT.
    auth = {
      mode: 'pat',
      pat: '',
      orgId: '',
      tokenId: '',
      mcpAcl: normalizeMcpAcl(),
      bootstrap: true
    }
  } else {
    console.warn('[mcp] rejected: missing Bearer hb_pat_* / hb_conn_* token')
    return c.json({ error: 'Missing Bearer token (hb_pat_* for dashboard sessions, hb_conn_* for agent sessions)' }, 401)
  }

  const requestSessionId = c.req.header('mcp-session-id') ?? undefined
  let parsedBody: unknown
  if (c.req.method === 'POST') {
    try {
      parsedBody = await c.req.json()
    } catch {
      return c.json({ error: 'Invalid JSON body' }, 400)
    }
  }

  const methodLabel = c.req.method === 'POST' ? describeMcpBody(parsedBody) : c.req.method
  console.log(
    `[mcp] ${c.req.method} /mcp session=${sessionHeader ?? 'new'} methods=${methodLabel} host=${c.req.header('host') ?? '-'}`
  )

  const handleOptions = c.req.method === 'POST' ? { parsedBody } : undefined

  async function finalizeMcpResponse(response: Response): Promise<Response> {
    if (c.req.method === 'GET') {
      return wrapSseResponseWithKeepalive(response)
    }
    return response
  }

  if (requestSessionId) {
    const existing = mcpSessions.get(requestSessionId)
    if (existing) {
      if (existing.auth.orgId !== auth.orgId) {
        return c.json({ error: 'Session belongs to another organization' }, 403)
      }
      const response = await existing.transport.handleRequest(c.req.raw, handleOptions)
      if (c.req.method === 'DELETE') {
        mcpSessions.delete(requestSessionId)
        deleteSession(requestSessionId)
      }
      return finalizeMcpResponse(response)
    }
    console.warn(`[mcp] stale session ${requestSessionId} — restart MCP in Cursor after hebrah-mcp-host restarts`)
    return sessionNotFoundResponse()
  }

  if (c.req.method !== 'POST' || !bodyHasInitialize(parsedBody)) {
    return sessionRequiredResponse()
  }

  const session = await createMcpSession(auth)
  return finalizeMcpResponse(await session.transport.handleRequest(c.req.raw, handleOptions))
})

serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`hebrah-mcp-host listening on http://0.0.0.0:${config.port}`)
  console.log(`[mcp] Cursor clients must use http://localhost:${config.port}/mcp (not 0.0.0.0)`)
})
