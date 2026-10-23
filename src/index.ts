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
  redactSecrets,
  validatePat,
  type McpAuth
} from './tools.js'

const PAT_TOKEN_RE = /^hb_pat_[A-Za-z0-9_-]{6,128}$/
const AGENT_TOKEN_RE = /^hb_(?:conn|live|test)_[A-Za-z0-9_-]{6,128}$/
const HEBRAH_CLOUD_RUN_HOST_RE = /^hebrah-[a-z0-9-]+(?:-[a-z0-9]+-[a-z0-9]+)?\.a\.run\.app$/
const MAX_MCP_SESSIONS = 1_000
const MAX_BODY_BYTES = 1_048_576
const MAX_TOOL_OUTPUT_CHARS = 250_000
const SESSION_IDLE_TTL_MS = 60 * 60 * 1000

const MCP_RATE_WINDOW_MS = 60_000
const MCP_RATE_MAX_REQUESTS = 120
const MCP_AUTH_FAIL_WINDOW_MS = 5 * 60_000
const MCP_AUTH_FAIL_MAX = 15
const MCP_AUTH_LOCKOUT_MS = 15 * 60_000
const MAX_TRACKED_IPS = 5_000

interface IpRateEntry {
  count: number
  resetAt: number
}

interface IpAuthFailEntry {
  failures: number
  windowResetAt: number
  lockedUntil: number
}

const ipRateLimits = new Map<string, IpRateEntry>()
const ipAuthFailures = new Map<string, IpAuthFailEntry>()

export function resetMcpRateLimitState(): void {
  ipRateLimits.clear()
  ipAuthFailures.clear()
}

function extractClientIp(xffHeader: string | undefined, cfIpHeader: string | undefined): string {
  if (cfIpHeader && cfIpHeader.trim()) {
    return cfIpHeader.trim().slice(0, 64)
  }
  if (xffHeader) {
    const parts = xffHeader.split(',').map(s => s.trim()).filter(Boolean)
    if (parts.length > 0) {
      return parts[parts.length - 1]!.slice(0, 64)
    }
  }
  return 'local'
}

function checkIpRateLimit(ip: string, now = Date.now()): { allowed: boolean, retryAfterSec: number } {
  const existing = ipRateLimits.get(ip)
  if (!existing || now >= existing.resetAt) {
    if (ipRateLimits.size >= MAX_TRACKED_IPS) {
      const oldestKey = ipRateLimits.keys().next().value
      if (oldestKey) ipRateLimits.delete(oldestKey)
    }
    ipRateLimits.set(ip, { count: 1, resetAt: now + MCP_RATE_WINDOW_MS })
    return { allowed: true, retryAfterSec: 0 }
  }
  existing.count += 1
  if (existing.count > MCP_RATE_MAX_REQUESTS) {
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000))
    }
  }
  return { allowed: true, retryAfterSec: 0 }
}

function checkIpAuthLockout(ip: string, now = Date.now()): { locked: boolean, retryAfterSec: number } {
  const entry = ipAuthFailures.get(ip)
  if (!entry) return { locked: false, retryAfterSec: 0 }
  if (entry.lockedUntil > now) {
    return {
      locked: true,
      retryAfterSec: Math.max(1, Math.ceil((entry.lockedUntil - now) / 1000))
    }
  }
  if (now >= entry.windowResetAt) {
    ipAuthFailures.delete(ip)
  }
  return { locked: false, retryAfterSec: 0 }
}

function recordIpAuthFailure(ip: string, now = Date.now()): void {
  const existing = ipAuthFailures.get(ip)
  if (!existing || now >= existing.windowResetAt) {
    if (ipAuthFailures.size >= MAX_TRACKED_IPS) {
      const oldestKey = ipAuthFailures.keys().next().value
      if (oldestKey) ipAuthFailures.delete(oldestKey)
    }
    ipAuthFailures.set(ip, {
      failures: 1,
      windowResetAt: now + MCP_AUTH_FAIL_WINDOW_MS,
      lockedUntil: 0
    })
    return
  }
  existing.failures += 1
  if (existing.failures >= MCP_AUTH_FAIL_MAX) {
    existing.lockedUntil = now + MCP_AUTH_LOCKOUT_MS
  }
}

const ONE_TIME_SECRET_TOOLS = new Set([
  'create_account',
  'create_sandbox_api_key',
  'rotate_connection_webhook_secret'
])

export function isAllowedMcpOrigin(originHeader: string | undefined): boolean {
  if (!originHeader) return true
  let parsed: URL
  try {
    parsed = new URL(originHeader)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1'
  if (isLoopback) {
    const isProdCloudRun = Boolean(process.env.K_SERVICE) || process.env.NODE_ENV === 'production'
    return !isProdCloudRun
  }
  try {
    const dashOrigin = new URL(config.dashboardUrl).origin
    if (parsed.origin === dashOrigin) return true
  } catch {
    // ignore invalid dashboardUrl
  }
  const extraAllowed = (process.env.MCP_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
  if (extraAllowed.includes(parsed.origin)) {
    return true
  }
  if (parsed.protocol !== 'https:') {
    return false
  }
  if (host === 'hebrah.com' || host.endsWith('.hebrah.com')) return true
  if (host === 'hebrah.dev' || host.endsWith('.hebrah.dev')) return true
  if (HEBRAH_CLOUD_RUN_HOST_RE.test(host)) return true
  return false
}

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
  'Agents authenticate with hb_conn_*, hb_live_*, or hb_test_* keys (from POST /v1/agent/account, hebrah login, or create_account); dashboard integrators use hb_pat_* tokens.'
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
      let text = JSON.stringify(result, null, 2)
      if (!ONE_TIME_SECRET_TOOLS.has(name)) {
        text = redactSecrets(text)
      }
      if (text.length > MAX_TOOL_OUTPUT_CHARS) {
        text = `${text.slice(0, MAX_TOOL_OUTPUT_CHARS)}\n...[TRUNCATED: output exceeded ${MAX_TOOL_OUTPUT_CHARS} chars]`
      }
      return { content: [{ type: 'text', text }] }
    } catch (error) {
      const message = redactSecrets(error instanceof Error ? error.message : String(error))
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
  createdAt: number
  lastActiveAt: number
}

const BOOTSTRAP_SESSION_TTL_MS = 10 * 60 * 1000
const mcpSessions = new Map<string, McpSession>()

function evictMcpSession(sid: string, session?: McpSession) {
  const target = session ?? mcpSessions.get(sid)
  mcpSessions.delete(sid)
  deleteSession(sid)
  if (target) {
    target.server.close().catch(() => {})
  }
}

function sweepExpiredSessions(now = Date.now()) {
  for (const [sid, session] of mcpSessions.entries()) {
    const expiredBootstrap = session.auth.bootstrap && now - session.createdAt > BOOTSTRAP_SESSION_TTL_MS
    const expiredIdle = now - session.lastActiveAt > SESSION_IDLE_TTL_MS
    if (expiredBootstrap || expiredIdle) {
      evictMcpSession(sid, session)
    }
  }
}

function redactSessionId(sessionId: string | undefined): string {
  if (!sessionId) return 'new'
  return `${sessionId.slice(0, 8)}…`
}

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

async function createMcpSession(auth: McpAuth, requestedSessionId?: string): Promise<McpSession> {
  sweepExpiredSessions()
  const sessionId = requestedSessionId ?? crypto.randomUUID()
  const server = createMcpServer(auth, sessionId)
  let sessionRef: McpSession | null = null

  const registerSession = (sid: string) => {
    if (sessionRef) {
      if (!mcpSessions.has(sid) && mcpSessions.size >= MAX_MCP_SESSIONS) {
        const oldest = mcpSessions.keys().next().value
        if (oldest) {
          evictMcpSession(oldest)
        }
      }
      mcpSessions.set(sid, sessionRef)
    }
  }

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    enableJsonResponse: true,
    onsessioninitialized: (sid) => {
      registerSession(sid)
    },
    onsessionclosed: (sid) => {
      evictMcpSession(sid)
    }
  })

  transport.onclose = () => {
    const sid = transport.sessionId
    if (sid) {
      evictMcpSession(sid)
    }
  }

  const now = Date.now()
  sessionRef = { transport, server, auth, createdAt: now, lastActiveAt: now }
  await server.connect(transport)

  if (requestedSessionId) {
    const internalTransport = transport as unknown as {
      sessionId?: string
      _initialized?: boolean
    }
    internalTransport.sessionId = sessionId
    internalTransport._initialized = true
    registerSession(sessionId)
  }

  return sessionRef
}

export const app = new Hono()

app.use('*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'DENY')
  c.header('Referrer-Policy', 'no-referrer')
  c.header('Cache-Control', 'no-store')
  c.header('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet')
  c.header('X-Permitted-Cross-Domain-Policies', 'none')
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  if (c.req.header('x-forwarded-proto') === 'https' || process.env.NODE_ENV === 'production') {
    c.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
  }
})

app.get('/robots.txt', c => c.text('User-agent: *\nDisallow: /\n'))

app.get('/health', c => c.json({ ok: true }))

app.all('/mcp', async (c) => {
  const clientIp = extractClientIp(c.req.header('x-forwarded-for'), c.req.header('cf-connecting-ip'))
  const lockout = checkIpAuthLockout(clientIp)
  if (lockout.locked) {
    c.header('Retry-After', String(lockout.retryAfterSec))
    return c.json({ error: 'Too many failed authentication attempts. IP temporarily blocked.' }, 429)
  }
  const rateCheck = checkIpRateLimit(clientIp)
  if (!rateCheck.allowed) {
    c.header('Retry-After', String(rateCheck.retryAfterSec))
    return c.json({ error: 'Rate limit exceeded' }, 429)
  }

  if (!isAllowedMcpOrigin(c.req.header('origin'))) {
    recordIpAuthFailure(clientIp)
    return c.json({ error: 'Origin not allowed' }, 403)
  }
  const contentLength = Number(c.req.header('content-length') ?? '0')
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return c.json({ error: 'Payload too large' }, 413)
  }

  sweepExpiredSessions()
  const sessionHeader = c.req.header('mcp-session-id')
  const existingSession = sessionHeader ? mcpSessions.get(sessionHeader) : undefined

  const rawAuthHeader = c.req.header('authorization')
  const bearer = extractBearerToken(rawAuthHeader)

  if (rawAuthHeader && rawAuthHeader.trim().length > 0 && !bearer) {
    recordIpAuthFailure(clientIp)
    console.warn('[mcp] rejected: malformed Authorization header')
    return c.json({ error: 'Invalid or expired token' }, 401)
  }

  let auth: McpAuth
  if (bearer?.kind === 'agent') {
    // Agent-key session (hb_conn_* / hb_live_* / hb_test_*): the key is validated
    // by hebrah-api on every call — no dashboard lookup needed. The hashed key
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
      const message = redactSecrets(error instanceof Error ? error.message : 'Dashboard unreachable')
      return c.json({ error: message }, 503)
    }
    if (!validated) {
      recordIpAuthFailure(clientIp)
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
    recordIpAuthFailure(clientIp)
    console.warn('[mcp] rejected: missing Bearer hb_pat_* / hb_conn_* / hb_live_* / hb_test_* token')
    return c.json({ error: 'Missing Bearer token (hb_pat_* for dashboard sessions, hb_conn_*/hb_live_*/hb_test_* for agent sessions)' }, 401)
  }

  const requestSessionId = c.req.header('mcp-session-id') ?? undefined
  let parsedBody: unknown
  if (c.req.method === 'POST') {
    let rawText: string
    try {
      rawText = await c.req.text()
    } catch {
      return c.json({ error: 'Invalid request body' }, 400)
    }
    if (Buffer.byteLength(rawText, 'utf8') > MAX_BODY_BYTES) {
      return c.json({ error: 'Payload too large' }, 413)
    }
    try {
      parsedBody = JSON.parse(rawText)
    } catch {
      return c.json({ error: 'Invalid JSON body' }, 400)
    }
  }

  const methodLabel = c.req.method === 'POST' ? describeMcpBody(parsedBody) : c.req.method
  console.log(
    `[mcp] ${c.req.method} /mcp session=${redactSessionId(sessionHeader)} methods=${methodLabel} host=${c.req.header('host') ?? '-'}`
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
      existing.lastActiveAt = Date.now()
      const response = await existing.transport.handleRequest(c.req.raw, handleOptions)
      if (c.req.method === 'DELETE') {
        evictMcpSession(requestSessionId, existing)
      }
      return finalizeMcpResponse(response)
    }
    if (!auth.bootstrap && /^[a-zA-Z0-9_-]{8,128}$/.test(requestSessionId)) {
      console.info(
        `[mcp] re-hydrating cold-start session ${redactSessionId(requestSessionId)} for org=${auth.orgId}`
      )
      const rehydrated = await createMcpSession(auth, requestSessionId)
      const response = await rehydrated.transport.handleRequest(c.req.raw, handleOptions)
      if (c.req.method === 'DELETE') {
        evictMcpSession(requestSessionId, rehydrated)
      }
      return finalizeMcpResponse(response)
    }
    console.warn(`[mcp] stale session ${redactSessionId(requestSessionId)} — restart MCP in Cursor after hebrah-mcp-host restarts`)
    return sessionNotFoundResponse()
  }

  if (c.req.method !== 'POST') {
    return sessionRequiredResponse()
  }

  if (!bodyHasInitialize(parsedBody)) {
    if (parsedBody === undefined) {
      return sessionRequiredResponse()
    }
    const statelessSessionId = `stateless-${crypto.randomUUID()}`
    const statelessServer = createMcpServer(auth, statelessSessionId)
    const statelessTransport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    })
    await statelessServer.connect(statelessTransport)
    try {
      const response = await statelessTransport.handleRequest(c.req.raw, handleOptions)
      return finalizeMcpResponse(response)
    } finally {
      statelessServer.close().catch(() => {})
      deleteSession(statelessSessionId)
    }
  }

  const session = await createMcpSession(auth)
  return finalizeMcpResponse(await session.transport.handleRequest(c.req.raw, handleOptions))
})

const isTestRunner =
  process.env.MCP_SKIP_LISTEN === '1' ||
  process.env.NODE_ENV === 'test' ||
  Boolean(process.env.NODE_TEST_CONTEXT) ||
  process.execArgv.includes('--test') ||
  process.argv.includes('--test')

if (!isTestRunner) {
  serve({ fetch: app.fetch, port: config.port }, () => {
    console.log(`hebrah-mcp-host listening on http://0.0.0.0:${config.port}`)
    console.log(`[mcp] Cursor clients must use http://localhost:${config.port}/mcp (not 0.0.0.0)`)
  })
}

