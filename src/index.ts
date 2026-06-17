#!/usr/bin/env node
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js'
import { config } from './config.js'
import { logMcpAudit } from './audit.js'
import { filterToolsForAcl } from './connectionPolicyGate.js'
import { callTool, toolDefinitions, validatePat, type McpAuth } from './tools.js'

function extractPat(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null
  const token = authHeader.slice(7).trim()
  return token.startsWith('hb_pat_') ? token : null
}

function policyDecisionFromError(message: string): string {
  if (message.includes('read-only')) return 'deny_live_write'
  if (message.includes('disabled for this organization')) return 'deny_mcp_acl'
  if (message.includes('humanIntentMessage') || message.includes('confirm_action')) return 'deny_remove_confirm'
  return 'error'
}

function createMcpServer(auth: McpAuth, sessionId: string) {
  const server = new Server(
    { name: 'hebrah-hosted', version: '0.1.0' },
    { capabilities: { tools: {} } }
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: filterToolsForAcl(toolDefinitions, auth.mcpAcl).map(t => ({
      ...t,
      inputSchema: {
        type: 'object',
        properties: {
          connectionId: { type: 'string' },
          name: { type: 'string' },
          ehrVendor: { type: 'string' },
          dataFormat: { type: 'string' },
          resourceTypes: { type: 'array' },
          action: { type: 'string' },
          confirmationToken: { type: 'string' },
          humanIntentMessage: { type: 'string' },
          mappings: { type: 'array' },
          toVersionId: { type: 'string' },
          title: { type: 'string' },
          description: { type: 'string' },
          submit: { type: 'boolean' }
        }
      }
    }))
  }))

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name
    const args = (request.params.arguments ?? {}) as Record<string, unknown>
    try {
      const result = await callTool(auth, sessionId, name, args)
      await logMcpAudit({
        orgId: auth.orgId,
        tokenId: auth.tokenId,
        sessionId,
        toolName: name,
        connectionId: typeof args.connectionId === 'string' ? args.connectionId : undefined,
        policyDecision: 'allow',
        outcome: 'ok'
      })
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      await logMcpAudit({
        orgId: auth.orgId,
        tokenId: auth.tokenId,
        sessionId,
        toolName: name,
        connectionId: typeof args.connectionId === 'string' ? args.connectionId : undefined,
        policyDecision: policyDecisionFromError(message),
        outcome: 'error'
      })
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

async function createMcpSession(auth: McpAuth): Promise<McpSession> {
  const sessionId = crypto.randomUUID()
  const server = createMcpServer(auth, sessionId)
  let sessionRef: McpSession | null = null

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    onsessioninitialized: (sid) => {
      if (sessionRef) {
        mcpSessions.set(sid, sessionRef)
      }
    },
    onsessionclosed: (sid) => {
      mcpSessions.delete(sid)
    }
  })

  sessionRef = { transport, server, auth }
  await server.connect(transport)
  return sessionRef
}

const app = new Hono()

app.get('/health', c => c.json({ ok: true }))

app.all('/mcp', async (c) => {
  const pat = extractPat(c.req.header('authorization'))
  if (!pat) {
    return c.json({ error: 'Missing Bearer hb_pat_* token' }, 401)
  }

  const validated = await validatePat(pat)
  if (!validated) {
    return c.json({ error: 'Invalid or expired token' }, 401)
  }

  const auth: McpAuth = {
    pat,
    orgId: validated.orgId,
    tokenId: validated.tokenId,
    mcpAcl: validated.mcpAcl
  }

  const requestSessionId = c.req.header('mcp-session-id') ?? undefined

  if (requestSessionId) {
    const existing = mcpSessions.get(requestSessionId)
    if (existing) {
      if (existing.auth.orgId !== auth.orgId) {
        return c.json({ error: 'Session belongs to another organization' }, 403)
      }
      const response = await existing.transport.handleRequest(c.req.raw)
      if (c.req.method === 'DELETE') {
        mcpSessions.delete(requestSessionId)
      }
      return response
    }
    return sessionNotFoundResponse()
  }

  const session = await createMcpSession(auth)
  return session.transport.handleRequest(c.req.raw)
})

serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`hebrah-mcp-host listening on http://0.0.0.0:${config.port}`)
})
