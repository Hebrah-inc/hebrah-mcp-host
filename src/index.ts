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
import { callTool, toolDefinitions, validatePat, type McpAuth } from './tools.js'

function extractPat(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null
  const token = authHeader.slice(7).trim()
  return token.startsWith('wh_pat_') ? token : null
}

function createMcpServer(auth: McpAuth, sessionId: string) {
  const server = new Server(
    { name: 'while-health-hosted', version: '0.1.0' },
    { capabilities: { tools: {} } }
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDefinitions.map(t => ({
      ...t,
      inputSchema: {
        type: 'object',
        properties: {
          connectionId: { type: 'string' },
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
        policyDecision: message.includes('read-only') ? 'deny_live_write' : 'error',
        outcome: 'error'
      })
      return { content: [{ type: 'text', text: message }], isError: true }
    }
  })

  return server
}

const app = new Hono()

app.get('/health', c => c.json({ ok: true }))

app.all('/mcp', async (c) => {
  const pat = extractPat(c.req.header('authorization'))
  if (!pat) {
    return c.json({ error: 'Missing Bearer wh_pat_* token' }, 401)
  }

  const validated = await validatePat(pat)
  if (!validated) {
    return c.json({ error: 'Invalid or expired token' }, 401)
  }

  const auth: McpAuth = {
    pat,
    orgId: validated.orgId,
    tokenId: validated.tokenId
  }

  const sessionId = c.req.header('mcp-session-id') ?? crypto.randomUUID()

  const server = createMcpServer(auth, sessionId)
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId
  })

  await server.connect(transport)
  return transport.handleRequest(c.req.raw)
})

serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`while-mcp-host listening on http://0.0.0.0:${config.port}`)
})
