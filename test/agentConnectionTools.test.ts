import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

process.env.MCP_INTERNAL_SECRET = process.env.MCP_INTERNAL_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'
process.env.HEBRAH_API_URL = process.env.HEBRAH_API_URL || 'http://api.test'

const { callTool, agentToolDefinitions, AGENT_TOOL_NAMES, bootstrapToolDefinitions } = await import('../src/tools.js')

const agentAuth = {
  mode: 'agent' as const,
  pat: '',
  agentKey: 'hb_conn_test1234567890abcdef',
  orgId: 'agent:abc123',
  tokenId: 'agent-key',
  mcpAcl: { connections: 'write', promotions: 'none', credentials: 'none' } as never
}

const bootstrapAuth = {
  mode: 'pat' as const,
  pat: '',
  orgId: '',
  tokenId: '',
  mcpAcl: { connections: 'none', promotions: 'none', credentials: 'none' },
  bootstrap: true
}

const calls: Array<{ url: string, init?: RequestInit }> = []
const mockResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  calls.length = 0
  // @ts-expect-error test stub — node 22+ globalThis.fetch is writable
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init })
    return mockResponse({
      orgId: 'org-1',
      apiKey: 'hb_conn_fresh1',
      keyPrefix: 'hb_conn_fresh',
      mcpEndpointUrl: 'http://mcp.test/mcp',
      trial: { credits: { queries: 100, egressBytes: 5_000_000 } }
    })
  }
})

describe('agent-key sessions (hb_conn_*)', () => {
  it('exposes exactly the connection-surface tools', () => {
    assert.deepEqual(
      agentToolDefinitions.map(t => t.name).sort(),
      [...AGENT_TOOL_NAMES].sort()
    )
  })

  it('routes discover_data_sources to the merged API with the agent key', async () => {
    await callTool(agentAuth, 'sess-agent-1', 'discover_data_sources', {})
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/connections/targets'))
    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers.Authorization, 'Bearer hb_conn_test1234567890abcdef')
  })

  it('routes connect_to_data_source to POST /v1/connections with target_id', async () => {
    await callTool(
      agentAuth,
      'sess-agent-1',
      'connect_to_data_source',
      { target_id: 'demo-sqlite-research', scopes: ['table:articles'], ttl_seconds: 3600 }
    )
    assert.ok(calls[0].url.endsWith('/v1/connections'))
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.target_id, 'demo-sqlite-research')
    assert.equal(body.ttl_seconds, 3600)
  })

  it('rejects legacy dashboard tools in agent-key sessions', async () => {
    await assert.rejects(
      callTool(agentAuth, 'sess-agent-1', 'get_account_status', {}),
      /requires a dashboard PAT session/
    )
    await assert.rejects(
      callTool(agentAuth, 'sess-agent-1', 'create_promotion', {}),
      /requires a dashboard PAT session/
    )
  })

  it('rejects unknown tools in agent-key sessions', async () => {
    await assert.rejects(
      callTool(agentAuth, 'sess-agent-1', 'not_a_tool', {}),
      /requires a dashboard PAT session/
    )
  })
})

describe('bootstrap sessions (no auth)', () => {
  it('exposes create_account only', () => {
    assert.equal(bootstrapToolDefinitions.length, 1)
    assert.equal(bootstrapToolDefinitions[0].name, 'create_account')
  })

  it('create_account calls the agent API with headless signup', async () => {
    const { config } = await import('../src/config.js')
    const original = config.allowHeadlessSignup
    ;(config as { allowHeadlessSignup: boolean }).allowHeadlessSignup = true
    const result = await callTool(
      bootstrapAuth,
      'sess-bootstrap-1',
      'create_account',
      { orgName: 'eval-agent' }
    ) as { apiKey: string, keyPrefix: string, mcpEndpointUrl: string, note: string }
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/agent/account'))
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.headless, true)
    assert.equal(body.orgName, 'eval-agent')
    assert.match(result.apiKey, /hb_conn_/)
    assert.ok(result.mcpEndpointUrl)
    assert.match(result.note, /Reconnect to this MCP server/)
    ;(config as { allowHeadlessSignup: boolean }).allowHeadlessSignup = original
  })

  it('create_account requires allowHeadlessSignup', async () => {
    const { config } = await import('../src/config.js')
    const original = config.allowHeadlessSignup
    ;(config as { allowHeadlessSignup: boolean }).allowHeadlessSignup = false
    await assert.rejects(
      callTool(bootstrapAuth, 'sess-bootstrap-2', 'create_account', { orgName: 'eval-agent' }),
      /not currently available/
    )
    ;(config as { allowHeadlessSignup: boolean }).allowHeadlessSignup = original
  })
})