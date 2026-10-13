import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

process.env.MCP_INTERNAL_SECRET = process.env.MCP_INTERNAL_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'
process.env.HEBRAH_API_URL = process.env.HEBRAH_API_URL || 'http://api.test'

const { callTool } = await import('../src/tools.js')

const agentAuth = {
  mode: 'agent' as const,
  pat: '',
  agentKey: 'hb_conn_test1234567890abcdef',
  orgId: 'agent:abc123',
  tokenId: 'agent-key',
  mcpAcl: { connections: 'write', promotions: 'none', credentials: 'none' } as never
}

const patAuth = {
  mode: 'pat' as const,
  pat: 'hb_pat_test1234567890abcdef',
  orgId: 'org-test-1',
  tokenId: 'tok-test-1',
  mcpAcl: { connections: 'write', promotions: 'read', credentials: 'none' } as never
}

const calls: Array<{ url: string, init?: RequestInit }> = []
const mockResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  calls.length = 0
  // @ts-expect-error test stub — node 22+ globalThis.fetch is writable
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init })
    return mockResponse({ success: true, result: 'mocked' })
  }
})

describe('agent environment tools (hb_conn_*)', () => {
  it('routes env_list to GET /v1/environments with Bearer token', async () => {
    await callTool(agentAuth, 'sess-env-1', 'env_list', {})
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.includes('/v1/environments'))
    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers.Authorization, 'Bearer hb_conn_test1234567890abcdef')
    assert.equal(calls[0].init?.method ?? 'GET', 'GET')
  })

  it('routes env_create to POST /v1/environments and sets session activeEnvironmentId', async () => {
    // Mock response returning environment with id
    // @ts-expect-error test stub
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init })
      return mockResponse({
        id: 'env-created-99',
        name: 'Agent Research Clinic',
        clinic_type: 'ambulatory_clinic',
        addons: ['sqlite', 'postgres16'],
        status: 'ready'
      })
    }

    const res = await callTool(agentAuth, 'sess-env-create-1', 'env_create', {
      name: 'Agent Research Clinic',
      clinic_type: 'ambulatory_clinic',
      database_packs: ['sqlite', 'postgres16']
    }) as { id: string }

    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/environments'))
    assert.equal(calls[0].init?.method, 'POST')
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.name, 'Agent Research Clinic')
    assert.equal(body.clinic_type, 'ambulatory_clinic')
    assert.deepEqual(body.addons, ['sqlite', 'postgres16'])
    assert.equal(res.id, 'env-created-99')

    // Now test that subsequent call infers activeEnvironmentId
    await callTool(agentAuth, 'sess-env-create-1', 'env_get', {})
    assert.equal(calls.length, 2)
    assert.ok(calls[1].url.endsWith('/v1/environments/env-created-99'))
  })

  it('routes env_query_db with credential blindness', async () => {
    await callTool(agentAuth, 'sess-env-query', 'env_query_db', {
      environment_id: 'env-target-1',
      pack: 'postgres',
      query: 'SELECT * FROM patients LIMIT 5;'
    })

    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/environments/env-target-1/db/query'))
    assert.equal(calls[0].init?.method, 'POST')
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.addon, 'postgres')
    assert.equal(body.sql, 'SELECT * FROM patients LIMIT 5;')
  })

  it('routes env_trigger_scenario and env_get_patient_chart', async () => {
    await callTool(agentAuth, 'sess-env-scen', 'env_trigger_scenario', {
      environment_id: 'env-target-1',
      scenario_id: 'sepsis_alert',
      notes: 'Urgent bedside check'
    })
    assert.ok(calls[0].url.endsWith('/v1/environments/env-target-1/ehr/scenarios/trigger'))
    assert.equal(calls[0].init?.method, 'POST')
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.scenario, 'sepsis_alert')
    assert.equal(body.notes, 'Urgent bedside check')

    await callTool(agentAuth, 'sess-env-scen', 'env_get_patient_chart', {
      environment_id: 'env-target-1',
      patient_id: 'pat-100'
    })
    assert.ok(calls[1].url.endsWith('/v1/environments/env-target-1/ehr/patients/pat-100'))
    assert.equal(calls[1].init?.method ?? 'GET', 'GET')
  })

  it('routes env_pause and env_resume', async () => {
    await callTool(agentAuth, 'sess-env-pause', 'env_pause', {
      environment_id: 'env-target-1'
    })
    assert.ok(calls[0].url.endsWith('/v1/environments/env-target-1/pause'))
    assert.equal(calls[0].init?.method, 'POST')

    await callTool(agentAuth, 'sess-env-pause', 'env_resume', {
      environment_id: 'env-target-1'
    })
    assert.ok(calls[1].url.endsWith('/v1/environments/env-target-1/resume'))
    assert.equal(calls[1].init?.method, 'POST')
  })
})

describe('PAT environment tools (hb_pat_*)', () => {
  it('routes env_list to GET /api/environments via dashboard proxy', async () => {
    await callTool(patAuth, 'sess-pat-1', 'env_list', {})
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.includes('/api/environments'))
    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers.Authorization, 'Bearer hb_pat_test1234567890abcdef')
    assert.equal(calls[0].init?.method ?? 'GET', 'GET')
  })

  it('routes env_create and env_query_db via dashboard proxy', async () => {
    await callTool(patAuth, 'sess-pat-2', 'env_create', {
      name: 'Human Clinical Lab',
      clinic_type: 'cardiology_center'
    })
    assert.ok(calls[0].url.endsWith('/api/environments'))
    assert.equal(calls[0].init?.method, 'POST')

    await callTool(patAuth, 'sess-pat-2', 'env_query_db', {
      environment_id: 'env-lab-1',
      pack: 'sqlite',
      query: 'SELECT count(*) FROM lab_results'
    })
    assert.ok(calls[1].url.endsWith('/api/environments/env-lab-1/db/query'))
    assert.equal(calls[1].init?.method, 'POST')
  })
})
