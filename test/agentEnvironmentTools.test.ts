import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

process.env.MCP_INTERNAL_SECRET = process.env.MCP_INTERNAL_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'
process.env.HEBRAH_API_URL = process.env.HEBRAH_API_URL || 'http://api.test'

const { callTool, assertSafeSidecarUrl, safeId, AGENT_TOOL_NAMES } = await import('../src/tools.js')
const { issueConfirmationToken, consumeConfirmationToken } = await import('../src/guardrails.js')

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
  it('includes all Isolated Health Environment tools in AGENT_TOOL_NAMES', () => {
    for (const tool of [
      'env_list',
      'env_create',
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
      'env_resume'
    ]) {
      assert.ok(AGENT_TOOL_NAMES.includes(tool), `Expected ${tool} in AGENT_TOOL_NAMES`)
    }
  })

  it('routes env_list to GET /v1/environments with Bearer token', async () => {
    await callTool(agentAuth, 'sess-env-1', 'env_list', {})
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.includes('/v1/environments'))
    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers.Authorization, 'Bearer hb_conn_test1234567890abcdef')
    assert.equal(calls[0].init?.method ?? 'GET', 'GET')
  })

  it('routes env_connect to POST /v1/environments/{id}/agents/connect and sets activeEnvironmentId', async () => {
    const res = await callTool(agentAuth, 'sess-env-connect-1', 'env_connect', {
      environment_id: 'env-memorial-01',
      agent_name: 'Triage Agent',
      client: 'mcp'
    }) as { activeEnvironmentId: string }

    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/environments/env-memorial-01/agents/connect'))
    assert.equal(calls[0].init?.method, 'POST')
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.agent_name, 'Triage Agent')
    assert.equal(body.client, 'mcp')
    assert.equal(res.activeEnvironmentId, 'env-memorial-01')

    // Subsequent tools default to activeEnvironmentId
    await callTool(agentAuth, 'sess-env-connect-1', 'env_list_tables', {})
    assert.equal(calls.length, 2)
    assert.ok(calls[1].url.endsWith('/v1/environments/env-memorial-01/db/tables'))
  })

  it('routes env_create to POST /v1/environments and sets session activeEnvironmentId', async () => {
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

    await callTool(agentAuth, 'sess-env-create-1', 'env_get', {})
    assert.equal(calls.length, 2)
    assert.ok(calls[1].url.endsWith('/v1/environments/env-created-99'))
  })

  it('routes env_query_db and env_record_outcome with credential blindness', async () => {
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

    await callTool(agentAuth, 'sess-env-query', 'env_record_outcome', {
      environment_id: 'env-target-1',
      outcome_type: 'sepsis_risk_flag',
      summary: 'Elevated lactate on patient pat_001',
      patient_id: 'pat_001',
      score: 0.92,
      source_agent: 'triage-bot'
    })
    assert.equal(calls.length, 2)
    assert.ok(calls[1].url.endsWith('/v1/environments/env-target-1/db/outcomes'))
    assert.equal(calls[1].init?.method, 'POST')
    const outcomeBody = JSON.parse(String(calls[1].init?.body))
    assert.equal(outcomeBody.outcome_type, 'sepsis_risk_flag')
    assert.equal(outcomeBody.patient_id, 'pat_001')
    assert.equal(outcomeBody.score, 0.92)
  })

  it('routes env_trigger_scenario, env_list_patients, env_get_patient_chart, and env_get_logs', async () => {
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

    await callTool(agentAuth, 'sess-env-scen', 'env_list_patients', {
      environment_id: 'env-target-1',
      limit: 10
    })
    assert.ok(calls[1].url.endsWith('/v1/environments/env-target-1/ehr/patients?limit=10'))

    await callTool(agentAuth, 'sess-env-scen', 'env_get_patient_chart', {
      environment_id: 'env-target-1',
      patient_id: 'pat-100'
    })
    assert.ok(calls[2].url.endsWith('/v1/environments/env-target-1/ehr/patients/pat-100'))
    assert.equal(calls[2].init?.method ?? 'GET', 'GET')

    await callTool(agentAuth, 'sess-env-scen', 'env_get_logs', {
      environment_id: 'env-target-1',
      limit: 25,
      event_type: 'db_query'
    })
    assert.ok(calls[3].url.endsWith('/v1/environments/env-target-1/logs?limit=25&event_type=db_query'))
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

  it('parses snake_case parameters in set_auto_reload', async () => {
    await callTool(agentAuth, 'sess-wallet-1', 'set_auto_reload', {
      auto_reload_enabled: true,
      auto_reload_threshold_cents: 500,
      auto_reload_amount_cents: 2500
    })
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/agent/wallet/config'))
    const body = JSON.parse(String(calls[0].init?.body))
    assert.equal(body.auto_reload_enabled, true)
    assert.equal(body.auto_reload_threshold_cents, 500)
    assert.equal(body.auto_reload_amount_cents, 2500)
  })

  it('routes env_consult_architect and env_admit_patients in agent mode', async () => {
    assert.ok(AGENT_TOOL_NAMES.includes('env_consult_architect'))
    assert.ok(AGENT_TOOL_NAMES.includes('hebrah_consult_architect'))
    assert.ok(AGENT_TOOL_NAMES.includes('env_admit_patients'))

    await callTool(agentAuth, 'sess-arch-1', 'env_consult_architect', {
      message: 'Spin up an ICU sepsis shock cohort with ventilator telemetry and DICOM CT imaging',
      auto_provision: true
    })
    assert.equal(calls.length, 1)
    assert.ok(calls[0].url.endsWith('/v1/environments/architect/chat'))
    assert.equal(calls[0].init?.method, 'POST')
    const archBody = JSON.parse(String(calls[0].init?.body))
    assert.equal(archBody.auto_provision, true)
    assert.equal(archBody.channel, 'agent_mcp')

    await callTool(agentAuth, 'sess-arch-1', 'env_admit_patients', {
      environment_id: 'env-target-1',
      count: 6,
      departments: ['Critical Care / ICU'],
      diagnosis_pathways: ['Sepsis / Septic Shock'],
      acuity_levels: ['Critical (ICU)']
    })
    assert.equal(calls.length, 2)
    assert.ok(calls[1].url.endsWith('/v1/environments/env-target-1/ehr/patients/generate'))
    assert.equal(calls[1].init?.method, 'POST')
    const admitBody = JSON.parse(String(calls[1].init?.body))
    assert.equal(admitBody.count, 6)
    assert.deepEqual(admitBody.departments, ['Critical Care / ICU'])

    await callTool(agentAuth, 'sess-arch-1', 'hebrah_concierge_chat', {
      message: 'What datasets and capability packs are available in Hebrah?'
    })
    assert.equal(calls.length, 3)
    assert.ok(calls[2].url.endsWith('/v1/concierge/chat'))
    assert.equal(calls[2].init?.method, 'POST')

    await callTool(agentAuth, 'sess-arch-1', 'env_invite_human', {
      invite_email: 'founder@clinic-lab.org',
      org_name: 'Clinic Lab'
    })
    assert.equal(calls.length, 4)
    assert.ok(calls[3].url.endsWith('/v1/agent/invite-human'))
    assert.equal(calls[3].init?.method, 'POST')
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

  it('routes env_create, env_connect, env_list_tables, env_query_db, and env_record_outcome via dashboard proxy', async () => {
    await callTool(patAuth, 'sess-pat-2', 'env_create', {
      name: 'Human Clinical Lab',
      clinic_type: 'cardiology_center'
    })
    assert.ok(calls[0].url.endsWith('/api/environments'))
    assert.equal(calls[0].init?.method, 'POST')

    await callTool(patAuth, 'sess-pat-2', 'env_connect', {
      environment_id: 'env-lab-1'
    })
    assert.ok(calls[1].url.endsWith('/api/environments/env-lab-1'))

    await callTool(patAuth, 'sess-pat-2', 'env_list_tables', {})
    assert.ok(calls[2].url.endsWith('/api/environments/env-lab-1/db/tables'))

    await callTool(patAuth, 'sess-pat-2', 'env_query_db', {
      pack: 'sqlite',
      query: 'SELECT count(*) FROM lab_results'
    })
    assert.ok(calls[3].url.endsWith('/api/environments/env-lab-1/db/query'))
    assert.equal(calls[3].init?.method, 'POST')

    await callTool(patAuth, 'sess-pat-2', 'env_record_outcome', {
      outcome_type: 'audit_finding',
      summary: 'Verified lab cohort'
    })
    assert.ok(calls[4].url.endsWith('/api/environments/env-lab-1/db/outcomes'))
    assert.equal(calls[4].init?.method, 'POST')

    await callTool(patAuth, 'sess-pat-2', 'hebrah_consult_architect', {
      message: 'Oncology breast cancer staging cohort with genomics',
      auto_provision: false
    })
    assert.ok(calls[5].url.endsWith('/api/environments/architect/chat'))
    assert.equal(calls[5].init?.method, 'POST')

    await callTool(patAuth, 'sess-pat-2', 'env_admit_patients', {
      count: 4,
      departments: ['Oncology & Infusion']
    })
    assert.ok(calls[6].url.endsWith('/api/environments/env-lab-1/ehr/patients/generate'))
    assert.equal(calls[6].init?.method, 'POST')
  })
})

describe('MCP security hardening (SSRF, safeId, org-bound confirm tokens)', () => {
  it('blocks cloud metadata and non-http protocols in assertSafeSidecarUrl', () => {
    assert.throws(() => assertSafeSidecarUrl('http://169.254.169.254/latest/meta-data'), /cloud metadata/)
    assert.throws(() => assertSafeSidecarUrl('http://metadata.google.internal/computeMetadata/v1/'), /cloud metadata/)
    assert.throws(() => assertSafeSidecarUrl('file:///etc/passwd'), /must use http:\/\/ or https:\/\//)
  })

  it('rejects path traversal and unsafe characters in safeId', () => {
    assert.equal(safeId('4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94', 'environment_id'), '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94')
    assert.throws(() => safeId('../admin', 'environment_id'), /Invalid environment_id/)
    assert.throws(() => safeId('env/../../secret', 'environment_id'), /Invalid environment_id/)
    assert.throws(() => safeId('env?admin=1', 'environment_id'), /Invalid environment_id/)
  })

  it('binds confirmation tokens to orgId and prevents cross-org consumption', () => {
    const token = issueConfirmationToken('remove_connection', 'conn-123', 'org-alpha')
    assert.throws(
      () => consumeConfirmationToken(token, 'remove_connection', 'conn-123', 'org-beta'),
      /another organization/
    )
    // Valid org still succeeds if we issue a fresh token
    const token2 = issueConfirmationToken('remove_connection', 'conn-123', 'org-alpha')
    consumeConfirmationToken(token2, 'remove_connection', 'conn-123', 'org-alpha')
  })
})

