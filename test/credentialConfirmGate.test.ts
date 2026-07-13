import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { MCP_ACL_DEFAULTS } from '../src/connectionPolicyGate.js'
import { issueConfirmationToken } from '../src/guardrails.js'
import { callTool, type McpAuth } from '../src/tools.js'

const auth: McpAuth = {
  pat: 'hb_pat_test_token',
  orgId: '898ed7d4-fc69-44c2-9b55-761e035237a2',
  tokenId: 'token-test',
  mcpAcl: MCP_ACL_DEFAULTS
}

const connectionId = 'conn-sa-demo'

describe('credential write confirm gate', () => {
  it('rejects create_sandbox_api_key without humanIntentMessage', async () => {
    await assert.rejects(
      () => callTool(auth, 'credential-gate-session', 'create_sandbox_api_key', {
        connectionId,
        confirmationToken: 'confirm_missing'
      }),
      /humanIntentMessage required/
    )
  })

  it('rejects create_sandbox_api_key without confirmation token', async () => {
    await assert.rejects(
      () => callTool(auth, 'credential-gate-session', 'create_sandbox_api_key', {
        connectionId,
        humanIntentMessage: 'Mint demo key for local clinical-chart-demo'
      }),
      /confirm_action first/
    )
  })

  it('rejects set_connection_webhook_url without confirmation', async () => {
    await assert.rejects(
      () => callTool(auth, 'credential-gate-session', 'set_connection_webhook_url', {
        connectionId,
        webhookUrl: 'http://localhost:3009/api/webhooks/hebrah',
        humanIntentMessage: 'Wire demo receiver'
      }),
      /confirm_action first/
    )
  })

  it('rejects rotate_connection_webhook_secret without humanIntentMessage', async () => {
    const token = issueConfirmationToken('rotate_connection_webhook_secret', connectionId)
    await assert.rejects(
      () => callTool(auth, 'credential-gate-session', 'rotate_connection_webhook_secret', {
        connectionId,
        confirmationToken: token
      }),
      /humanIntentMessage required/
    )
  })

  it('rejects revoke_sandbox_api_key when token target does not match keyId', async () => {
    const token = issueConfirmationToken('revoke_sandbox_api_key', `${connectionId}:key-a`)
    await assert.rejects(
      () => callTool(auth, 'credential-gate-session', 'revoke_sandbox_api_key', {
        connectionId,
        keyId: 'key-b',
        confirmationToken: token,
        humanIntentMessage: 'Revoke stale demo key'
      }),
      /does not match/
    )
  })

  it('issues credential confirm_action tokens', async () => {
    const result = await callTool(auth, 'credential-gate-session', 'confirm_action', {
      action: 'create_sandbox_api_key',
      connectionId
    }) as { confirmationToken: string, action: string }

    assert.match(result.confirmationToken, /^confirm_/)
    assert.equal(result.action, 'create_sandbox_api_key')
  })

  it('requires keyId for revoke confirm_action', async () => {
    await assert.rejects(
      () => callTool(auth, 'credential-gate-session', 'confirm_action', {
        action: 'revoke_sandbox_api_key',
        connectionId
      }),
      /keyId required/
    )
  })
})
