import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  consumeConfirmationToken,
  issueConfirmationToken
} from '../src/guardrails.js'

describe('remove_connection confirmation tokens', () => {
  it('issues and consumes a remove_connection token', () => {
    const token = issueConfirmationToken('remove_connection', 'conn-sa-abc')
    assert.doesNotThrow(() =>
      consumeConfirmationToken(token, 'remove_connection', 'conn-sa-abc')
    )
  })

  it('rejects token for wrong connection', () => {
    const token = issueConfirmationToken('remove_connection', 'conn-sa-abc')
    assert.throws(
      () => consumeConfirmationToken(token, 'remove_connection', 'conn-sa-other'),
      /does not match/
    )
  })

  it('rejects promotion consume on remove token', () => {
    const token = issueConfirmationToken('remove_connection', 'conn-sa-abc')
    assert.throws(
      () => consumeConfirmationToken(token, 'approve_promotion', 'conn-sa-abc'),
      /does not match/
    )
  })
})

describe('credential write confirmation tokens', () => {
  const connectionId = 'conn-sa-demo'

  it('issues and consumes create_sandbox_api_key token', () => {
    const token = issueConfirmationToken('create_sandbox_api_key', connectionId)
    assert.doesNotThrow(() =>
      consumeConfirmationToken(token, 'create_sandbox_api_key', connectionId)
    )
  })

  it('issues and consumes rotate_connection_webhook_secret token', () => {
    const token = issueConfirmationToken('rotate_connection_webhook_secret', connectionId)
    assert.doesNotThrow(() =>
      consumeConfirmationToken(token, 'rotate_connection_webhook_secret', connectionId)
    )
  })

  it('issues and consumes set_connection_webhook_url token', () => {
    const token = issueConfirmationToken('set_connection_webhook_url', connectionId)
    assert.doesNotThrow(() =>
      consumeConfirmationToken(token, 'set_connection_webhook_url', connectionId)
    )
  })

  it('issues and consumes revoke_sandbox_api_key token with composite target', () => {
    const targetId = `${connectionId}:key-123`
    const token = issueConfirmationToken('revoke_sandbox_api_key', targetId)
    assert.doesNotThrow(() =>
      consumeConfirmationToken(token, 'revoke_sandbox_api_key', targetId)
    )
  })

  it('rejects revoke token when keyId does not match', () => {
    const token = issueConfirmationToken('revoke_sandbox_api_key', `${connectionId}:key-123`)
    assert.throws(
      () => consumeConfirmationToken(token, 'revoke_sandbox_api_key', `${connectionId}:key-456`),
      /does not match/
    )
  })

  it('rejects credential token reused for a different action', () => {
    const token = issueConfirmationToken('create_sandbox_api_key', connectionId)
    assert.throws(
      () => consumeConfirmationToken(token, 'set_connection_webhook_url', connectionId),
      /does not match/
    )
  })
})
