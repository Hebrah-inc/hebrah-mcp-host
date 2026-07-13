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

describe('set_connection_webhook_url confirmation tokens', () => {
  it('issues and consumes a set_connection_webhook_url token', () => {
    const token = issueConfirmationToken('set_connection_webhook_url', 'conn-sa-abc')
    assert.doesNotThrow(() =>
      consumeConfirmationToken(token, 'set_connection_webhook_url', 'conn-sa-abc')
    )
  })

  it('rejects token for wrong connection', () => {
    const token = issueConfirmationToken('set_connection_webhook_url', 'conn-sa-abc')
    assert.throws(
      () => consumeConfirmationToken(token, 'set_connection_webhook_url', 'conn-sa-other'),
      /does not match/
    )
  })
})
