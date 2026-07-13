import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { resolveWebhookUrlFromSetArgs } from '../src/webhookUrl.js'

describe('resolveWebhookUrlFromSetArgs', () => {
  it('returns explicit webhookUrl when provided', () => {
    assert.equal(
      resolveWebhookUrlFromSetArgs({
        webhookUrl: 'https://example.com/hooks/hebrah'
      }),
      'https://example.com/hooks/hebrah'
    )
  })

  it('builds docker URL from port and deliveryTarget', () => {
    assert.equal(
      resolveWebhookUrlFromSetArgs({
        port: 3009,
        deliveryTarget: 'docker'
      }),
      'http://host.docker.internal:3009/api/webhooks/hebrah'
    )
  })

  it('rejects missing URL source', () => {
    assert.throws(
      () => resolveWebhookUrlFromSetArgs({ deliveryTarget: 'docker' }),
      /webhookUrl or localAppUrl or port/
    )
  })

  it('rejects invalid deliveryTarget', () => {
    assert.throws(
      () => resolveWebhookUrlFromSetArgs({ port: 3009, deliveryTarget: 'invalid' }),
      /deliveryTarget must be/
    )
  })
})
