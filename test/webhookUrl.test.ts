import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildLocalWebhookReceiverUrl,
  parseLocalAppUrlFromArgs,
  suggestedWebhookUrls,
  webhookReceiverPath
} from '../src/webhookUrl.js'

describe('webhookReceiverPath', () => {
  it('returns the hebrah webhook receiver path', () => {
    assert.equal(webhookReceiverPath(), '/api/webhooks/hebrah')
  })
})

describe('buildLocalWebhookReceiverUrl', () => {
  it('maps port with docker delivery target', () => {
    assert.equal(
      buildLocalWebhookReceiverUrl({ port: 3009, deliveryTarget: 'docker' }),
      'http://host.docker.internal:3009/api/webhooks/hebrah'
    )
  })

  it('keeps localhost with host delivery target', () => {
    assert.equal(
      buildLocalWebhookReceiverUrl({ localAppUrl: 'http://localhost:3009', deliveryTarget: 'host' }),
      'http://localhost:3009/api/webhooks/hebrah'
    )
  })

  it('maps loopback to host.docker.internal with auto delivery target', () => {
    assert.equal(
      buildLocalWebhookReceiverUrl({ localAppUrl: 'http://localhost:3009', deliveryTarget: 'auto' }),
      'http://host.docker.internal:3009/api/webhooks/hebrah'
    )
  })

  it('keeps non-loopback host with auto delivery target', () => {
    assert.equal(
      buildLocalWebhookReceiverUrl({ localAppUrl: 'http://myapp.local:4000', deliveryTarget: 'auto' }),
      'http://myapp.local:4000/api/webhooks/hebrah'
    )
  })
})

describe('suggestedWebhookUrls', () => {
  it('returns host and docker variants for a port', () => {
    assert.deepEqual(suggestedWebhookUrls({ port: 3009 }), {
      host: 'http://localhost:3009/api/webhooks/hebrah',
      docker: 'http://host.docker.internal:3009/api/webhooks/hebrah'
    })
  })
})

describe('parseLocalAppUrlFromArgs', () => {
  it('parses localAppUrl from snake_case args', () => {
    assert.deepEqual(parseLocalAppUrlFromArgs({ local_app_url: 'http://localhost:3002' }), {
      localAppUrl: 'http://localhost:3002'
    })
  })

  it('parses port and host', () => {
    assert.deepEqual(parseLocalAppUrlFromArgs({ port: 3003, host: '127.0.0.1' }), {
      port: 3003,
      host: '127.0.0.1'
    })
  })

  it('rejects invalid port', () => {
    assert.throws(() => parseLocalAppUrlFromArgs({ port: 70000 }), /port must be/)
  })
})
