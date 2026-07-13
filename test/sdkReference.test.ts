import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  NODE_SDK_PACKAGE,
  NODE_SDK_REFERENCE_MARKDOWN,
  NODE_SDK_VERSION
} from '../src/generated/nodeSdkReference.js'
import { buildSdkReference } from '../src/sdkReference.js'

describe('NODE_SDK_REFERENCE', () => {
  it('contains core SDK identifiers', () => {
    assert.ok(NODE_SDK_REFERENCE_MARKDOWN.length > 500)
    assert.match(NODE_SDK_REFERENCE_MARKDOWN, /@hebrah\/sdk/)
    assert.match(NODE_SDK_REFERENCE_MARKDOWN, /HebrahClient/)
    assert.match(NODE_SDK_REFERENCE_MARKDOWN, /verifyWebhookSignature/)
    assert.match(NODE_SDK_REFERENCE_MARKDOWN, /MCP tool → SDK method mapping/)
  })

  it('exports package metadata', () => {
    assert.equal(NODE_SDK_PACKAGE, '@hebrah/sdk')
    assert.match(NODE_SDK_VERSION, /^\d+\.\d+\.\d+/)
  })
})

describe('buildSdkReference', () => {
  it('returns expected shape without connectionId', () => {
    const ref = buildSdkReference()
    assert.equal(ref.package, '@hebrah/sdk')
    assert.equal(ref.npmUrl, 'https://www.npmjs.com/package/@hebrah/sdk')
    assert.ok(ref.markdown.includes('npm install @hebrah/sdk'))
    assert.ok(typeof ref.mcpToSdk.get_sandbox_catalog === 'string')
    assert.equal(ref.connectionEnv, undefined)
  })

  it('includes connection-scoped env when connectionId is set', () => {
    const ref = buildSdkReference('conn-sa-demo-01')
    assert.equal(ref.connectionEnv?.connectionId, 'conn-sa-demo-01')
    assert.match(ref.connectionEnv?.snippet ?? '', /HEBRAH_CONNECTION_ID=conn-sa-demo-01/)
    assert.match(ref.markdown, /Connection-scoped environment/)
    assert.match(ref.markdown, /conn-sa-demo-01/)
  })
})
