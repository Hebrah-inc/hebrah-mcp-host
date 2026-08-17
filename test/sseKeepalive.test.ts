import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  SSE_KEEPALIVE_FRAME,
  SSE_KEEPALIVE_INTERVAL_MS,
  wrapSseResponseWithKeepalive
} from '../src/sseKeepalive.js'

describe('wrapSseResponseWithKeepalive', () => {
  it('passes through non-SSE responses unchanged', () => {
    const original = new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    })
    const wrapped = wrapSseResponseWithKeepalive(original)
    assert.equal(wrapped.headers.get('Content-Type'), 'application/json')
  })

  it('wraps SSE responses and sets no-buffer header', () => {
    const original = new Response(new ReadableStream(), {
      status: 200,
      headers: { 'Content-Type': 'text/event-stream' }
    })
    const wrapped = wrapSseResponseWithKeepalive(original)
    assert.equal(wrapped.headers.get('Content-Type'), 'text/event-stream')
    assert.equal(wrapped.headers.get('X-Accel-Buffering'), 'no')
  })

  it('exports keepalive constants for ops docs', () => {
    assert.equal(SSE_KEEPALIVE_FRAME, ': keepalive\n\n')
    assert.equal(SSE_KEEPALIVE_INTERVAL_MS, 25_000)
  })
})
