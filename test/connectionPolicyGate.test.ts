import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  assertMcpConnectionActionAllowed,
  filterToolsForAcl,
  MCP_ACL_DEFAULTS,
  normalizeMcpAcl
} from '../src/connectionPolicyGate.js'

describe('normalizeMcpAcl', () => {
  it('applies defaults when acl is missing', () => {
    assert.deepEqual(normalizeMcpAcl(null), MCP_ACL_DEFAULTS)
  })

  it('merges partial overrides', () => {
    assert.deepEqual(normalizeMcpAcl({ connectionRemoval: true }), {
      connectionCreation: true,
      connectionPause: true,
      connectionRemoval: true
    })
  })
})

describe('assertMcpConnectionActionAllowed', () => {
  it('allows creation by default', () => {
    assert.doesNotThrow(() => assertMcpConnectionActionAllowed(MCP_ACL_DEFAULTS, 'creation'))
  })

  it('blocks removal by default', () => {
    assert.throws(
      () => assertMcpConnectionActionAllowed(MCP_ACL_DEFAULTS, 'removal'),
      /removal is disabled/
    )
  })
})

describe('filterToolsForAcl', () => {
  const tools = [
    { name: 'list_connections' },
    { name: 'create_connection' },
    { name: 'pause_connection' },
    { name: 'remove_connection' }
  ]

  it('hides remove_connection when removal is off', () => {
    const filtered = filterToolsForAcl(tools, MCP_ACL_DEFAULTS)
    assert.deepEqual(filtered.map(t => t.name), [
      'list_connections',
      'create_connection',
      'pause_connection'
    ])
  })

  it('shows remove_connection when enabled', () => {
    const filtered = filterToolsForAcl(tools, { ...MCP_ACL_DEFAULTS, connectionRemoval: true })
    assert.ok(filtered.some(t => t.name === 'remove_connection'))
  })
})
