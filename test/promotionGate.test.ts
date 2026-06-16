import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { assertCanPromoteToLive } from '../src/promotionGate.js'

describe('assertCanPromoteToLive', () => {
  it('allows when canPromoteToLive is true', () => {
    assert.doesNotThrow(() => assertCanPromoteToLive(true))
  })

  it('blocks Sandbox tier when canPromoteToLive is false', () => {
    assert.throws(() => assertCanPromoteToLive(false), /Pro plan/)
  })

  it('blocks when status field is missing', () => {
    assert.throws(() => assertCanPromoteToLive(undefined), /Pro plan/)
  })
})
