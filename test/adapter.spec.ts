import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { atLeast } from '../src/cli/versions.ts'
describe('atLeast', () => {
  it('compares versions part by part', () => {
    assert.ok(atLeast('2.1.316', [2, 1, 287]))
    assert.ok(atLeast('2.1.287', [2, 1, 287]))
    assert.ok(!atLeast('2.1.169', [2, 1, 287]))
    assert.ok(atLeast('3.0.0', [2, 1, 287]))
  })
})
