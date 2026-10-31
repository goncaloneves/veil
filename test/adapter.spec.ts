import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { atLeast } from '../src/cli/versions.ts'
import { ENVIRONMENT_KEYS } from '../src/sources/load.ts'

describe('the Claude Code hooks module', () => {
  it('reads exactly the environment variables the core knows', () => {
    const source = readFileSync(new URL('../hooks/register.ts', import.meta.url), 'utf8')
    const block = source.slice(source.indexOf('vars: {'), source.indexOf('},', source.indexOf('vars: {')))
    const names = [...block.matchAll(/\$\.env\.get\('([A-Z_]+)'\)/g)].map(match => match[1])
    assert.deepEqual([...names].sort(), [...ENVIRONMENT_KEYS].sort())
  })
})

describe('atLeast', () => {
  it('compares versions part by part', () => {
    assert.ok(atLeast('2.1.316', [2, 1, 287]))
    assert.ok(atLeast('2.1.287', [2, 1, 287]))
    assert.ok(!atLeast('2.1.169', [2, 1, 287]))
    assert.ok(atLeast('3.0.0', [2, 1, 287]))
  })
})
