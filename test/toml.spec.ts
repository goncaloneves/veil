import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { TomlError, parseToml as parseRaw } from '../src/config/toml.ts'

const parseToml = (src: string) => JSON.parse(JSON.stringify(parseRaw(src))) as Record<string, unknown>

describe('parseToml', () => {
  it('reads tables, dotted keys and scalar values', () => {
    const doc = parseToml(`
title = "veil" # trailing comment
[sources]
project = true
project_depth = 2
ratio = 0.5
big = 1_000
hex = 0xff
nested.key = 'literal \\n kept'
`)
    assert.deepEqual(doc, {
      title: 'veil',
      sources: { project: true, project_depth: 2, ratio: 0.5, big: 1000, hex: 255, nested: { key: 'literal \\n kept' } },
    })
  })

  it('reads basic string escapes and unicode', () => {
    assert.deepEqual(parseToml('a = "tab\\tquote\\"slash\\\\ \\u00e9"'), { a: 'tab\tquote"slash\\ é' })
  })

  it('reads multi-line strings', () => {
    const doc = parseToml(`a = '''
first
  second'''
b = """
one \\
   two"""`)
    assert.equal(doc.a, 'first\n  second')
    assert.equal(doc.b, 'one two')
  })

  it('reads arrays across lines with comments and trailing commas', () => {
    assert.deepEqual(parseToml('list = [\n  "a", # one\n  "b",\n]\nempty = []'), { list: ['a', 'b'], empty: [] })
  })

  it('reads arrays of tables and their sub-tables', () => {
    const doc = parseToml(`
[[rules]]
id = "one"
[[rules.allowlists]]
regexes = ['''x''']
[[rules]]
id = "two"
`)
    assert.deepEqual(doc, { rules: [{ id: 'one', allowlists: [{ regexes: ['x'] }] }, { id: 'two' }] })
  })

  it('reads inline tables', () => {
    assert.deepEqual(parseToml('point = { x = 1, y = "two" }'), { point: { x: 1, y: 'two' } })
  })

  it('rejects duplicate keys with the line number', () => {
    assert.throws(() => parseToml('a = 1\na = 2'), (error: unknown) => error instanceof TomlError && error.line === 2)
  })

  it('rejects unterminated strings', () => {
    assert.throws(() => parseToml('a = "open'), TomlError)
  })

  it('builds tables with no prototype and refuses keys that could pollute one', () => {
    assert.equal(Object.getPrototypeOf(parseRaw('[a]\nb = 1')), null)
    for (const doc of ['[__proto__]\nmode = "always"', '"__proto__" = 1', 'constructor.prototype.x = 1', '[a.prototype]']) {
      assert.throws(() => parseRaw(doc), TomlError, doc)
    }
    assert.equal(({} as Record<string, unknown>).mode, undefined)
  })

  it('accepts keys named like Object methods', () => {
    assert.deepEqual(parseToml('toString = 1\nvalueOf = 2'), { toString: 1, valueOf: 2 })
  })
})
