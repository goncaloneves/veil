export type TomlValue = string | number | boolean | TomlValue[] | TomlTable
export type TomlTable = { [key: string]: TomlValue }

export class TomlError extends Error {
  readonly line: number

  constructor(message: string, line: number) {
    super(`${message} (line ${line})`)
    this.line = line
  }
}

const BARE_KEY = /[A-Za-z0-9_-]/
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function newTable(): TomlTable {
  return Object.create(null) as TomlTable
}
const ESCAPES: Record<string, string> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' }

function isTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

class Parser {
  readonly #src: string
  #at = 0

  constructor(src: string) {
    this.#src = src.replace(/^﻿/, '')
  }

  parse(): TomlTable {
    const root = newTable()
    let current = root
    for (;;) {
      this.#skipBlank()
      if (this.#at >= this.#src.length) return root
      if (this.#peek('[[')) {
        this.#at += 2
        const path = this.#keyPath(']]')
        current = this.#appendTable(root, path)
      } else if (this.#peek('[')) {
        this.#at += 1
        const path = this.#keyPath(']')
        current = this.#openTable(root, path)
      } else {
        const path = this.#keyPath('=')
        this.#skipInline()
        const value = this.#value()
        this.#assign(current, path, value)
      }
      this.#endOfLine()
    }
  }

  #line(): number {
    return this.#src.slice(0, this.#at).split('\n').length
  }

  #fail(message: string): never {
    throw new TomlError(message, this.#line())
  }

  #peek(text: string): boolean {
    return this.#src.startsWith(text, this.#at)
  }

  #char(): string {
    return this.#src[this.#at] ?? ''
  }

  #skipInline(): void {
    while (this.#char() === ' ' || this.#char() === '\t') this.#at++
  }

  #skipComment(): void {
    if (this.#char() === '#') while (this.#at < this.#src.length && this.#char() !== '\n') this.#at++
  }

  #skipBlank(): void {
    for (;;) {
      this.#skipInline()
      this.#skipComment()
      if (this.#char() === '\n' || this.#char() === '\r') this.#at++
      else return
    }
  }

  #endOfLine(): void {
    this.#skipInline()
    this.#skipComment()
    if (this.#at >= this.#src.length) return
    if (this.#peek('\r\n')) this.#at += 2
    else if (this.#char() === '\n') this.#at++
    else this.#fail(`Unexpected "${this.#char()}"`)
  }

  #keyPath(end: string): string[] {
    const path: string[] = []
    for (;;) {
      this.#skipInline()
      const quote = this.#char()
      if (quote === '"') path.push(this.#basicString())
      else if (quote === "'") path.push(this.#literalString())
      else {
        const start = this.#at
        while (BARE_KEY.test(this.#char())) this.#at++
        if (start === this.#at) this.#fail('Expected a key')
        path.push(this.#src.slice(start, this.#at))
      }
      if (FORBIDDEN_KEYS.has(path[path.length - 1] ?? '')) this.#fail(`The key "${path[path.length - 1]}" is not allowed`)
      this.#skipInline()
      if (this.#char() === '.') {
        this.#at++
        continue
      }
      if (!this.#peek(end)) this.#fail(`Expected "${end}"`)
      this.#at += end.length
      return path
    }
  }

  #descend(table: TomlTable, key: string): TomlTable {
    const existing = Object.hasOwn(table, key) ? table[key] : undefined
    if (existing === undefined) {
      const created = newTable()
      table[key] = created
      return created
    }
    if (Array.isArray(existing)) {
      const last = existing[existing.length - 1]
      if (isTable(last)) return last
      this.#fail(`"${key}" is not a table`)
    }
    if (isTable(existing)) return existing
    this.#fail(`"${key}" is not a table`)
  }

  #openTable(root: TomlTable, path: readonly string[]): TomlTable {
    let table = root
    for (const key of path) table = this.#descend(table, key)
    return table
  }

  #appendTable(root: TomlTable, path: readonly string[]): TomlTable {
    let table = root
    for (const key of path.slice(0, -1)) table = this.#descend(table, key)
    const last = path[path.length - 1] ?? ''
    const existing = Object.hasOwn(table, last) ? table[last] : undefined
    const created = newTable()
    if (existing === undefined) table[last] = [created]
    else if (Array.isArray(existing)) existing.push(created)
    else this.#fail(`"${last}" is not an array of tables`)
    return created
  }

  #assign(table: TomlTable, path: readonly string[], value: TomlValue): void {
    let target = table
    for (const key of path.slice(0, -1)) target = this.#descend(target, key)
    const last = path[path.length - 1] ?? ''
    if (Object.hasOwn(target, last)) this.#fail(`Duplicate key "${last}"`)
    target[last] = value
  }

  #value(): TomlValue {
    const char = this.#char()
    if (this.#peek('"""')) return this.#multilineBasic()
    if (this.#peek("'''")) return this.#multilineLiteral()
    if (char === '"') return this.#basicString()
    if (char === "'") return this.#literalString()
    if (char === '[') return this.#array()
    if (char === '{') return this.#inlineTable()
    if (this.#peek('true')) {
      this.#at += 4
      return true
    }
    if (this.#peek('false')) {
      this.#at += 5
      return false
    }
    return this.#number()
  }

  #escape(): string {
    const code = this.#char()
    this.#at++
    if (code in ESCAPES) return ESCAPES[code] ?? ''
    if (code === 'u' || code === 'U') {
      const width = code === 'u' ? 4 : 8
      const hex = this.#src.slice(this.#at, this.#at + width)
      if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== width) this.#fail('Invalid unicode escape')
      this.#at += width
      return String.fromCodePoint(parseInt(hex, 16))
    }
    this.#fail(`Invalid escape "\\${code}"`)
  }

  #basicString(): string {
    this.#at++
    let out = ''
    for (;;) {
      const char = this.#char()
      if (char === '' || char === '\n') this.#fail('Unterminated string')
      this.#at++
      if (char === '"') return out
      out += char === '\\' ? this.#escape() : char
    }
  }

  #literalString(): string {
    this.#at++
    const end = this.#src.indexOf("'", this.#at)
    const newline = this.#src.indexOf('\n', this.#at)
    if (end === -1 || (newline !== -1 && newline < end)) this.#fail('Unterminated string')
    const out = this.#src.slice(this.#at, end)
    this.#at = end + 1
    return out
  }

  #trimLeadingNewline(): void {
    if (this.#peek('\r\n')) this.#at += 2
    else if (this.#char() === '\n') this.#at++
  }

  #multilineBasic(): string {
    this.#at += 3
    this.#trimLeadingNewline()
    let out = ''
    for (;;) {
      if (this.#at >= this.#src.length) this.#fail('Unterminated string')
      if (this.#peek('"""')) {
        let quotes = 3
        while (this.#src[this.#at + quotes] === '"' && quotes < 5) quotes++
        out += '"'.repeat(quotes - 3)
        this.#at += quotes
        return out
      }
      const char = this.#char()
      this.#at++
      if (char !== '\\') {
        out += char
        continue
      }
      const rest = this.#src.slice(this.#at).match(/^[ \t]*\r?\n/)
      if (rest) {
        this.#at += rest[0].length
        while (/[\s]/.test(this.#char()) && this.#at < this.#src.length) this.#at++
      } else out += this.#escape()
    }
  }

  #multilineLiteral(): string {
    this.#at += 3
    this.#trimLeadingNewline()
    const end = this.#src.indexOf("'''", this.#at)
    if (end === -1) this.#fail('Unterminated string')
    let close = end
    while (this.#src[close + 3] === "'" && close - end < 2) close++
    const out = this.#src.slice(this.#at, close)
    this.#at = close + 3
    return out
  }

  #array(): TomlValue[] {
    this.#at++
    const items: TomlValue[] = []
    for (;;) {
      this.#skipBlank()
      if (this.#char() === ']') {
        this.#at++
        return items
      }
      items.push(this.#value())
      this.#skipBlank()
      if (this.#char() === ',') this.#at++
      else if (this.#char() !== ']') this.#fail('Expected "," or "]"')
    }
  }

  #inlineTable(): TomlTable {
    this.#at++
    const table = newTable()
    this.#skipInline()
    if (this.#char() === '}') {
      this.#at++
      return table
    }
    for (;;) {
      const path = this.#keyPath('=')
      this.#skipInline()
      this.#assign(table, path, this.#value())
      this.#skipInline()
      if (this.#char() === ',') {
        this.#at++
        continue
      }
      if (this.#char() === '}') {
        this.#at++
        return table
      }
      this.#fail('Expected "," or "}"')
    }
  }

  #number(): number {
    const match = this.#src.slice(this.#at).match(/^[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|(?:\d[\d_]*)(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?|inf|nan)/)
    if (!match || match[0] === '' || match[0] === '+' || match[0] === '-') this.#fail('Expected a value')
    this.#at += match[0].length
    const text = match[0].replaceAll('_', '')
    const sign = text.startsWith('-') ? -1 : 1
    const body = text.replace(/^[+-]/, '')
    if (body === 'inf') return sign * Infinity
    if (body === 'nan') return NaN
    if (/^0[xob]/.test(body)) return sign * Number(body)
    return Number(text)
  }
}

export function parseToml(src: string): TomlTable {
  return new Parser(src).parse()
}
