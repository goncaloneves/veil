import { isReference } from './env-policy.ts'

export type EnvEntry = {
  readonly key: string
  readonly value: string
  readonly reference?: boolean
  readonly literal?: boolean
}

export type DotenvOptions = {
  readonly shell?: boolean
}

const KEY = /^(?:(?:export|declare\s+-[a-zA-Z]*x[a-zA-Z]*|typeset\s+-[a-zA-Z]*x[a-zA-Z]*)\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s?/
const DOUBLE_ESCAPES: Record<string, string> = { n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\', $: '$' }

function expands(value: string, shell: boolean): boolean {
  return isReference(value, shell ? 'shell' : 'dotenv')
}

function entry(key: string, value: string, reference: boolean, literal = false): EnvEntry {
  if (reference) return { key, value, reference: true }
  return literal ? { key, value, literal: true } : { key, value }
}

export function parseDotenv(text: string, options: DotenvOptions = {}): EnvEntry[] {
  const shell = options.shell ?? false
  const entries: EnvEntry[] = []
  const src = text.replace(/^﻿/, '').replace(/\r\n/g, '\n')
  let at = 0
  while (at < src.length) {
    const lineEnd = src.indexOf('\n', at)
    const line = src.slice(at, lineEnd === -1 ? src.length : lineEnd)
    const match = line.trimStart().match(KEY)
    if (!match || line.trimStart().startsWith('#')) {
      at = lineEnd === -1 ? src.length : lineEnd + 1
      continue
    }
    const key = match[1] ?? ''
    const valueStart = at + (line.length - line.trimStart().length) + match[0].length
    const rest = src.slice(valueStart)
    const quote = rest[0]
    if (quote === '"' || quote === "'" || quote === '`') {
      const close = findClose(rest, quote)
      if (close !== -1) {
        const raw = rest.slice(1, close)
        const literal = quote === "'" || (quote === '`' && !shell)
        entries.push(entry(key, quote === '"' ? unescapeDouble(raw) : raw, !literal && expands(quote === '`' ? `\`${raw}\`` : raw.replace(/\\[\s\S]/g, ''), shell), quote === "'"))
        const after = src.indexOf('\n', valueStart + close)
        at = after === -1 ? src.length : after + 1
        continue
      }
    }
    const end = rest.indexOf('\n')
    const raw = rest.slice(0, end === -1 ? rest.length : end)
    const value = raw.replace(/\s+#.*$/, '').trim()
    entries.push(entry(key, value, expands(value, shell)))
    at = end === -1 ? src.length : valueStart + end + 1
  }
  return entries
}

function findClose(text: string, quote: string): number {
  for (let i = 1; i < text.length; i++) {
    if (text[i] === '\\' && quote === '"') {
      i++
      continue
    }
    if (text[i] === quote) return i
  }
  return -1
}

function unescapeDouble(raw: string): string {
  return raw.replace(/\\(.)/g, (whole, char: string) => DOUBLE_ESCAPES[char] ?? whole)
}
