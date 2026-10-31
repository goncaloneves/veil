import { parseToml } from '../config/toml.ts'
import { base64Decode } from '../core/encoding.ts'
import type { Secret } from '../core/types.ts'
import { MIN_VALUE, OPEN_POLICY, envSecrets, isPublicName, isReference, isTrivialValue, keyStrength, keyWords, looksRandom, needsRandomValue, valueSecrets, type EnvPolicy, type KeyStrength, type ReferenceMode } from './env-policy.ts'
import type { EnvEntry } from './dotenv.ts'
import { decodeUri } from './util.ts'

export type Leaf = {
  readonly path: readonly string[]
  readonly value: string
}

export function treeLeaves(tree: unknown, path: readonly string[] = []): Leaf[] {
  const out: Leaf[] = []
  const visit = (node: unknown, at: readonly string[]): void => {
    if (typeof node === 'string') out.push({ path: at, value: node })
    else if (Array.isArray(node)) node.forEach((item, index) => visit(item, [...at, String(index)]))
    else if (node !== null && typeof node === 'object') {
      const record = node as Record<string, unknown>
      const pair = typeof record.name === 'string' ? record.name : typeof record.key === 'string' ? record.key : undefined
      if (pair !== undefined && typeof record.value === 'string' && Object.keys(record).length <= 3) out.push({ path: [...at, pair], value: record.value })
      else for (const [key, value] of Object.entries(record)) visit(value, [...at, key])
    }
  }
  visit(tree, path)
  return out
}

function stripJsonComments(text: string): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const char = text[i] ?? ''
    if (char === '"') {
      const start = i
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === '\\') i++
      out += text.slice(start, i + 1)
    } else if (char === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++
      out += '\n'
    } else if (char === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end === -1 ? text.length : end + 1
    } else out += char
  }
  return out.replace(/,(\s*[}\]])/g, '$1')
}

export function parseJson(text: string): unknown {
  const clean = text.replace(/^﻿/, '')
  try {
    return JSON.parse(clean)
  } catch {
    try {
      return JSON.parse(stripJsonComments(clean))
    } catch {
      return undefined
    }
  }
}

export function jsonLeaves(text: string): Leaf[] {
  const tree = parseJson(text)
  return tree === undefined ? [] : treeLeaves(tree)
}

export function tomlLeaves(text: string): Leaf[] {
  try {
    return treeLeaves(parseToml(text.replace(/\r\n/g, '\n')))
  } catch {
    return keyedLeaves(text)
  }
}

type Frame = { readonly indent: number; readonly key: string; readonly item: boolean }

const QUOTED_KEY = /^:?(["'])((?:\\.|(?!\1).)*)\1\s*(?::(?=\s|$)|=)\s*(.*)$/
const PLAIN_KEY = /^:?((?:[^\s=:#;]|:(?!\s|$))(?:[^=:]|:(?!\s|$))*?)\s*(?::(?=\s|$)|=)\s*(.*)$/
const YAML_KEY = /^:?((?:[^\s:#]|:(?!\s|$))(?:[^:]|:(?!\s|$))*?)\s*:(?=\s|$)\s*(.*)$/
const BLOCK = /^[|>][-+0-9]*\s*(?:#.*)?$/
const INLINE_PAIR = /([\w.-]+)\s*[=:]\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^,}\s]+)/g

function unquote(rest: string): string | undefined {
  const quote = rest[0]
  if (quote === '"') {
    for (let i = 1; i < rest.length; i++) {
      if (rest[i] === '\\') i++
      else if (rest[i] === '"') return rest.slice(1, i).replace(/\\(.)/g, (_, char: string) => ({ n: '\n', t: '\t', r: '\r' })[char] ?? char)
    }
    return undefined
  }
  if (quote === "'") {
    for (let i = 1; i < rest.length; i++) {
      if (rest[i] === "'" && rest[i + 1] === "'") i++
      else if (rest[i] === "'") return rest.slice(1, i).replace(/''/g, "'")
    }
    return undefined
  }
  return rest.replace(/\s+[#;].*$/, '').trim()
}

function flowLeaves(rest: string, path: readonly string[]): Leaf[] {
  const tree = parseJson(rest.replace(/\s+#.*$/, ''))
  if (tree !== undefined && typeof tree === 'object') return treeLeaves(tree, path)
  if (!rest.startsWith('{')) return []
  return [...rest.matchAll(INLINE_PAIR)].map(match => ({ path: [...path, match[1] ?? ''], value: unquote(match[2] ?? '') ?? '' }))
}

export function keyedLeaves(text: string): Leaf[] {
  const leaves: Leaf[] = []
  const lines = text.replace(/^﻿/, '').split(/\r?\n/)
  let section: string[] = []
  const stack: Frame[] = []
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index] ?? ''
    const trimmed = line.trim()
    if (!trimmed || /^[#;!]/.test(trimmed) || trimmed === '---' || trimmed === '...') continue
    const header = trimmed.match(/^\[\[?\s*([^\]]+?)\s*\]\]?$/)
    if (header?.[1]) {
      section = [header[1].replace(/^["']|["']$/g, '')]
      stack.length = 0
      continue
    }
    let indent = line.length - line.trimStart().length
    let body = trimmed
    const dash = body.match(/^-(?:\s+|$)(.*)$/)
    if (dash) {
      while (stack.length > 0 && ((stack[stack.length - 1]?.indent ?? 0) > indent || (stack[stack.length - 1]?.indent === indent && stack[stack.length - 1]?.item))) stack.pop()
      stack.push({ indent, key: String(index), item: true })
      body = dash[1] ?? ''
      indent += trimmed.length - body.length
      if (!body) continue
    } else while (stack.length > 0 && (stack[stack.length - 1]?.indent ?? 0) >= indent) stack.pop()
    const at = [...section, ...stack.map(frame => frame.key)]
    const pair = body.match(QUOTED_KEY) ?? body.match(dash ? YAML_KEY : PLAIN_KEY)
    if (!pair) {
      if (dash) {
        const value = unquote(body)
        if (value) leaves.push({ path: at, value })
      }
      continue
    }
    const key = (pair.length === 4 ? pair[2] : pair[1]) ?? ''
    const rest = (pair.length === 4 ? pair[3] : pair[2]) ?? ''
    if (!rest) {
      stack.push({ indent, key, item: false })
      continue
    }
    if (BLOCK.test(rest)) {
      const block: string[] = []
      while (index + 1 < lines.length) {
        const next = lines[index + 1] ?? ''
        if (next.trim() && next.length - next.trimStart().length <= indent) break
        block.push(next)
        index++
      }
      const margin = Math.min(...block.filter(item => item.trim()).map(item => item.length - item.trimStart().length))
      const value = block.map(item => item.slice(Number.isFinite(margin) ? margin : 0)).join(rest.startsWith('>') ? ' ' : '\n').trim()
      if (value) leaves.push({ path: [...at, key], value })
      continue
    }
    if (rest.startsWith('{') || rest.startsWith('[')) {
      leaves.push(...flowLeaves(rest, [...at, key]))
      continue
    }
    const value = unquote(rest)
    if (value) leaves.push({ path: [...at, key], value })
  }
  return leaves
}

export type PickOptions = {
  readonly keys?: readonly string[]
  readonly all?: boolean
  readonly skip?: readonly string[]
  readonly ignore?: readonly string[]
  readonly strong?: readonly string[]
  readonly config?: boolean
  readonly literal?: boolean
}

const ENV_PARENTS = new Set(['env', 'environment'])
const HEADER_PARENT = /^(?!env).*headers?$/i
const AUTHORIZATION = /^(?:proxy-)?authori[sz]ation$/i
const SCHEME = /^(bearer|basic|token|apikey|api-key)\s+(\S+)$/i
const DEFAULT_SKIP = ['username', 'user', 'login', 'email', 'url', 'uri', 'host', 'hostname', 'type', 'name', 'registry', 'region']

function norm(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function isIndex(segment: string): boolean {
  return /^\d+$/.test(segment)
}

function isMapKey(segment: string): boolean {
  return /[.:/@]/.test(segment)
}

export function usable(value: string, mode: ReferenceMode = 'config'): boolean {
  return value.length >= MIN_VALUE && !isReference(value, mode)
}

export function schemeSecrets(value: string, name: string, source: string): Secret[] {
  const scheme = value.trim().match(SCHEME)
  if (!scheme?.[2] || !usable(scheme[2]) || isTrivialValue(scheme[2], 'strong')) return []
  const out: Secret[] = [{ name: `${name}.token`, value: scheme[2], source, strong: true }]
  if (scheme[1]?.toLowerCase() === 'basic') {
    const password = base64Decode(scheme[2])?.split(':').slice(1).join(':')
    if (password && password.length >= MIN_VALUE) out.push({ name: `${name}.password`, value: password, source, strong: true })
  }
  return out
}

export function headerSecrets(header: string, value: string, source: string, name: string): Secret[] {
  const trimmed = value.trim()
  if (!usable(trimmed)) return []
  if (AUTHORIZATION.test(header) || SCHEME.test(trimmed)) {
    const parts = schemeSecrets(trimmed, name, source)
    return SCHEME.test(trimmed) && parts.length === 0 ? [] : isTrivialValue(trimmed, 'strong') ? [] : [{ name, value: trimmed, source, strong: true }, ...parts]
  }
  const strength = keyStrength(header)
  if (strength === 'none' || isPublicName(header) || isTrivialValue(trimmed, strength)) return []
  return [{ name, value: trimmed, source, strong: true }]
}

export function headerListSecrets(list: string, source: string, name: string): Secret[] {
  const out: Secret[] = []
  const parts = /\n/.test(list) ? list.split(/\r?\n/) : /^[^:=]*=/.test(list) ? list.split(',') : [list]
  for (const part of parts) {
    const cut = Math.min(...[part.indexOf(':'), part.indexOf('=')].filter(index => index > 0))
    if (!Number.isFinite(cut)) continue
    const header = decodeUri(part.slice(0, cut).trim())
    out.push(...headerSecrets(header, decodeUri(part.slice(cut + 1).trim()), source, `${name}.${header}`))
  }
  return out
}

export function flagSecrets(tokens: readonly string[], source: string, name: string, expands: readonly boolean[] = [], mode: ReferenceMode = 'config'): Secret[] {
  const out: Secret[] = []
  for (let i = 0; i < tokens.length; i++) {
    const flag = (tokens[i] ?? '').match(/^--?([A-Za-z][\w-]*)(?:=(.*))?$/)
    if (!flag?.[1]) continue
    const strength = keyStrength(flag[1])
    if (strength === 'none' || keyWords(flag[1]).at(-1) === 'KEYS') continue
    const inline = flag[2] !== undefined
    const value = inline ? flag[2] : tokens[i + 1]
    if (value === undefined || value.startsWith('-') || expands[inline ? i : i + 1]) continue
    if (usable(value, mode) && !isTrivialValue(value, strength)) out.push({ name: `${name}.${flag[1]}`, value, source, strong: true })
  }
  return out
}

export function envEntrySecrets(entries: readonly EnvEntry[], source: string, policy: EnvPolicy = OPEN_POLICY): Secret[] {
  const plain: EnvEntry[] = []
  const out: Secret[] = []
  for (const entry of entries) {
    if (entry.reference) continue
    if (keyWords(entry.key).at(-1) === 'HEADERS') {
      out.push(...headerListSecrets(entry.value, source, entry.key))
      continue
    }
    plain.push(entry)
    if (/^\s*\{/.test(entry.value) && (keyStrength(entry.key) !== 'none' || policy.known?.has(entry.key))) {
      const tree = parseJson(entry.value)
      if (tree !== undefined) out.push(...pickSecrets(treeLeaves(tree), source, entry.key))
    }
  }
  return [...envSecrets(plain, source, policy), ...out]
}

function ancestorStrength(named: readonly string[], extra: ReadonlySet<string>): KeyStrength {
  for (let i = named.length - 2; i >= 0; i--) {
    const segment = named[i] ?? ''
    if (isMapKey(segment)) continue
    const strength = keyStrength(segment)
    return strength === 'none' && extra.has(norm(segment)) ? 'weak' : strength
  }
  return 'none'
}

export function pickSecrets(leaves: readonly Leaf[], source: string, prefix: string, options: PickOptions = {}): Secret[] {
  const out: Secret[] = []
  const extra = new Set((options.keys ?? []).map(norm))
  const skip = new Set((options.skip ?? DEFAULT_SKIP).map(norm))
  const ignore = new Set((options.ignore ?? []).map(norm))
  const forced = new Set((options.strong ?? []).map(norm))
  const mode: ReferenceMode = options.literal ? 'literal' : 'config'
  for (const leaf of leaves) {
    const value = leaf.value.trim()
    if (!usable(value, mode)) continue
    const named = leaf.path.filter(segment => !isIndex(segment))
    const key = named[named.length - 1] ?? ''
    const parent = named[named.length - 2] ?? ''
    const name = `${prefix}/${named.join('.')}`
    if (ignore.has(norm(key))) continue
    if (ENV_PARENTS.has(norm(parent))) {
      out.push(...envEntrySecrets([{ key, value, literal: true }], source).map(secret => ({ ...secret, name: `${prefix}/${named.slice(0, -1).join('.')}.${secret.name}` })))
      continue
    }
    out.push(...valueSecrets(value, source, name))
    if (HEADER_PARENT.test(parent) && !isIndex(leaf.path[leaf.path.length - 1] ?? '')) {
      out.push(...headerSecrets(key, value, source, name))
      continue
    }
    if (options.all) {
      if (!skip.has(norm(key)) && !key.startsWith('//') && !/\s/.test(value.replace(SCHEME, '$2')) && !isTrivialValue(value, 'weak')) {
        out.push({ name, value, source, strong: true }, ...schemeSecrets(value, name, source))
      }
      continue
    }
    let strength = forced.has(norm(key)) ? 'strong' : keyStrength(key)
    if (strength === 'none' && extra.has(norm(key))) strength = 'weak'
    if (strength === 'none' && isMapKey(key)) strength = ancestorStrength(named, extra)
    if (strength === 'none' || isPublicName(key)) continue
    if (needsRandomValue(key) && !forced.has(norm(key)) && !extra.has(norm(key)) && !looksRandom(value)) continue
    if (options.config && strength !== 'strong' && !looksRandom(value)) continue
    if (options.config && isIndex(leaf.path[leaf.path.length - 1] ?? '') && /^[A-Za-z_][\w.-]*$/.test(value)) continue
    if (strength !== 'strong' && /[ \t]/.test(value) && !SCHEME.test(value) && !/-----BEGIN /.test(value)) continue
    if (isTrivialValue(value, strength)) continue
    out.push({ name, value, source, ...(options.config && strength !== 'strong' ? {} : { strong: true }) }, ...schemeSecrets(value, name, source))
    const assigned = value.match(/^[\w.-]+=(\S{4,})$/)?.[1]
    if (assigned && !options.config && usable(assigned, mode) && !isTrivialValue(assigned, 'strong')) out.push({ name: `${name}.value`, value: assigned, source, strong: true })
  }
  return out
}
