import { base64Cores, base64Encode, utf16leBytes, utf8Encode } from './encoding.ts'
import { checkDeadline } from './timeout.ts'
import type { Encoding, Secret } from './types.ts'

export type Scope = 'anywhere' | 'token' | 'context' | 'either'

export type Needle = {
  readonly text: string
  readonly label: string
  readonly source: string
  readonly name: string
  readonly scope: Scope
}

export type NeedleOptions = {
  readonly minLength: number
  readonly encodings: readonly Encoding[]
}

export type Span = {
  readonly start: number
  readonly end: number
  readonly label: string
}

export type Found = {
  readonly start: number
  readonly end: number
  readonly needle: Needle
}

const LINE_MIN = 16
export const TOKEN_MIN = 6
export const CONTEXT_MIN = 4
const TRIVIAL = /^(?:true|false|yes|no|on|off|null|none|nil|undefined)$/i
const DEFAULT_MAX = 8
const ARMOR_HEADER = /^[A-Za-z][\w-]*:\s/
const VERSION = /^v?\d+(?:[._-]\d+)+[A-Za-z]*$/
const SLUG = /^(?:[a-z0-9]+(?:[-_.:/][a-z0-9]+)+|[A-Z0-9]+(?:[-_.:/][A-Z0-9]+)+)$/

export function isTrivialWord(value: string): boolean {
  return TRIVIAL.test(value)
}

export function isLowerWords(value: string): boolean {
  return /^[a-z0-9]+(?:[-_.:][a-z0-9]+)*$/.test(value) && value.split(/[-_.:]/).every(part => /^(?:[a-z]+|\d+|[a-z]+\d+[a-z]*)$/.test(part))
}

export function isDefaultWord(value: string): boolean {
  return value.length <= DEFAULT_MAX && /^(?:[a-z]+|[A-Z]+)$/.test(value)
}

function mergeScope(a: Scope, b: Scope): Scope {
  if (a === b) return a
  if (a === 'anywhere' || b === 'anywhere') return 'anywhere'
  return 'either'
}

function classOf(char: string): number {
  if (char >= 'a' && char <= 'z') return 0
  if (char >= 'A' && char <= 'Z') return 1
  if (char >= '0' && char <= '9') return 2
  return 3
}

export function looksRandomShort(value: string): boolean {
  if (/\s/.test(value) || /^\d+$/.test(value) || VERSION.test(value) || SLUG.test(value)) return false
  const chars = [...value]
  if (new Set(chars).size < chars.length - 1) return false
  const classes = new Set<number>()
  let switches = 0
  let last = -1
  for (const char of chars) {
    const kind = classOf(char)
    classes.add(kind)
    if (last !== -1 && kind !== last) switches++
    last = kind
  }
  return classes.size >= 3 || (classes.size === 2 && switches >= 3)
}

export function scopeOf(secret: Secret, minLength: number): Scope | undefined {
  const length = secret.value.length
  const context = secret.strong === true && length >= CONTEXT_MIN && !isTrivialWord(secret.value) && secret.value.trim() === secret.value
  if (context && isDefaultWord(secret.value)) return 'context'
  if (length >= minLength) return 'anywhere'
  const token = length >= TOKEN_MIN && looksRandomShort(secret.value)
  if (token && context) return 'either'
  return token ? 'token' : context ? 'context' : undefined
}

function hex4(unit: number, upper: boolean): string {
  const digits = unit.toString(16).padStart(4, '0')
  return upper ? digits.toUpperCase() : digits
}

function unicodeForms(value: string): string[] {
  const forms = [value.normalize('NFC'), value.normalize('NFD')]
  if (/[^\x00-\x7f]/.test(value)) forms.push(value.replace(/[^\x00-\x7f]/gu, '\ufffd'), value.replace(/[^\x00-\x7f]/gu, '?'))
  return forms
}

function jsonForms(value: string): string[] {
  const plain = JSON.stringify(value).slice(1, -1)
  const ascii = (upper: boolean) => plain.replace(/[<>&'\u0080-\uffff]/g, char => `\\u${hex4(char.charCodeAt(0), upper)}`)
  return [plain, plain.replaceAll('/', '\\/'), ascii(false), ascii(false).replaceAll('/', '\\/'), ascii(true)]
}

function urlForms(value: string): string[] {
  let component: string
  try {
    component = encodeURIComponent(value)
  } catch {
    return []
  }
  const strict = component.replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
  const tilde = strict.replaceAll('~', '%7E')
  const bases = [component, strict, strict.replaceAll('%2F', '/'), strict.replaceAll('%20', '+'), tilde, tilde.replaceAll('%20', '+')]
  return bases.flatMap(base => [base, base.replace(/%[0-9A-F]{2}/g, escape => escape.toLowerCase())])
}

function base64Forms(value: string): string[] {
  const padded = base64Encode(value)
  const cores = base64Cores(utf8Encode(value))
  const urlSafe = (text: string) => text.replaceAll('+', '-').replaceAll('/', '_')
  return [padded, padded.replace(/=+$/, ''), base64Encode(value, true), ...cores, ...cores.map(urlSafe)]
}

function shellForms(value: string): string[] {
  return [
    value.replaceAll("'", "''"),
    value.replaceAll("'", "'\\''"),
    value.replace(/[&|<>^]/g, '^$&'),
    value.replace(/["$`\\]/g, '\\$&'),
    value.replace(/[$"`]/g, '`$&'),
  ]
}

export function needlesFor(secrets: readonly Secret[], options: NeedleOptions): Needle[] {
  const encodings = new Set(options.encodings)
  const seen = new Map<string, number>()
  const needles: Needle[] = []
  for (const secret of secrets) {
    const scope = scopeOf(secret, options.minLength)
    if (scope === undefined) continue
    const value = secret.value
    const used = new Map<string, number>()
    const add = (text: string, suffix: string, min: number, scopeHere: Scope = 'anywhere') => {
      if (text.length < min) return
      const known = seen.get(text)
      if (known !== undefined) {
        const held = needles[known]
        if (held && held.scope !== scopeHere) needles[known] = { ...held, scope: mergeScope(held.scope, scopeHere) }
        return
      }
      seen.set(text, needles.length)
      const count = (used.get(suffix) ?? 0) + 1
      used.set(suffix, count)
      const label = `${secret.name}${suffix}${count > 1 ? `.${count}` : ''}`
      needles.push({ text, label, source: secret.source, name: secret.name, scope: scopeHere })
    }
    if (scope !== 'anywhere') {
      add(value, '', CONTEXT_MIN, scope)
      if (encodings.has('json')) for (const form of jsonForms(value)) add(form, '~json', CONTEXT_MIN, scope)
      if (encodings.has('url')) for (const form of urlForms(value)) add(form, '~url', CONTEXT_MIN, scope)
      if (encodings.has('base64') && value.length >= options.minLength) for (const form of base64Forms(value)) add(form, '~base64', options.minLength)
      continue
    }
    const min = options.minLength
    add(value, '', min)
    for (const form of unicodeForms(value)) add(form, '~unicode', min)
    if (encodings.has('json')) for (const form of jsonForms(value)) add(form, '~json', min)
    if (encodings.has('url')) for (const form of urlForms(value)) add(form, '~url', min)
    if (encodings.has('base64')) for (const form of base64Forms(value)) add(form, '~base64', min)
    if (encodings.has('base64')) {
      const units = utf16leBytes(value)
      for (const form of base64Cores(units)) add(form, '~utf16', min)
      add(units.map(byte => byte.toString(16).padStart(2, '0')).join(','), '~utf16', min)
    }
    for (const form of shellForms(value)) add(form, '~escaped', min)
    if (encodings.has('lines') && /[\r\n]/.test(value)) {
      const keyBlock = value.includes('-----BEGIN')
      value.split(/\r?\n|\r/).forEach((line, index) => {
        const trimmed = line.trim()
        if (trimmed.startsWith('-----') || (keyBlock && ARMOR_HEADER.test(trimmed))) return
        add(trimmed, `~line${index + 1}`, Math.max(LINE_MIN, min))
      })
      add(value.replace(/\r?\n[ \t]*|\r/g, ''), '~unwrapped', min)
    }
  }
  return needles
}

const BANDS = [32, 16, 8, 4, 1]
const BASE = 0x01000193

type Band = {
  readonly width: number
  readonly power: number
  readonly shift: number
  readonly filter: Uint8Array
  readonly buckets: Map<number, Needle[]>
}

function hashOf(text: string, start: number, width: number): number {
  let hash = 0
  for (let i = 0; i < width; i++) hash = (Math.imul(hash, BASE) + text.charCodeAt(start + i)) | 0
  return hash
}

function powerOf(width: number): number {
  let power = 1
  for (let i = 1; i < width; i++) power = Math.imul(power, BASE)
  return power
}

export class NeedleIndex {
  readonly #bands: Band[] = []
  readonly anywhere: boolean

  constructor(needles: readonly Needle[]) {
    const groups = new Map<number, Needle[]>()
    for (const needle of needles) {
      const width = BANDS.find(band => needle.text.length >= band)
      if (width === undefined) continue
      const group = groups.get(width)
      if (group) group.push(needle)
      else groups.set(width, [needle])
    }
    for (const [width, group] of groups) {
      const bits = Math.min(20, Math.max(10, Math.ceil(Math.log2(group.length * 8))))
      const shift = 32 - bits
      const filter = new Uint8Array(1 << bits)
      const buckets = new Map<number, Needle[]>()
      for (const needle of group) {
        const hash = hashOf(needle.text, 0, width)
        filter[hash >>> shift] = 1
        const bucket = buckets.get(hash)
        if (bucket) bucket.push(needle)
        else buckets.set(hash, [needle])
      }
      this.#bands.push({ width, power: powerOf(width), shift, filter, buckets })
    }
    this.anywhere = needles.some(needle => needle.scope === 'anywhere')
  }

  find(text: string, deadline = Infinity, anywhereOnly = false): Found[] {
    checkDeadline(deadline)
    const found: Found[] = []
    const lastEnd = new Map<Needle, number>()
    let work = 0
    for (const { width, power, shift, filter, buckets } of this.#bands) {
      if (text.length < width) continue
      let hash = hashOf(text, 0, width)
      for (let at = 0; ; at++) {
        if ((++work & 16383) === 0) checkDeadline(deadline)
        if (filter[hash >>> shift] === 1) {
          const bucket = buckets.get(hash)
          if (bucket !== undefined) {
            for (const needle of bucket) {
              if ((++work & 16383) === 0) checkDeadline(deadline)
              if (anywhereOnly && needle.scope !== 'anywhere') continue
              if ((lastEnd.get(needle) ?? 0) > at || !text.startsWith(needle.text, at)) continue
              lastEnd.set(needle, at + needle.text.length)
              found.push({ start: at, end: at + needle.text.length, needle })
            }
          }
        }
        const next = at + width
        if (next >= text.length) break
        hash = (Math.imul((hash - Math.imul(text.charCodeAt(at), power)) | 0, BASE) + text.charCodeAt(next)) | 0
      }
    }
    return found
  }
}
