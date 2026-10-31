import { fnv1a } from './encoding.ts'
import type { HitKind } from './types.ts'

export const PLACEHOLDER = /\[veil:([A-Za-z0-9_.\/@:+~#-]+)\]/g

const UNSAFE = /[^A-Za-z0-9_.\/@:+~-]+/g

export function placeholder(label: string): string {
  return `[veil:${label}]`
}

export type LabelStat = {
  readonly label: string
  readonly kind: HitKind
  readonly count: number
}

function clean(base: string): string {
  return base.replace(UNSAFE, '_').replace(/^_+|_+$/g, '') || 'secret'
}

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1) || path
}

export class Vault {
  readonly #salt: string
  readonly #labelOf = new Map<string, string>()
  readonly #textOf = new Map<string, string>()
  readonly #kindOf = new Map<string, HitKind>()
  readonly #sourceOf = new Map<string, string>()
  readonly #counts = new Map<string, number>()
  readonly #current = new Set<string>()

  constructor(salt: string) {
    this.#salt = salt
  }

  setCurrent(texts: Iterable<string>): void {
    this.#current.clear()
    for (const text of texts) this.#current.add(text)
  }

  isCurrent(label: string): boolean {
    const text = this.#textOf.get(label)
    if (text === undefined) return false
    return this.#kindOf.get(label) === 'rule' || this.#current.has(text)
  }

  labelOf(text: string): string | undefined {
    return this.#labelOf.get(text)
  }

  register(text: string, base: string, source: string): string {
    const known = this.#labelOf.get(text)
    if (known !== undefined) return known
    const name = clean(base)
    const holder = this.#textOf.get(name)
    if (holder !== undefined && this.#kindOf.get(name) === 'known' && !this.#current.has(holder)) this.#retire(name, holder)
    let label = name
    if (this.#textOf.has(label)) label = clean(`${name}@${basename(source)}`)
    for (let n = 2; this.#textOf.has(label); n++) label = clean(`${name}@${basename(source)}.${n}`)
    this.#store(text, label, 'known', source)
    return label
  }

  label(text: string, base: string): string {
    const known = this.#labelOf.get(text)
    if (known !== undefined) return known
    const name = clean(base)
    let label = this.#hashed(name, text, 6)
    for (let width = 8; this.#textOf.has(label); width += 2) label = this.#hashed(name, text, width)
    this.#store(text, label, 'rule')
    return label
  }

  count(label: string): void {
    this.#counts.set(label, (this.#counts.get(label) ?? 0) + 1)
  }

  text(label: string): string | undefined {
    return this.#textOf.get(label)
  }

  source(label: string): string | undefined {
    return this.#sourceOf.get(label)
  }

  stats(): LabelStat[] {
    return [...this.#counts].map(([label, count]) => ({ label, kind: this.#kindOf.get(label) ?? 'rule', count }))
  }

  #retire(label: string, text: string): void {
    let next = this.#hashed(`${label}~previous`, text, 6)
    for (let width = 8; this.#textOf.has(next); width += 2) next = this.#hashed(`${label}~previous`, text, width)
    const source = this.#sourceOf.get(label)
    this.#textOf.delete(label)
    this.#kindOf.delete(label)
    this.#sourceOf.delete(label)
    this.#store(text, next, 'known', source)
  }

  #store(text: string, label: string, kind: HitKind, source?: string): void {
    this.#labelOf.set(text, label)
    this.#textOf.set(label, text)
    this.#kindOf.set(label, kind)
    if (source !== undefined) this.#sourceOf.set(label, source)
  }

  #hashed(base: string, text: string, width: number): string {
    const digest = fnv1a(this.#salt + text) + fnv1a(text + this.#salt)
    return `${base}#${digest.slice(0, Math.min(width, digest.length))}`
  }
}
