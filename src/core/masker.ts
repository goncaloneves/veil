import { findNeedles, needlesFor, type Needle, type Span } from './known.ts'
import { MaskTimeout, compileRules, findRuleSpans, type CompiledRules } from './rules.ts'
import type { Encoding, Hit, HitKind, Masked, Restored, RuleSet, Secret } from './types.ts'
import { PLACEHOLDER, Vault, placeholder } from './vault.ts'

export { MaskTimeout }

export type MaskerSettings = {
  readonly secrets: readonly Secret[]
  readonly ruleSet: RuleSet
  readonly disabledRules?: readonly string[]
  readonly minLength: number
  readonly encodings: readonly Encoding[]
}

export type MaskerOptions = MaskerSettings & {
  readonly salt: string
  readonly budgetMs?: number
}

export type MaskerInfo = {
  readonly needles: number
  readonly rules: number
  readonly failedRules: readonly string[]
  readonly ruleSetVersion: string
}

type Candidate = Span & { readonly kind: HitKind }

function rank(a: Candidate, b: Candidate): number {
  return (a.kind === b.kind ? 0 : a.kind === 'known' ? -1 : 1) || b.end - b.start - (a.end - a.start) || a.start - b.start
}

export class Masker {
  readonly vault: Vault
  readonly #budgetMs: number
  #settings: MaskerSettings
  #rules: CompiledRules
  #needles: Needle[] = []
  #retired: Needle[] = []

  constructor(options: MaskerOptions) {
    this.vault = new Vault(options.salt)
    this.#budgetMs = options.budgetMs ?? Infinity
    this.#settings = options
    this.#rules = compileRules(options.ruleSet, options.disabledRules)
    this.#setNeedles(options)
  }

  get info(): MaskerInfo {
    return {
      needles: this.#needles.length,
      rules: this.#rules.rules.length,
      failedRules: this.#rules.failed,
      ruleSetVersion: this.#settings.ruleSet.version,
    }
  }

  configure(settings: MaskerSettings): void {
    const rulesChanged =
      settings.ruleSet !== this.#settings.ruleSet || (settings.disabledRules ?? []).join() !== (this.#settings.disabledRules ?? []).join()
    this.#settings = settings
    if (rulesChanged) this.#rules = compileRules(settings.ruleSet, settings.disabledRules)
    this.#setNeedles(settings)
  }

  setSecrets(secrets: readonly Secret[]): void {
    this.configure({ ...this.#settings, secrets })
  }

  holds(value: string): boolean {
    return this.#needles.some(needle => needle.text === value)
  }

  #setNeedles(settings: MaskerSettings): void {
    const found = needlesFor(settings.secrets, settings)
    this.vault.setCurrent(found.map(needle => needle.text))
    const needles = found.map(needle => ({ ...needle, label: this.vault.register(needle.text, needle.label, needle.source) }))
    const current = new Set(needles.map(needle => needle.text))
    const retired = [...this.#retired, ...this.#needles].filter(needle => !current.has(needle.text))
    this.#retired = [...new Map(retired.map(needle => [needle.text, needle])).values()]
    this.#needles = needles.sort((a, b) => b.text.length - a.text.length)
  }

  #reserved(text: string): Span[] {
    const spans: Span[] = []
    for (const match of text.matchAll(PLACEHOLDER)) {
      const label = match[1] ?? ''
      if (this.vault.text(label) !== undefined) spans.push({ start: match.index, end: match.index + match[0].length, label })
    }
    return spans
  }

  mask(text: string, options: { readonly deadline?: number } = {}): Masked {
    if (!text) return { text, hits: [] }
    const deadline = options.deadline ?? (this.#budgetMs === Infinity ? Infinity : Date.now() + this.#budgetMs)
    const reserved = this.#reserved(text)
    const candidates: Candidate[] = [
      ...findNeedles(text, [...this.#needles, ...this.#retired]).map(span => ({
        ...span,
        label: this.vault.labelOf(text.slice(span.start, span.end)) ?? span.label,
        kind: 'known' as const,
      })),
      ...findRuleSpans(text, this.#rules, deadline).map(span => ({ ...span, kind: 'rule' as const })),
    ].filter(span => !reserved.some(spot => spot.start <= span.start && span.end <= spot.end))
    if (candidates.length === 0) return { text, hits: [] }
    candidates.sort((a, b) => a.start - b.start || b.end - a.end)
    const groups: Candidate[][] = []
    let groupEnd = -1
    for (const candidate of candidates) {
      if (candidate.start < groupEnd) {
        groups[groups.length - 1]?.push(candidate)
        groupEnd = Math.max(groupEnd, candidate.end)
      } else {
        groups.push([candidate])
        groupEnd = candidate.end
      }
    }
    const hits: Hit[] = []
    let out = ''
    let cursor = 0
    for (const group of groups) {
      const primary = [...group].sort(rank)[0]
      if (!primary) continue
      const start = Math.min(...group.map(span => span.start))
      const end = Math.max(...group.map(span => span.end))
      const covered = text.slice(start, end)
      const whole = primary.start === start && primary.end === end
      const label = whole
        ? primary.kind === 'known'
          ? primary.label
          : this.vault.label(covered, primary.label)
        : this.vault.label(covered, `${primary.label.replace(/#.*$/, '')}~joined`)
      this.vault.count(label)
      out += text.slice(cursor, start) + placeholder(label)
      cursor = end
      hits.push({ start, end, label, kind: whole ? primary.kind : 'rule' })
    }
    return { text: out + text.slice(cursor), hits }
  }

  restore(text: string): Restored {
    const restored: string[] = []
    const unknown: string[] = []
    const out = text.replace(PLACEHOLDER, (whole, label: string) => {
      const value = this.vault.text(label)
      if (value === undefined) {
        unknown.push(label)
        return whole
      }
      restored.push(label)
      return value
    })
    return { text: out, restored, unknown }
  }
}
