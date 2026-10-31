import { inAssignment, isWholeToken } from './context.ts'
import { NeedleIndex, needlesFor, type Found, type Needle, type Span } from './known.ts'
import { MaskTimeout, compileRules, findRuleSpans, type CompiledRules } from './rules.ts'
import { checkDeadline } from './timeout.ts'
import type { Encoding, Hit, HitKind, Masked, Restored, RuleSet, Secret } from './types.ts'
import { PLACEHOLDER, Vault, placeholder } from './vault.ts'
import { interleaved, joinedLines, joinedList, toOriginal, unescaped, withoutAnsi, type View } from './views.ts'

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

const RULE_LABEL = /#[0-9a-f]{6,16}$/

function accepts(text: string, found: Found): boolean {
  const { needle, start, end } = found
  if (needle.scope === 'anywhere') return true
  if ((needle.scope === 'token' || needle.scope === 'either') && isWholeToken(text, start, end)) return true
  return (needle.scope === 'context' || needle.scope === 'either') && inAssignment(text, start, end, needle.name)
}

function rank(a: Candidate, b: Candidate): number {
  return (a.kind === b.kind ? 0 : a.kind === 'known' ? -1 : 1) || b.end - b.start - (a.end - a.start) || a.start - b.start
}

function lastStartingBefore(spans: readonly Span[], position: number): Span | undefined {
  let low = 0
  let high = spans.length - 1
  let best: Span | undefined
  while (low <= high) {
    const middle = (low + high) >> 1
    const spot = spans[middle]
    if (!spot) break
    if (spot.start < position) {
      best = spot
      low = middle + 1
    } else high = middle - 1
  }
  return best
}

function inside(spans: readonly Span[], candidate: Span): boolean {
  const spot = lastStartingBefore(spans, candidate.start + 1)
  return spot !== undefined && candidate.end <= spot.end
}

function overlaps(spans: readonly Span[], candidate: Span): boolean {
  const spot = lastStartingBefore(spans, candidate.end)
  return spot !== undefined && spot.end > candidate.start
}

export class Masker {
  readonly vault: Vault
  readonly #budgetMs: number
  #settings: MaskerSettings
  #rules: CompiledRules
  #needles: Needle[] = []
  #retired: Needle[] = []
  #index = new NeedleIndex([])

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
    const all = [...this.#needles, ...this.#retired]
    this.#index = new NeedleIndex(all)
  }

  #found(view: View | string, deadline: number, crossingOnly = false): Candidate[] {
    const text = typeof view === 'string' ? view : view.text
    const out: Candidate[] = []
    let checked = 0
    for (const found of this.#index.find(text, deadline, crossingOnly)) {
      if ((++checked & 4095) === 0) checkDeadline(deadline)
      if (!crossingOnly && !accepts(text, found)) continue
      const span = typeof view === 'string' ? found : toOriginal(view, found.start, found.end)
      if (crossingOnly && span.end - span.start === found.needle.text.length) continue
      out.push({ start: span.start, end: span.end, label: this.vault.labelOf(found.needle.text) ?? found.needle.label, kind: 'known' })
    }
    return out
  }

  #ruled(view: View, deadline: number): Candidate[] {
    return findRuleSpans(view.text, this.#rules, deadline).map(span => ({ ...toOriginal(view, span.start, span.end), label: span.label, kind: 'rule' as const }))
  }

  #candidates(text: string, deadline: number): Candidate[] {
    const out: Candidate[] = [...this.#found(text, deadline), ...findRuleSpans(text, this.#rules, deadline).map(span => ({ ...span, kind: 'rule' as const }))]
    const joined = this.#index.anywhere ? joinedLines(text) : undefined
    if (joined) out.push(...this.#found(joined, deadline, true))
    for (const view of [withoutAnsi(text), unescaped(text), ...interleaved(text)]) {
      if (view) out.push(...this.#found(view, deadline), ...this.#ruled(view, deadline))
    }
    const list = joinedList(text)
    if (list) out.push(...this.#ruled(list, deadline))
    return out
  }

  #reserved(text: string): { readonly known: Span[]; readonly rules: Span[]; readonly shaped: Span[] } {
    const known: Span[] = []
    const rules: Span[] = []
    const shaped: Span[] = []
    for (const match of text.matchAll(PLACEHOLDER)) {
      const label = match[1] ?? ''
      const span = { start: match.index, end: match.index + match[0].length, label }
      shaped.push(span)
      if (this.vault.text(label) !== undefined) {
        known.push(span)
        rules.push(span)
      } else if (RULE_LABEL.test(label)) rules.push(span)
    }
    return { known, rules, shaped }
  }

  mask(text: string, options: { readonly deadline?: number } = {}): Masked {
    if (!text) return { text, hits: [] }
    const deadline = options.deadline ?? (this.#budgetMs === Infinity ? Infinity : Date.now() + this.#budgetMs)
    const reserved = this.#reserved(text)
    const candidates: Candidate[] = []
    let checked = 0
    for (const candidate of this.#candidates(text, deadline)) {
      if ((++checked & 4095) === 0) checkDeadline(deadline)
      const held =
        candidate.kind === 'known'
          ? inside(reserved.known, candidate)
          : overlaps(reserved.rules, candidate) || (overlaps(reserved.shaped, candidate) && !inside(reserved.shaped, candidate))
      if (!held) candidates.push(candidate)
    }
    if (candidates.length === 0) return { text, hits: [] }
    candidates.sort((a, b) => a.start - b.start || b.end - a.end)
    checkDeadline(deadline)
    const groups: { members: Candidate[]; start: number; end: number }[] = []
    for (const candidate of candidates) {
      const last = groups[groups.length - 1]
      if (last && candidate.start < last.end) {
        last.members.push(candidate)
        last.end = Math.max(last.end, candidate.end)
      } else groups.push({ members: [candidate], start: candidate.start, end: candidate.end })
    }
    const hits: Hit[] = []
    let out = ''
    let cursor = 0
    for (const { members, start, end } of groups) {
      let primary = members[0]
      for (const member of members) if (primary && rank(member, primary) < 0) primary = member
      if (!primary) continue
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
