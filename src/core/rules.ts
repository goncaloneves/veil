import { shannonEntropy } from './encoding.ts'
import type { Allowlist, AllowTarget, RuleSet } from './types.ts'
import type { Span } from './known.ts'

type CompiledAllowlist = {
  readonly patterns: readonly RegExp[]
  readonly stopwords: readonly string[]
  readonly target: AllowTarget
}

export type CompiledRule = {
  readonly id: string
  readonly pattern: RegExp
  readonly keywords: readonly string[]
  readonly secretGroup: number
  readonly entropy: number
  readonly needsDigit: boolean
  readonly multiline: boolean
  readonly allowlists: readonly CompiledAllowlist[]
}

export type CompiledRules = {
  readonly rules: readonly CompiledRule[]
  readonly allowlists: readonly CompiledAllowlist[]
  readonly failed: readonly string[]
}

export class MaskTimeout extends Error {
  constructor() {
    super('masking ran out of time')
  }
}

const GROUP = 8192
const LONG_LINE = 32768
const LONG_OVERLAP = 8192
const LINE_OVERLAP = 2

function compileAllowlist(allowlist: Allowlist): CompiledAllowlist | undefined {
  try {
    return {
      patterns: allowlist.patterns.map(source => new RegExp(source)),
      stopwords: allowlist.stopwords.map(word => word.toLowerCase()),
      target: allowlist.target,
    }
  } catch {
    return undefined
  }
}

export function compileRules(set: RuleSet, disabled: readonly string[] = []): CompiledRules {
  const off = new Set(disabled)
  const rules: CompiledRule[] = []
  const failed: string[] = []
  for (const rule of set.rules) {
    if (off.has(rule.id)) continue
    try {
      rules.push({
        id: rule.id,
        pattern: new RegExp(rule.pattern, 'gd'),
        keywords: rule.keywords.map(word => word.toLowerCase()),
        secretGroup: rule.secretGroup,
        entropy: rule.entropy,
        needsDigit: rule.id.startsWith('generic'),
        multiline: rule.pattern.includes('\\s\\S'),
        allowlists: rule.allowlists.flatMap(list => compileAllowlist(list) ?? []),
      })
    } catch {
      failed.push(rule.id)
    }
  }
  return { rules, allowlists: set.allowlists.flatMap(list => compileAllowlist(list) ?? []), failed }
}

type Segment = {
  readonly start: number
  readonly text: string
  readonly lower: string
}

export function segments(text: string): Segment[] {
  const lines: { start: number; end: number }[] = []
  for (let start = 0; ; ) {
    const newline = text.indexOf('\n', start)
    lines.push({ start, end: newline === -1 ? text.length : newline })
    if (newline === -1) break
    start = newline + 1
  }
  const out: Segment[] = []
  const push = (start: number, end: number) => {
    const slice = text.slice(start, end)
    out.push({ start, text: slice, lower: slice.toLowerCase() })
  }
  for (let i = 0; i < lines.length; ) {
    const line = lines[i]
    if (!line) break
    if (line.end - line.start > LONG_LINE) {
      for (let at = line.start; ; at += LONG_LINE - LONG_OVERLAP) {
        push(at, Math.min(line.end, at + LONG_LINE))
        if (at + LONG_LINE >= line.end) break
      }
      i++
      continue
    }
    let j = i
    for (;;) {
      const next = lines[j + 1]
      if (!next || next.end - next.start > LONG_LINE) break
      if (next.end - line.start > GROUP && j > i) break
      j++
    }
    push(line.start, lines[j]?.end ?? line.end)
    if (j + 1 >= lines.length) break
    i = Math.max(i + 1, j + 1 - LINE_OVERLAP)
  }
  return out
}

function pickGroup(match: RegExpMatchArray, secretGroup: number): number {
  if (secretGroup > 0 && match[secretGroup] !== undefined) return secretGroup
  for (let group = 1; group < match.length; group++) if (match[group]) return group
  return 0
}

function lineAround(text: string, start: number, end: number): string {
  const from = text.lastIndexOf('\n', start - 1) + 1
  const to = text.indexOf('\n', end)
  return text.slice(from, to === -1 ? text.length : to)
}

function isAllowed(lists: readonly CompiledAllowlist[], secret: string, match: string, line: () => string): boolean {
  const lower = secret.toLowerCase()
  for (const list of lists) {
    if (list.stopwords.some(word => lower.includes(word))) return true
    const target = list.target === 'match' ? match : list.target === 'line' ? line() : secret
    if (list.patterns.some(pattern => pattern.test(target))) return true
  }
  return false
}

function hasKeyword(lower: string, keywords: readonly string[]): boolean {
  return keywords.length === 0 || keywords.some(word => lower.includes(word))
}

export function findRuleSpans(text: string, compiled: CompiledRules, deadline = Infinity): Span[] {
  const spans: Span[] = []
  const seen = new Set<string>()
  const lower = text.toLowerCase()
  let parts: Segment[] | undefined
  const scan = (rule: CompiledRule, part: Segment) => {
    rule.pattern.lastIndex = 0
    for (const match of part.text.matchAll(rule.pattern)) {
      if (Date.now() > deadline) throw new MaskTimeout()
      const group = pickGroup(match, rule.secretGroup)
      const secret = match[group]
      const range = match.indices?.[group]
      if (!secret || !range) continue
      if (rule.entropy > 0 && shannonEntropy(secret) <= rule.entropy) continue
      if (rule.needsDigit && !/\d/.test(secret)) continue
      const start = part.start + range[0]
      const end = part.start + range[1]
      const line = () => lineAround(text, start, end)
      if (isAllowed(rule.allowlists, secret, match[0], line)) continue
      if (isAllowed(compiled.allowlists, secret, match[0], line)) continue
      const key = `${start}:${end}:${rule.id}`
      if (seen.has(key)) continue
      seen.add(key)
      spans.push({ start, end, label: rule.id })
    }
  }
  for (const rule of compiled.rules) {
    if (Date.now() > deadline) throw new MaskTimeout()
    if (!hasKeyword(lower, rule.keywords)) continue
    if (rule.multiline) {
      scan(rule, { start: 0, text, lower })
      continue
    }
    parts ??= segments(text)
    for (const part of parts) {
      if (Date.now() > deadline) throw new MaskTimeout()
      if (hasKeyword(part.lower, rule.keywords)) scan(rule, part)
    }
  }
  return spans
}

export function emptyRuleSet(): RuleSet {
  return { version: 'none', rules: [], allowlists: [] }
}
