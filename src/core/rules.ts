import { shannonEntropy } from './encoding.ts'
import type { Allowlist, AllowTarget, Rule, RuleSet } from './types.ts'
import type { Span } from './known.ts'
import { maxMatchLength, maxNewlines } from './reach.ts'
import { MaskTimeout } from './timeout.ts'
import { forRules } from './views.ts'

export { MaskTimeout }

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
  readonly mode: ScanMode
  readonly reach: number
  readonly global: boolean
  readonly continuation?: RegExp
  readonly allowlists: readonly CompiledAllowlist[]
}

export type ScanMode = 'window' | 'lines' | 'keyword'

export type CompiledRules = {
  readonly rules: readonly CompiledRule[]
  readonly allowlists: readonly CompiledAllowlist[]
  readonly failed: readonly string[]
  readonly lineOverlap: number
}

const GROUP = 8192
const LONG_LINE = 12288
const LONG_OVERLAP = 8192
const MIN_LINE_OVERLAP = 2
const MAX_LINE_OVERLAP = 16
const STOPWORD_MAX = 64
const CONTINUATIONS = 64
const WINDOW = 2048
const WINDOW_REACH = 1024
const SHORT_WINDOW = 1024
const SHORT_REACH = 256
const KEYWORD_BEFORE = 4096
const KEYWORD_AFTER = 32768
const KEYWORD_KEEP = 16384

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

export function scanMode(rule: Rule): ScanMode {
  if (rule.multiline ?? rule.pattern.includes('\\s\\S')) return 'keyword'
  return maxMatchLength(rule.pattern) <= WINDOW_REACH ? 'window' : 'lines'
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
        mode: scanMode(rule),
        ...(rule.continuation === undefined ? {} : { continuation: new RegExp(rule.continuation, 'y') }),
        reach: maxMatchLength(rule.pattern) <= SHORT_REACH ? SHORT_REACH : WINDOW_REACH,
        global: rule.own !== true,
        allowlists: rule.allowlists.flatMap(list => compileAllowlist(list) ?? []),
      })
    } catch {
      failed.push(rule.id)
    }
  }
  const spans = rules.filter(rule => rule.mode === 'lines').map(rule => maxNewlines(rule.pattern.source))
  const lineOverlap = Math.min(MAX_LINE_OVERLAP, Math.max(MIN_LINE_OVERLAP, ...spans.map(span => span + 1)))
  return { rules, allowlists: set.allowlists.flatMap(list => compileAllowlist(list) ?? []), failed, lineOverlap }
}

type Segment = {
  readonly start: number
  readonly text: string
  readonly lower: string
}

export function segments(text: string, overlap = MIN_LINE_OVERLAP): Segment[] {
  const lines: { start: number; end: number }[] = []
  for (let start = 0; ; ) {
    const newline = text.indexOf('\n', start)
    lines.push({ start, end: newline === -1 ? text.length : newline })
    if (newline === -1) break
    start = newline + 1
  }
  const out: Segment[] = []
  const push = (start: number, end: number) => out.push(piece(text, start, end))
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
      if (!next) break
      const size = next.end - line.start
      if (size > LONG_LINE || (size > GROUP && j > i)) break
      j++
    }
    push(line.start, lines[j]?.end ?? line.end)
    if (j + 1 >= lines.length) break
    i = Math.max(i + 1, j + 1 - overlap)
  }
  return out
}

function piece(text: string, start: number, end: number): Segment {
  const slice = text.slice(start, end)
  return { start, text: slice, lower: slice.toLowerCase() }
}

export function windows(text: string, reach = WINDOW_REACH): Segment[] {
  const size = reach <= SHORT_REACH ? SHORT_WINDOW : WINDOW
  const out: Segment[] = []
  for (let at = 0; ; at += size - reach) {
    out.push(piece(text, at, Math.min(text.length, at + size)))
    if (at + size >= text.length) break
  }
  return out
}

export function keywordWindows(text: string, lower: string, keywords: readonly string[]): Segment[] {
  if (lower.length !== text.length || keywords.length === 0) {
    const out: Segment[] = []
    for (let at = 0; ; at += KEYWORD_AFTER - KEYWORD_KEEP) {
      out.push(piece(text, at, Math.min(text.length, at + KEYWORD_AFTER + KEYWORD_BEFORE)))
      if (at + KEYWORD_AFTER + KEYWORD_BEFORE >= text.length) break
    }
    return out
  }
  const hits: number[] = []
  for (const word of keywords) for (let at = lower.indexOf(word); at !== -1; at = lower.indexOf(word, at + 1)) hits.push(at)
  hits.sort((a, b) => a - b)
  const out: Segment[] = []
  let end = -1
  for (const hit of hits) {
    if (hit + KEYWORD_KEEP <= end || end === text.length) continue
    const start = Math.max(0, hit - KEYWORD_BEFORE)
    end = Math.min(text.length, hit + KEYWORD_AFTER)
    out.push(piece(text, start, end))
  }
  return out
}

function lastBreak(text: string, start: number, end: number): number {
  const at = Math.max(text.lastIndexOf('\n', end - 1), text.lastIndexOf('\\n', end - 1), text.lastIndexOf(' ', end - 1), text.lastIndexOf('\t', end - 1))
  return at > start ? at : end
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
    if (secret.length <= STOPWORD_MAX && list.stopwords.some(word => lower.includes(word))) return true
    const target = list.target === 'match' ? match : list.target === 'line' ? line() : secret
    if (list.patterns.some(pattern => pattern.test(target))) return true
  }
  return false
}

function hasKeyword(lower: string, keywords: readonly string[]): boolean {
  return keywords.length === 0 || keywords.some(word => lower.includes(word))
}

export function findRuleSpans(original: string, compiled: CompiledRules, deadline = Infinity): Span[] {
  const text = forRules(original)
  const spans: Span[] = []
  const seen = new Set<string>()
  const lower = text.toLowerCase()
  let lines: Segment[] | undefined
  const fixed = new Map<number, Segment[]>()
  const windowed = (reach: number) => {
    const known = fixed.get(reach)
    if (known) return known
    const made = windows(text, reach)
    fixed.set(reach, made)
    return made
  }
  const extend = (pattern: RegExp, start: number, end: number): number => {
    let reach = end
    for (let round = 0; round < CONTINUATIONS && reach < text.length; round++) {
      if (Date.now() > deadline) throw new MaskTimeout()
      const from = lastBreak(text, start, reach)
      const chunk = text.slice(from, from + KEYWORD_AFTER)
      pattern.lastIndex = 0
      const length = pattern.exec(chunk)?.[0].length ?? 0
      if (from + length <= reach) break
      reach = from + length
      if (length < chunk.length) break
    }
    return reach
  }
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
      const edge = part.start + part.text.length
      const end = rule.continuation && part.start + range[1] === edge && edge < text.length ? extend(rule.continuation, start, edge) : part.start + range[1]
      const line = () => lineAround(text, start, end)
      if (isAllowed(rule.allowlists, secret, match[0], line)) continue
      if (rule.global && isAllowed(compiled.allowlists, secret, match[0], line)) continue
      const key = `${start}:${end}:${rule.id}`
      if (seen.has(key)) continue
      seen.add(key)
      spans.push({ start, end, label: rule.id })
    }
  }
  for (const rule of compiled.rules) {
    if (Date.now() > deadline) throw new MaskTimeout()
    if (!hasKeyword(lower, rule.keywords)) continue
    const parts = rule.mode === 'keyword' ? keywordWindows(text, lower, rule.keywords) : rule.mode === 'window' ? windowed(rule.reach) : (lines ??= segments(text, compiled.lineOverlap))
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
