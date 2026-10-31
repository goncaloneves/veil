export type View = {
  readonly text: string
  readonly origin: (index: number) => number
  readonly after: (index: number) => number
}

export type Range = {
  readonly start: number
  readonly end: number
}

const LINE_BREAK = /\\?\r?\n[ \t]*/g
const ANSI = /\x1b(?:\[[0-?]*[ -\/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])|(?:\\u001[bB]|\\x1[bB]|\\033|\\e)\[[0-?]{0,32}[ -\/]{0,4}[@-~]/g
const HAS_ANSI = /\x1b|\\(?:u001[bB]|x1[bB]|033|e)\[/
const INTERLEAVED = /(?:[^\0]\0){8,}/g
const JSON_ESCAPE = /\\(?:u([0-9a-fA-F]{4})|(["\\\/bfnrt]))/g
const HAS_JSON_ESCAPE = /\\(?:u[0-9a-fA-F]{4}|["\\\/bfnrt])/
const LIST_LINE = /^([A-Za-z][\w.-]*(?: [\w.-]+)*) +: (?=\S)/
const SIMPLE: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
const RULE_BREAKS = /\0|\r(?!\n)/g
const RULE_CONTROLS = /[\x01-\x08\x0e-\x1f\x7f]/g
const NEEDS_RULE_FIX = /[\0-\x08\x0e-\x1f\x7f]|\r(?!\n)/

export function toOriginal(view: View, start: number, end: number): Range {
  return { start: view.origin(start), end: view.after(end - 1) }
}

type Piece = {
  readonly start: number
  readonly origin: number
  readonly width: number
}

function mapped(pieces: readonly Piece[], parts: readonly string[]): View {
  const find = (index: number): Piece => {
    let low = 0
    let high = pieces.length - 1
    while (low < high) {
      const middle = (low + high + 1) >> 1
      if ((pieces[middle]?.start ?? 0) <= index) low = middle
      else high = middle - 1
    }
    return pieces[low] ?? { start: 0, origin: 0, width: 0 }
  }
  return {
    text: parts.join(''),
    origin: index => {
      const piece = find(index)
      return piece.width > 0 ? piece.origin : piece.origin + index - piece.start
    },
    after: index => {
      const piece = find(index)
      return piece.width > 0 ? piece.origin + piece.width : piece.origin + index - piece.start + 1
    },
  }
}

function removing(text: string, ranges: Iterable<Range>): View | undefined {
  const pieces: Piece[] = []
  const parts: string[] = []
  let cursor = 0
  let length = 0
  let removed = false
  const keep = (end: number) => {
    if (end <= cursor) return
    pieces.push({ start: length, origin: cursor, width: 0 })
    parts.push(text.slice(cursor, end))
    length += end - cursor
  }
  for (const range of ranges) {
    keep(range.start)
    cursor = Math.max(cursor, range.end)
    removed = true
  }
  if (!removed) return undefined
  keep(text.length)
  return mapped(pieces, parts)
}

function* matches(text: string, pattern: RegExp): Generator<Range> {
  for (const match of text.matchAll(pattern)) yield { start: match.index, end: match.index + match[0].length }
}

export function joinedLines(text: string): View | undefined {
  return text.includes('\n') ? removing(text, matches(text, LINE_BREAK)) : undefined
}

export function withoutAnsi(text: string): View | undefined {
  return HAS_ANSI.test(text) ? removing(text, matches(text, ANSI)) : undefined
}

function* listBreaks(text: string): Generator<Range> {
  let at = 0
  while (at < text.length) {
    const end = text.indexOf('\n', at)
    const lineEnd = end === -1 ? text.length : end
    const head = text.slice(at, Math.min(lineEnd, at + 256)).match(LIST_LINE)
    if (head && end !== -1) {
      const indent = ' '.repeat(head[0].length)
      let next = end
      while (next !== -1 && text.startsWith(indent, next + 1) && /\S/.test(text[next + 1 + indent.length] ?? ' ')) {
        const from = text[next - 1] === '\r' ? next - 1 : next
        yield { start: from, end: next + 1 + indent.length }
        next = text.indexOf('\n', next + 1)
      }
      at = next === -1 ? text.length : next + 1
      continue
    }
    at = lineEnd + 1
  }
}

export function joinedList(text: string): View | undefined {
  return text.includes(' : ') ? removing(text, listBreaks(text)) : undefined
}

export function unescaped(text: string): View | undefined {
  if (!HAS_JSON_ESCAPE.test(text)) return undefined
  const pieces: Piece[] = []
  const parts: string[] = []
  let cursor = 0
  let length = 0
  for (const match of text.matchAll(JSON_ESCAPE)) {
    if (match.index > cursor) {
      pieces.push({ start: length, origin: cursor, width: 0 })
      parts.push(text.slice(cursor, match.index))
      length += match.index - cursor
    }
    const unit = match[1] === undefined ? (SIMPLE[match[2] ?? ''] ?? '') : String.fromCharCode(parseInt(match[1], 16))
    pieces.push({ start: length, origin: match.index, width: match[0].length })
    parts.push(unit)
    length += 1
    cursor = match.index + match[0].length
  }
  if (cursor < text.length) {
    pieces.push({ start: length, origin: cursor, width: 0 })
    parts.push(text.slice(cursor))
  }
  return mapped(pieces, parts)
}

export function interleaved(text: string): View[] {
  if (!text.includes('\0')) return []
  const views: View[] = []
  for (const match of text.matchAll(INTERLEAVED)) {
    const base = match.index
    let compact = ''
    for (let i = 0; i < match[0].length; i += 2) compact += match[0][i]
    views.push({ text: compact, origin: index => base + 2 * index, after: index => base + 2 * index + 1 })
  }
  return views
}

export function forRules(text: string): string {
  return NEEDS_RULE_FIX.test(text) ? text.replace(RULE_BREAKS, '\n').replace(RULE_CONTROLS, ' ') : text
}
