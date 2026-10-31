type Mode = { readonly i: boolean; readonly s: boolean }

type ClassItem =
  | { readonly kind: 'char'; readonly text: string; readonly code: number }
  | { readonly kind: 'range'; readonly text: string; readonly from: number; readonly to: number }
  | { readonly kind: 'other'; readonly text: string }

const POSIX: Record<string, string> = {
  alnum: 'A-Za-z0-9',
  alpha: 'A-Za-z',
  digit: '0-9',
  lower: 'a-z',
  upper: 'A-Z',
  space: '\\s',
  xdigit: '0-9A-Fa-f',
  word: '\\w',
  punct: '!-\\/:-@\\[-`{-~',
}

const SIMPLE_ESCAPES: Record<string, number> = { n: 10, r: 13, t: 9, f: 12, v: 11 }

function isLetter(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
}

function swap(code: number): number {
  return code >= 97 ? code - 32 : code + 32
}

function literal(code: number): string {
  const char = String.fromCharCode(code)
  return /[\\\]\[^-]/.test(char) ? `\\${char}` : char
}

function applyFlags(mode: Mode, flags: string): Mode {
  let { i, s } = mode
  let on = true
  for (const flag of flags) {
    if (flag === '-') on = false
    else if (flag === 'i') i = on
    else if (flag === 's') s = on
    else if (flag !== 'm' && flag !== 'U') throw new Error(`unsupported flag "${flag}"`)
  }
  return { i, s }
}

function readEscape(src: string, at: number): { text: string; code?: number; length: number } {
  const next = src[at + 1] ?? ''
  if (next === 'x') {
    const braced = src.slice(at + 2).match(/^\{([0-9a-fA-F]{1,4})\}/)
    if (braced?.[1]) {
      const code = parseInt(braced[1], 16)
      return { text: `\\u${braced[1].padStart(4, '0')}`, code, length: braced[0].length + 2 }
    }
    const hex = src.slice(at + 2, at + 4)
    if (/^[0-9a-fA-F]{2}$/.test(hex)) return { text: `\\x${hex}`, code: parseInt(hex, 16), length: 4 }
  }
  if (next in SIMPLE_ESCAPES) return { text: `\\${next}`, code: SIMPLE_ESCAPES[next] ?? 0, length: 2 }
  if (/[dDwWsSbB]/.test(next)) return { text: `\\${next}`, length: 2 }
  if (next === 'p' || next === 'P' || next === 'Q') throw new Error(`unsupported escape \\${next}`)
  return { text: `\\${next}`, code: next.charCodeAt(0), length: 2 }
}

function convertClass(src: string, start: number, mode: Mode): { text: string; end: number } {
  let at = start + 1
  let negated = false
  if (src[at] === '^') {
    negated = true
    at++
  }
  const items: ClassItem[] = []
  let first = true
  while (at < src.length && (src[at] !== ']' || first)) {
    first = false
    let item: ClassItem
    const posix = src.slice(at).match(/^\[:([a-z]+):\]/)
    if (posix?.[1]) {
      const expansion = POSIX[posix[1]]
      if (!expansion) throw new Error(`unsupported class [:${posix[1]}:]`)
      items.push({ kind: 'other', text: expansion })
      at += posix[0].length
      continue
    }
    if (src[at] === '\\') {
      const escape = readEscape(src, at)
      at += escape.length
      item = escape.code === undefined ? { kind: 'other', text: escape.text } : { kind: 'char', text: escape.text, code: escape.code }
    } else {
      const char = src[at] ?? ''
      at++
      item = { kind: 'char', text: char === '[' || char === '-' ? `\\${char}` : char, code: char.charCodeAt(0) }
    }
    if (item.kind === 'char' && src[at] === '-' && src[at + 1] !== ']' && at + 1 < src.length) {
      at++
      let to: { text: string; code: number }
      if (src[at] === '\\') {
        const escape = readEscape(src, at)
        if (escape.code === undefined) throw new Error('range ends in a class escape')
        to = { text: escape.text, code: escape.code }
        at += escape.length
      } else {
        const char = src[at] ?? ''
        to = { text: char, code: char.charCodeAt(0) }
        at++
      }
      items.push({ kind: 'range', text: `${item.text}-${to.text}`, from: item.code, to: to.code })
      continue
    }
    items.push(item)
  }
  if (src[at] !== ']') throw new Error('unterminated class')
  const extra: string[] = []
  if (mode.i) {
    for (const item of items) {
      if (item.kind === 'char' && isLetter(item.code)) extra.push(literal(swap(item.code)))
      if (item.kind === 'range') {
        for (const [lo, hi] of [[97, 122], [65, 90]] as const) {
          const from = Math.max(item.from, lo)
          const to = Math.min(item.to, hi)
          if (from <= to) extra.push(`${literal(swap(from))}-${literal(swap(to))}`)
        }
      }
    }
  }
  const body = items.map(item => item.text).join('') + extra.join('')
  return { text: `[${negated ? '^' : ''}${body}]`, end: at + 1 }
}

export function re2ToJs(src: string): string {
  const stack: Mode[] = [{ i: false, s: false }]
  let out = ''
  let at = 0
  const mode = () => stack[stack.length - 1] ?? { i: false, s: false }
  while (at < src.length) {
    const char = src[at] ?? ''
    if (char === '\\') {
      const next = src[at + 1] ?? ''
      if (next === 'z') {
        out += '$'
        at += 2
        continue
      }
      if (next === 'A') {
        out += '^'
        at += 2
        continue
      }
      const escape = readEscape(src, at)
      out += mode().i && escape.code !== undefined && isLetter(escape.code) && escape.text.length === 2 && !/[nrtfv]/.test(src[at + 1] ?? '')
        ? `[${literal(escape.code)}${literal(swap(escape.code))}]`
        : escape.text
      at += escape.length
      continue
    }
    if (char === '[') {
      const converted = convertClass(src, at, mode())
      out += converted.text
      at = converted.end
      continue
    }
    if (char === '(') {
      const flagsOnly = src.slice(at).match(/^\(\?([imsU-]+)\)/)
      if (flagsOnly?.[1]) {
        stack[stack.length - 1] = applyFlags(mode(), flagsOnly[1])
        at += flagsOnly[0].length
        continue
      }
      const scoped = src.slice(at).match(/^\(\?([imsU-]+):/)
      if (scoped?.[1]) {
        stack.push(applyFlags(mode(), scoped[1]))
        out += '(?:'
        at += scoped[0].length
        continue
      }
      const named = src.slice(at).match(/^\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>/)
      if (named?.[1]) {
        stack.push(mode())
        out += `(?<${named[1]}>`
        at += named[0].length
        continue
      }
      const special = src.slice(at).match(/^\(\?(?::|=|!|<=|<!)/)
      stack.push(mode())
      out += special ? special[0] : '('
      at += special ? special[0].length : 1
      continue
    }
    if (char === ')') {
      if (stack.length > 1) stack.pop()
      out += ')'
      at++
      continue
    }
    if (char === '{') {
      const quantifier = src.slice(at).match(/^\{\d*(?:,\d*)?\}/)
      if (quantifier) {
        out += quantifier[0]
        at += quantifier[0].length
        continue
      }
    }
    if (char === '.') {
      out += mode().s ? '[\\s\\S]' : '[^\\n]'
      at++
      continue
    }
    const code = char.charCodeAt(0)
    out += mode().i && isLetter(code) ? `[${char}${String.fromCharCode(swap(code))}]` : char
    at++
  }
  return out
}
