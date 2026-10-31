const QUANTIFIER = /^(?:\*|\+|\?|\{(\d+)(,(\d*))?\})/
const GROUP_OPEN = /^\?(?::|=|!|<=|<!|<[A-Za-z_][A-Za-z0-9_]*>)/
const LOOKAROUND = /^\?(?:=|!|<=|<!)$/
const NEWLINE_ESCAPE = /^\\(?:n|s|W|D|x0[aA]|u000[aA])$/
const NEWLINE_IN_CLASS = /\\(?:n|s|W|D|x0[aA]|u000[aA])/

type Weigh = (atom: string, kind: 'char' | 'escape' | 'class') => number

function analyze(source: string, weigh: Weigh): number {
  let at = 0
  let groups = 0
  const lengths: number[] = []
  const atom = (): number => {
    const start = at
    const char = source[at]
    if (char === '\\') {
      const next = source[at + 1] ?? ''
      if (next === 'x') at += 4
      else if (next === 'u') at = source[at + 2] === '{' ? source.indexOf('}', at) + 1 : at + 6
      else if (next === 'k') {
        at = source.indexOf('>', at) + 1
        return Infinity
      } else at += 2
      if (/[1-9]/.test(next)) return lengths[Number(next)] ?? Infinity
      if (next === 'b' || next === 'B') return 0
      return weigh(source.slice(start, at), 'escape')
    }
    if (char === '[') {
      at++
      if (source[at] === '^') at++
      if (source[at] === ']') at++
      while (at < source.length && source[at] !== ']') at += source[at] === '\\' ? 2 : 1
      at++
      return weigh(source.slice(start, at), 'class')
    }
    if (char === '(') {
      at++
      const open = source.slice(at).match(GROUP_OPEN)?.[0] ?? ''
      at += open.length
      const index = open === '' || (open.startsWith('?<') && !LOOKAROUND.test(open)) ? ++groups : 0
      const inner = alternation()
      at++
      if (index > 0) lengths[index] = inner
      return LOOKAROUND.test(open) ? 0 : inner
    }
    at++
    return char === '^' || char === '$' ? 0 : weigh(char ?? '', 'char')
  }
  const sequence = (): number => {
    let total = 0
    while (at < source.length && source[at] !== '|' && source[at] !== ')') {
      let length = atom()
      const quantifier = source.slice(at).match(QUANTIFIER)
      if (quantifier) {
        at += quantifier[0].length
        if (source[at] === '?') at++
        const [whole, low, comma, high] = quantifier
        if (whole === '*' || whole === '+') length = length === 0 ? 0 : Infinity
        else if (whole !== '?' && length > 0) length *= comma === undefined ? Number(low) : high === '' ? Infinity : Number(high)
      }
      total += length
    }
    return total
  }
  const alternation = (): number => {
    let longest = sequence()
    while (source[at] === '|') {
      at++
      longest = Math.max(longest, sequence())
    }
    return longest
  }
  return alternation()
}

export function maxMatchLength(source: string): number {
  return analyze(source, () => 1)
}

function matchesNewline(atom: string, kind: 'char' | 'escape' | 'class'): boolean {
  if (kind === 'char') return atom === '\n'
  if (kind === 'escape') return NEWLINE_ESCAPE.test(atom)
  const negated = atom.startsWith('[^')
  const body = atom.slice(negated ? 2 : 1, -1)
  const named = NEWLINE_IN_CLASS.test(body) || body.includes('\n')
  return negated ? !named : named
}

export function maxNewlines(source: string): number {
  return analyze(source, (atom, kind) => (matchesNewline(atom, kind) ? 1 : 0))
}
