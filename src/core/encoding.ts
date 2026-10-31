const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function utf8Encode(text: string): number[] {
  const bytes: number[] = []
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0
    if (code < 0x80) bytes.push(code)
    else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 63))
    else if (code < 0x10000) bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63))
    else bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63))
  }
  return bytes
}

export function utf8Decode(bytes: readonly number[]): string | undefined {
  let out = ''
  for (let i = 0; i < bytes.length; ) {
    const first = bytes[i] ?? 0
    const width = first < 0x80 ? 1 : first >> 5 === 6 ? 2 : first >> 4 === 14 ? 3 : first >> 3 === 30 ? 4 : 0
    if (width === 0 || i + width > bytes.length) return undefined
    let code = width === 1 ? first : first & (0xff >> (width + 1))
    for (let j = 1; j < width; j++) {
      const next = bytes[i + j] ?? 0
      if (next >> 6 !== 2) return undefined
      code = (code << 6) | (next & 63)
    }
    out += String.fromCodePoint(code)
    i += width
  }
  return out
}

export function base64Encode(text: string, urlSafe = false): string {
  const bytes = utf8Encode(text)
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0
    const b = bytes[i + 1]
    const c = bytes[i + 2]
    const triple = (a << 16) | ((b ?? 0) << 8) | (c ?? 0)
    out += ALPHABET[(triple >> 18) & 63]
    out += ALPHABET[(triple >> 12) & 63]
    out += b === undefined ? '=' : ALPHABET[(triple >> 6) & 63]
    out += c === undefined ? '=' : ALPHABET[triple & 63]
  }
  return urlSafe ? out.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '') : out
}

export function base64Decode(input: string): string | undefined {
  const clean = input.trim().replaceAll('-', '+').replaceAll('_', '/').replace(/=+$/, '')
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) return undefined
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const char of clean) {
    buffer = (buffer << 6) | ALPHABET.indexOf(char)
    bits += 6
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >> bits) & 0xff)
    }
  }
  return utf8Decode(bytes)
}

export function fnv1a(text: string): string {
  let hash = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

export function shannonEntropy(text: string): number {
  const chars = [...text]
  if (chars.length === 0) return 0
  const counts = new Map<string, number>()
  for (const char of chars) counts.set(char, (counts.get(char) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / chars.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}
