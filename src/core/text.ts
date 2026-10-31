import { bytesFromBase64, utf8Decode } from './encoding.ts'

export { bytesFromBase64 }

const SAMPLE = 64

function utf16(bytes: Uint8Array, start: number, littleEndian: boolean): string {
  const parts: string[] = []
  let chunk: number[] = []
  for (let i = start; i + 1 < bytes.length; i += 2) {
    const low = bytes[i] ?? 0
    const high = bytes[i + 1] ?? 0
    chunk.push(littleEndian ? low | (high << 8) : (low << 8) | high)
    if (chunk.length === 8192) {
      parts.push(String.fromCharCode(...chunk))
      chunk = []
    }
  }
  parts.push(String.fromCharCode(...chunk))
  return parts.join('')
}

function zeroShare(bytes: Uint8Array, offset: number): number {
  const pairs = Math.min(SAMPLE, Math.floor(bytes.length / 2))
  if (pairs === 0) return 0
  let zeros = 0
  for (let i = 0; i < pairs; i++) if (bytes[i * 2 + offset] === 0) zeros++
  return zeros / pairs
}

export function decodeBytes(bytes: Uint8Array): string {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return utf16(bytes, 2, true)
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return utf16(bytes, 2, false)
  if (bytes.length >= 4 && zeroShare(bytes, 1) >= 0.9 && zeroShare(bytes, 0) === 0) return utf16(bytes, 0, true)
  if (bytes.length >= 4 && zeroShare(bytes, 0) >= 0.9 && zeroShare(bytes, 1) === 0) return utf16(bytes, 0, false)
  const start = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0
  const body = Array.from(bytes.subarray(start))
  return utf8Decode(body) ?? body.map(byte => String.fromCharCode(byte)).join('')
}

export function looksMisdecoded(text: string): boolean {
  if (text.startsWith('\uFFFD\uFFFD')) return true
  const sample = text.slice(0, SAMPLE * 2)
  if (sample.length < 4) return false
  let odd = 0
  let even = 0
  for (let i = 0; i < sample.length; i++) if (sample.charCodeAt(i) === 0) i % 2 === 0 ? even++ : odd++
  const half = Math.floor(sample.length / 2)
  return odd >= half * 0.9 || even >= half * 0.9
}

export async function readText(text: () => Promise<string>, base64: () => Promise<string>): Promise<string> {
  const read = await text()
  if (read.startsWith('\uFEFF')) return read.slice(1)
  if (!looksMisdecoded(read)) return read
  return decodeBytes(bytesFromBase64(await base64()))
}
