import { base64Encode } from './encoding.ts'
import type { Encoding, Secret } from './types.ts'

export type Needle = {
  readonly text: string
  readonly label: string
  readonly source: string
}

export type NeedleOptions = {
  readonly minLength: number
  readonly encodings: readonly Encoding[]
}

export type Span = {
  readonly start: number
  readonly end: number
  readonly label: string
}

const LINE_MIN = 16

export function needlesFor(secrets: readonly Secret[], options: NeedleOptions): Needle[] {
  const encodings = new Set(options.encodings)
  const seen = new Set<string>()
  const needles: Needle[] = []
  for (const secret of secrets) {
    const value = secret.value
    if (value.length < options.minLength) continue
    const add = (text: string, label: string, min = options.minLength) => {
      if (text.length < min || seen.has(text)) return
      seen.add(text)
      needles.push({ text, label, source: secret.source })
    }
    add(value, secret.name)
    if (encodings.has('json')) {
      const json = JSON.stringify(value).slice(1, -1)
      if (json !== value) add(json, `${secret.name}~json`)
    }
    if (encodings.has('url')) {
      const url = encodeURIComponent(value)
      if (url !== value) add(url, `${secret.name}~url`)
    }
    if (encodings.has('base64')) {
      const padded = base64Encode(value)
      add(padded, `${secret.name}~base64`)
      const bare = padded.replace(/=+$/, '')
      if (bare !== padded) add(bare, `${secret.name}~base64`)
      const urlSafe = base64Encode(value, true)
      if (urlSafe !== bare) add(urlSafe, `${secret.name}~base64url`)
    }
    if (encodings.has('lines') && /\r?\n/.test(value)) {
      value.split(/\r?\n/).forEach((line, index) => {
        const trimmed = line.trim()
        if (!trimmed.startsWith('-----')) add(trimmed, `${secret.name}~line${index + 1}`, Math.max(LINE_MIN, options.minLength))
      })
    }
  }
  return needles
}

export function findNeedles(text: string, needles: readonly Needle[]): Span[] {
  const spans: Span[] = []
  for (const needle of needles) {
    for (let at = text.indexOf(needle.text); at !== -1; at = text.indexOf(needle.text, at + needle.text.length)) {
      spans.push({ start: at, end: at + needle.text.length, label: needle.label })
    }
  }
  return spans
}
