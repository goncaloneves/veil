import type { Secret } from '../core/types.ts'
import { parseJson } from './tree.ts'

const PRIVATE_BLOCK = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?|ARGO TUNNEL TOKEN)-----[\s\S]+?-----END \1-----/g
const JWK_PRIVATE = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'inverseq']

function numbered(name: string, index: number): string {
  return index === 0 ? name : `${name}#${index + 1}`
}

export function privateKeyBlocks(text: string, name: string, source: string): Secret[] {
  return [...text.matchAll(PRIVATE_BLOCK)].map((match, index) => ({ name: numbered(name, index), value: match[0], source, strong: true }))
}

export function puttyKeys(text: string, name: string, source: string): Secret[] {
  const lines = text.split(/\r?\n/)
  const out: Secret[] = []
  for (let i = 0; i < lines.length; i++) {
    const count = Number(lines[i]?.match(/^Private-Lines:\s*(\d+)\s*$/)?.[1] ?? NaN)
    if (!Number.isInteger(count) || count < 1) continue
    const body = lines.slice(i + 1, i + 1 + count).map(line => line.trim()).join('\n')
    if (body.length >= 16) out.push({ name: numbered(name, out.length), value: body, source, strong: true })
  }
  return out
}

export function gpgKeyParts(text: string, name: string, source: string): Secret[] {
  const out: Secret[] = []
  for (const match of text.matchAll(/\((d|p|q|u)\s+#([0-9A-Fa-f\s]{32,}?)#\)/g)) {
    const value = (match[2] ?? '').trim()
    if (value.length >= 32) out.push({ name: `${name}.${match[1]}${out.length === 0 ? '' : `#${out.length + 1}`}`, value, source, strong: true })
  }
  return out
}

function jwkMembers(node: unknown, name: string, source: string, out: Secret[]): void {
  if (Array.isArray(node)) {
    node.forEach(item => jwkMembers(item, name, source, out))
    return
  }
  if (node === null || typeof node !== 'object') return
  const record = node as Record<string, unknown>
  const lowered = new Map(Object.entries(record).map(([key, value]) => [key.toLowerCase(), value]))
  if (lowered.has('kty') || lowered.has('modulus') || lowered.has('n')) {
    for (const member of JWK_PRIVATE) {
      const value = lowered.get(member)
      if (typeof value === 'string' && value.length >= 16) out.push({ name: `${name}.${member}`, value, source, strong: true })
    }
  }
  for (const value of Object.values(record)) if (value !== null && typeof value === 'object') jwkMembers(value, name, source, out)
}

export function jwkSecrets(text: string, name: string, source: string): Secret[] {
  const out: Secret[] = []
  jwkMembers(parseJson(text), name, source, out)
  return out
}

export function keyFileSecrets(text: string, name: string, source: string): Secret[] {
  if (/^PuTTY-User-Key-File-/m.test(text)) return puttyKeys(text, name, source)
  if (/\(\s*(?:protected-)?private-key\b/.test(text)) return gpgKeyParts(text, name, source)
  if (/^\s*[{[]/.test(text)) return jwkSecrets(text, name, source)
  return privateKeyBlocks(text, name, source)
}
