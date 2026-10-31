import type { SourceFs } from '../src/sources/load.ts'

export function seeded(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const UPPER_DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const HEX = '0123456789abcdef'

export function fakeToken(random: () => number, length: number, alphabet = ALNUM): string {
  let out = ''
  for (let i = 0; i < length; i++) out += alphabet[Math.floor(random() * alphabet.length)]
  return out
}

function base64url(text: string): string {
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export const fake = {
  jwt: (random: () => number, padding = 600) =>
    [
      base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })),
      base64url(JSON.stringify({ sub: fakeToken(random, 12), data: fakeToken(random, padding) })),
      fakeToken(random, 43, `${ALNUM}-_`),
    ].join('.'),
  githubPat: (random: () => number) => ['gh', 'p_'].join('') + fakeToken(random, 36),
  awsKeyId: (random: () => number) => ['AK', 'IA'].join('') + fakeToken(random, 16, UPPER_DIGITS),
  slackBot: (random: () => number) => ['xo', 'xb-'].join('') + fakeToken(random, 11, '0123456789') + '-' + fakeToken(random, 12, '0123456789') + '-' + fakeToken(random, 24),
  hex: (random: () => number, length: number) => fakeToken(random, length, HEX),
  password: (random: () => number) => fakeToken(random, 20),
  privateKey: (random: () => number) => {
    const body = Array.from({ length: 5 }, () => fakeToken(random, 64, `${ALNUM}+/`)).join('\n')
    const kind = ['OPENSSH', 'PRIVATE KEY'].join(' ')
    return `-----BEGIN ${kind}-----\n${body}\n-----END ${kind}-----`
  },
}

export function memoryFs(files: Record<string, string>): SourceFs {
  const dirs = new Map<string, Map<string, 'file' | 'dir'>>()
  const addEntry = (dir: string, name: string, kind: 'file' | 'dir') => {
    if (!dirs.has(dir)) dirs.set(dir, new Map())
    dirs.get(dir)?.set(name, kind)
  }
  for (const path of Object.keys(files)) {
    const parts = path.split('/').filter(Boolean)
    for (let i = 0; i < parts.length; i++) {
      const dir = `/${parts.slice(0, i).join('/')}`.replace(/^\/$/, '/')
      addEntry(dir === '' ? '/' : dir, parts[i] ?? '', i === parts.length - 1 ? 'file' : 'dir')
    }
  }
  return {
    read: async path => {
      const text = files[path]
      if (text === undefined) throw new Error(`ENOENT ${path}`)
      return text
    },
    list: async dir => {
      const entries = dirs.get(dir.replace(/\/$/, '') || '/')
      if (!entries) throw new Error(`ENOENT ${dir}`)
      return [...entries].map(([name, kind]) => ({ name, kind }))
    },
    exists: async path => path in files || dirs.has(path),
    kindOf: async path => {
      if (path in files) return 'file'
      if (dirs.has(path)) return 'dir'
      throw new Error(`ENOENT ${path}`)
    },
  }
}
