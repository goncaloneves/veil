import { pathKey } from '../src/core/paths.ts'
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
  anthropic: (random: () => number, kind = 'api03') => `${['sk', 'ant', kind].join('-')}-${fakeToken(random, 93, `${ALNUM}-_`)}AA`,
  googleAccess: (random: () => number) => `${['ya', '29.'].join('')}${fakeToken(random, 150, `${ALNUM}-_`)}`,
  googleRefresh: (random: () => number) => `${['1/', '/0'].join('')}${fakeToken(random, 100, `${ALNUM}-_`)}`,
  symbolPassword: (random: () => number, length = 16) => `${fakeToken(random, length - 4, `${ALNUM}!#%*^@&+=`)}Q7!z`,
  privateKey: (random: () => number) => {
    const body = Array.from({ length: 5 }, () => fakeToken(random, 64, `${ALNUM}+/`)).join('\n')
    const kind = ['OPENSSH', 'PRIVATE KEY'].join(' ')
    return `-----BEGIN ${kind}-----\n${body}\n-----END ${kind}-----`
  },
}

export const LOWER = 'abcdefghijklmnopqrstuvwxyz'

export function keyHeader(kind = '', options: { readonly end?: boolean; readonly block?: boolean; readonly ssh2?: boolean } = {}): string {
  const name = [kind, ['PRIV', 'ATE'].join(''), 'KEY', options.block ? 'BLOCK' : ''].filter(Boolean).join(' ')
  const marker = options.end ? 'END' : 'BEGIN'
  return options.ssh2 ? `---- ${marker} ${name} ----` : `-----${marker} ${name}-----`
}

export function utf16le(text: string): string {
  return [...text].map(char => `${char}\0`).join('')
}

export function utf16leBase64(text: string): string {
  const bytes: number[] = []
  for (let i = 0; i < text.length; i++) bytes.push(text.charCodeAt(i) & 0xff, text.charCodeAt(i) >> 8)
  return btoa(String.fromCharCode(...bytes))
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

export type PathFsOptions = {
  readonly platform?: string
  readonly denied?: readonly string[]
  readonly onRead?: (path: string) => void
}

export function pathFs(files: Record<string, string>, options: PathFsOptions = {}): SourceFs {
  const platform = options.platform ?? 'linux'
  const key = (path: string) => pathKey(path, platform)
  const texts = new Map<string, string>()
  const dirs = new Map<string, Map<string, 'file' | 'dir'>>()
  for (const [path, text] of Object.entries(files)) {
    texts.set(key(path), text)
    const parts = path.replace(/\\/g, '/').split('/')
    for (let i = 1; i < parts.length; i++) {
      const dir = key(parts.slice(0, i).join('/') || '/')
      if (!dirs.has(dir)) dirs.set(dir, new Map())
      dirs.get(dir)?.set(parts[i] ?? '', i === parts.length - 1 ? 'file' : 'dir')
    }
  }
  const denied = new Set((options.denied ?? []).map(key))
  const guard = (path: string) => {
    if (denied.has(key(path))) throw Object.assign(new Error(`EACCES: permission denied, ${path}`), { code: 'EACCES' })
  }
  return {
    read: async path => {
      guard(path)
      options.onRead?.(path)
      const text = texts.get(key(path))
      if (text === undefined) throw Object.assign(new Error(`ENOENT ${path}`), { code: 'ENOENT' })
      return text
    },
    list: async dir => {
      guard(dir)
      const entries = dirs.get(key(dir))
      if (!entries) throw Object.assign(new Error(`ENOENT ${dir}`), { code: 'ENOENT' })
      return [...entries].map(([name, kind]) => ({ name, kind }))
    },
    exists: async path => texts.has(key(path)) || dirs.has(key(path)),
    kindOf: async path => {
      guard(path)
      if (texts.has(key(path))) return 'file'
      if (dirs.has(key(path))) return 'dir'
      throw Object.assign(new Error(`ENOENT ${path}`), { code: 'ENOENT' })
    },
  }
}

export const PRINTABLE = Array.from({ length: 94 }, (_, index) => String.fromCharCode(33 + index)).join('')
