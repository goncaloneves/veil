import { DEFAULT_CONFIG } from './config/config.ts'
import { Masker } from './core/masker.ts'
import { basename, isAbsolutePath, pathKey, samePath } from './core/paths.ts'
import type { Secret } from './core/types.ts'
import { PLACEHOLDER } from './core/vault.ts'
import { loadState, maskerSettings, reloadSources, type VeilHost, type VeilState } from './engine.ts'
import { report } from './report.ts'
import { ruleSet } from './rules/index.ts'
import { isRawJson } from './wire/json.ts'
import { isEnvFileName, type SourceFs } from './sources/load.ts'
import { errorMessage } from './sources/util.ts'

export const WITHHELD = '[veil withheld this content: it could not be checked for secrets]'

export const NOTE = [
  'Secret values in this session are replaced by veil, a local masking tool, with placeholders such as [veil:DATABASE_URL].',
  'Treat each placeholder as an opaque reference to a real value you cannot see: never ask for the real value or try to reveal it.',
  'In file edits, keep placeholders exactly as written; veil writes the real value back only into the file it came from or a file that already holds it, never anywhere else.',
  'Placeholders do not work in shell commands; use environment variables there instead.',
].join(' ')

const BUDGET_MS = 3000
const MAX_DEPTH = 256
const CACHE_BYTES = 64 * 1024 * 1024

export type StartLog = {
  readonly transcript: readonly string[]
  readonly debug: readonly string[]
}

export type SessionFs = SourceFs & { readonly realPath: (path: string) => Promise<string | undefined> }

export type Skip = {
  readonly keys?: ReadonlySet<string>
  readonly types?: ReadonlySet<string>
  readonly free?: ReadonlySet<string>
  readonly schema?: ReadonlySet<string>
  readonly media?: boolean
}

export type MaskOptions = {
  readonly strict?: boolean
  readonly scope?: string
}

type Mode = 'structural' | 'free' | 'schema'

export type EditTarget = { readonly content: string; readonly realPath?: string | undefined }

export type Restoration = { readonly text: string; readonly refused?: string }

const REFRESH_MS = 15_000

function randomSalt(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

const MEDIA_TYPES = new Set(['image', 'document', 'audio', 'video', 'pdf', 'parts'])
const BINARY_TEXT = /^[A-Za-z0-9+/=_-]+$/
const BASE64_TEXT = /^[A-Za-z0-9+/=\r\n]+$/
const MEDIA_KEYS = new Set(['url', 'image_url', 'file_data', 'data', 'image', 'image_data'])
const MEDIA_ARRAYS = new Set(['images'])
const MEDIA_MIME = /^(?:image\/(?!svg)[\w.+-]+|audio\/[\w.+-]+|video\/[\w.+-]+|application\/pdf)$/i
const MEDIA_URL = /^data:(?:image\/(?!svg)[\w.+-]+|audio\/[\w.+-]+|video\/[\w.+-]+|application\/pdf);base64,[A-Za-z0-9+/=\r\n]*$/i
const SCHEMA_KEYWORDS = new Set(['type', 'format', 'pattern', '$ref', '$schema', '$id', '$anchor', 'required', 'name', 'strict'])

function svgData(record: Record<string, unknown>): boolean {
  const nested = record.image_url !== null && typeof record.image_url === 'object' ? (record.image_url as Record<string, unknown>).url : record.image_url
  return [record.url, nested, record.image].some(value => typeof value === 'string' && /^data:image\/svg/i.test(value))
}

function isMediaUrl(value: string, key: string | undefined): boolean {
  return key !== undefined && MEDIA_KEYS.has(key) && MEDIA_URL.test(value)
}

function mediaMime(record: Record<string, unknown>): boolean {
  const media = record.media_type ?? record.mediaType ?? record.mimeType ?? record.mime_type ?? record.mime
  return typeof media === 'string' && MEDIA_MIME.test(media)
}

function isMediaData(record: Record<string, unknown>): boolean {
  return mediaMime(record) && typeof record.data === 'string' && BASE64_TEXT.test(record.data)
}

function isMedia(record: Record<string, unknown>): boolean {
  if (typeof record.text === 'string') return false
  const source = record.source !== null && typeof record.source === 'object' ? (record.source as Record<string, unknown>) : undefined
  if (source?.type === 'text' || typeof source?.text === 'string') return false
  if (typeof record.type === 'string' && MEDIA_TYPES.has(record.type)) return true
  return mediaMime(record)
}

function encodedJson(text: string): boolean {
  if (!/^\s*[[{]/.test(text)) return false
  try {
    JSON.parse(text)
    return true
  } catch {
    return false
  }
}

function jsonEscape(value: string): string {
  return JSON.stringify(value).slice(1, -1)
}

function assign(out: Record<string, unknown>, key: string, value: unknown): void {
  if (key === '__proto__') Object.defineProperty(out, key, { value, enumerable: true, writable: true, configurable: true })
  else out[key] = value
}

function secretsKey(secrets: readonly Secret[]): string {
  return secrets.map(secret => `${secret.name}\u0000${secret.source}\u0000${secret.strong ? 1 : 0}\u0000${secret.value}`).join('\u0001')
}

export type VeilOptions = {
  readonly budgetMs?: number
  readonly cache?: boolean
}

export class Veil {
  readonly masker = new Masker({
    secrets: [],
    ruleSet,
    minLength: DEFAULT_CONFIG.mask.minLength,
    encodings: DEFAULT_CONFIG.mask.encodings,
    salt: randomSalt(),
  })
  #state: VeilState | undefined
  #host: VeilHost | undefined
  #realPaths = new Map<string, string>()
  #refreshedAt = 0
  readonly #budgetMs: number
  readonly #caching: boolean
  readonly #caches = new Map<string, Map<string, string>>()
  #cacheBytes = 0
  #secretsKey = ''

  constructor(options: VeilOptions = {}) {
    this.#budgetMs = options.budgetMs ?? BUDGET_MS
    this.#caching = options.cache ?? false
  }

  #forget(): void {
    this.#caches.clear()
    this.#cacheBytes = 0
  }

  #cacheFor(scope: string | undefined): Map<string, string> | undefined {
    if (!this.#caching) return undefined
    const name = scope ?? ''
    let cache = this.#caches.get(name)
    if (!cache) {
      cache = new Map()
      this.#caches.set(name, cache)
    }
    return cache
  }

  async start(fs: SessionFs, host: VeilHost): Promise<StartLog> {
    this.#host = host
    try {
      return await this.#apply(await loadState(fs, host), fs)
    } catch (error) {
      const message = errorMessage(error)
      return { transcript: [`veil: could not load your secrets (${message}); only pattern rules are active`], debug: [] }
    }
  }

  async reload(fs: SessionFs): Promise<StartLog> {
    if (!this.#host) return { transcript: [], debug: [] }
    return this.#apply(await loadState(fs, this.#host), fs)
  }

  async refreshSources(fs: SessionFs): Promise<StartLog> {
    if (!this.#state || !this.#host) return { transcript: [], debug: [] }
    this.#refreshedAt = Date.now()
    const state = await reloadSources(this.#state, fs, this.#host)
    this.#state = state
    const key = secretsKey(state.loaded.secrets)
    if (key !== this.#secretsKey) {
      this.masker.setSecrets(state.loaded.secrets)
      this.#secretsKey = key
      this.#forget()
    }
    await this.#recordRealPaths(state, fs)
    return { transcript: [], debug: state.loaded.errors.map(({ path, message }) => `veil: could not read ${path}: ${message}`) }
  }

  refreshDue(path?: string): boolean {
    if (!this.#state) return false
    return (path !== undefined && this.isSource(path)) || Date.now() - this.#refreshedAt >= REFRESH_MS
  }

  async #apply(state: VeilState, fs: SessionFs): Promise<StartLog> {
    this.#state = state
    this.#refreshedAt = Date.now()
    this.masker.configure(maskerSettings(state, ruleSet))
    this.#secretsKey = secretsKey(state.loaded.secrets)
    this.#forget()
    await this.#recordRealPaths(state, fs)
    return {
      transcript: state.warnings.map(warning => `veil: ${warning}`),
      debug: state.loaded.errors.map(({ path, message }) => `veil: could not read ${path}: ${message}`),
    }
  }

  async #recordRealPaths(state: VeilState, fs: SessionFs): Promise<void> {
    const paths = [...state.sourcePaths].filter(isAbsolutePath)
    const reals = await Promise.all(paths.map(path => fs.realPath(path).catch(() => undefined)))
    const recorded = new Map<string, string>()
    paths.forEach((path, index) => {
      const real = reals[index]
      if (real !== undefined) recorded.set(this.#key(path), real)
    })
    this.#realPaths = recorded
  }

  get #platform(): string {
    return this.#host?.platform ?? 'linux'
  }

  #key(path: string): string {
    return pathKey(path, this.#platform)
  }

  isSource(path: string): boolean {
    const sources = this.#state?.sourcePaths
    if (sources?.has(path)) return true
    if (isEnvFileName(basename(path))) return true
    if (!sources) return false
    const key = this.#key(path)
    for (const source of sources) if (this.#key(source) === key) return true
    return false
  }

  #fromHere(label: string, target: EditTarget): boolean {
    const vault = this.masker.vault
    const source = vault.source(label)
    const real = target.realPath
    if (source === undefined || real === undefined) return false
    const value = vault.text(label)
    const secret = value === undefined ? undefined : this.#state?.loaded.secrets.find(item => item.value === value)
    const sources = secret?.sources ?? [source]
    return sources.some(path => {
      const recorded = this.#realPaths.get(this.#key(path))
      return recorded !== undefined && samePath(recorded, real, this.#platform)
    })
  }

  #deadline(): number {
    return Date.now() + this.#budgetMs
  }

  #maskText(text: string, deadline: number, options: MaskOptions = {}): string {
    const cache = this.#cacheFor(options.scope)
    const cached = cache?.get(text)
    if (cached !== undefined) return cached
    let masked: string
    try {
      masked = this.masker.mask(text, { deadline }).text
    } catch (error) {
      if (options.strict) throw error
      return WITHHELD
    }
    if (cache) {
      if (this.#cacheBytes + text.length + masked.length > CACHE_BYTES) this.#forget()
      this.#cacheFor(options.scope)?.set(text, masked)
      this.#cacheBytes += text.length + masked.length
    }
    return masked
  }

  mask(text: string): string {
    return this.#maskText(text, this.#deadline())
  }

  holdsSecret(text: string): boolean {
    return this.mask(text) !== text
  }

  maskValue(value: unknown, skip?: Skip, options: MaskOptions = {}): unknown {
    return this.#walk(value, skip, this.#deadline(), undefined, 'structural', options, 0)
  }

  protected maskWithin(deadline: number): (text: string) => string {
    return text => this.#maskText(text, deadline)
  }

  protected newDeadline(): number {
    return this.#deadline()
  }

  #walk(value: unknown, skip: Skip | undefined, deadline: number, key: string | undefined, mode: Mode, options: MaskOptions, depth: number): unknown {
    if (depth > MAX_DEPTH && value !== null && (typeof value === 'object' || typeof value === 'string')) return WITHHELD
    if (typeof value === 'string') {
      if (mode === 'schema' && key !== undefined && SCHEMA_KEYWORDS.has(key)) return value
      if (mode === 'structural' && key !== undefined && skip?.keys?.has(key)) return value
      if (skip?.media && (isMediaUrl(value, key) || (key !== undefined && MEDIA_ARRAYS.has(key) && value.length >= 64 && BASE64_TEXT.test(value)))) return value
      return value.length > 1_000_000 && BINARY_TEXT.test(value) ? value : this.#maskText(value, deadline, options)
    }
    if (Array.isArray(value)) {
      const out = value.map(item => this.#walk(item, skip, deadline, key, mode, options, depth + 1))
      return out.every((item, index) => item === value[index]) ? value : out
    }
    if (value !== null && typeof value === 'object') {
      if (isRawJson(value)) return value
      const record = value as Record<string, unknown>
      if (mode !== 'schema' && (skip?.media ? isMediaData(record) : false)) return value
      if (mode === 'structural' && (skip?.types ? typeof record.type === 'string' && skip.types.has(record.type) && !svgData(record) : isMedia(record))) return value
      let changed = false
      const out: Record<string, unknown> = {}
      for (const [field, item] of Object.entries(record)) {
        const free = mode === 'structural' && depth > 0 && skip?.free?.has(field)
        const next: Mode = free ? 'free' : mode === 'structural' && skip?.schema?.has(field) ? 'schema' : mode
        const name = mode === 'free' ? this.#maskText(field, deadline, options) : field
        const masked = this.#walk(item, skip, deadline, field, next, options, depth + 1)
        if (masked !== item || name !== field) changed = true
        assign(out, name, masked)
      }
      return changed ? out : value
    }
    return value
  }

  unreadable(path: string): string {
    return `veil could not check ${path}: it is outside the project, or not a regular, readable file, so veil refused this edit.`
  }

  restorePlaceholders(text: string, path: string, target: EditTarget): Restoration {
    const mode = this.#state?.config.restore.mode ?? DEFAULT_CONFIG.restore.mode
    const minLength = this.#state?.config.mask.minLength ?? DEFAULT_CONFIG.mask.minLength
    const vault = this.masker.vault
    const fileContent = target.content
    const escape = encodedJson(text) ? jsonEscape : undefined
    let refused: string | undefined
    const restored = text.replace(PLACEHOLDER, (whole, label: string) => {
      const value = vault.text(label)
      if (value !== undefined && mode !== 'never') {
        const written = escape ? escape(value) : value
        if (value.length >= minLength && (fileContent.includes(value) || fileContent.includes(written))) return written
        if (vault.isCurrent(label) && (mode === 'always' || this.#fromHere(label, target))) return written
      }
      if (fileContent.includes(whole)) return whole
      if (value === undefined) refused ??= `veil cannot resolve ${whole} in this session. Read ${path} again so veil can map its secrets, then retry the edit.`
      else if (mode === 'never') refused ??= `veil's restore mode is never: it will not write the value behind ${whole}, and writing the placeholder would replace real content. Ask the user to make this edit.`
      else if (!vault.isCurrent(label)) refused ??= `${whole} no longer matches a value in your secret files, so veil will not write it. Read ${path} again and retry.`
      else refused ??= `veil keeps ${whole} out of ${path} because that file does not already hold it. Reference the value through an environment variable instead, or ask the user to add it.`
      return whole
    })
    return refused === undefined ? { text: restored } : { text: restored, refused }
  }


  report(manifest: string, home: string): string {
    if (!this.#state) return 'veil: still loading'
    let version: string | undefined
    try {
      const parsed = JSON.parse(manifest) as { version?: unknown }
      if (typeof parsed.version === 'string') version = parsed.version
    } catch {}
    return report(this.masker, this.#state, { ...(version ? { version } : {}), home })
  }
}

export async function settled(entries: readonly (readonly [string, Promise<string | undefined>])[]): Promise<Record<string, string | undefined>> {
  const values = await Promise.all(entries.map(([, value]) => value.catch(() => undefined)))
  return Object.fromEntries(entries.map(([name], index) => [name, values[index]]))
}

export function replaceItems(items: unknown[], masked: unknown): void {
  if (masked !== items && Array.isArray(masked)) items.splice(0, items.length, ...masked)
}
