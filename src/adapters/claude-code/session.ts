import { DEFAULT_CONFIG } from '../../config/config.ts'
import { Masker } from '../../core/masker.ts'
import { PLACEHOLDER } from '../../core/vault.ts'
import { loadState, maskerSettings, reloadSources, type VeilHost, type VeilState } from '../../engine.ts'
import { report } from '../../report.ts'
import { ruleSet } from '../../rules/index.ts'
import { isEnvFileName, type SourceFs } from '../../sources/load.ts'
import { WITHHELD, rewriteBlocks, withheldBlocks, type Block } from './blocks.ts'

export type { Block }
export { WITHHELD }

export const NOTE_ID = 'veil:note'

export const NOTE = [
  'Secret values in this session are replaced by veil, a local masking tool, with placeholders such as [veil:DATABASE_URL].',
  'Treat each placeholder as an opaque reference to a real value you cannot see: never ask for the real value or try to reveal it.',
  'In file edits, keep placeholders exactly as written; veil writes the real value back only into the file it came from or a file that already holds it, and refuses other edits that hold a placeholder.',
  'Placeholders do not work in shell commands; use environment variables there instead.',
].join(' ')

export const DROP_REASON = 'veil could not check this for secrets, so it was held back.'

const BUDGET_MS = 3000

export type StartLog = {
  readonly transcript: readonly string[]
  readonly debug: readonly string[]
}

export type EditCheck<K extends string> = { readonly fields: Record<K, string> } | { readonly deny: string }

function randomSalt(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1)
}

const MEDIA_TYPES = new Set(['image', 'document', 'audio', 'video', 'pdf', 'parts'])
const MEDIA_PATH = /\.(?:png|jpe?g|gif|webp|bmp|ico|heic|tiff?|pdf|mp3|m4a|wav|ogg|mp4|mov|webm)$/i
const BINARY_TEXT = /^[A-Za-z0-9+/=_-]+$/

function isMedia(record: Record<string, unknown>): boolean {
  if (typeof record.type === 'string' && MEDIA_TYPES.has(record.type)) return true
  const media = record.media_type ?? record.mediaType ?? record.mimeType ?? record.mime_type
  return typeof media === 'string' && /^(?:image|audio|video)\/|^application\/pdf$/.test(media)
}

export function isMediaPath(path: string): boolean {
  return MEDIA_PATH.test(path)
}

export class VeilSession {
  readonly masker = new Masker({
    secrets: [],
    ruleSet,
    minLength: DEFAULT_CONFIG.mask.minLength,
    encodings: DEFAULT_CONFIG.mask.encodings,
    salt: randomSalt(),
  })
  #state: VeilState | undefined
  #host: VeilHost | undefined

  async start(fs: SourceFs, host: VeilHost): Promise<StartLog> {
    this.#host = host
    try {
      return this.#apply(await loadState(fs, host))
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { transcript: [`veil: could not load your secrets (${message}); only pattern rules are active`], debug: [] }
    }
  }

  async reload(fs: SourceFs): Promise<StartLog> {
    if (!this.#host) return { transcript: [], debug: [] }
    return this.#apply(await loadState(fs, this.#host))
  }

  async refreshSources(fs: SourceFs): Promise<StartLog> {
    if (!this.#state || !this.#host) return { transcript: [], debug: [] }
    const state = await reloadSources(this.#state, fs, this.#host)
    this.#state = state
    this.masker.setSecrets(state.loaded.secrets)
    return { transcript: [], debug: state.loaded.errors.map(({ path, message }) => `veil: could not read ${path}: ${message}`) }
  }

  #apply(state: VeilState): StartLog {
    this.#state = state
    this.masker.configure(maskerSettings(state, ruleSet))
    return {
      transcript: state.warnings.map(warning => `veil: ${warning}`),
      debug: state.loaded.errors.map(({ path, message }) => `veil: could not read ${path}: ${message}`),
    }
  }

  isSource(path: string): boolean {
    return (this.#state?.sourcePaths.has(path) ?? false) || isEnvFileName(basename(path))
  }

  #deadline(): number {
    return Date.now() + BUDGET_MS
  }

  #maskText(text: string, deadline: number): string {
    try {
      return this.masker.mask(text, { deadline }).text
    } catch {
      return WITHHELD
    }
  }

  mask(text: string): string {
    return this.#maskText(text, this.#deadline())
  }

  holdsSecret(text: string): boolean {
    return this.mask(text) !== text
  }

  maskValue(value: unknown, deadline = this.#deadline()): unknown {
    if (typeof value === 'string') return value.length > 1_000_000 && BINARY_TEXT.test(value) ? value : this.#maskText(value, deadline)
    if (Array.isArray(value)) {
      const out = value.map(item => this.maskValue(item, deadline))
      return out.every((item, index) => item === value[index]) ? value : out
    }
    if (value !== null && typeof value === 'object') {
      const record = value as Record<string, unknown>
      if (isMedia(record)) return value
      let changed = false
      const out: Record<string, unknown> = {}
      for (const [key, item] of Object.entries(record)) {
        const masked = this.maskValue(item, deadline)
        if (masked !== item) changed = true
        out[key] = masked
      }
      return changed ? out : value
    }
    return value
  }

  maskBlocks(blocks: readonly Block[]): Block[] | undefined {
    const deadline = this.#deadline()
    return rewriteBlocks(blocks, text => this.#maskText(text, deadline))
  }

  withheld(blocks: readonly Block[]): Block[] {
    return withheldBlocks(blocks)
  }

  hasPlaceholder(texts: readonly string[]): boolean {
    return texts.some(text => text.includes('[veil:'))
  }

  checkEdit<K extends string>(path: string, fields: Record<K, string>, fileContent: string): EditCheck<K> {
    const mode = this.#state?.config.restore.mode ?? DEFAULT_CONFIG.restore.mode
    const vault = this.masker.vault
    const out = {} as Record<K, string>
    for (const key of Object.keys(fields) as K[]) {
      let refused: string | undefined
      out[key] = fields[key].replace(PLACEHOLDER, (whole, label: string) => {
        const value = vault.text(label)
        if (value !== undefined && mode !== 'never') {
          if (fileContent.includes(value)) return value
          const fromHere = vault.source(label) === path && (this.#state?.sourcePaths.has(path) ?? false)
          if (vault.isCurrent(label) && (mode === 'always' || fromHere)) return value
        }
        if (fileContent.includes(whole)) return whole
        if (value === undefined) refused ??= `veil cannot resolve ${whole} in this session. Read ${path} again so veil can map its secrets, then retry the edit.`
        else if (mode === 'never') refused ??= `veil's restore mode is never: it will not write the value behind ${whole}, and writing the placeholder would replace real content. Ask the user to make this edit.`
        else if (!vault.isCurrent(label)) refused ??= `${whole} no longer matches a value in your secret files, so veil will not write it. Read ${path} again and retry.`
        else refused ??= `veil keeps ${whole} out of ${path} because that file does not already hold it. Reference the value through an environment variable instead, or ask the user to add it.`
        return whole
      })
      if (refused) return { deny: refused }
    }
    return { fields: out }
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
