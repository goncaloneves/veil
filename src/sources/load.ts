import type { Config } from '../config/config.ts'
import { basename, caseInsensitive, expandHome, isAbsolutePath, isFilesystemRoot, joinPath, lastSeparator, normalizePath, pathKey } from '../core/paths.ts'
import type { Secret } from '../core/types.ts'
import { parseGitConfig, rawSecret, treeParser, type Parser } from './credentials.ts'
import { parseDotenv } from './dotenv.ts'
import type { EnvPolicy } from './env-policy.ts'
import { ENVIRONMENT_KEYS, LOCATION_KEYS, environmentSecrets, parseEnviron, secretFileVariables } from './environment.ts'
import { composerAuth, dotenvParser, homeCatalog, projectParser, projectRootFiles, systemCatalog, systemRawDirs, type DirSource, type FileSource } from './places.ts'
import { errorMessage, globRegExp } from './util.ts'

export { ENVIRONMENT_KEYS, LOCATION_KEYS, expandHome }

export type FsKind = 'file' | 'dir' | 'other'

export type FsEntry = {
  readonly name: string
  readonly kind: FsKind
  readonly isLink?: boolean
}

export type FsInfo = {
  readonly kind: FsKind
  readonly size?: number
  readonly mtimeMs?: number
  readonly ctimeMs?: number
  readonly ino?: number
  readonly realPath?: string | undefined
}

export type SourceFs = {
  read(path: string): Promise<string>
  list(dir: string): Promise<readonly FsEntry[]>
  exists(path: string): Promise<boolean>
  kindOf(path: string): Promise<FsKind>
  realPath?: (path: string) => Promise<string | undefined>
  stat?: (path: string) => Promise<FsInfo>
  readTail?: (path: string, bytes: number) => Promise<string>
}

export async function isRegularFile(fs: SourceFs, path: string): Promise<boolean> {
  try {
    return (await fs.kindOf(path)) === 'file'
  } catch {
    return false
  }
}

function followable(entry: FsEntry): boolean {
  return entry.kind === 'file' || entry.isLink === true
}

export type SourceHost = {
  readonly home: string
  readonly root: string
  readonly cwd?: string
  readonly platform?: string
  readonly vars: Readonly<Record<string, string | undefined>>
  readonly locations?: Readonly<Record<string, string | undefined>>
  readonly environ?: string | null | undefined
}

export type SourceFile = {
  readonly path: string
  readonly kind: string
  readonly count: number
}

export type LoadError = {
  readonly path: string
  readonly message: string
  readonly quiet?: boolean
}

export type SourceCache = ReadonlyMap<string, { readonly stamp: string; readonly found: readonly Secret[]; readonly kind: string; readonly follows: readonly FileSource[] }>

export type WalkCache = {
  readonly at: number
  readonly key: string
  readonly sources: readonly FileSource[]
  readonly folders: readonly string[]
}

export type Loaded = {
  readonly secrets: readonly Secret[]
  readonly files: readonly SourceFile[]
  readonly errors: readonly LoadError[]
  readonly warnings: readonly string[]
  readonly skipped?: readonly LoadError[]
  readonly cache?: SourceCache
  readonly walk?: WalkCache
}

type Scope = 'project' | 'configured' | 'home' | 'system' | 'environment'

type Candidate = FileSource & { readonly scope: Scope; readonly pattern?: string }

const TEMPLATE_WORDS = new Set(['example', 'examples', 'sample', 'samples', 'template', 'templates', 'dist', 'default', 'defaults', 'tmpl', 'tpl'])
const STAGE_NAMES = new Set(['local', 'production', 'prod', 'development', 'dev', 'staging', 'stage', 'test', 'testing', 'qa', 'preview', 'uat', 'ci'])
const SKIP_DIRS = new Set(['node_modules', 'vendor', 'dist', 'build', 'target', 'coverage', 'out', 'tmp', '__pycache__', 'venv', 'bower_components', 'Pods', 'DerivedData', 'site-packages'])
const DOT_DIRS = new Set(['.devcontainer', '.docker', '.streamlit', '.secrets'])
const ROOT_SKIP = new Set(['proc', 'sys', 'dev', 'usr', 'bin', 'sbin', 'lib', 'lib32', 'lib64', 'libx32', 'boot', 'snap', 'run', 'lost+found', 'nix', 'System', 'Library', 'Applications', 'Volumes', 'private', 'cores', 'Users', 'home', 'mnt', 'media', 'net', 'Network', 'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs'])
const HOME_SKIP = new Set(['Library', 'Pictures', 'Music', 'Movies', 'Applications', 'Public', 'AppData', 'Downloads', 'Documents', 'Desktop', 'OneDrive', 'Dropbox', 'Google Drive'])
const WALK_TTL = 3 * 60 * 1000
const MAX_DIRS = 2000
const MAX_DIR_FILES = 256
const MAX_FOLLOWS = 32
const FOLLOW_ROUNDS = 3

export const MAX_TEXT = 8 * 1024 * 1024

export function isEnvFileName(name: string): boolean {
  const lower = name.toLowerCase()
  if (lower.split(/[.\-_]/).some(part => TEMPLATE_WORDS.has(part))) return false
  if (lower === '.env' || lower === '.envrc' || lower === '.dev.vars') return true
  if (lower.startsWith('.env.') || lower.startsWith('.env-') || lower.startsWith('.dev.vars.')) return true
  if (lower.startsWith('env.') && STAGE_NAMES.has(lower.slice(4))) return true
  return lower.endsWith('.env') && lower.length > 4
}

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code
  if (typeof code === 'string') return code
  return errorMessage(error).match(/\b(ENOENT|ENOTDIR|EACCES|EPERM)\b/)?.[1] ?? ''
}

function isMissing(error: unknown): boolean {
  const code = errorCode(error)
  return code === 'ENOENT' || code === 'ENOTDIR'
}

function isDenied(error: unknown): boolean {
  const code = errorCode(error)
  return code === 'EACCES' || code === 'EPERM'
}

function isKernelPath(path: string): boolean {
  return /^\/(?:proc|sys|dev)(?:\/|$)/.test(normalizePath(path))
}

function emptyOnDisk(info: FsInfo): boolean {
  return info.size === 0 && (info.mtimeMs ?? 0) > 0
}

function isFile(info: FsInfo | 'missing' | { readonly error: unknown }): boolean {
  return typeof info === 'object' && 'kind' in info && info.kind === 'file'
}

function defined(record: Readonly<Record<string, string | undefined>> | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(record ?? {})) if (typeof value === 'string' && value !== '') out[key] = value
  return out
}

async function settle<T>(items: readonly T[], limit: number, run: (item: T, index: number) => Promise<void>): Promise<void> {
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const index = next++
      await run(items[index] as T, index)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
}

function detect(text: string, policy: EnvPolicy): { readonly kind: string; readonly parse: Parser } {
  const trimmed = text.trim()
  if (/^[{[]/.test(trimmed)) return { kind: 'json', parse: treeParser('file', {}, 'json') }
  if (parseDotenv(text).some(entry => entry.value.replace(/=+$/, '') !== '')) return { kind: 'dotenv', parse: dotenvParser(policy) }
  if (!/\n/.test(trimmed)) return { kind: 'raw', parse: (value, source) => rawSecret(basename(source))(value, source) }
  return { kind: 'config', parse: treeParser('file', {}, 'keyed') }
}

export function secretMounts(mountinfo: string): string[] {
  const mounts: string[] = []
  for (const line of mountinfo.split('\n')) {
    const [before, after] = line.split(' - ')
    const fields = (before ?? '').split(' ')
    const mount = fields[4]?.replace(/\\([0-7]{3})/g, (_, octal: string) => String.fromCharCode(Number.parseInt(octal, 8)))
    const type = (after ?? '').split(' ')[0]
    const readOnly = (fields[5] ?? '').split(',').includes('ro')
    if (!mount || type !== 'tmpfs' || !readOnly || isKernelPath(mount) || /^\/var\/lib\/kubelet(?:\/|$)/.test(mount)) continue
    mounts.push(mount)
  }
  return mounts
}

export async function loadSecrets(fs: SourceFs, host: SourceHost, config: Config, previous?: Loaded): Promise<Loaded> {
  const platform = host.platform ?? 'linux'
  const vars: Record<string, string> = { ...parseEnviron(host.environ ?? ''), ...defined(host.vars), ...defined(host.locations) }
  const policy: EnvPolicy = { secretKeys: config.env.secretKeys, ignoreKeys: config.env.ignoreKeys }
  const errors: LoadError[] = []
  const skipped: LoadError[] = []
  const warnings: string[] = []
  const candidates: Candidate[] = []
  const configuredPatterns = new Map<string, number>()
  const fail = (path: string, error: unknown, quiet: boolean) => errors.push({ path, message: errorMessage(error), ...(quiet ? { quiet: true } : {}) })
  const add = (source: FileSource, scope: Scope, pattern?: string) => candidates.push({ ...source, scope, ...(pattern === undefined ? {} : { pattern }) })

  const inspect = async (path: string): Promise<FsInfo | 'missing' | { readonly error: unknown }> => {
    try {
      if (fs.stat) return await fs.stat(path)
      const kind = await fs.kindOf(path)
      return kind === 'file' && fs.realPath ? { kind, realPath: await fs.realPath(path).catch(() => undefined) } : { kind }
    } catch (error) {
      return isMissing(error) ? 'missing' : { error }
    }
  }

  const list = async (dir: string, scope: Scope): Promise<readonly FsEntry[]> => {
    try {
      return await fs.list(dir)
    } catch (error) {
      if (scope === 'system' && isDenied(error)) skipped.push({ path: dir, message: errorMessage(error), quiet: true })
      else if (!isMissing(error)) fail(dir, error, scope !== 'configured')
      return []
    }
  }

  const readSmall = async (path: string): Promise<string> => {
    const info = await inspect(path)
    if (typeof info !== 'object' || !('kind' in info) || info.kind !== 'file' || emptyOnDisk(info) || (info.size ?? 0) > MAX_TEXT) return ''
    if (platform !== 'win32' && (isKernelPath(path) || isKernelPath(info.realPath ?? path))) return ''
    const text = await fs.read(path).catch(() => '')
    return text.length > MAX_TEXT ? '' : text
  }

  let walk: WalkCache | undefined
  if (config.sources.project) {
    const roots = [host.root, ...(host.cwd && pathKey(host.cwd, platform) !== pathKey(host.root, platform) ? [host.cwd] : [])]
    const key = JSON.stringify([roots.map(root => pathKey(root, platform)), config.sources.projectDepth])
    const found = new Map<string, FileSource>()
    const folders = new Set<string>()
    const classify = (dir: string, entry: FsEntry): void => {
      if (!followable(entry)) return
      const path = joinPath(dir, entry.name)
      const source = isEnvFileName(entry.name)
        ? { path, kind: 'dotenv', parse: dotenvParser(policy, entry.name.toLowerCase() === '.envrc') }
        : projectParser(entry.name, basename(dir), policy)
      if (!source) return
      found.set(pathKey(path, platform), { ...source, path })
      folders.add(dir)
    }
    const now = Date.now()
    const prior = previous?.walk
    if (prior && prior.key === key && now - prior.at < WALK_TTL) {
      for (const source of prior.sources) found.set(pathKey(source.path, platform), source)
      for (const dir of new Set([...roots, ...prior.folders])) for (const entry of await list(dir, 'project')) classify(dir, entry)
      walk = { ...prior, sources: [...found.values()], folders: [...new Set([...prior.folders, ...folders])] }
    } else {
      let budget = MAX_DIRS
      const visit = async (dir: string, depth: number): Promise<void> => {
        if (budget-- <= 0) return
        const atRoot = isFilesystemRoot(dir)
        const atHome = host.home !== '' && pathKey(dir, platform) === pathKey(host.home, platform)
        for (const entry of await list(dir, 'project')) {
          classify(dir, entry)
          if (entry.kind !== 'dir' || depth <= 0) continue
          if (entry.name.startsWith('.') ? !DOT_DIRS.has(entry.name) : SKIP_DIRS.has(entry.name)) continue
          if ((atRoot && ROOT_SKIP.has(entry.name)) || (atHome && HOME_SKIP.has(entry.name))) continue
          await visit(joinPath(dir, entry.name), depth - 1)
        }
      }
      for (const root of roots) await visit(root, config.sources.projectDepth)
      walk = { at: now, key, sources: [...found.values()], folders: [...folders] }
    }
    for (const source of walk.sources) add(source, 'project')
    for (const root of roots) {
      for (const source of projectRootFiles(root, policy)) add(source, 'project')
      if (isFile(await inspect(joinPath(root, 'composer.json')))) add({ path: joinPath(root, 'auth.json'), kind: 'composer', parse: composerAuth }, 'project')
      const gitdir = (await readSmall(joinPath(root, '.git'))).match(/^gitdir:\s*(.+?)\s*$/m)?.[1]
      if (gitdir) {
        const resolved = isAbsolutePath(gitdir) ? gitdir : joinPath(root, gitdir)
        const common = (await readSmall(joinPath(resolved, 'commondir'))).trim()
        const base = common ? (isAbsolutePath(common) ? common : joinPath(resolved, common)) : resolved
        add({ path: joinPath(base, 'config'), kind: 'gitconfig', parse: parseGitConfig }, 'project')
      }
    }
  }

  for (const pattern of config.sources.files) {
    const path = expandHome(pattern, host.home)
    const cut = lastSeparator(path)
    const name = path.slice(cut + 1)
    configuredPatterns.set(pattern, 0)
    if (!/[*?]/.test(name)) {
      add({ path, kind: 'auto', parse: () => [] }, 'configured', pattern)
      continue
    }
    const dir = cut <= 0 ? (cut === 0 ? path.slice(0, 1) : '.') : path.slice(0, cut)
    try {
      const matcher = globRegExp(name, { segment: true, caseInsensitive: caseInsensitive(platform) })
      for (const entry of await fs.list(dir)) {
        if (followable(entry) && matcher.test(entry.name) && !entry.name.startsWith('..')) add({ path: joinPath(dir, entry.name), kind: 'auto', parse: () => [] }, 'configured', pattern)
      }
    } catch (error) {
      warnings.push(`sources.files: could not list ${dir} for "${pattern}": ${errorMessage(error)}`)
      configuredPatterns.delete(pattern)
    }
  }

  if (config.sources.environment) for (const [name, path] of secretFileVariables(vars)) add({ path, kind: 'raw', parse: rawSecret(name) }, 'environment')

  const places = { home: host.home, platform, env: (name: string) => vars[name], policy }
  const dirSources: [DirSource, Scope][] = []
  if (config.sources.home && host.home) {
    const catalog = homeCatalog(places)
    for (const source of catalog.files) add(source, 'home')
    for (const source of catalog.dirs) dirSources.push([source, 'home'])
  }
  if (config.sources.system) {
    const catalog = systemCatalog(places)
    for (const source of catalog.files) add(source, 'system')
    for (const source of catalog.dirs) dirSources.push([source, 'system'])
    if (platform === 'linux') for (const source of systemRawDirs(secretMounts(await fs.read('/proc/self/mountinfo').catch(() => '')))) dirSources.push([source, 'system'])
  }
  for (const [source, scope] of dirSources) {
    let count = 0
    let capped = false
    const visit = async (dir: string, depth: number, relative: string): Promise<void> => {
      const entries = await list(dir, scope)
      for (const entry of entries) {
        if (entry.kind === 'dir' || !followable(entry) || !source.match(entry.name)) continue
        if (count >= MAX_DIR_FILES) {
          capped = true
          return
        }
        count++
        const name = relative ? `${relative}/${entry.name}` : entry.name
        add({ path: joinPath(dir, entry.name), kind: source.kind, parse: source.parse(name), ...(source.follow ? { follow: source.follow } : {}) }, scope)
      }
      for (const entry of entries) {
        if (entry.kind !== 'dir' || depth <= 0 || entry.name.startsWith('..') || !(source.enter?.(entry.name) ?? true)) continue
        await visit(joinPath(dir, entry.name), depth - 1, relative ? `${relative}/${entry.name}` : entry.name)
      }
    }
    await visit(source.dir, source.depth, '')
    if (capped) warnings.push(`veil read only the first ${MAX_DIR_FILES} files under ${source.dir}`)
  }

  type Found = { readonly found: readonly Secret[]; readonly kind: string; readonly id: string; readonly follows: readonly FileSource[]; readonly stamp?: string; readonly cacheKey: string }
  type Outcome = Found | { readonly error: unknown; readonly quiet: boolean } | { readonly warning: string } | { readonly skip: string }
  const cache = new Map<string, { readonly stamp: string; readonly found: readonly Secret[]; readonly kind: string; readonly follows: readonly FileSource[] }>()
  const examine = async (candidate: Candidate): Promise<Outcome | undefined> => {
    const quiet = candidate.scope !== 'project' && candidate.scope !== 'configured'
    const info = await inspect(candidate.path)
    if (info === 'missing') return candidate.scope === 'configured' && !/[*?]/.test(candidate.pattern ?? '') ? { warning: `sources.files: ${candidate.pattern} was not found` } : undefined
    if ('error' in info) return candidate.scope === 'system' && isDenied(info.error) ? { skip: errorMessage(info.error) } : { error: info.error, quiet }
    if (info.kind !== 'file') return candidate.scope === 'configured' ? { warning: `sources.files: ${candidate.path} is not a regular file, so veil skipped it` } : undefined
    const real = info.realPath ?? candidate.path
    if (platform !== 'win32' && (isKernelPath(real) || isKernelPath(candidate.path))) return { skip: `${real} is a kernel file, so veil skipped it` }
    if (emptyOnDisk(info)) return undefined
    const id = pathKey(real, platform)
    const cacheKey = `${id}\u0000${candidate.kind}`
    const stamp = info.size !== undefined && info.mtimeMs !== undefined && info.mtimeMs > 0 ? [info.size, info.mtimeMs, info.ctimeMs ?? '', info.ino ?? ''].join(':') : undefined
    const hit = stamp === undefined ? undefined : previous?.cache?.get(cacheKey)
    if (hit && hit.stamp === stamp) return { found: hit.found, kind: hit.kind, follows: hit.follows, id, stamp, cacheKey }
    try {
      const tail = candidate.kind === 'history'
      let text: string
      if (info.size !== undefined && info.size > MAX_TEXT) {
        if (!tail || !fs.readTail) throw new Error(`larger than ${MAX_TEXT / 1024 / 1024} MiB`)
        text = await fs.readTail(candidate.path, MAX_TEXT)
        text = text.slice(text.indexOf('\n') + 1)
      } else text = await fs.read(candidate.path)
      if (text.length > MAX_TEXT) {
        if (!tail) throw new Error(`larger than ${MAX_TEXT / 1024 / 1024} MiB`)
        text = text.slice(-MAX_TEXT)
        text = text.slice(text.indexOf('\n') + 1)
      }
      const chosen = candidate.kind === 'auto' ? detect(text, policy) : candidate
      return { found: chosen.parse(text, candidate.path), kind: chosen.kind, follows: candidate.follow?.(text, candidate.path) ?? [], id, cacheKey, ...(stamp === undefined ? {} : { stamp }) }
    } catch (error) {
      return candidate.scope === 'system' && isDenied(error) ? { skip: errorMessage(error) } : { error, quiet }
    }
  }

  const all: Candidate[] = [...candidates]
  const outcomes: (Outcome | undefined)[] = []
  let batch = { from: 0, to: all.length }
  let followed = 0
  for (let round = 0; round <= FOLLOW_ROUNDS && batch.from < batch.to; round++) {
    const slice = all.slice(batch.from, batch.to)
    const offset = batch.from
    await settle(slice, 16, async (candidate, index) => {
      outcomes[offset + index] = await examine(candidate)
    })
    const known = new Set(all.map(candidate => pathKey(candidate.path, platform)))
    const start = all.length
    for (let index = batch.from; index < batch.to; index++) {
      const outcome = outcomes[index]
      const parent = all[index]
      if (!outcome || !parent || !('follows' in outcome)) continue
      for (const source of outcome.follows) {
        if (followed >= MAX_FOLLOWS || known.has(pathKey(source.path, platform))) continue
        known.add(pathKey(source.path, platform))
        followed++
        all.push({ ...source, scope: parent.scope === 'configured' ? 'home' : parent.scope })
      }
    }
    batch = { from: start, to: all.length }
  }

  const secrets: Secret[] = []
  const files: SourceFile[] = []
  const taken = new Set<string>()
  all.forEach((candidate, index) => {
    const outcome = outcomes[index]
    if (!outcome) return
    if ('warning' in outcome) return void warnings.push(outcome.warning)
    if ('skip' in outcome) return void skipped.push({ path: candidate.path, message: outcome.skip, quiet: true })
    if ('error' in outcome) return void fail(candidate.path, outcome.error, outcome.quiet)
    if (outcome.stamp !== undefined) cache.set(outcome.cacheKey, { stamp: outcome.stamp, found: outcome.found, kind: outcome.kind, follows: outcome.follows })
    if (taken.has(outcome.id)) return
    taken.add(outcome.id)
    secrets.push(...outcome.found)
    files.push({ path: candidate.path, kind: outcome.kind, count: outcome.found.length })
    if (candidate.pattern !== undefined) {
      configuredPatterns.set(candidate.pattern, (configuredPatterns.get(candidate.pattern) ?? 0) + 1)
      if (outcome.found.length === 0) warnings.push(`sources.files: ${candidate.path} holds no values veil recognises`)
    }
  })
  for (const [pattern, matched] of configuredPatterns) if (matched === 0 && /[*?]/.test(pattern)) warnings.push(`sources.files: "${pattern}" matched no files`)

  if (config.sources.environment) {
    if (host.environ === null) warnings.push('could not read /proc/self/environ, so only the well-known secret variables in the environment are checked')
    if (host.environ === '') errors.push({ path: '/proc/self/environ', message: 'it read empty, so only the well-known secret variables in the environment are checked', quiet: true })
    const found = environmentSecrets(vars, policy)
    if (found.length > 0) {
      secrets.push(...found)
      files.push({ path: 'environment', kind: 'environment', count: found.length })
    }
  }

  const unique = new Map<string, Secret>()
  for (const secret of secrets) {
    const seen = unique.get(secret.value)
    if (!seen) {
      unique.set(secret.value, secret)
      continue
    }
    const sources = [...new Set([...(seen.sources ?? [seen.source]), secret.source])]
    unique.set(secret.value, { ...seen, strong: seen.strong || secret.strong === true, ...(sources.length > 1 ? { sources } : {}) })
  }
  return { secrets: [...unique.values()], files, errors, warnings, skipped, cache, ...(walk ? { walk } : {}) }
}
