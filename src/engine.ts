import { DEFAULT_CONFIG, configPaths, parseConfig, weakenings, type Config } from './config/config.ts'
import type { MaskerSettings } from './core/masker.ts'
import { emptyRuleSet } from './core/rules.ts'
import type { RuleSet } from './core/types.ts'
import { isRegularFile, loadSecrets, type Loaded, type SourceFs, type SourceHost } from './sources/load.ts'

export type VeilHost = SourceHost & {
  readonly platform: string
  readonly veilConfig?: string | undefined
  readonly xdgConfigHome?: string | undefined
}

export type LoadedConfig = {
  readonly config: Config
  readonly path?: string
  readonly warnings: readonly string[]
}

export type VeilState = {
  readonly config: Config
  readonly configPath?: string
  readonly warnings: readonly string[]
  readonly loaded: Loaded
  readonly sourcePaths: ReadonlySet<string>
}

export function normalize(path: string): string {
  const parts: string[] = []
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') parts.pop()
    else parts.push(part)
  }
  return `/${parts.join('/')}`
}

function inside(path: string, dir: string): boolean {
  const target = normalize(path)
  const base = normalize(dir)
  return target === base || target.startsWith(base === '/' ? '/' : `${base}/`)
}

export async function loadConfig(fs: SourceFs, host: VeilHost): Promise<LoadedConfig> {
  const notes: string[] = []
  let veilConfig = host.veilConfig
  if (veilConfig && (!veilConfig.startsWith('/') || inside(veilConfig, host.root) || (host.cwd && inside(veilConfig, host.cwd)))) {
    notes.push(`VEIL_CONFIG=${veilConfig} was ignored: it must be an absolute path outside the project`)
    veilConfig = undefined
  }
  const paths = configPaths({ home: host.home, platform: host.platform, veilConfig, xdgConfigHome: host.xdgConfigHome })
  for (const path of paths) {
    try {
      if (!(await isRegularFile(fs, path))) {
        if (await fs.exists(path).catch(() => false)) notes.push(`${path} is not a regular file, so veil skipped it`)
        continue
      }
      const { config, warnings } = parseConfig(await fs.read(path))
      return { config, path, warnings: [...notes, ...warnings, ...weakenings(config).map(note => `config: ${note}`)] }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { config: DEFAULT_CONFIG, path, warnings: [...notes, `could not read ${path}: ${message}; using the defaults`] }
    }
  }
  return { config: DEFAULT_CONFIG, warnings: notes }
}

export async function loadState(fs: SourceFs, host: VeilHost): Promise<VeilState> {
  const { config, path, warnings } = await loadConfig(fs, host)
  const loaded = await loadSecrets(fs, host, config)
  return {
    config,
    ...(path === undefined ? {} : { configPath: path }),
    warnings,
    loaded,
    sourcePaths: new Set(loaded.files.map(file => file.path)),
  }
}

export async function reloadSources(state: VeilState, fs: SourceFs, host: VeilHost): Promise<VeilState> {
  const loaded = await loadSecrets(fs, host, state.config)
  return { ...state, loaded, sourcePaths: new Set(loaded.files.map(file => file.path)) }
}

export function maskerSettings(state: VeilState, ruleSet: RuleSet): MaskerSettings {
  return {
    secrets: state.loaded.secrets,
    ruleSet: state.config.rules.gitleaks ? ruleSet : emptyRuleSet(),
    disabledRules: state.config.rules.disable,
    minLength: state.config.mask.minLength,
    encodings: state.config.mask.encodings,
  }
}
