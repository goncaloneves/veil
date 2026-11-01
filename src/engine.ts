import { DEFAULT_CONFIG, configPaths, parseConfig, weakenings, type Config } from './config/config.ts'
import type { MaskerSettings } from './core/masker.ts'
import { emptyRuleSet } from './core/rules.ts'
import { isAbsolutePath, isInside } from './core/paths.ts'
import type { RuleSet } from './core/types.ts'
import { isRegularFile, loadSecrets, type Loaded, type SourceFs, type SourceHost } from './sources/load.ts'
import { errorMessage } from './sources/util.ts'

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
  readonly home?: string
  readonly platform?: string
}

async function real(fs: SourceFs, path: string): Promise<string> {
  return (fs.realPath ? await fs.realPath(path).catch(() => undefined) : undefined) ?? path
}

async function insideProject(fs: SourceFs, host: VeilHost, path: string): Promise<boolean> {
  const platform = host.platform
  const resolved = await real(fs, path)
  const home = host.home ? await real(fs, host.home) : undefined
  for (const dir of [host.root, host.cwd]) {
    if (!dir) continue
    const base = await real(fs, dir)
    if (host.home && home && (isInside(host.home, dir, platform) || isInside(home, base, platform))) continue
    if (isInside(path, dir, platform) || isInside(resolved, dir, platform) || isInside(resolved, base, platform)) return true
  }
  return false
}

export async function configCandidates(fs: SourceFs, host: VeilHost): Promise<{ readonly paths: string[]; readonly notes: string[]; readonly veilConfig: string | undefined }> {
  const notes: string[] = []
  let veilConfig = host.veilConfig
  if (veilConfig && (!isAbsolutePath(veilConfig) || (await insideProject(fs, host, veilConfig)))) {
    notes.push(`VEIL_CONFIG=${veilConfig} was ignored: it must be an absolute path outside the project`)
    veilConfig = undefined
  }
  let xdgConfigHome = host.xdgConfigHome
  if (xdgConfigHome && (!isAbsolutePath(xdgConfigHome) || (await insideProject(fs, host, xdgConfigHome)))) {
    notes.push(`XDG_CONFIG_HOME=${xdgConfigHome} was ignored for veil's config: it must be an absolute path outside the project`)
    xdgConfigHome = undefined
  }
  return { paths: configPaths({ home: host.home, platform: host.platform, veilConfig, xdgConfigHome }), notes, veilConfig }
}

export async function loadConfig(fs: SourceFs, host: VeilHost): Promise<LoadedConfig> {
  const { paths, notes, veilConfig } = await configCandidates(fs, host)
  for (const path of paths) {
    try {
      if (!(await isRegularFile(fs, path))) {
        if (await fs.exists(path).catch(() => false)) notes.push(`${path} is not a regular file, so veil skipped it`)
        else if (path === veilConfig) notes.push(`VEIL_CONFIG=${veilConfig} does not exist; using the defaults`)
        continue
      }
      const { config, warnings } = parseConfig(await fs.read(path))
      return { config, path, warnings: [...notes, ...warnings, ...weakenings(config).map(note => `config: ${note}`)] }
    } catch (error) {
      return { config: DEFAULT_CONFIG, path, warnings: [...notes, `could not read ${path}: ${errorMessage(error)}; using the defaults`] }
    }
  }
  return { config: DEFAULT_CONFIG, warnings: notes }
}

function sourceWarnings(loaded: Loaded): string[] {
  return [...loaded.warnings, ...loaded.errors.filter(error => !error.quiet).map(error => `could not read ${error.path}: ${error.message}`)]
}

export async function loadState(fs: SourceFs, host: VeilHost): Promise<VeilState> {
  const { config, path, warnings } = await loadConfig(fs, host)
  const loaded = await loadSecrets(fs, host, config)
  return {
    config,
    ...(path === undefined ? {} : { configPath: path }),
    warnings: [...warnings, ...sourceWarnings(loaded)],
    loaded,
    sourcePaths: new Set(loaded.files.map(file => file.path)),
    home: host.home,
    platform: host.platform,
  }
}

export async function reloadSources(state: VeilState, fs: SourceFs, host: VeilHost): Promise<VeilState> {
  const loaded = await loadSecrets(fs, host, state.config, state.loaded)
  return { ...state, loaded, sourcePaths: new Set(loaded.files.map(file => file.path)) }
}

export function maskerSettings(state: VeilState, ruleSet: RuleSet): MaskerSettings {
  return {
    secrets: state.loaded.secrets,
    ruleSet: state.config.rules.gitleaks ? ruleSet : { ...emptyRuleSet(), rules: ruleSet.rules.filter(rule => rule.own) },
    disabledRules: state.config.rules.disable,
    minLength: state.config.mask.minLength,
    encodings: state.config.mask.encodings,
  }
}
