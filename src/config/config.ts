import type { Encoding } from '../core/types.ts'
import { parseToml, type TomlTable, type TomlValue } from './toml.ts'

export type RestoreMode = 'holding' | 'always' | 'never'

export type Config = {
  readonly sources: {
    readonly project: boolean
    readonly projectDepth: number
    readonly home: boolean
    readonly system: boolean
    readonly environment: boolean
    readonly files: readonly string[]
  }
  readonly env: {
    readonly secretKeys: readonly string[]
    readonly ignoreKeys: readonly string[]
  }
  readonly rules: {
    readonly gitleaks: boolean
    readonly disable: readonly string[]
  }
  readonly mask: {
    readonly minLength: number
    readonly encodings: readonly Encoding[]
  }
  readonly restore: {
    readonly mode: RestoreMode
  }
}

export const ENCODINGS: readonly Encoding[] = ['base64', 'url', 'json', 'lines']

export const DEFAULT_CONFIG: Config = {
  sources: { project: true, projectDepth: 3, home: true, system: true, environment: true, files: [] },
  env: { secretKeys: [], ignoreKeys: [] },
  rules: { gitleaks: true, disable: [] },
  mask: { minLength: 8, encodings: ENCODINGS },
  restore: { mode: 'holding' },
}

export type ConfigHost = {
  readonly home: string
  readonly platform: string
  readonly veilConfig?: string | undefined
  readonly xdgConfigHome?: string | undefined
}

export function configPaths(host: ConfigHost): string[] {
  if (host.veilConfig) return [host.veilConfig]
  const xdg = host.xdgConfigHome || `${host.home}/.config`
  const paths = [`${xdg}/veil/config.toml`]
  if (host.platform === 'darwin') paths.push(`${host.home}/Library/Application Support/veil/config.toml`)
  return paths
}

export type ParsedConfig = {
  readonly config: Config
  readonly warnings: readonly string[]
}

function table(value: TomlValue | undefined): TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : {}
}

export function parseConfig(text: string): ParsedConfig {
  const root = parseToml(text)
  const warnings: string[] = []
  const read = <T>(section: string, key: string, fallback: T, check: (value: TomlValue) => T | undefined): T => {
    const value = table(root[section])[key]
    if (value === undefined) return fallback
    const checked = check(value)
    if (checked === undefined) {
      warnings.push(`${section}.${key} has an invalid value; using the default`)
      return fallback
    }
    return checked
  }
  const bool = (value: TomlValue) => (typeof value === 'boolean' ? value : undefined)
  const count = (min: number, max: number) => (value: TomlValue) =>
    typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max ? value : undefined
  const strings = (value: TomlValue) =>
    Array.isArray(value) && value.every(item => typeof item === 'string') ? (value as string[]) : undefined
  const encodings = (value: TomlValue) => {
    const list = strings(value)
    return list?.every(item => (ENCODINGS as readonly string[]).includes(item)) ? (list as Encoding[]) : undefined
  }
  const restoreMode = (value: TomlValue) =>
    value === 'holding' || value === 'always' || value === 'never' ? value : undefined

  const known: Record<string, readonly string[]> = {
    sources: ['project', 'project_depth', 'home', 'system', 'environment', 'files'],
    env: ['secret_keys', 'ignore_keys'],
    rules: ['gitleaks', 'disable'],
    mask: ['min_length', 'encodings'],
    restore: ['mode'],
  }
  for (const [section, value] of Object.entries(root)) {
    const keys = known[section]
    if (!keys) {
      warnings.push(`unknown section [${section}]`)
      continue
    }
    for (const key of Object.keys(table(value))) if (!keys.includes(key)) warnings.push(`unknown key ${section}.${key}`)
  }

  const d = DEFAULT_CONFIG
  const config: Config = {
    sources: {
      project: read('sources', 'project', d.sources.project, bool),
      projectDepth: read('sources', 'project_depth', d.sources.projectDepth, count(0, 6)),
      home: read('sources', 'home', d.sources.home, bool),
      system: read('sources', 'system', d.sources.system, bool),
      environment: read('sources', 'environment', d.sources.environment, bool),
      files: read('sources', 'files', d.sources.files, strings),
    },
    env: {
      secretKeys: read('env', 'secret_keys', d.env.secretKeys, strings),
      ignoreKeys: read('env', 'ignore_keys', d.env.ignoreKeys, strings),
    },
    rules: {
      gitleaks: read('rules', 'gitleaks', d.rules.gitleaks, bool),
      disable: read('rules', 'disable', d.rules.disable, strings),
    },
    mask: {
      minLength: read('mask', 'min_length', d.mask.minLength, count(4, 256)),
      encodings: read('mask', 'encodings', d.mask.encodings, encodings),
    },
    restore: { mode: read('restore', 'mode', d.restore.mode, restoreMode) },
  }
  return { config, warnings }
}

export function weakenings(config: Config): string[] {
  const d = DEFAULT_CONFIG
  const out: string[] = []
  if (!config.rules.gitleaks) out.push('the gitleaks pattern rules are off')
  if (config.rules.disable.length > 0) out.push(`rules turned off: ${config.rules.disable.join(', ')}`)
  if (!config.sources.project) out.push("the project's secret files are not read")
  if (!config.sources.home) out.push('the credentials in your home folder are not read')
  if (!config.sources.system) out.push('secret files outside your home folder, such as /run/secrets, are not read')
  if (!config.sources.environment) out.push('secret variables and *_FILE files in the environment are not read')
  if (config.sources.projectDepth < d.sources.projectDepth) out.push(`project files are read only ${config.sources.projectDepth} folders deep`)
  if (config.mask.minLength > d.mask.minLength) out.push(`values shorter than ${config.mask.minLength} characters are masked at most as whole tokens or where they are assigned`)
  const missing = d.mask.encodings.filter(encoding => !config.mask.encodings.includes(encoding))
  if (missing.length > 0) out.push(`encoded forms not matched: ${missing.join(', ')}`)
  if (config.env.ignoreKeys.length > 0) out.push(`variables never treated as secret: ${config.env.ignoreKeys.join(', ')}`)
  if (config.restore.mode === 'always') out.push('placeholders are restored into any file')
  return out
}

export const STARTER_CONFIG = `# veil configuration. Every key is optional; the values shown are the defaults.

[sources]
project = true          # .env files and other secret files in the project, up to project_depth folders down
project_depth = 3
home = true             # credential files in your home folder: cloud CLIs, keys, registries, agents, shell history
system = true           # /run/secrets, Kubernetes service accounts, k3s and server keys outside your home folder
environment = true      # secret variables in the environment veil runs in (the Claude Code plugin reads every variable only on Linux)
files = []              # more secret files: dotenv, JSON, YAML, INI or a raw value, such as "~/.config/myapp/*.env"

[env]
secret_keys = []        # more variable-name patterns to treat as secret, such as "*_DSN"
ignore_keys = []        # variable-name patterns never treated as secret, such as "SENTRY_ENVIRONMENT"

[rules]
gitleaks = true         # gitleaks' pattern rules, for secrets veil has not seen in a file; veil's own rules always run
disable = []            # rule ids to turn off, such as "generic-api-key"

[mask]
min_length = 8          # shorter values are masked at most as a whole token or where they are assigned
encodings = ["base64", "url", "json", "lines"]

[restore]
mode = "holding"        # holding: into the value's own file or a file that already holds it; always: any file; never: no file
`
