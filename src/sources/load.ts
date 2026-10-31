import type { Config } from '../config/config.ts'
import type { Secret } from '../core/types.ts'
import {
  parseAwsCredentials,
  parseDockerConfig,
  parseGhHosts,
  parseGitCredentials,
  parseKubeConfig,
  parseNetrc,
  parseNpmrc,
  parsePgpass,
  privateKeyBlocks,
} from './credentials.ts'
import { parseDotenv } from './dotenv.ts'
import { envSecrets, type EnvPolicy } from './env-policy.ts'

export type FsKind = 'file' | 'dir' | 'other'

export type FsEntry = {
  readonly name: string
  readonly kind: FsKind
  readonly isLink?: boolean
}

export type SourceFs = {
  read(path: string): Promise<string>
  list(dir: string): Promise<readonly FsEntry[]>
  exists(path: string): Promise<boolean>
  kindOf(path: string): Promise<FsKind>
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
  readonly vars: Readonly<Record<string, string | undefined>>
}

export type SourceFile = {
  readonly path: string
  readonly kind: string
  readonly count: number
}

export type Loaded = {
  readonly secrets: readonly Secret[]
  readonly files: readonly SourceFile[]
  readonly errors: readonly { readonly path: string; readonly message: string }[]
}

export const ENVIRONMENT_KEYS = [
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN', 'OPENAI_API_KEY', 'AZURE_OPENAI_API_KEY',
  'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'MISTRAL_API_KEY', 'GROQ_API_KEY', 'XAI_API_KEY', 'DEEPSEEK_API_KEY',
  'OPENROUTER_API_KEY', 'TOGETHER_API_KEY', 'FIREWORKS_API_KEY', 'COHERE_API_KEY', 'PERPLEXITY_API_KEY',
  'HF_TOKEN', 'HUGGINGFACE_TOKEN', 'REPLICATE_API_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'GITLAB_TOKEN',
  'NPM_TOKEN', 'NODE_AUTH_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'DIGITALOCEAN_ACCESS_TOKEN',
  'CLOUDFLARE_API_TOKEN', 'VERCEL_TOKEN', 'NETLIFY_AUTH_TOKEN', 'FLY_API_TOKEN', 'STRIPE_SECRET_KEY',
  'SLACK_BOT_TOKEN', 'SLACK_TOKEN', 'SENTRY_AUTH_TOKEN', 'DATABASE_URL', 'REDIS_URL',
] as const

const TEMPLATE = /^\.env\.(?:example|sample|template|dist|defaults)$/i
const SKIP_DIRS = new Set(['node_modules', 'vendor', 'dist', 'build', 'target', 'coverage', 'out', 'tmp', '__pycache__'])
const SSH_SKIP = /^(?:config|known_hosts.*|authorized_keys.*|environment|rc|.*\.pub)$/

export function isEnvFileName(name: string): boolean {
  if (TEMPLATE.test(name)) return false
  return name === '.env' || name === '.envrc' || name.startsWith('.env.') || (name.endsWith('.env') && name.length > 4)
}

export function expandHome(path: string, home: string): string {
  return path === '~' ? home : path.startsWith('~/') ? `${home}${path.slice(1)}` : path
}

function join(dir: string, name: string): string {
  return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`
}

function wildcard(pattern: string): RegExp {
  return new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`)
}

export async function loadSecrets(fs: SourceFs, host: SourceHost, config: Config): Promise<Loaded> {
  const secrets: Secret[] = []
  const files: SourceFile[] = []
  const errors: { path: string; message: string }[] = []
  const policy: EnvPolicy = { ...config.env, minLength: config.mask.minLength }

  const taken = new Set<string>()
  const take = async (path: string, kind: string, parse: (text: string, source: string) => Secret[]) => {
    if (taken.has(path)) return
    taken.add(path)
    try {
      if (!(await isRegularFile(fs, path))) return
      const found = parse(await fs.read(path), path)
      secrets.push(...found)
      files.push({ path, kind, count: found.length })
    } catch (error) {
      errors.push({ path, message: error instanceof Error ? error.message : String(error) })
    }
  }
  const dotenv = (text: string, source: string) => envSecrets(parseDotenv(text), source, policy)

  if (config.sources.project) {
    const walk = async (dir: string, depth: number): Promise<void> => {
      let entries: readonly FsEntry[]
      try {
        entries = await fs.list(dir)
      } catch {
        return
      }
      for (const entry of entries) {
        const path = join(dir, entry.name)
        if (followable(entry) && isEnvFileName(entry.name)) await take(path, 'dotenv', dotenv)
        else if (entry.kind === 'dir' && depth > 0 && !entry.name.startsWith('.') && !SKIP_DIRS.has(entry.name)) {
          await walk(path, depth - 1)
        }
      }
    }
    await walk(host.root, config.sources.projectDepth)
    if (host.cwd && host.cwd !== host.root) await walk(host.cwd, config.sources.projectDepth)
  }

  for (const pattern of config.sources.files) {
    const path = expandHome(pattern, host.home)
    const slash = path.lastIndexOf('/')
    const name = path.slice(slash + 1)
    if (!/[*?]/.test(name)) {
      await take(path, 'dotenv', dotenv)
      continue
    }
    const dir = path.slice(0, slash) || '/'
    try {
      const matcher = wildcard(name)
      for (const entry of await fs.list(dir)) {
        if (followable(entry) && matcher.test(entry.name)) await take(join(dir, entry.name), 'dotenv', dotenv)
      }
    } catch (error) {
      errors.push({ path: dir, message: error instanceof Error ? error.message : String(error) })
    }
  }

  if (config.sources.home) {
    const home = host.home
    await take(`${home}/.aws/credentials`, 'aws', parseAwsCredentials)
    await take(`${home}/.netrc`, 'netrc', parseNetrc)
    await take(`${home}/.pgpass`, 'pgpass', parsePgpass)
    await take(`${home}/.git-credentials`, 'git-credentials', parseGitCredentials)
    await take(`${home}/.npmrc`, 'npmrc', parseNpmrc)
    await take(`${home}/.docker/config.json`, 'docker', parseDockerConfig)
    await take(`${home}/.config/gh/hosts.yml`, 'gh', parseGhHosts)
    await take(`${home}/.kube/config`, 'kube', parseKubeConfig)
    try {
      for (const entry of await fs.list(`${home}/.ssh`)) {
        if (!followable(entry) || SSH_SKIP.test(entry.name)) continue
        await take(`${home}/.ssh/${entry.name}`, 'ssh', (text, source) => privateKeyBlocks(text, `ssh/${entry.name}`, source))
      }
    } catch {}
  }

  if (config.sources.environment) {
    const found: Secret[] = []
    for (const key of ENVIRONMENT_KEYS) {
      const value = host.vars[key]
      if (value && value.length >= config.mask.minLength) found.push({ name: key, value, source: 'environment' })
    }
    if (found.length > 0) {
      secrets.push(...found)
      files.push({ path: 'environment', kind: 'environment', count: found.length })
    }
  }

  const unique = new Map<string, Secret>()
  for (const secret of secrets) if (!unique.has(secret.value)) unique.set(secret.value, secret)
  return { secrets: [...unique.values()], files, errors }
}
