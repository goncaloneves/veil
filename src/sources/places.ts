import { basename, isAbsolutePath, joinPath } from '../core/paths.ts'
import {
  configParser,
  envMapParser,
  parseAwsCredentials,
  parseBundlerConfig,
  parseClaudeJson,
  parseDockerConfig,
  parseGhHosts,
  parseGitConfig,
  parseGitCredentials,
  parseKubeConfig,
  parseNetrc,
  parseNpmrc,
  parseOpenvpnAuth,
  parsePgpass,
  parseSqliteTokens,
  parseSvnAuth,
  parseXmlCredentials,
  parseYarnrc,
  rawSecret,
  treeParser,
  type Parser,
} from './credentials.ts'
import { parseDotenv } from './dotenv.ts'
import { envSecrets, type EnvPolicy } from './env-policy.ts'
import { envEntrySecrets } from './tree.ts'
import { keyFileSecrets } from './keys.ts'
import { environmentFiles, fishVariables, fstabSecrets, historySecrets, shellEntries, sourcedFiles, systemdEntries } from './shell.ts'

export type Follow = (text: string, source: string) => readonly FileSource[]

export type FileSource = {
  readonly path: string
  readonly kind: string
  readonly parse: Parser
  readonly follow?: Follow
}

export type DirSource = {
  readonly dir: string
  readonly kind: string
  readonly depth: number
  readonly match: (name: string) => boolean
  readonly parse: (relative: string) => Parser
  readonly enter?: (name: string) => boolean
  readonly follow?: Follow
}

export type Catalog = {
  readonly files: readonly FileSource[]
  readonly dirs: readonly DirSource[]
}

export type Places = {
  readonly home: string
  readonly platform: string
  readonly env: (name: string) => string | undefined
  readonly policy: EnvPolicy
}

type Part = string | undefined

function at(...parts: Part[]): string | undefined {
  if (parts.some(part => part === undefined || part === '')) return undefined
  return (parts as string[]).reduce((dir, name) => joinPath(dir, name))
}

function absolute(value: string | undefined): string | undefined {
  return value && isAbsolutePath(value) ? value : undefined
}

export function dotenvParser(policy: EnvPolicy, shell = false): Parser {
  return (text, source) => envEntrySecrets(parseDotenv(text, { shell }), source, policy)
}

export function shellParser(policy: EnvPolicy): Parser {
  return (text, source) => envEntrySecrets(shellEntries(text), source, { ...policy, random: false })
}

export function systemdParser(policy: EnvPolicy): Parser {
  return (text, source) => envEntrySecrets(systemdEntries(text), source, { ...policy, random: false })
}

export function shellFollow(policy: EnvPolicy, home: string): Follow {
  const follow: Follow = (text, source) => sourcedFiles(text, source, home).map(path => ({ path, kind: 'shell', parse: shellParser(policy), follow }))
  return follow
}

export function systemdFollow(policy: EnvPolicy): Follow {
  return text => environmentFiles(text).map(path => ({ path, kind: 'shell', parse: shellParser(policy) }))
}

const UNIT = (name: string) => /\.(?:service|conf)$/.test(name)
const DROP_IN = (name: string) => /\.service\.d$/.test(name)

export function keysIn(prefix: string): (relative: string) => Parser {
  return relative => (text, source) => keyFileSecrets(text, `${prefix}/${relative}`, source)
}

const json = (prefix: string, options = {}) => treeParser(prefix, { literal: true, ...options }, 'json')
const toml = (prefix: string, options = {}) => treeParser(prefix, { literal: true, ...options }, 'toml')
const keyed = (prefix: string, options = {}) => treeParser(prefix, { literal: true, ...options }, 'keyed')
const expanding = (prefix: string, format: 'json' | 'toml' | 'keyed' = 'json') => treeParser(prefix, {}, format)
const always = () => true
const raw = (relative: string) => rawSecret(`secret/${relative}`)

const SSH_SKIP = /^(?:config|known_hosts.*|authorized_keys.*|environment|rc|.*\.pub|.*\.crt|.*-cert\.pub|.*\.sock|agent.*)$/i
const RAW_SKIP = /^(?:namespace|.*\.crt|.*\.pub|\.\..*)$/

function split(list: string | undefined, platform: string): string[] {
  return (list ?? '').split(platform === 'win32' ? ';' : ':').filter(Boolean)
}

export function homeCatalog(places: Places): Catalog {
  const { home: h, platform, env } = places
  const windows = platform === 'win32'
  const mac = platform === 'darwin'
  const config = absolute(env('XDG_CONFIG_HOME')) ?? at(h, '.config')
  const data = absolute(env('XDG_DATA_HOME')) ?? at(h, '.local', 'share')
  const cache = absolute(env('XDG_CACHE_HOME')) ?? at(h, '.cache')
  const appData = windows ? (absolute(env('APPDATA')) ?? at(h, 'AppData', 'Roaming')) : undefined
  const localAppData = windows ? (absolute(env('LOCALAPPDATA')) ?? at(h, 'AppData', 'Local')) : undefined
  const support = mac ? at(h, 'Library', 'Application Support') : undefined
  const preferences = mac ? at(h, 'Library', 'Preferences') : undefined
  const zdot = absolute(env('ZDOTDIR')) ?? h
  const claude = env('CLAUDE_CONFIG_DIR') ?? at(h, '.claude')
  const gcloud = env('CLOUDSDK_CONFIG') ?? (windows ? at(appData, 'gcloud') : at(h, '.config', 'gcloud'))
  const gnupg = env('GNUPGHOME') ?? (windows ? at(appData, 'gnupg') : at(h, '.gnupg'))
  const rc = shellParser(places.policy)
  const follow = shellFollow(places.policy, h)
  const history: Parser = (text, source) => historySecrets(text, source, places.policy)
  const fish: Parser = (text, source) => envSecrets(fishVariables(text), source, { ...places.policy, random: false })

  const files: [string, Parser, ...Part[]][] = [
    ['aws', parseAwsCredentials, env('AWS_SHARED_CREDENTIALS_FILE') ?? at(h, '.aws', 'credentials'), env('AWS_CONFIG_FILE') ?? at(h, '.aws', 'config')],
    ['netrc', parseNetrc, env('NETRC') ?? at(h, '.netrc'), at(h, '_netrc')],
    ['pgpass', parsePgpass, env('PGPASSFILE') ?? (windows ? at(appData, 'postgresql', 'pgpass.conf') : at(h, '.pgpass'))],
    ['pg_service', keyed('pg_service'), env('PGSERVICEFILE') ?? (windows ? at(appData, 'postgresql', '.pg_service.conf') : at(h, '.pg_service.conf'))],
    ['mysql', keyed('mysql'), at(h, '.my.cnf')],
    ['git-credentials', parseGitCredentials, at(h, '.git-credentials'), at(config, 'git', 'credentials')],
    ['gitconfig', parseGitConfig, at(h, '.gitconfig'), at(config, 'git', 'config')],
    ['npmrc', parseNpmrc, env('NPM_CONFIG_USERCONFIG') ?? env('npm_config_userconfig') ?? at(h, '.npmrc'), at(appData, 'npm', 'etc', 'npmrc')],
    ['yarnrc', parseYarnrc, at(h, '.yarnrc.yml')],
    ['bunfig', toml('bunfig'), at(h, '.bunfig.toml'), at(config, '.bunfig.toml')],
    ['docker', parseDockerConfig, env('DOCKER_CONFIG') ? at(env('DOCKER_CONFIG'), 'config.json') : at(h, '.docker', 'config.json'), env('REGISTRY_AUTH_FILE'), at(absolute(env('XDG_RUNTIME_DIR')), 'containers', 'auth.json'), at(config, 'containers', 'auth.json'), env('HELM_REGISTRY_CONFIG') ?? at(config, 'helm', 'registry', 'config.json')],
    ['gh', parseGhHosts, at(env('GH_CONFIG_DIR') ?? (absolute(env('XDG_CONFIG_HOME')) ? at(config, 'gh') : windows ? at(appData, 'GitHub CLI') : at(h, '.config', 'gh')), 'hosts.yml')],
    ['glab', keyed('glab'), at(env('GLAB_CONFIG_DIR') ?? at(config, 'glab-cli'), 'config.yml'), at(support, 'glab-cli', 'config.yml'), at(appData, 'glab-cli', 'config.yml')],
    ['kube', parseKubeConfig, ...(env('KUBECONFIG') ? split(env('KUBECONFIG'), platform) : [at(h, '.kube', 'config')])],
    ['claude', json('claude'), at(claude, '.credentials.json')],
    ['claude', parseClaudeJson, env('CLAUDE_CONFIG_DIR') ? at(env('CLAUDE_CONFIG_DIR'), '.claude.json') : at(h, '.claude.json')],
    ['claude', expanding('claude-settings'), at(claude, 'settings.json'), at(claude, 'settings.local.json')],
    ['mcp', expanding('mcp'), at(support, 'Claude', 'claude_desktop_config.json'), at(appData, 'Claude', 'claude_desktop_config.json'), at(config, 'Claude', 'claude_desktop_config.json'), at(h, '.cursor', 'mcp.json'), at(h, '.codeium', 'windsurf', 'mcp_config.json'), at(support, 'Code', 'User', 'mcp.json'), at(config, 'Code', 'User', 'mcp.json'), at(appData, 'Code', 'User', 'mcp.json')],
    ['codex', json('codex'), at(env('CODEX_HOME') ?? at(h, '.codex'), 'auth.json')],
    ['codex', expanding('codex', 'toml'), at(env('CODEX_HOME') ?? at(h, '.codex'), 'config.toml')],
    ['gemini', json('gemini'), at(h, '.gemini', 'oauth_creds.json')],
    ['gemini', expanding('gemini'), at(h, '.gemini', 'settings.json')],
    ['dotenv', dotenvParser(places.policy), at(h, '.gemini', '.env')],
    ['opencode', json('opencode', { keys: ['access', 'refresh'] }), at(data, 'opencode', 'auth.json')],
    ['opencode', expanding('opencode'), at(config, 'opencode', 'opencode.json'), at(config, 'opencode', 'opencode.jsonc')],
    ['copilot', json('copilot'), at(config, 'github-copilot', 'hosts.json'), at(config, 'github-copilot', 'apps.json'), at(localAppData, 'github-copilot', 'hosts.json'), at(localAppData, 'github-copilot', 'apps.json')],
    ['aider', keyed('aider'), at(h, '.aider.conf.yml')],
    ['continue', expanding('continue'), at(h, '.continue', 'config.json')],
    ['continue', expanding('continue', 'keyed'), at(h, '.continue', 'config.yaml')],
    ['llm', json('llm', { all: true }), env('LLM_USER_PATH') ? at(env('LLM_USER_PATH'), 'keys.json') : (at(support, 'io.datasette.llm', 'keys.json') ?? at(appData, 'io.datasette.llm', 'keys.json') ?? at(config, 'io.datasette.llm', 'keys.json'))],
    ['goose', keyed('goose', { all: true }), at(config, 'goose', 'secrets.yaml'), at(appData, 'Block', 'goose', 'config', 'secrets.yaml')],
    ['gcloud', json('gcloud'), at(gcloud, 'application_default_credentials.json'), env('GOOGLE_APPLICATION_CREDENTIALS'), at(config, 'configstore', 'firebase-tools.json')],
    ['gcloud', parseSqliteTokens, at(gcloud, 'credentials.db'), at(gcloud, 'access_tokens.db')],
    ['boto', keyed('boto'), env('BOTO_CONFIG') ?? at(h, '.boto')],
    ['azure', json('azure'), ...['msal_token_cache.json', 'service_principal_entries.json', 'accessTokens.json'].map(name => at(env('AZURE_CONFIG_DIR') ?? at(h, '.azure'), name))],
    ['hcloud', toml('hcloud'), env('HCLOUD_CONFIG') ?? at(config, 'hcloud', 'cli.toml'), at(support, 'hcloud', 'cli.toml'), at(appData, 'hcloud', 'cli.toml')],
    ['linode', keyed('linode'), at(config, 'linode-cli'), at(h, '.linode-cli')],
    ['scw', keyed('scw', { ignore: ['access_key'] }), env('SCW_CONFIG_PATH') ?? at(h, '.config', 'scw', 'config.yaml'), at(config, 'scw', 'config.yaml')],
    ['vercel', json('vercel'), at(support, 'com.vercel.cli', 'auth.json'), at(data, 'com.vercel.cli', 'auth.json'), at(appData, 'xdg.data', 'com.vercel.cli', 'auth.json'), at(h, '.vercel', 'auth.json'), at(h, '.now', 'auth.json')],
    ['netlify', json('netlify'), at(preferences, 'netlify', 'config.json'), at(config, 'netlify', 'config.json'), at(appData, 'netlify', 'Config', 'config.json'), at(h, '.netlify', 'config.json')],
    ['wrangler', toml('wrangler'), at(preferences, '.wrangler', 'config', 'default.toml'), at(config, '.wrangler', 'config', 'default.toml'), at(appData, 'xdg.config', '.wrangler', 'config', 'default.toml'), at(h, '.wrangler', 'config', 'default.toml')],
    ['railway', json('railway'), at(h, '.railway', 'config.json')],
    ['terraform', keyed('terraform'), env('TF_CLI_CONFIG_FILE') ?? (windows ? at(appData, 'terraform.rc') : at(h, '.terraformrc'))],
    ['terraform', json('terraform'), windows ? at(appData, 'terraform.d', 'credentials.tfrc.json') : at(h, '.terraform.d', 'credentials.tfrc.json')],
    ['kaggle', json('kaggle'), at(env('KAGGLE_CONFIG_DIR') ?? at(h, '.kaggle'), 'kaggle.json'), at(config, 'kaggle', 'kaggle.json')],
    ['pulumi', json('pulumi'), at(env('PULUMI_HOME') ?? at(h, '.pulumi'), 'credentials.json')],
    ['doctl', keyed('doctl'), at(config, 'doctl', 'config.yaml'), at(support, 'doctl', 'config.yaml'), at(appData, 'doctl', 'config.yaml')],
    ['fly', keyed('fly'), at(h, '.fly', 'config.yml')],
    ['ngrok', keyed('ngrok'), at(config, 'ngrok', 'ngrok.yml'), at(support, 'ngrok', 'ngrok.yml'), at(localAppData, 'ngrok', 'ngrok.yml'), at(h, '.ngrok2', 'ngrok.yml')],
    ['okta', keyed('okta'), at(h, '.okta', 'okta.yaml')],
    ['sentry', keyed('sentry'), at(h, '.sentryclirc')],
    ['databricks', keyed('databricks'), env('DATABRICKS_CONFIG_FILE') ?? at(h, '.databrickscfg')],
    ['snowflake', toml('snowflake'), at(env('SNOWFLAKE_HOME') ?? at(h, '.snowflake'), 'connections.toml'), at(env('SNOWFLAKE_HOME') ?? at(h, '.snowflake'), 'config.toml')],
    ['dbt', expanding('dbt', 'keyed'), at(env('DBT_PROFILES_DIR') ?? at(h, '.dbt'), 'profiles.yml')],
    ['stripe', toml('stripe'), at(config, 'stripe', 'config.toml')],
    ['atlas', toml('atlas'), at(config, 'atlascli', 'config.toml'), at(support, 'atlascli', 'config.toml')],
    ['twilio', json('twilio'), at(h, '.twilio-cli', 'config.json')],
    ['expo', json('expo'), at(h, '.expo', 'state.json')],
    ['cargo', toml('cargo'), at(env('CARGO_HOME') ?? at(h, '.cargo'), 'credentials.toml'), at(env('CARGO_HOME') ?? at(h, '.cargo'), 'credentials')],
    ['gem', keyed('gem', { all: true }), at(h, '.gem', 'credentials'), at(data, 'gem', 'credentials')],
    ['composer', json('composer', { all: true, skip: ['username'] }), at(env('COMPOSER_HOME'), 'auth.json'), at(h, '.composer', 'auth.json'), at(config, 'composer', 'auth.json'), at(appData, 'Composer', 'auth.json')],
    ['maven', parseXmlCredentials, at(h, '.m2', 'settings.xml'), at(h, '.m2', 'settings-security.xml')],
    ['nuget', parseXmlCredentials, at(h, '.nuget', 'NuGet', 'NuGet.Config'), at(appData, 'NuGet', 'NuGet.Config')],
    ['gradle', keyed('gradle'), at(env('GRADLE_USER_HOME') ?? at(h, '.gradle'), 'gradle.properties')],
    ['poetry', toml('poetry'), ...['auth.toml', 'config.toml'].map(name => at(env('POETRY_CONFIG_DIR') ?? (mac ? at(support, 'pypoetry') : windows ? at(appData, 'pypoetry') : at(config, 'pypoetry')), name))],
    ['pypirc', keyed('pypirc'), at(h, '.pypirc')],
    ['pip', keyed('pip'), at(config, 'pip', 'pip.conf'), at(h, '.pip', 'pip.conf'), at(support, 'pip', 'pip.conf'), at(appData, 'pip', 'pip.ini')],
    ['helm', keyed('helm'), env('HELM_REPOSITORY_CONFIG') ?? (mac ? at(preferences, 'helm', 'repositories.yaml') : windows ? at(appData, 'helm', 'repositories.yaml') : at(config, 'helm', 'repositories.yaml'))],
    ['rclone', keyed('rclone'), at(config, 'rclone', 'rclone.conf'), at(appData, 'rclone', 'rclone.conf'), at(h, '.rclone.conf')],
    ['oci', keyed('oci'), at(h, '.oci', 'config')],
    ['smb', keyed('smb'), at(h, '.smbcredentials')],
    ['raw', rawSecret('supabase/access-token'), at(h, '.supabase', 'access-token')],
    ['raw', rawSecret('vault-token'), at(h, '.vault-token')],
    ['raw', rawSecret('kaggle/access_token'), at(h, '.kaggle', 'access_token')],
    ['raw', rawSecret('huggingface/token'), env('HF_TOKEN_PATH') ?? at(env('HF_HOME') ?? at(cache, 'huggingface'), 'token'), at(h, '.huggingface', 'token')],
    ['huggingface', keyed('huggingface'), at(env('HF_HOME') ?? at(cache, 'huggingface'), 'stored_tokens')],
    ['key', (text, source) => keyFileSecrets(text, 'cloudflared/cert.pem', source), at(h, '.cloudflared', 'cert.pem')],
    ['key', (text, source) => keyFileSecrets(text, 'minikube/ca.key', source), at(env('MINIKUBE_HOME') ?? at(h, '.minikube'), 'ca.key')],
    ['jwk', (text, source) => keyFileSecrets(text, 'actions-runner', source), at(h, 'actions-runner', '.credentials_rsaparams')],
    ['dotenv', dotenvParser(places.policy), at(h, '.env')],
    ['pi', json('pi', { keys: ['access', 'refresh'] }), at(env('PI_CODING_AGENT_DIR') ?? at(h, '.pi', 'agent'), 'auth.json')],
    ['s3cfg', keyed('s3cfg', { ignore: ['access_key'], strong: ['secret_key'] }), env('S3CMD_CONFIG') ?? at(h, '.s3cfg')],
    ['minio', json('minio', { ignore: ['accessKey'], strong: ['secretKey'] }), at(env('MC_CONFIG_DIR') ?? at(h, windows ? 'mc' : '.mc'), 'config.json')],
    ['openstack', keyed('openstack'), env('OS_CLIENT_CONFIG_FILE'), at(config, 'openstack', 'clouds.yaml'), at(config, 'openstack', 'secure.yaml')],
    ['bundler', parseBundlerConfig, env('BUNDLE_USER_CONFIG') ?? at(h, '.bundle', 'config')],
    ['shell', fish, at(config, 'fish', 'fish_variables')],
    ['history', history, env('HISTFILE'), at(h, '.bash_history'), at(zdot, '.zsh_history'), at(zdot, '.zhistory'), at(data, 'fish', 'fish_history'), at(appData, 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt'), at(data, 'powershell', 'PSReadLine', 'ConsoleHost_history.txt'), at(h, '.psql_history'), at(h, '.mysql_history'), at(h, '.mongodb', 'mongosh', 'mongosh_repl_history'), at(h, '.dbshell'), at(h, '.rediscli_history')],
  ]
  const shellFiles = [
    ...['.bashrc', '.bash_profile', '.bash_login', '.profile', '.bashrc.local'].map(name => at(h, name)),
    ...['.zshrc', '.zshenv', '.zprofile', '.zlogin', '.zshrc.local'].map(name => at(zdot, name)),
    at(config, 'fish', 'config.fish'),
    at(config, 'powershell', 'Microsoft.PowerShell_profile.ps1'),
    at(config, 'powershell', 'profile.ps1'),
    ...(windows ? ['Documents', at('OneDrive', 'Documents')].flatMap(docs => ['PowerShell', 'WindowsPowerShell'].map(dir => at(h, docs, dir, 'Microsoft.PowerShell_profile.ps1'))) : []),
  ]

  const dirs: DirSource[] = []
  const dir = (path: string | undefined, kind: string, depth: number, match: (name: string) => boolean, parse: (relative: string) => Parser, enter?: (name: string) => boolean, follow?: Follow) => {
    if (path) dirs.push({ dir: path, kind, depth, match, parse, ...(enter ? { enter } : {}), ...(follow ? { follow } : {}) })
  }
  dir(at(h, '.ssh'), 'ssh', 2, name => !SSH_SKIP.test(name), keysIn('ssh'))
  dir(at(gnupg, 'private-keys-v1.d'), 'gpg', 0, name => name.endsWith('.key'), keysIn('gpg'))
  for (const cacheDir of ['sso', 'cli', 'login']) dir(at(h, '.aws', cacheDir, 'cache'), 'aws', 0, name => name.endsWith('.json'), () => json('aws'))
  dir(at(gcloud, 'legacy_credentials'), 'gcloud', 1, name => name === 'adc.json' || name === '.boto', relative => (basename(relative) === '.boto' ? keyed('boto') : json('gcloud')))
  dir(at(h, '.subversion', 'auth', 'svn.simple'), 'svn', 0, always, () => parseSvnAuth)
  dir(at(appData, 'Subversion', 'auth', 'svn.simple'), 'svn', 0, always, () => parseSvnAuth)
  dir(at(config, 'fish', 'conf.d'), 'shell', 0, name => name.endsWith('.fish'), () => rc)
  dir(at(h, '.bashrc.d'), 'shell', 0, always, () => rc, undefined, follow)
  dir(absolute(env('ZSH_CUSTOM')) ?? at(h, '.oh-my-zsh', 'custom'), 'shell', 0, name => name.endsWith('.zsh'), () => rc, undefined, follow)
  dir(at(config, 'environment.d'), 'shell', 0, name => name.endsWith('.conf'), () => rc)
  dir(h, 'raw', 0, name => /^\.vault[_-]?pass/.test(name), relative => rawSecret(`ansible/${relative}`))
  dir(at(h, '.cloudflared'), 'cloudflared', 0, name => name.endsWith('.json'), () => json('cloudflared'))
  dir(at(env('MINIKUBE_HOME') ?? at(h, '.minikube'), 'profiles'), 'key', 1, name => name.endsWith('.key'), keysIn('minikube'))
  dir(at(h, '.oci'), 'key', 0, name => name.endsWith('.pem'), keysIn('oci'))
  if (!windows && !mac) dir(at(config, 'systemd', 'user'), 'systemd', 1, UNIT, () => systemdParser(places.policy), DROP_IN, systemdFollow(places.policy))

  return { files: [...expand(files), ...shellFiles.flatMap(path => (path ? [{ path, kind: 'shell', parse: rc, follow }] : []))], dirs }
}

function expand(rows: readonly [string, Parser, ...Part[]][]): FileSource[] {
  const out: FileSource[] = []
  for (const [kind, parse, ...paths] of rows) for (const path of paths) if (path) out.push({ path, kind, parse })
  return out
}

export function systemCatalog(places: Places): Catalog {
  if (places.platform === 'win32') return { files: [], dirs: [] }
  const rc = shellParser(places.policy)
  const files = expand([
    ['shell', rc, '/etc/environment'],
    ['kube', parseKubeConfig, '/etc/rancher/k3s/k3s.yaml', '/etc/rancher/rke2/rke2.yaml', '/etc/kubernetes/admin.conf', '/etc/kubernetes/super-admin.conf'],
    ['raw', rawSecret('rke2/token'), '/var/lib/rancher/rke2/server/token'],
    ['openstack', keyed('openstack'), '/etc/openstack/clouds.yaml'],
    ['raw', rawSecret('k3s/token'), '/var/lib/rancher/k3s/server/token'],
    ['raw', rawSecret('k3s/node-token'), '/var/lib/rancher/k3s/server/node-token'],
    ['raw', rawSecret('jenkins/initialAdminPassword'), '/var/lib/jenkins/secrets/initialAdminPassword'],
    ['openvpn', parseOpenvpnAuth, '/etc/openvpn/auth.txt', '/etc/openvpn/client/auth.txt'],
    ['wifi', keyed('wifi'), '/etc/wpa_supplicant/wpa_supplicant.conf'],
    ['fstab', fstabSecrets, '/etc/fstab'],
    ['jwk', (text, source) => keyFileSecrets(text, 'actions-runner', source), '/opt/actions-runner/.credentials_rsaparams', '/actions-runner/.credentials_rsaparams'],
  ])
  const dirs: DirSource[] = [
    { dir: '/run/secrets', kind: 'raw', depth: 2, match: name => !RAW_SKIP.test(name), parse: raw },
    { dir: '/var/run/secrets', kind: 'raw', depth: 3, match: name => !RAW_SKIP.test(name), parse: raw },
    ...['/vault/secrets', '/mnt/secrets-store', '/etc/secrets', '/secrets'].map(dir => ({ dir, kind: 'raw', depth: 2, match: (name: string) => !RAW_SKIP.test(name), parse: raw })),
    { dir: '/etc/pki/tls/private', kind: 'key', depth: 0, match: name => /\.(?:key|pem)$/.test(name), parse: keysIn('pki') },
    { dir: '/etc/wireguard', kind: 'wireguard', depth: 0, match: name => name.endsWith('.conf'), parse: () => keyed('wireguard') },
    { dir: '/etc/ssl/private', kind: 'key', depth: 0, match: name => /\.(?:key|pem)$/.test(name), parse: keysIn('ssl') },
    { dir: '/etc/letsencrypt/live', kind: 'key', depth: 1, match: name => name === 'privkey.pem', parse: keysIn('letsencrypt') },
    { dir: '/etc/letsencrypt/accounts', kind: 'jwk', depth: 4, match: name => name === 'private_key.json', parse: keysIn('letsencrypt') },
    { dir: '/etc/ssh', kind: 'key', depth: 0, match: name => /^ssh_host_.*_key$/.test(name), parse: keysIn('ssh-host') },
    { dir: '/etc/kubernetes/pki', kind: 'key', depth: 1, match: name => name.endsWith('.key'), parse: keysIn('kubernetes') },
    { dir: '/etc/NetworkManager/system-connections', kind: 'wifi', depth: 0, match: name => name.endsWith('.nmconnection'), parse: () => keyed('wifi') },
    { dir: '/etc/systemd/system', kind: 'systemd', depth: 1, match: UNIT, parse: () => systemdParser(places.policy), enter: DROP_IN, follow: systemdFollow(places.policy) },
  ]
  return { files, dirs }
}

const TFVARS = /(?:^|\.)tfvars$/
const COMPOSE = /^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/
const APPLICATION = /^application(?:-[\w.-]+)?\.(?:ya?ml|properties)$/
const APPSETTINGS = /^appsettings(?:\.[\w-]+)?\.json$/
const MISE = /^\.?mise(?:\.[\w-]+)?\.toml$/

export function systemRawDirs(mounts: readonly string[]): DirSource[] {
  return mounts.map(dir => ({ dir, kind: 'raw', depth: 2, match: (name: string) => !RAW_SKIP.test(name), parse: raw }))
}

export function projectParser(name: string, parent: string, policy: EnvPolicy): { readonly kind: string; readonly parse: Parser } | undefined {
  const lower = name.toLowerCase()
  if (lower === '.npmrc') return { kind: 'npmrc', parse: parseNpmrc }
  if (lower === '.yarnrc.yml') return { kind: 'yarnrc', parse: parseYarnrc }
  if (lower === 'bunfig.toml') return { kind: 'bunfig', parse: toml('bunfig') }
  if (lower === 'nuget.config') return { kind: 'nuget', parse: parseXmlCredentials }
  if (lower === 'gradle.properties') return { kind: 'gradle', parse: keyed('gradle') }
  if (lower === '.mcp.json') return { kind: 'mcp', parse: expanding('mcp') }
  if (lower === 'local.settings.json') return { kind: 'azure-functions', parse: envMapParser('azure-functions', path => (path[0] === 'Values' && path.length === 2 ? path[1] : undefined), 'json', policy) }
  if (MISE.test(lower)) return { kind: 'mise', parse: envMapParser('mise', path => (path[0] === 'env' && (path.length === 2 || (path.length === 3 && path[2] === 'value')) ? path[1] : undefined), 'toml', policy) }
  if (TFVARS.test(lower)) return { kind: 'tfvars', parse: envMapParser('tfvars', path => (path.length === 1 ? path[0] : undefined), 'keyed', policy) }
  if (lower === 'secrets.toml' && parent === '.streamlit') return { kind: 'streamlit', parse: toml('streamlit', { all: true }) }
  if (lower === 'master.key' && parent === 'config') return { kind: 'raw', parse: rawSecret('rails/master.key') }
  if (lower.endsWith('.key') && parent === 'credentials') return { kind: 'raw', parse: rawSecret(`rails/${name}`) }
  if (COMPOSE.test(lower) || APPLICATION.test(lower) || lower === 'database.yml' || /^serverless\.ya?ml$/.test(lower)) return { kind: 'config', parse: configParser('config', 'yaml') }
  if (APPSETTINGS.test(lower)) return { kind: 'config', parse: configParser('config', 'json') }
  if (lower === 'wp-config.php' || lower === 'settings.py') return { kind: 'config', parse: configParser('config', 'code') }
  return undefined
}

export function projectRootFiles(root: string, policy: EnvPolicy): FileSource[] {
  return expand([
    ['gitconfig', parseGitConfig, at(root, '.git', 'config')],
    ['claude', expanding('claude-settings'), at(root, '.claude', 'settings.json'), at(root, '.claude', 'settings.local.json')],
    ['mcp', expanding('mcp'), at(root, '.cursor', 'mcp.json'), at(root, '.vscode', 'mcp.json'), at(root, '.gemini', 'settings.json')],
    ['dotenv', dotenvParser(policy), at(root, '.gemini', '.env')],
    ['opencode', expanding('opencode'), at(root, 'opencode.json'), at(root, 'opencode.jsonc')],
    ['bundler', parseBundlerConfig, at(root, '.bundle', 'config')],
    ['openstack', keyed('openstack'), at(root, 'clouds.yaml')],
  ])
}

export const composerAuth = json('composer', { all: true, skip: ['username'] })

