import { base64Decode } from '../core/encoding.ts'
import { isAbsolutePath } from '../core/paths.ts'
import type { Secret } from '../core/types.ts'
import { parseDotenv, type EnvEntry } from './dotenv.ts'
import { MIN_VALUE, OPEN_POLICY, envSecrets, isReference, isTrivialValue, keyStrength, looksRandom, type EnvPolicy, type ReferenceMode } from './env-policy.ts'
import { privateKeyBlocks } from './keys.ts'
import { flagSecrets, headerSecrets, jsonLeaves, keyedLeaves, parseJson, pickSecrets, tomlLeaves, treeLeaves, usable, type Leaf, type PickOptions } from './tree.ts'
import { decodeUri } from './util.ts'

export type Parser = (text: string, source: string) => Secret[]

function credential(name: string, value: string, source: string, mode: ReferenceMode = 'literal'): Secret[] {
  return usable(value, mode) && !isTrivialValue(value, 'strong') ? [{ name, value, source, strong: true }] : []
}

const TOKEN_PREFIX = /^(?:gh[pousr]_|github_pat_|glpat-|gldt-|glptt-|ATBB|xox[abpr]-|npm_|hf_|pypi-)/

export function looksLikeToken(value: string): boolean {
  return TOKEN_PREFIX.test(value) || looksRandom(value)
}

export const parseAwsCredentials: Parser = (text, source) => {
  const secrets: Secret[] = []
  let profile = 'default'
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    const section = line.match(/^\[\s*(?:profile\s+|sso-session\s+)?([^\]]+?)\s*\]$/)
    if (section?.[1]) {
      profile = section[1]
      continue
    }
    const pair = line.match(/^(aws_secret_access_key|aws_session_token|aws_security_token)\s*[=:]\s*(\S+)/i)
    if (pair?.[1] && pair[2]) secrets.push(...credential(`aws/${profile}/${pair[1].toLowerCase()}`, pair[2], source))
  }
  return secrets
}

export const parseNetrc: Parser = (text, source) => {
  const secrets: Secret[] = []
  const tokens = text.replace(/^\s*#.*$/gm, '').split(/\s+/).filter(Boolean)
  let machine = 'default'
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    const next = tokens[i + 1]
    if (token === 'machine' && next) machine = next
    if (token === 'password' && next) secrets.push(...credential(`netrc/${machine}`, next, source))
    if (token === 'account' && next && usable(next, 'literal') && !isTrivialValue(next, 'weak')) secrets.push({ name: `netrc/${machine}/account`, value: next, source })
  }
  return secrets
}

export const parsePgpass: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue
    const fields: string[] = ['']
    for (let i = 0; i < line.length; i++) {
      const char = line[i] ?? ''
      if (char === '\\' && i + 1 < line.length) fields[fields.length - 1] += line[++i] ?? ''
      else if (char === ':') fields.push('')
      else fields[fields.length - 1] += char
    }
    const [host, , , user, password] = fields
    if (password) secrets.push(...credential(`pgpass/${host ?? '*'}/${user ?? '*'}`, password, source))
  }
  return secrets
}

export const parseGitCredentials: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^:/@\s]*:)?([^:@\s]+)@([^/\s]+)/i)
    if (match?.[1] && match[2]) secrets.push(...credential(`git-credentials/${match[2]}`, decodeUri(match[1]), source))
  }
  return secrets
}

export const parseGitConfig: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    for (const match of line.matchAll(/[a-z][a-z0-9+.-]*:\/\/([^\s/@"']+)@([^\s/"']+)/gi)) {
      const [user, password] = [(match[1] ?? '').split(':')[0] ?? '', (match[1] ?? '').split(':').slice(1).join(':')]
      if (password) secrets.push(...credential(`gitconfig/${match[2]}`, decodeUri(password), source))
      else if (looksLikeToken(decodeUri(user))) secrets.push(...credential(`gitconfig/${match[2]}`, decodeUri(user), source))
    }
    const header = line.match(/^\s*extraheader\s*=\s*"?([^:"]+):\s*([^"]+?)"?\s*$/i)
    if (header?.[1] && header[2]) secrets.push(...headerSecrets(header[1].trim(), header[2], source, `gitconfig/${header[1].trim().toLowerCase()}`))
  }
  return secrets
}

export const parseNpmrc: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^([^=#;]*(?:_authToken|_auth|_password))\s*=\s*(.+)$/)
    if (!match?.[1] || !match[2]) continue
    const key = match[1].trim()
    const value = match[2].trim().replace(/^"(.*)"$/, '$1')
    if (/\$\{.+\}/.test(value)) continue
    secrets.push(...credential(`npmrc/${key}`, value, source))
    const decoded = key.endsWith('_password') ? base64Decode(value) : key.endsWith('_auth') ? base64Decode(value)?.split(':').slice(1).join(':') : undefined
    if (decoded) secrets.push(...credential(`npmrc/${key}.decoded`, decoded, source))
  }
  return secrets
}

export const parseDockerConfig: Parser = (text, source) => {
  const secrets: Secret[] = []
  const auths = (parseJson(text) as { auths?: Record<string, Record<string, unknown>> } | undefined)?.auths ?? {}
  for (const [registry, entry] of Object.entries(auths)) {
    for (const field of ['auth', 'identitytoken', 'registrytoken', 'password'] as const) {
      const value = entry?.[field]
      if (typeof value !== 'string' || !value) continue
      secrets.push(...credential(`docker/${registry}/${field}`, value, source))
      if (field === 'auth') {
        const password = base64Decode(value)?.split(':').slice(1).join(':')
        if (password) secrets.push(...credential(`docker/${registry}/password`, password, source))
      }
    }
  }
  return secrets
}

export const parseGhHosts: Parser = (text, source) => {
  const secrets: Secret[] = []
  let host = 'github.com'
  for (const line of text.split(/\r?\n/)) {
    const top = line.match(/^([^\s#][^:]*):\s*$/)
    if (top?.[1]) host = top[1].trim()
    const token = line.match(/^\s+(?:oauth_token|token):\s*["']?([^\s"']+)/)
    if (token?.[1]) secrets.push(...credential(`gh/${host}`, token[1], source))
  }
  return secrets
}

const KUBE_FIELD = /^\s*-?\s*(token|client-key-data|password|refresh-token|id-token|access-token|client-secret|idp-refresh-token):\s*["']?([^\s"']+)/
const KUBE_KEYS = ['client-key-data', 'access-token', 'idp-refresh-token', 'refresh-token', 'id-token', 'client-secret']

export const parseKubeConfig: Parser = (text, source) => {
  if (/^\s*\{/.test(text)) return pickSecrets(jsonLeaves(text), source, 'kube', { keys: KUBE_KEYS })
  const secrets: Secret[] = []
  const lines = text.split(/\r?\n/)
  let user = 'kube'
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ''
    const name = line.match(/^\s*-?\s*name:\s*["']?([^\s"']+)/)
    const pair = name ? lines[i + 1]?.match(/^\s*value:\s*(?:"([^"]*)"|'([^']*)'|(\S.*?))\s*$/) : undefined
    if (name?.[1] && pair) {
      const entry: EnvEntry = { key: name[1], value: pair[1] ?? pair[2] ?? pair[3] ?? '', literal: true }
      secrets.push(...envSecrets([entry], source, OPEN_POLICY).map(secret => ({ ...secret, name: `kube/${user}/env/${secret.name}` })))
      i++
      continue
    }
    if (name?.[1]) user = name[1]
    const field = line.match(KUBE_FIELD)
    if (field?.[1] && field[2]) secrets.push(...credential(`kube/${user}/${field[1]}`, field[2], source))
  }
  return secrets
}

function argSecrets(tree: unknown, source: string, prefix: string): Secret[] {
  const out: Secret[] = []
  const visit = (node: unknown, path: readonly string[]): void => {
    if (Array.isArray(node)) {
      if (path[path.length - 1] === 'args') out.push(...flagSecrets(node.filter((item): item is string => typeof item === 'string'), source, `${prefix}/${path.slice(0, -1).join('.')}`))
      node.forEach((item, index) => visit(item, [...path, String(index)]))
    } else if (node !== null && typeof node === 'object') for (const [key, value] of Object.entries(node)) visit(value, [...path, key])
  }
  visit(tree, [])
  return out
}

export function treeParser(prefix: string, options: PickOptions = {}, format: 'json' | 'toml' | 'keyed' | 'auto' = 'json'): Parser {
  return (text, source) => {
    const json = format === 'json' || (format === 'auto' && /^\s*[{[]/.test(text))
    const tree = json ? parseJson(text) : undefined
    const leaves: Leaf[] = json ? (tree === undefined ? [] : treeLeaves(tree)) : format === 'keyed' ? keyedLeaves(text) : tomlLeaves(text)
    return [...pickSecrets(leaves, source, prefix, options), ...(tree === undefined ? [] : argSecrets(tree, source, prefix))]
  }
}

export const parseClaudeJson: Parser = (text, source) => {
  const tree = parseJson(text) as { primaryApiKey?: unknown; mcpServers?: unknown; projects?: Record<string, { mcpServers?: unknown }> } | undefined
  if (!tree || typeof tree !== 'object') return []
  const out: Secret[] = typeof tree.primaryApiKey === 'string' ? credential('claude/primaryApiKey', tree.primaryApiKey, source) : []
  const servers: unknown[] = [tree.mcpServers, ...Object.values(tree.projects ?? {}).map(entry => entry?.mcpServers)]
  for (const node of servers) {
    if (node === undefined) continue
    out.push(...pickSecrets(treeLeaves(node, ['mcpServers']), source, 'claude'), ...argSecrets(node, source, 'claude/mcpServers'))
  }
  return out
}

export const parseYarnrc: Parser = (text, source) => {
  const leaves = keyedLeaves(text)
  const out = pickSecrets(leaves, source, 'yarnrc', { keys: ['npmAuthIdent', 'npmPassword'] })
  for (const leaf of leaves) {
    if (leaf.path[leaf.path.length - 1] !== 'npmAuthIdent') continue
    const password = leaf.value.split(':').slice(1).join(':')
    out.push(...credential(`yarnrc/${leaf.path.join('.')}.password`, password, source))
  }
  return out
}

const XML_ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }

function xmlText(value: string): string {
  return value.replace(/&(amp|lt|gt|quot|apos);/g, (_, name: string) => XML_ENTITIES[name] ?? '')
}

export const parseXmlCredentials: Parser = (text, source) => {
  const secrets: Secret[] = []
  let context = 'settings'
  const pattern = /<(id|password|passphrase|master)>\s*([^<]*?)\s*<\/\1>|<add\s+key\s*=\s*"([^"]*)"\s+value\s*=\s*"([^"]*)"|<([A-Za-z][\w.-]*)>/gi
  for (const match of text.matchAll(pattern)) {
    if (match[5]) {
      if (/^apikeys$/i.test(match[5])) context = 'apikeys'
      else if (!/^(?:settings|servers|server|proxies|proxy|configuration|packageSourceCredentials|username)$/i.test(match[5])) context = match[5]
      continue
    }
    if (match[1]?.toLowerCase() === 'id') {
      context = xmlText(match[2] ?? '') || context
      continue
    }
    if (match[1]) {
      secrets.push(...credential(`xml/${context}/${match[1].toLowerCase()}`, xmlText(match[2] ?? ''), source, 'config'))
      continue
    }
    const key = xmlText(match[3] ?? '')
    const value = xmlText(match[4] ?? '')
    if (keyStrength(key) === 'strong' || (context === 'apikeys' && /:\/\//.test(key))) secrets.push(...credential(`xml/${context}/${key}`, value, source, 'config'))
  }
  return secrets
}

export const parseSvnAuth: Parser = (text, source) => {
  const lines = text.split(/\r?\n/)
  const secrets: Secret[] = []
  let realm = 'svn'
  for (let i = 0; i + 3 < lines.length; i++) {
    if (!/^K \d+$/.test(lines[i] ?? '') || !/^V \d+$/.test(lines[i + 2] ?? '')) continue
    const key = lines[i + 1] ?? ''
    const value = lines[i + 3] ?? ''
    if (key === 'svn:realmstring') realm = value
    if (key === 'password') secrets.push(...credential(`svn/${realm}`, value, source))
    i += 3
  }
  return secrets
}

const SQLITE_JSON = /"(refresh_token|client_secret|private_key|access_token|token)"\s*:\s*"((?:[^"\\]|\\.)*)"/g
const GOOGLE_TOKEN = /(?:ya29\.|1\/\/0)(?:(?!\d{4}-\d{2}-\d{2}[ T]\d{2}:)[\w.-]){20,}/g

export const parseSqliteTokens: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const match of text.matchAll(SQLITE_JSON)) {
    let value = match[2] ?? ''
    try {
      value = JSON.parse(`"${value}"`) as string
    } catch {}
    secrets.push(...credential(`sqlite/${match[1]}`, value, source))
  }
  for (const match of text.matchAll(GOOGLE_TOKEN)) secrets.push(...credential('sqlite/token', match[0], source))
  return secrets.filter((secret, index) => secrets.findIndex(other => other.value === secret.value) === index)
}

export function rawSecret(name: string): Parser {
  return (text, source) => {
    const value = text.trim()
    if (value.length < MIN_VALUE || value.length > 65536) return []
    if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY/.test(value)) return privateKeyBlocks(value, name, source)
    if (/^-----BEGIN /.test(value)) return []
    if (/^\s*\{/.test(value)) {
      const tree = parseJson(value)
      const docker = tree === undefined ? [] : parseDockerConfig(value, source)
      if (tree !== undefined) return docker.length > 0 ? docker : pickSecrets(treeLeaves(tree), source, name)
    }
    if (/\n/.test(value) || /^(?:export\s+)?[A-Z_][A-Z0-9_]*=\S/.test(value)) {
      const entries = parseDotenv(value)
      return entries.length > 0 ? envSecrets(entries, source, OPEN_POLICY) : pickSecrets(keyedLeaves(value), source, name)
    }
    return credential(name, value, source)
  }
}

export const parseBundlerConfig: Parser = (text, source) => {
  const out: Secret[] = []
  for (const leaf of keyedLeaves(text)) {
    const key = leaf.path[leaf.path.length - 1] ?? ''
    if (!/^BUNDLE_(?!MIRROR__|BUILD__|LOCAL__).+__/.test(key) || (/:\/\//.test(leaf.value) && !/@/.test(leaf.value))) continue
    if (/^-/.test(leaf.value) || /^(?:\.{1,2}[\\/]|[\w.-]+[\\/])/.test(leaf.value) || isAbsolutePath(leaf.value)) continue
    out.push(...credential(`bundler/${key}`, leaf.value, source))
    const password = leaf.value.split(':').slice(1).join(':')
    if (password) out.push(...credential(`bundler/${key}.password`, password, source))
  }
  return out
}

export const parseOpenvpnAuth: Parser = (text, source) => {
  const password = text.split(/\r?\n/)[1]?.trim() ?? ''
  return credential('openvpn/password', password, source)
}

export function envMapParser(prefix: string, section: (path: readonly string[]) => string | undefined, format: 'json' | 'toml' | 'keyed', policy: EnvPolicy): Parser {
  return (text, source) => {
    const leaves = format === 'json' ? jsonLeaves(text) : format === 'toml' ? tomlLeaves(text) : keyedLeaves(text)
    const entries: EnvEntry[] = []
    for (const leaf of leaves) {
      const key = section(leaf.path)
      if (key !== undefined) entries.push(isReference(leaf.value, 'config') ? { key, value: leaf.value, reference: true } : { key, value: leaf.value, literal: true })
    }
    const extra = format === 'json' ? pickSecrets(leaves.filter(leaf => section(leaf.path) === undefined), source, prefix, { config: true }) : []
    return [...envSecrets(entries, source, policy), ...extra]
  }
}

const QUOTED_ASSIGNMENT = /([A-Za-z_][\w.-]*)['"]?\s*(?:=>|[:=])\s*(['"])((?:\\.|(?!\2).)*)\2/g
const DEFINE = /define\(\s*['"]([A-Za-z_]\w*)['"]\s*,\s*(['"])((?:\\.|(?!\2).)*)\2/g

function configEntry(key: string, value: string, source: string, name: string): Secret[] {
  if (!usable(value)) return []
  const strength = keyStrength(key)
  if (strength === 'strong' && !isTrivialValue(value, strength)) return [{ name, value, source, strong: true }]
  if (strength === 'weak' && looksRandom(value)) return [{ name, value, source }]
  return []
}

export function configParser(prefix: string, format: 'yaml' | 'json' | 'code'): Parser {
  return (text, source) => {
    if (format === 'json') return pickSecrets(jsonLeaves(text), source, prefix, { config: true })
    if (format === 'code') {
      const out: Secret[] = []
      for (const match of [...text.matchAll(DEFINE), ...text.matchAll(QUOTED_ASSIGNMENT)]) out.push(...configEntry(match[1] ?? '', match[3] ?? '', source, `${prefix}/${match[1]}`))
      return out
    }
    const leaves = keyedLeaves(text)
    const out = pickSecrets(leaves, source, prefix, { config: true })
    for (const leaf of leaves) {
      const assignment = leaf.value.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/)
      if (assignment?.[1] && assignment[2]) out.push(...configEntry(assignment[1], assignment[2].trim(), source, `${prefix}/${assignment[1]}`))
    }
    return out
  }
}
