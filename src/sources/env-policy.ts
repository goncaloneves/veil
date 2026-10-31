import { shannonEntropy } from '../core/encoding.ts'
import type { Secret } from '../core/types.ts'
import type { EnvEntry } from './dotenv.ts'
import { keyWords } from '../core/context.ts'
import { isLowerWords, isTrivialWord } from '../core/known.ts'
import { decodeUri, globRegExp } from './util.ts'

export { keyWords }

export const MIN_VALUE = 4

export type EnvPolicy = {
  readonly secretKeys: readonly string[]
  readonly ignoreKeys: readonly string[]
  readonly random?: boolean
  readonly known?: ReadonlySet<string>
}

export const OPEN_POLICY: EnvPolicy = { secretKeys: [], ignoreKeys: [], random: true }

const STRONG_PARTS = ['PASSWORD', 'PASSWD', 'PASSPHRASE', 'PASSCODE', 'SECRET', 'CREDENTIAL', 'APIKEY', 'PRIVATEKEY', 'PRIVKEY', 'PASSKEY', 'ACCESSKEY', 'AUTHTOKEN']
const STRONG_WORDS = new Set(['PW', 'PWD', 'PASS', 'DSN', 'CREDS', 'PIN', 'OTP', 'TOTP', 'PSK'])
const LAST_WORDS = new Set(['KEY', 'KEYS', 'TOKEN', 'TOKENS', 'AUTH', 'SESSION', 'COOKIE', 'SALT', 'JWT', 'BEARER', 'WEBHOOK'])
const ANY_WORDS = new Set(['KEY', 'KEYS', 'TOKEN', 'TOKENS'])
const REFERENCE_WORDS = new Set(['ENV', 'VAR', 'VARS', 'VARIABLE', 'VARIABLES'])
const STAGES = new Set(['PROD', 'PRODUCTION', 'DEV', 'DEVELOPMENT', 'STAGING', 'STAGE', 'TEST', 'TESTING', 'LOCAL', 'QA', 'UAT', 'PREVIEW', 'CI', 'LIVE', 'SANDBOX', 'V'])
const PLAIN_LAST_WORDS = new Set(['ID', 'IDS', 'HASH', 'SHA', 'DIGEST', 'CHECKSUM', 'SUM', 'COMMIT', 'REVISION', 'REV', 'VERSION', 'UUID', 'GUID', 'ETAG', 'FINGERPRINT', 'INTEGRITY'])
const DESCRIPTOR_WORDS = new Set(['TYPE', 'TYPES', 'KIND', 'MODE', 'FORMAT', 'ALGORITHM', 'ALG', 'PROVIDER', 'METHOD', 'SCHEME', 'STRATEGY', 'POLICY', 'LENGTH', 'SIZE', 'TTL', 'EXPIRY', 'EXPIRES', 'EXPIRATION', 'AT', 'PATH', 'FILE', 'DIR', 'DIRECTORY', 'ENDPOINT', 'URI', 'URL', 'HOST', 'PORT', 'REGION', 'NAME', 'LABEL', 'PREFIX', 'SUFFIX', 'ENABLED', 'DISABLED', 'COUNT', 'LIMIT', 'TIMEOUT', 'STDIN', 'PROMPT', 'SECONDS', 'MINUTES', 'HOURS', 'DAYS', 'MS', 'HEADER', 'HEADERS', 'AUDIENCE', 'ISSUER', 'PARAM', 'PARAMS', 'PARAMETER', 'FIELD', 'FIELDS', 'COLUMN', 'COLUMNS', 'SCOPE', 'SCOPES', 'PERMISSION', 'PERMISSIONS', 'CLAIM', 'CLAIMS', 'LOCATION', 'QUERY'])
const SECRET_FINGERPRINT_WORDS = new Set(['PRIVATE', 'SECRET', 'SIGNING'])
const PUBLIC_WORDS = new Set(['PUBLIC', 'PUBLISHABLE', 'ANON', 'PUBKEY', 'SITEKEY'])
const FINGERPRINT_WORDS = new Set(['GPG', 'PGP'])
const PUBLIC_VALUE = /^(?:pk_(?:live|test)_|sb_publishable_|pk\.eyJ|phc_)|\.apps\.googleusercontent\.com$/
const PLACEHOLDER_WORDS = /^(?:change[-_ ]?me|replace[-_ ]?me|todo|fixme|tbd|placeholder|redacted|dummy|n\/a)$/i
const PLACEHOLDER_PHRASE = /^your[-_ ](?:[a-z0-9]+[-_ ])*(?:key|token|secret|password|pass|here)$/i
const URL_START = /^(?:jdbc:)?[a-z][a-z0-9+.-]*:\/\//i

const DEFAULT_SECRET = ['TF_TOKEN_*', 'OP_SESSION_*']
const DEFAULT_IGNORE = ['NEXT_PUBLIC_*', 'VITE_*', 'PUBLIC_*', 'EXPO_PUBLIC_*', 'REACT_APP_PUBLIC_*', 'NUXT_PUBLIC_*', 'NODE_ENV', 'PORT', 'HOST', 'TZ', 'LOG_LEVEL', 'PWD', 'OLDPWD', 'WT_SESSION', 'WT_PROFILE_ID']

export function matchesAny(key: string, globs: readonly string[]): boolean {
  return globs.some(glob => globRegExp(glob, { caseInsensitive: true }).test(key))
}


function stageless(key: string): string[] {
  const words = keyWords(key)
  while (words.length > 1 && STAGES.has(words[words.length - 1] ?? '')) words.pop()
  return words
}

export type KeyStrength = 'strong' | 'weak' | 'none'

function strongWord(word: string): boolean {
  return STRONG_WORDS.has(word) || STRONG_PARTS.some(part => word.includes(part))
}

type KeyClass = { readonly strength: KeyStrength; readonly inner: boolean }

function classify(key: string): KeyClass {
  const none = { strength: 'none' as const, inner: false }
  const words = stageless(key)
  const last = words[words.length - 1]
  if (last === undefined || DESCRIPTOR_WORDS.has(last) || /^env_?key$/i.test(key)) return none
  const secretAt = words.findLastIndex(word => strongWord(word) || LAST_WORDS.has(word))
  if (words.some((word, index) => REFERENCE_WORDS.has(word) && index > secretAt)) return none
  if (strongWord(last) || words.slice(-2).join('') === 'PASSPHRASE') return { strength: 'strong', inner: false }
  if (LAST_WORDS.has(last)) return { strength: 'weak', inner: false }
  if (words.some(strongWord)) return { strength: 'weak', inner: false }
  if (!PLAIN_LAST_WORDS.has(last) && words.some(word => ANY_WORDS.has(word))) return { strength: 'weak', inner: true }
  return none
}

export function keyStrength(key: string): KeyStrength {
  return classify(key).strength
}

export function needsRandomValue(key: string): boolean {
  return classify(key).inner
}

export function isSecretKey(key: string): boolean {
  return keyStrength(key) !== 'none'
}

export function isPublicName(key: string): boolean {
  const words = stageless(key)
  const last = words[words.length - 1] ?? ''
  if (strongWord(last)) return false
  if (last === 'KEY' && words[words.length - 2] === 'SITE') return true
  if ((last === 'KEY' || last === 'KEYS') && words.some(word => FINGERPRINT_WORDS.has(word)) && !words.some(word => SECRET_FINGERPRINT_WORDS.has(word))) return true
  return words.some(word => PUBLIC_WORDS.has(word))
}

export function isPublicValue(value: string): boolean {
  return PUBLIC_VALUE.test(value)
}

function plainLast(key: string): boolean {
  const words = stageless(key)
  return PLAIN_LAST_WORDS.has(words[words.length - 1] ?? '')
}

export function isUrl(value: string): boolean {
  return URL_START.test(value) && !/\s/.test(value)
}

export function urlPassword(value: string): string | undefined {
  const match = value.match(/^(?:jdbc:)?[a-z][a-z0-9+.-]*:\/\/[^\s/:@]*:([^\s/@]+)@/i)
  return match?.[1] ? decodeUri(match[1]) : undefined
}

export function looksRandom(value: string): boolean {
  return value.length >= 24 && !/\s/.test(value) && shannonEntropy(value) >= 4
}

function urlHoldsSecret(value: string): boolean {
  const userinfo = value.match(/^(?:jdbc:)?[a-z][a-z0-9+.-]*:\/\/([^\s/@]+)@/i)?.[1]
  if (userinfo && userinfo.length >= 8) return true
  return value
    .replace(/^(?:jdbc:)?[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '')
    .split(/[/?&=#]+/)
    .some(part => part.length >= 20 && shannonEntropy(part) >= 3.5)
}

const PATH_START = /^(?:~?[\\/]|\.{1,2}[\\/]|[A-Za-z]:[\\/])/
const PLAIN_PATH = /^(?:~|\.{1,2}|[A-Za-z]:)?(?:[\\/][\w .@+-]+)+[\\/]?$/

function isPathValue(value: string, strength: KeyStrength): boolean {
  if (!PATH_START.test(value) || /\n/.test(value) || looksRandom(value)) return false
  if (strength !== 'strong') return true
  return PLAIN_PATH.test(value) && ((value.match(/[\\/]/g)?.length ?? 0) >= 2 || /\.[A-Za-z0-9]{1,6}$/.test(value))
}

export function isPlaceholder(value: string): boolean {
  const trimmed = value.trim()
  if (/^<[\w .:/-]+>$/.test(trimmed) || /^\[[\w .:/-]+\]$/.test(trimmed)) return true
  if (PLACEHOLDER_WORDS.test(trimmed) || PLACEHOLDER_PHRASE.test(trimmed)) return true
  if (/^[xX*•.#?_-]{3,}$/.test(trimmed) || /(?:\.\.\.|…)$/.test(trimmed)) return true
  return /([xX*•])\1{3,}$/.test(trimmed) || /([xX*•])\1{7,}/.test(trimmed)
}

export function isTrivialValue(value: string, strength: KeyStrength = 'weak'): boolean {
  if (isTrivialWord(value)) return true
  if (isPlaceholder(value) || isPathValue(value, strength)) return true
  if (strength === 'strong') return false
  if (/^[-+]?\d+(?:[._]\d+)*$/.test(value)) return true
  if (isUrl(value) && !urlHoldsSecret(value)) return true
  if (/^(?:file|sqlite3?|memory|mem|unix|socket):(?!\/\/[^/]*@)/i.test(value)) return true
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value) && !looksRandom(value)) return true
  if (isLowerWords(value) && !looksRandom(value)) return true
  return false
}

export type ReferenceMode = 'literal' | 'dotenv' | 'config' | 'shell'

const BRACED = /\$\{(?:[A-Za-z_][\w.]*(?::?[-=?+][^}]*)?|(?:env|input|config|secrets?|vars?):[\w.-]+)\}/
const WHOLE_VARIABLE = /^\$[A-Za-z_]\w*$/
const CONFIG_REFERENCE = /\{\{[^{}]*\}\}|<%[\s\S]*?%>|\{(?:env|file):[^{}\s]+\}/
const WHOLE_CONFIG_REFERENCE = /^(?:#\{[\s\S]*\}|!(?:Ref|Sub|GetAtt|ImportValue|Join|Select|FindInMap|Base64|If)\s[\s\S]*|@Microsoft\.KeyVault\([\s\S]*\)|%[A-Za-z_]\w*%|\$env:[A-Za-z_]\w*)$/
const SHELL_REFERENCE = /\$\([^)]*\)|`[^`]*`|\$[A-Za-z_{]/

export function isReference(value: string, mode: ReferenceMode = 'config'): boolean {
  if (mode === 'literal') return false
  if (/^op:\/\//.test(value) || BRACED.test(value) || WHOLE_VARIABLE.test(value)) return true
  if (mode === 'shell') return SHELL_REFERENCE.test(value)
  return mode === 'config' && (CONFIG_REFERENCE.test(value) || WHOLE_CONFIG_REFERENCE.test(value.trim()))
}

function lastWord(key: string): string {
  const words = stageless(key)
  return words[words.length - 1] ?? ''
}

export function querySecrets(value: string, source: string, name: string): Secret[] {
  if (!isUrl(value)) return []
  const out: Secret[] = []
  for (const match of value.matchAll(/[?&;]([^=&#;]+)=([^&#;]+)/g)) {
    const param = match[1] ?? ''
    const found = decodeUri(match[2] ?? '')
    const strength = keyStrength(param)
    if (strength !== 'none' && found.length >= MIN_VALUE && !isReference(found, 'dotenv') && !isTrivialValue(found, strength)) out.push({ name: `${name}.${param}`, value: found, source, strong: true })
  }
  return out
}

export function connectionSecrets(value: string, source: string, name: string): Secret[] {
  if (!/;/.test(value) || !/=/.test(value)) return []
  const out: Secret[] = []
  for (const match of value.matchAll(/(?:^|;)\s*([^;=]+?)\s*=\s*([^;]*)/g)) {
    const key = (match[1] ?? '').trim().replace(/^.*:/, '')
    const found = (match[2] ?? '').trim().replace(/^(['"])(.*)\1$/, '$2')
    const strength = keyStrength(key)
    if (strength !== 'none' && found.length >= MIN_VALUE && !isReference(found, 'dotenv') && !isTrivialValue(found, strength)) out.push({ name: `${name}.${key}`, value: found, source, strong: true })
  }
  return out
}

export function urlSecrets(value: string, source: string, name: string): Secret[] {
  const out: Secret[] = []
  for (const match of value.matchAll(/(?:jdbc:)?[a-z][a-z0-9+.-]*:\/\/[^\s/:@,|]*:([^\s/@,|]+)@/gi)) {
    const password = decodeUri(match[1] ?? '')
    if (password.length >= MIN_VALUE && !isReference(password, 'dotenv') && !isPlaceholder(password)) out.push({ name: `${name}.password`, value: password, source, strong: true })
  }
  return [...out, ...querySecrets(value, source, name)]
}

export function valueSecrets(value: string, source: string, name: string): Secret[] {
  return [...urlSecrets(value, source, name), ...connectionSecrets(value, source, name)]
}

export function envSecrets(entries: readonly EnvEntry[], source: string, policy: EnvPolicy): Secret[] {
  const secrets: Secret[] = []
  const ignore = [...DEFAULT_IGNORE, ...policy.ignoreKeys]
  for (const entry of entries) {
    const { key, value } = entry
    if (value.length < MIN_VALUE || entry.reference || /^op:\/\//.test(value)) continue
    const named = matchesAny(key, policy.secretKeys) || matchesAny(key, DEFAULT_SECRET)
    const known = policy.known?.has(key) ?? false
    if (!named && (matchesAny(key, ignore) || isPublicName(key) || isPublicValue(value))) continue
    const natural = keyStrength(key)
    const strength: KeyStrength = known && natural === 'none' ? 'weak' : natural
    const proven = named || known || strength === 'strong'
    const strong = proven ? { strong: true } : {}
    const parts = valueSecrets(value, source, key)
    if (urlPassword(value) !== undefined) {
      secrets.push({ name: key, value, source, ...strong }, ...parts)
      continue
    }
    secrets.push(...parts)
    if (named) {
      if (!isPlaceholder(value)) secrets.push({ name: key, value, source, strong: true })
      continue
    }
    if (strength !== 'none' && lastWord(key) === 'DSN' && /^[a-z][\w+.-]*:/i.test(value)) continue
    if (parts.length > 0 && strength === 'none') continue
    if (!known && needsRandomValue(key) && !looksRandom(value)) continue
    const random = strength === 'none' && policy.random !== false && !plainLast(key) && looksRandom(value)
    if ((strength !== 'none' || random) && !isTrivialValue(value, strength)) secrets.push({ name: key, value, source, ...strong })
  }
  return secrets
}
