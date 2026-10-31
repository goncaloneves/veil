import { shannonEntropy } from '../core/encoding.ts'
import type { Secret } from '../core/types.ts'
import type { EnvEntry } from './dotenv.ts'

export type EnvPolicy = {
  readonly secretKeys: readonly string[]
  readonly ignoreKeys: readonly string[]
  readonly minLength: number
}

const STRONG_PARTS = ['PASSWORD', 'PASSWD', 'PASSPHRASE', 'PASSCODE', 'SECRET', 'CREDENTIAL', 'APIKEY', 'PRIVATEKEY', 'ACCESSKEY', 'AUTHTOKEN']
const STRONG_WORDS = new Set(['PW', 'PWD', 'PASS', 'DSN', 'CREDS', 'PIN', 'OTP', 'TOTP'])
const LAST_WORDS = new Set(['KEY', 'KEYS', 'TOKEN', 'TOKENS', 'AUTH', 'SESSION', 'COOKIE', 'SALT', 'JWT', 'BEARER', 'WEBHOOK'])
const STAGES = new Set(['PROD', 'PRODUCTION', 'DEV', 'DEVELOPMENT', 'STAGING', 'STAGE', 'TEST', 'TESTING', 'LOCAL', 'QA', 'UAT', 'PREVIEW', 'CI'])

const DEFAULT_IGNORE = ['NEXT_PUBLIC_*', 'VITE_*', 'PUBLIC_*', 'EXPO_PUBLIC_*', 'REACT_APP_PUBLIC_*', 'NODE_ENV', 'PORT', 'HOST', 'TZ', 'LOG_LEVEL']

function globToRegExp(glob: string): RegExp {
  const body = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`^${body}$`, 'i')
}

function matchesAny(key: string, globs: readonly string[]): boolean {
  return globs.some(glob => globToRegExp(glob).test(key))
}

export function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .map(word => word.replace(/\d+$/, ''))
    .filter(Boolean)
}

export type KeyStrength = 'strong' | 'weak' | 'none'

export function keyStrength(key: string): KeyStrength {
  const words = keyWords(key)
  while (words.length > 1 && STAGES.has(words[words.length - 1] ?? '')) words.pop()
  const strong = (word: string) => STRONG_WORDS.has(word) || STRONG_PARTS.some(part => word.includes(part))
  const last = words[words.length - 1]
  if (last !== undefined && strong(last)) return 'strong'
  if (last !== undefined && LAST_WORDS.has(last)) return 'weak'
  return words.some(strong) ? 'weak' : 'none'
}

export function isSecretKey(key: string): boolean {
  return keyStrength(key) !== 'none'
}

export function urlPassword(value: string): string | undefined {
  const match = value.match(/^[a-z][a-z0-9+.-]*:\/\/[^\s/:@]*:([^\s/@]+)@/i)
  if (!match?.[1]) return undefined
  try {
    return decodeURIComponent(match[1])
  } catch {
    return match[1]
  }
}

export function looksRandom(value: string): boolean {
  return value.length >= 24 && !/\s/.test(value) && shannonEntropy(value) >= 4
}

function urlHoldsSecret(value: string): boolean {
  const userinfo = value.match(/^[a-z][a-z0-9+.-]*:\/\/([^\s/@]+)@/i)?.[1]
  if (userinfo && userinfo.length >= 8) return true
  return value
    .replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '')
    .split(/[/?&=#]+/)
    .some(part => part.length >= 20 && shannonEntropy(part) >= 3.5)
}

export function isTrivialValue(value: string, strength: KeyStrength = 'weak'): boolean {
  if (/^(?:true|false|yes|no|on|off|null|none|undefined)$/i.test(value)) return true
  if (strength === 'strong') return false
  if (/^[-+]?\d+(?:[._]\d+)*$/.test(value)) return true
  if (/^(?:\/|~\/|\.{1,2}\/)\S*$/.test(value) && !looksRandom(value)) return true
  if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(value) && !urlHoldsSecret(value)) return true
  if (/^[a-z0-9]+(?:[-_.:][a-z0-9]+)*$/.test(value) && !looksRandom(value)) {
    if (value.split(/[-_.:]/).every(part => /^(?:[a-z]+|\d+|[a-z]+\d+[a-z]*)$/.test(part))) return true
  }
  return false
}

export function envSecrets(entries: readonly EnvEntry[], source: string, policy: EnvPolicy): Secret[] {
  const secrets: Secret[] = []
  const ignore = [...DEFAULT_IGNORE, ...policy.ignoreKeys]
  for (const { key, value } of entries) {
    if (value.length < policy.minLength) continue
    const named = matchesAny(key, policy.secretKeys)
    if (!named && matchesAny(key, ignore)) continue
    const password = urlPassword(value)
    if (password !== undefined) {
      secrets.push({ name: key, value, source })
      if (password.length >= policy.minLength) secrets.push({ name: `${key}.password`, value: password, source })
      continue
    }
    const strength = keyStrength(key)
    if (named || ((strength !== 'none' || looksRandom(value)) && !isTrivialValue(value, strength))) secrets.push({ name: key, value, source })
  }
  return secrets
}
