import { base64Decode } from '../core/encoding.ts'
import type { Secret } from '../core/types.ts'

type Parser = (text: string, source: string) => Secret[]

export const parseAwsCredentials: Parser = (text, source) => {
  const secrets: Secret[] = []
  let profile = 'default'
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    const section = line.match(/^\[\s*(?:profile\s+)?([^\]]+?)\s*\]$/)
    if (section?.[1]) {
      profile = section[1]
      continue
    }
    const pair = line.match(/^(aws_secret_access_key|aws_session_token|aws_access_key_id)\s*=\s*(\S+)/i)
    if (pair?.[1] && pair[2]) secrets.push({ name: `aws/${profile}/${pair[1].toLowerCase()}`, value: pair[2], source })
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
    if ((token === 'password' || token === 'account') && next) secrets.push({ name: `netrc/${machine}`, value: next, source })
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
    if (password) secrets.push({ name: `pgpass/${host ?? '*'}/${user ?? '*'}`, value: password, source })
  }
  return secrets
}

export const parseGitCredentials: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^:/@\s]*:)?([^:@\s]+)@([^/\s]+)/i)
    if (match?.[1] && match[2]) {
      let value = match[1]
      try {
        value = decodeURIComponent(value)
      } catch {}
      secrets.push({ name: `git-credentials/${match[2]}`, value, source })
    }
  }
  return secrets
}

export const parseNpmrc: Parser = (text, source) => {
  const secrets: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^([^=#;]*(?:_authToken|_auth|_password|:_authToken))\s*=\s*(.+)$/)
    if (!match?.[1] || !match[2]) continue
    const key = match[1].trim()
    const value = match[2].trim().replace(/^"(.*)"$/, '$1')
    if (/\$\{.+\}/.test(value)) continue
    secrets.push({ name: `npmrc/${key}`, value, source })
    if (key.endsWith('_password')) {
      const decoded = base64Decode(value)
      if (decoded) secrets.push({ name: `npmrc/${key}.decoded`, value: decoded, source })
    }
  }
  return secrets
}

export const parseDockerConfig: Parser = (text, source) => {
  const secrets: Secret[] = []
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return secrets
  }
  const auths = (parsed as { auths?: Record<string, Record<string, unknown>> }).auths ?? {}
  for (const [registry, entry] of Object.entries(auths)) {
    for (const field of ['auth', 'identitytoken', 'registrytoken', 'password'] as const) {
      const value = entry?.[field]
      if (typeof value !== 'string' || !value) continue
      secrets.push({ name: `docker/${registry}/${field}`, value, source })
      if (field === 'auth') {
        const password = base64Decode(value)?.split(':').slice(1).join(':')
        if (password) secrets.push({ name: `docker/${registry}/password`, value: password, source })
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
    if (token?.[1]) secrets.push({ name: `gh/${host}`, value: token[1], source })
  }
  return secrets
}

export const parseKubeConfig: Parser = (text, source) => {
  const secrets: Secret[] = []
  let user = 'kube'
  for (const line of text.split(/\r?\n/)) {
    const name = line.match(/^\s*-?\s*name:\s*["']?([^\s"']+)/)
    if (name?.[1]) user = name[1]
    const field = line.match(/^\s*(token|client-key-data|password|refresh-token|id-token):\s*["']?([^\s"']+)/)
    if (field?.[1] && field[2]) secrets.push({ name: `kube/${user}/${field[1]}`, value: field[2], source })
  }
  return secrets
}

const PRIVATE_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----/g

export function privateKeyBlocks(text: string, name: string, source: string): Secret[] {
  return [...text.matchAll(PRIVATE_KEY)].map((match, index) => ({
    name: index === 0 ? name : `${name}#${index + 1}`,
    value: match[0],
    source,
  }))
}
