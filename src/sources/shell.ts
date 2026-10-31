import { dirname, isAbsolutePath, joinPath } from '../core/paths.ts'
import type { Secret } from '../core/types.ts'
import { parseDotenv, type EnvEntry } from './dotenv.ts'
import { envSecrets, isTrivialValue, keyStrength, urlSecrets, type EnvPolicy } from './env-policy.ts'
import { flagSecrets, headerSecrets, usable } from './tree.ts'

type Token = { readonly text: string; readonly expands: boolean }

const POWERSHELL_ENV = /^\s*\$env:([A-Za-z_][\w]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/i
const DOTNET_ENV = /\[(?:System\.)?Environment\]::SetEnvironmentVariable\(\s*['"]([A-Za-z_]\w*)['"]\s*,\s*(?:"([^"]*)"|'([^']*)')/i
const FISH_SET = /^\s*set\s+((?:-{1,2}[A-Za-z]+\s+)*)([A-Za-z_]\w*)\s+(.+?)\s*$/

function powershellEntry(line: string): EnvEntry | undefined {
  const match = line.match(POWERSHELL_ENV) ?? line.match(DOTNET_ENV)
  if (!match?.[1]) return undefined
  const double = match[2]
  const value = double ?? match[3] ?? match[4] ?? ''
  if (match[3] !== undefined) return { key: match[1], value, literal: true }
  return /\$|%[A-Za-z_]\w*%/.test(value) ? { key: match[1], value, reference: true } : { key: match[1], value }
}

function fishEntry(line: string): EnvEntry | undefined {
  const match = line.match(FISH_SET)
  if (!match?.[2] || !match[3] || /(?:^|\s)-{1,2}(?:e|erase|q|query)\b/.test(match[1] ?? '')) return undefined
  const tokens = shellTokens(match[3])[0] ?? []
  if (tokens.length !== 1 || !tokens[0]) return undefined
  return tokenEntry(match[2], tokens[0].text, tokens[0].expands)
}

function tokenEntry(key: string, value: string, expands: boolean): EnvEntry {
  return expands ? { key, value, reference: true } : { key, value, literal: true }
}

export function shellEntries(text: string): EnvEntry[] {
  const entries = parseDotenv(text, { shell: true })
  for (const line of text.split(/\r?\n/)) {
    const found = powershellEntry(line) ?? fishEntry(line)
    if (found) entries.push(found)
  }
  return entries
}

export function fishVariables(text: string): EnvEntry[] {
  const entries: EnvEntry[] = []
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^SETUVAR\s+(?:--export\s+)?([A-Za-z_]\w*):(.*)$/)
    if (!match?.[1]) continue
    const value = (match[2] ?? '').replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16))).replace(/\\(.)/g, '$1')
    if (!value.includes('\x1e')) entries.push({ key: match[1], value, literal: true })
  }
  return entries
}

export function shellTokens(line: string): Token[][] {
  const commands: Token[][] = [[]]
  let text = ''
  let expands = false
  let started = false
  let quote = ''
  const flush = () => {
    if (started) commands[commands.length - 1]?.push({ text, expands })
    text = ''
    expands = false
    started = false
  }
  for (let i = 0; i < line.length; i++) {
    const char = line[i] ?? ''
    if (quote === "'") {
      if (char === "'") quote = ''
      else text += char
      continue
    }
    if (char === '\\' && i + 1 < line.length) {
      text += line[++i]
      started = true
      continue
    }
    if (quote === '"') {
      if (char === '"') quote = ''
      else {
        if (char === '$' || char === '`') expands = true
        text += char
      }
      continue
    }
    if (char === "'" || char === '"') {
      quote = char
      started = true
    } else if (/\s/.test(char)) flush()
    else if (char === ';' || char === '|' || char === '&') {
      flush()
      if (commands[commands.length - 1]?.length) commands.push([])
    } else {
      if (char === '$' || char === '`') expands = true
      text += char
      started = true
    }
  }
  flush()
  return commands.filter(command => command.length > 0)
}

const MYSQL = /^(?:mysql|mariadb|mysqldump|mysqladmin|mysqlsh|mariadb-dump)$/
const MONGO = /^(?:mongosh|mongo|mongodump|mongorestore|mongoexport|mongoimport)$/
const LOGIN = /^(?:docker|podman|nerdctl|buildah|skopeo|helm|oras|crane)$/

function shortFlagSecrets(tokens: readonly Token[], source: string): Secret[] {
  const words = tokens.map(token => token.text)
  const program = (words[0] === 'sudo' ? words[1] : words[0])?.replace(/^.*[\\/]/, '') ?? ''
  const out: Secret[] = []
  const take = (index: number, flag: string, pick: (text: string) => string = text => text) => {
    const token = tokens[index]
    if (!token || token.expands) return
    const value = pick(token.text)
    if (value && !value.startsWith('-') && usable(value, 'literal') && !isTrivialValue(value, 'strong')) out.push({ name: `history/${program}.${flag}`, value, source, strong: true })
  }
  const after = (index: number) => (tokens[index] && !tokens[index].text.startsWith('-') ? index : -1)
  const login = LOGIN.test(program) && words.includes('login')
  const ghSecret = program === 'gh' && words.includes('secret') && words.includes('set')
  words.forEach((word, index) => {
    if (MYSQL.test(program) && /^-p./.test(word)) take(index, 'p', text => text.slice(2))
    if ((program === 'sshpass' || MONGO.test(program) || login) && word === '-p') take(index + 1, 'p')
    if (program === 'redis-cli' && word === '-a') take(index + 1, 'a')
    if (program === 'curl' && (word === '-u' || word === '--user')) take(index + 1, 'u', text => text.split(':').slice(1).join(':'))
    if (ghSecret && (word === '-b' || word === '--body')) take(index + 1, 'body')
    if (ghSecret && word.startsWith('--body=')) take(index, 'body', text => text.slice(7))
  })
  if (program === 'aws' && words[1] === 'configure' && words[2] === 'set' && keyStrength(words[3] ?? '') !== 'none') take(after(4), words[3] ?? 'value')
  if (program === 'cargo' && words[1] === 'login') take(after(2), 'token')
  return out
}

function headerAndUrlSecrets(tokens: readonly Token[], source: string): Secret[] {
  const out: Secret[] = []
  tokens.forEach((token, index) => {
    if (token.expands) return
    out.push(...urlSecrets(token.text, source, 'history/url'))
    const previous = tokens[index - 1]?.text
    const header = previous === '-H' || previous === '--header' ? token.text : token.text.startsWith('--header=') ? token.text.slice(9) : undefined
    const cut = header?.indexOf(':') ?? -1
    if (header && cut > 0) out.push(...headerSecrets(header.slice(0, cut).trim(), header.slice(cut + 1).trim(), source, `history/header.${header.slice(0, cut).trim()}`))
  })
  return out
}

const SQL_PASSWORD = /\b(?:(?:ALTER|CREATE)\s+(?:USER|ROLE|LOGIN)\b[^'";]*?\bPASSWORD|IDENTIFIED\s+(?:WITH\s+\S+\s+)?BY|SET\s+PASSWORD\b[^;=]*=\s*(?:PASSWORD\s*\()?)\s*(['"])([^'"]+)\1/gi
const MONGO_AUTH = /\.auth\(\s*['"][^'"]*['"]\s*,\s*['"]([^'"]+)['"]/g
const REDIS_AUTH = /^\s*(?:AUTH\s+(?:\S+\s+)?|CONFIG\s+SET\s+requirepass\s+)(\S+)\s*$/i
const TOKENIZE = /(?:^|[\s;&|=])[A-Za-z_]\w*=|--?[\w-]*(?:pass|pwd|token|secret|key|auth|cred|otp|pin|body|header)|\s-H\s|:\/\/[^\s/@]*:[^\s@]*@|\bconfigure\s+set\b|\bcargo\s+login\b|(?:^|[\s;&|/])(?:mysql\S*|mariadb\S*|sshpass|mongo\S*|redis-cli|curl|docker|podman|nerdctl|buildah|skopeo|helm|oras|crane)\s/i
const SECURE_STRING = /ConvertTo-SecureString\s+(?:-String\s+)?(['"])([^'"]+)\1/gi

export function historySecrets(text: string, source: string, policy: EnvPolicy): Secret[] {
  const out: Secret[] = []
  const entries: EnvEntry[] = []
  const add = (name: string, value: string | undefined) => {
    if (value && usable(value, 'literal') && !isTrivialValue(value, 'strong')) out.push({ name, value, source, strong: true })
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^: \d+:\d+;/, '').replace(/^- cmd: /, '').replace(/\\040/g, ' ')
    if (!/[=]|\s-[paubH]|--|:\/\/[^\s/@]*:[^\s@]*@|SecureString|AUTH|requirepass|PASSWORD|IDENTIFIED|\.auth\(|\bset\s|\blogin\s/i.test(line)) continue
    const found = powershellEntry(line) ?? fishEntry(line)
    if (found) entries.push(found)
    for (const match of line.matchAll(SQL_PASSWORD)) add('history/sql.password', match[2])
    for (const match of line.matchAll(MONGO_AUTH)) add('history/mongo.password', match[1])
    for (const match of line.matchAll(SECURE_STRING)) add('history/securestring', match[2])
    add('history/redis.password', line.match(REDIS_AUTH)?.[1])
    if (!TOKENIZE.test(line)) continue
    for (const command of shellTokens(line)) {
      for (const token of command) {
        const assignment = token.text.replace(/^--?[\w-]+=(?=[A-Za-z_]\w*=)/, '').match(/^([A-Za-z_]\w*)=([\s\S]*)$/)
        if (assignment?.[1]) entries.push(tokenEntry(assignment[1], assignment[2] ?? '', token.expands))
      }
      const words = command.map(token => token.text)
      out.push(...flagSecrets(words, source, `history/${words[0] ?? 'command'}`, command.map(token => token.expands), 'literal'), ...shortFlagSecrets(command, source), ...headerAndUrlSecrets(command, source))
    }
  }
  return [...envSecrets(entries, source, { ...policy, random: false }), ...out]
}

export function sourcedFiles(text: string, source: string, home: string): string[] {
  const found: string[] = []
  for (const match of text.matchAll(/(?:^|[;&|]\s*|\bthen\s+)(?:source|\.)\s+("[^"]+"|'[^']+'|[^\s;&|]+)/gm)) {
    const raw = (match[1] ?? '').replace(/^(["'])(.*)\1$/, '$2').replace(/^~(?=[\\/])/, home).replace(/\$\{?HOME\}?/g, home)
    if (!raw || /[$`*?%]/.test(raw)) continue
    found.push(isAbsolutePath(raw) ? raw : joinPath(dirname(source), raw))
  }
  return found
}

export function environmentFiles(text: string): string[] {
  const found: string[] = []
  for (const match of text.matchAll(/^\s*EnvironmentFile\s*=\s*-?(\S+)\s*$/gm)) if (match[1] && isAbsolutePath(match[1]) && !/%/.test(match[1])) found.push(match[1])
  return found
}

export function systemdEntries(text: string): EnvEntry[] {
  const entries: EnvEntry[] = []
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*Environment\s*=\s*(.+)$/)
    if (!match?.[1]) continue
    for (const command of shellTokens(match[1].replace(/[;&|]/g, ' ')))
      for (const token of command) {
        const assignment = token.text.match(/^([A-Za-z_]\w*)=([\s\S]*)$/)
        if (assignment?.[1]) entries.push(tokenEntry(assignment[1], assignment[2] ?? '', token.expands))
      }
  }
  return entries
}

export function fstabSecrets(text: string, source: string): Secret[] {
  const out: Secret[] = []
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue
    for (const match of line.matchAll(/(?:^|[\s,])(?:password|pass)=([^,\s]+)/g)) if (usable(match[1] ?? '', 'literal') && !isTrivialValue(match[1] ?? '', 'strong')) out.push({ name: 'fstab/password', value: match[1] ?? '', source, strong: true })
  }
  return out
}
