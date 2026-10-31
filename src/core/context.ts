const WORD = /[\p{L}\p{N}_]/u
const TERMINATOR = /^[\s\0"'`;,&<>)\]}@|]$/
const QUOTES = new Set(['"', "'", '`'])
const LOOK_BACK = 256

const CREDENTIAL_WORDS = new Set([
  'pass',
  'passwd',
  'password',
  'pwd',
  'pw',
  'passphrase',
  'passcode',
  'secret',
  'secrets',
  'token',
  'auth',
  'credential',
  'credentials',
  'creds',
  'cred',
  'psk',
  'pin',
  'otp',
  'totp',
  'key',
  'apikey',
  'privatekey',
  'accesskey',
  'secretkey',
  'authtoken',
  'masterauth',
])
const CREDENTIAL_PARTS = ['password', 'passwd', 'passphrase', 'secret', 'credential', 'token']

const URL_USERINFO = /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:\/@]*:$/
const MYSQL_FLAG = /(?:^|\s)-p$/
const USER_FLAG = /(?:^|\s)(?:-u|--user|--proxy-user|-a|--auth)(?:=|\s*)["']?[^\s:"']{0,64}:$/
const ASSIGNMENT = /([A-Za-z0-9_.$-]+)["']?\]?[ \t]*(?:=>|:=|\?=|=|:)[ \t]*$/
const SIBLING_KEY = /(?:^|[\s{,"'<])(?:name|key)["']?\s*[:=]\s*["']?([A-Za-z0-9_.:\/-]+)["']?(?![\s\S]*(?:^|[\s{,"'<])(?:name|key)["']?\s*[:=])/i
const PGPASS = /^[^:\s]+:(?:\d+|\*):[^:\s]+:[^:\s]+:$/
const NETRC_WORDS = new Set(['machine', 'login', 'account', 'default'])
const CALL_ARGUMENT = /\(\s*(["'])([A-Za-z0-9_.-]+)\1\s*,\s*$/
const XML_ELEMENT = /<([A-Za-z_][\w:.-]*)(?:\s[^<>]*)?>$/

function codePointBefore(text: string, at: number): string {
  const low = text.charCodeAt(at - 1)
  if (low >= 0xdc00 && low <= 0xdfff && at >= 2) return text.slice(at - 2, at)
  return text.slice(at - 1, at)
}

function codePointAt(text: string, at: number): string {
  const point = text.codePointAt(at)
  return point === undefined ? '' : String.fromCodePoint(point)
}

export function isWholeToken(text: string, start: number, end: number): boolean {
  return !WORD.test(codePointBefore(text, start)) && !WORD.test(codePointAt(text, end))
}

export function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .map(word => word.replace(/\d+$/, ''))
    .filter(Boolean)
}

function words(key: string): string[] {
  return keyWords(key).map(word => word.toLowerCase())
}

function squash(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]/g, '')
}

export function credentialKey(key: string): boolean {
  return words(key).some(word => CREDENTIAL_WORDS.has(word) || CREDENTIAL_PARTS.some(part => word.includes(part)) || word.endsWith('pass'))
}

export function keyFits(key: string, name: string): boolean {
  const own = squash(key)
  if (own.length === 0) return false
  const tail = name.split(/[\/.@#]/).filter(Boolean).pop() ?? name
  if ((own === squash(name) || own === squash(tail)) && own.length >= 3) return true
  return credentialKey(key)
}

function lineBefore(text: string, at: number): string {
  let from = at
  while (from > 0 && at - from < LOOK_BACK) {
    const char = text[from - 1]
    if (char === '\n' || char === '\r' || char === '\0') break
    from--
  }
  return text.slice(from, at)
}

function siblingName(text: string, at: number): string | undefined {
  return text.slice(Math.max(0, at - LOOK_BACK), at).match(SIBLING_KEY)?.[1]
}

function bareForms(before: string, quote: string | undefined, name: string): boolean {
  if (!/\s$/.test(before)) return false
  const tokens = before.trim().split(/\s+/)
  const last = tokens[tokens.length - 1] ?? ''
  const previous = tokens[tokens.length - 2] ?? ''
  const third = tokens[tokens.length - 3] ?? ''
  if (/^--?[A-Za-z][\w-]*$/.test(last)) {
    const flag = last.replace(/^-+/, '')
    return flag === 'p' || (flag === 'a' && tokens.some(token => /(?:^|\/)redis-cli(?:\.exe)?$/.test(token))) || keyFits(flag, name)
  }
  const lower = last.toLowerCase()
  if (tokens.length === 1 && /\S[ \t]{2,}$/.test(before) && keyFits(last, name)) return true
  if (lower === 'password' && (quote === undefined || quote === '"') && (tokens.length === 1 || tokens.some(token => NETRC_WORDS.has(token)))) return true
  if (quote === "'" && (lower === 'password' || (lower === 'by' && tokens.some(token => token.toLowerCase() === 'identified')))) return true
  if (lower === 'auth' || lower === 'requirepass' || lower === 'masterauth' || previous.toLowerCase() === 'auth') return true
  if (quote !== undefined && (lower === 'convertto-securestring' || (lower === '-string' && /convertto-securestring/i.test(before)))) return true
  if ((previous === 'ENV' && tokens.length === 2) || previous === 'setenv' || previous === 'set' || (/^-[A-Za-z]*x[A-Za-z]*$/.test(previous) && third === 'set')) return keyFits(last, name)
  return false
}

function endsValue(text: string, end: number): boolean {
  const after = text[end]
  if (after === undefined || TERMINATOR.test(after)) return true
  return after === '.' && (end + 1 === text.length || TERMINATOR.test(text[end + 1] ?? ''))
}

export function inAssignment(text: string, start: number, end: number, name: string): boolean {
  if (!endsValue(text, end)) return false
  const after = text[end]
  const open = text[start - 1]
  const quote = open !== undefined && QUOTES.has(open) ? open : undefined
  if (quote !== undefined && after !== quote) return false
  const valueStart = quote === undefined ? start : start - 1
  const raw = lineBefore(text, valueStart)
  const before = raw.replaceAll('\\040', ' ')
  if (quote === undefined && after === '@' && URL_USERINFO.test(before)) return true
  if (MYSQL_FLAG.test(before) || USER_FLAG.test(before)) return true
  if (quote === undefined && PGPASS.test(before) && (after === undefined || /[\r\n\0]/.test(after))) return true
  const assignment = before.match(ASSIGNMENT)
  if (assignment?.[1]) {
    const key = assignment[1]
    if (squash(key) === 'value') {
      const named = siblingName(text, valueStart - raw.length + Math.max(0, raw.lastIndexOf(key)))
      return named !== undefined && keyFits(named, name)
    }
    return keyFits(key, name)
  }
  const argument = before.match(CALL_ARGUMENT)
  if (argument?.[2]) return quote !== undefined && keyFits(argument[2], name)
  const element = before.match(XML_ELEMENT)
  if (element?.[1]) return after === '<' && keyFits(element[1], name)
  return bareForms(before, quote, name)
}
