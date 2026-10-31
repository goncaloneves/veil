import { base64Cores, utf8Encode } from '../core/encoding.ts'
import type { Allowlist, Rule } from '../core/types.ts'
import { gitleaks } from './gitleaks.ts'

function ci(text: string): string {
  return text.replace(/[A-Za-z]/g, letter => `[${letter.toLowerCase()}${letter.toUpperCase()}]`)
}

function anyOf(words: readonly string[]): string {
  return `(?:${words.map(ci).join('|')})`
}

const LONG_WORDS = anyOf(['password', 'passwd', 'passphrase', 'passcode'])
const SHORT_WORDS = anyOf(['pass_phrase', 'pass', 'pwd', 'pw', 'psk', 'secret', 'requirepass', 'masterauth'])
const KEY_SUFFIX = `(?:[_.-]?(?:${ci('access')}[_.-]?)?${ci('key')}(?:[_.-]?${ci('base')})?)?\\d{0,3}`
const STRONG_KEY = `(?:[\\w.-]{0,60}${LONG_WORDS}|(?:[\\w.-]{0,60}[_.-]|[\\w.-]{0,60}[a-z0-9](?=[A-Z]))?${SHORT_WORDS})${KEY_SUFFIX}`
const KEY_END = anyOf(['password', 'passwd', 'passphrase', 'passcode', 'pass', 'pwd', 'psk', 'secret', 'token', 'apikey', 'api_key', 'secretkey', 'secret_key'])
const PASSWORD_KEYWORDS = ['pass', 'pwd', 'pw', 'psk', 'secret', 'masterauth']
const TOKEN_WORDS = anyOf(['apikey', 'api_key', 'api-key', 'accesskey', 'access_key', 'secretkey', 'secret_key', 'clientsecret', 'client_secret', 'token', 'secret', 'credential', 'credentials'])
const ENV_SECRET_NAME = '(?:[A-Z][A-Z0-9]{0,30}_){0,6}(?:KEY|KEYS|TOKEN|SECRET|PASSWORD|PASSWD|PWD|PASS|PASSPHRASE|AUTH|CREDENTIALS?)'
const GENERIC_NAMES: readonly Allowlist[] = (gitleaks.rules.find(item => item.id === 'generic-api-key')?.allowlists ?? [])
  .filter(list => list.target !== 'secret')
  .map(list => ({ ...list, stopwords: [] }))
const SEP = '(?:\\s|\\\\040)'
const SPACE = '[ \\t]{0,20}'
const GAP = '[ \\t]{1,20}'
const ASSIGN = '(?:=>|:=|=(?![=~>])|:(?!:))'
const LINE_END = '(?=\\s|$|[;|&)])'
const COMMAND_RUN = '[^\\n|;&]{0,300}?'

const SHAPE: Allowlist = { patterns: ['^\\[veil:[A-Za-z0-9_.\\/@:+~#-]+\\]$'], stopwords: [], target: 'secret' }

const PLACEHOLDERS: Allowlist = {
  patterns: [
    '^\\$\\{[^}]*\\}$',
    '^\\$\\([^)]*\\)?$',
    '^\\$[A-Za-z_][A-Za-z0-9_]*$',
    '^\\$env:[A-Za-z_][A-Za-z0-9_]*$',
    '^%[A-Za-z_][A-Za-z0-9_]*%$',
    '^<[^>]*>?$',
    '^\\{\\{.*\\}\\}$',
    '^\\{[A-Za-z_][\\w.]*\\}$',
    '\\$\\{|\\$\\(|\\{\\{|\\{%',
    '^[*x.\\u2022#-]+$',
    '^\\[[A-Za-z][A-Za-z _-]*\\]$',
    '^\\([A-Za-z][A-Za-z _-]*\\)$',
    '^[A-Z]+(?:_[A-Z]+)+$',
    '^(?:~|\\.{1,2})?\\/[\\w.\\/-]*$',
    '^[A-Za-z]:[\\\\/]',
    '^[A-Za-z][A-Za-z0-9+.-]*:\\/\\/',
    '^(?:ENC\\[|vault:|!vault|arn:aws:|env:|file:|fd:)',
    `^${anyOf(['password', 'passwd', 'pass', 'pwd', 'secret', 'changeme', 'stdin'])}$`,
  ],
  stopwords: ['changeme', 'change_me', 'placeholder', 'example', 'redacted', 'your_', 'your-', 'yourpass', 'xxxxxx', '******'],
  target: 'secret',
}

const CODE: Allowlist = {
  patterns: [
    '(?:^|[\\s=:>(,])[A-Za-z_$][\\w$]*(?:(?:\\.|::|->|\\?\\.)[A-Za-z_$][\\w$]*|\\([^()\\s"\'`]*\\)|\\[[^\\[\\]\\s"\'`]*\\])+(?:[(\\[][^()\\[\\]\\s"\'`]*)?[;,]?$',
    '(?:^|[\\s=:>(,])[A-Za-z_$][\\w$]{2,}[(\\[][^()\\[\\]\\s"\'`]*$',
  ],
  stopwords: [],
  target: 'match',
}

const WORDS: Allowlist = {
  patterns: [
    '^[A-Za-z_][A-Za-z_.:<>\\[\\]\\/-]*[;,?]*$',
    '^[A-Za-z\\u00c0-\\u024f\\u0370-\\u03ff\\u0400-\\u04ff\\u0590-\\u06ff\\u3040-\\u30ff\\u4e00-\\u9fff\\uac00-\\ud7af]+$',
  ],
  stopwords: [],
  target: 'secret',
}

const LITERALS = [PLACEHOLDERS, CODE]
const FREE_TEXT = [PLACEHOLDERS, CODE, WORDS]

function quotedOrBare(quotedMin: number, bareMin: number): string {
  return `(?:"((?:[^"\\\\\\s]|\\\\.){${quotedMin},200})"|'([^'\\s]{${quotedMin},200})'|\`([^\`\\s]{${quotedMin},200})\`|([^\\s"'\`=][^\\s"'\`]{${bareMin - 1},199}))`
}

function rule(id: string, pattern: string, keywords: readonly string[], options: Partial<Rule> = {}): Rule {
  return {
    id,
    pattern,
    keywords,
    secretGroup: options.secretGroup ?? 1,
    entropy: options.entropy ?? 0,
    allowlists: [SHAPE, ...(options.allowlists ?? LITERALS)],
    ...(options.multiline === undefined ? {} : { multiline: options.multiline }),
    ...(options.continuation === undefined ? {} : { continuation: options.continuation }),
  }
}

function cores(phrase: string): string[] {
  return base64Cores(utf8Encode(phrase)).map(core => core.replaceAll('+', '-').replaceAll('/', '_'))
}

const ANON_ROLE = [...cores('"role":"anon"'), ...cores('"role": "anon"')].join('|')

const NON_SECRET_KEYS_SOURCE = `${anyOf([
  'idempotency',
  'cache',
  'partition',
  'sort',
  'range',
  'object',
  'routing',
  'shard',
  'lookup',
  'dedupe',
  'dedup',
  'message',
  'translation',
  'i18n',
  'query',
  'row',
  'unique',
  'item',
  'entity',
  'react',
  'site',
  'publishable',
  'next',
  'page',
  'pagination',
  'continuation',
  'cursor',
  'sync',
  'resume',
  'etag',
])}[_.-]?${anyOf(['key', 'token'])}`
const NON_SECRET_KEYS = `^(?:[\\w.-]*?(?:[_.-]|[a-z0-9](?=[A-Z])))?${NON_SECRET_KEYS_SOURCE}`
const BARE_KEY_SLUG = `^${ci('key')}["']?[ \\t]*[:=][ \\t]*["']?(?=[^\\s"']*[a-z]{3})[a-z0-9]+(?:[-_.][a-z0-9]+)+["'\\s;,]*$`

export const RULE_ALLOWLISTS: Readonly<Record<string, readonly Allowlist[]>> = {
  'generic-api-key': [
    { patterns: [NON_SECRET_KEYS, BARE_KEY_SLUG], stopwords: [], target: 'match' },
    { patterns: ['^pk_(?:live|test)_'], stopwords: [], target: 'secret' },
  ],
  jwt: [{ patterns: [`^[^.]+\\.[^.]*(?:${ANON_ROLE})`], stopwords: [], target: 'secret' }],
}

const URL_PLACEHOLDERS: Allowlist = {
  patterns: [
    '^\\$\\{[^}]*\\}$',
    '^\\$[A-Za-z_][A-Za-z0-9_]*$',
    '^<[^>]*>$',
    '^\\{\\{.*\\}\\}$',
    '^[*x.]+$',
    '^%[A-Za-z_]+%$',
    `^${anyOf(['password', 'passwd', 'pass', 'pwd', 'secret', 'token'])}$`,
  ],
  stopwords: ['changeme', 'example', 'placeholder', 'your_', 'your-'],
  target: 'secret',
}

const B64 = '[A-Za-z0-9+\\/=]'
const PEM_BEGIN = base64Cores(utf8Encode('-----BEGIN'))
const PEM_PRIVATE = base64Cores(utf8Encode('PRIVATE KEY'))
const NEWLINE = '(?:\\r?\\n|\\\\?\\\\(?:r\\\\{1,2})?n)'
const KEY_LINE = `${NEWLINE}[ \\t]{0,40}(?:(?:${B64}{1,200}|[A-Za-z][\\w-]{0,40}:[^\\r\\n\\\\]{0,200})[ \\t]{0,40})?(?=${NEWLINE}|$|["'])`
const KEY_CHUNK = `[ \\t]{1,4}${B64}{16,200}`
const KEY_TAIL = `(?:${NEWLINE}[ \\t]{0,40}${B64}{1,200}|[ \\t]{1,4}${B64}{16,200})`
const KEY_END_LINE = `(?:${NEWLINE}|[ \\t]{1,4})-{4,5} ?${ci('end')}[ A-Za-z0-9_-]{0,100}-{4,5}`

export const VEIL_RULES: readonly Rule[] = [
  rule(
    'url-credentials',
    "\\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:\\/\\/[^\\s:\\/@'\"`]{0,64}:([^\\s\\/'\"`]{3,200}?)@[^\\s@\\/'\"`]{1,255}",
    ['://'],
    { allowlists: [URL_PLACEHOLDERS] },
  ),
  rule('url-token-userinfo', "\\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:\\/\\/([A-Za-z0-9_\\-.~%+]{20,200})@[^\\s@\\/'\"`:]{1,255}", ['://'], {
    entropy: 3.5,
    allowlists: [URL_PLACEHOLDERS, { patterns: [`@[^\\s\\/'"\`:]*${ci('sentry')}`], stopwords: [], target: 'match' }],
  }),
  rule('anthropic-token', '\\bsk-ant-[a-z]{2,10}\\d{2}-[A-Za-z0-9_-]{24,400}', ['sk-ant-'], { secretGroup: 0, entropy: 3, allowlists: [] }),
  rule('google-oauth-access-token', '\\bya29\\.[\\w-]{20,2048}(?:\\.[\\w-]{1,512}){0,4}', ['ya29.'], { secretGroup: 0, entropy: 3.5, allowlists: [] }),
  rule('google-oauth-refresh-token', '(?<![\\w/])1\\/\\/0[\\w-]{40,512}', ['1//0'], { secretGroup: 0, entropy: 3.5, allowlists: [] }),
  rule('google-oauth-client-secret', '\\bGOCSPX-[A-Za-z0-9_-]{28}(?![\\w-])', ['gocspx-'], { secretGroup: 0, entropy: 3, allowlists: [] }),
  rule('supabase-token', '\\b(?:sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,200})\\b', ['sbp_', 'sb_secret_'], { secretGroup: 0, entropy: 3, allowlists: [] }),
  rule('password-assignment', `(?<![\\w.;?&-])${STRONG_KEY}["']?\\]?\\??${SPACE}${ASSIGN}${SPACE}${quotedOrBare(6, 8)}`, PASSWORD_KEYWORDS, {
    entropy: 2,
    allowlists: FREE_TEXT,
  }),
  rule(
    'shell-set-password',
    `\\b(?:set|setenv|SETUVAR)(?:${GAP}-{1,2}[A-Za-z]{1,20}){0,4}${GAP}${STRONG_KEY}(?:${GAP}|:)${quotedOrBare(6, 8)}`,
    PASSWORD_KEYWORDS,
    { entropy: 2, allowlists: FREE_TEXT },
  ),
  rule(
    'hex-api-key',
    `(?<![\\w.-])[\\w.-]{0,50}?${anyOf(['access', 'auth', 'api', 'credential', 'creds', 'key', 'passwd', 'password', 'secret', 'token'])}[\\w.-]{0,20}["']?${SPACE}${ASSIGN}${SPACE}["']?([a-fA-F0-9]{32,64})(?![A-Za-z0-9_+\\/=-])`,
    ['access', 'auth', 'api', 'credential', 'creds', 'key', 'passwd', 'password', 'secret', 'token'],
    { entropy: 3, allowlists: [...GENERIC_NAMES, { patterns: [NON_SECRET_KEYS, `${ci('public')}[_.-]?${ci('key')}|${ci('key')}[_.-]?${ci('id')}`], stopwords: [], target: 'match' }] },
  ),
  rule('token-xml-element', `<(?:[\\w-]{1,40}:)?[\\w.-]{0,60}${TOKEN_WORDS}(?:\\s[^<>]{0,200})?>([^<\\s]{12,500})<\\/`, ['key', 'token', 'secret', 'credential'], {
    entropy: 3,
    allowlists: FREE_TEXT,
  }),
  rule('windows-registry-value', `(?:^|\\n)[ \\t]{1,40}${ENV_SECRET_NAME}[ \\t]{1,40}REG_(?:EXPAND_)?SZ[ \\t]{1,40}([^\\r\\n]{4,500})`, ['reg_sz', 'reg_expand_sz'], {
    entropy: 1.5,
    allowlists: FREE_TEXT,
  }),
  rule('environment-table-value', `(?:^|\\n)${ENV_SECRET_NAME}[ \\t]{2,200}([^\\s]{4,500})[ \\t]{0,40}(?=\\r?\\n|$)`, ['key', 'token', 'secret', 'pass', 'pwd', 'auth', 'credential'], {
    entropy: 1.5,
    allowlists: FREE_TEXT,
  }),
  rule(
    'environment-list-value',
    `${ci('name')}${SPACE}:${SPACE}${ENV_SECRET_NAME}${SPACE}\\r?\\n${ci('value')}${SPACE}:${SPACE}([^\\r\\n]{1,500}(?:\\r?\\n[ \\t]{2,40}[^\\r\\n]{1,500}){0,8})`,
    ['value'],
    { entropy: 1.5, allowlists: FREE_TEXT },
  ),
  rule('password-xml-element', `<(?:[\\w-]{1,40}:)?${STRONG_KEY}(?:\\s[^<>]{0,200})?>([^<\\s]{6,200})<\\/`, PASSWORD_KEYWORDS, { entropy: 1.5 }),
  rule(
    'password-xml-attribute',
    `\\b${ci('key')}${SPACE}=${SPACE}(["'])[\\w.:-]{0,80}(?<=${KEY_END}\\d{0,3})\\1[ \\t\\r\\n]{1,20}${ci('value')}${SPACE}=${SPACE}(["'])((?:(?!\\2)[^\\s]){4,200})\\2`,
    [...PASSWORD_KEYWORDS, 'token', 'apikey', 'api_key'],
    { secretGroup: 3, entropy: 1.5, allowlists: FREE_TEXT },
  ),
  rule(
    'password-argument',
    `\\(${SPACE}(["'])${STRONG_KEY}\\1${SPACE},${SPACE}(["'])((?:(?!\\2)[^\\s\\\\]|\\\\.){4,200})\\2`,
    PASSWORD_KEYWORDS,
    { secretGroup: 3, entropy: 1.5 },
  ),
  rule(
    'connection-string-password',
    `(?:^|;|["'])${SPACE}${anyOf(['password', 'pwd', 'user password'])}${SPACE}=(?!=)${SPACE}(?:'([^'\\n]{4,200})'|"([^"\\n]{4,200})"|\\{([^}\\n]{4,200})\\}|([^;'"\\s{][^;'"\\s]{3,199}))`,
    ['password', 'pwd'],
    { entropy: 1.5, allowlists: FREE_TEXT },
  ),
  rule('url-query-password', `[?&]${anyOf(['password', 'passwd', 'pwd', 'pass', 'passphrase'])}=([^&#\\s"'<>]{4,200})`, ['pass', 'pwd'], {
    entropy: 1.5,
  }),
  rule(
    'url-query-token',
    `[?&]${anyOf([
      'client_secret',
      'secret',
      'api_key',
      'apikey',
      'access_token',
      'refresh_token',
      'id_token',
      'token',
      'auth',
      'sig',
      'signature',
      'x-amz-signature',
      'x-amz-security-token',
      'x-goog-signature',
    ])}=([^&#\\s"'<>]{16,500})`,
    ['secret', 'key', 'token', 'auth', 'sig'],
    { entropy: 3 },
  ),
  rule('jdbc-oracle-password', "jdbc:oracle:[a-z]{1,20}:[^\\/@\\s:'\"]{1,64}\\/([^@\\s'\"]{4,200})@", ['jdbc:oracle'], { entropy: 1.5 }),
  rule(
    'authorization-header',
    `(?:${ci('proxy-')})?${ci('authori')}[sSzZ]${ci('ation')}["']?${SPACE}(?::(?!:)|=(?!=))${SPACE}["']?(?:${anyOf(['bearer', 'basic', 'token', 'digest', 'negotiate', 'ntlm', 'apikey', 'api-key', 'sso-key'])}(?:${GAP}|%20))?([\\w~+\\/=.:-]{8,500})`,
    ['authorization', 'authorisation'],
    { entropy: 3, allowlists: FREE_TEXT },
  ),
  rule(
    'api-key-header',
    `(?<![\\w-])(?:${ci('x-')})?${anyOf([
      'api-key',
      'api_key',
      'apikey',
      'api-token',
      'auth-token',
      'access-token',
      'private-token',
      'vault-token',
      'goog-api-key',
      'subscription-key',
      'figma-token',
      'session-token',
    ])}["']?${SPACE}(?::(?!:)|=(?!=))${SPACE}["']?([\\w~+\\/=.-]{16,500})`,
    ['key', 'token'],
    { entropy: 3.2 },
  ),
  rule(
    'session-cookie',
    `(?<![\\w.-])(?:(?:[\\w.-]{0,60}[_.-])?${anyOf(['session', 'sess', 'sid', 'jwt'])}[\\w.-]{0,40}|${anyOf(['phpsessid', 'jsessionid', 'aspsessionid'])}\\w{0,40})=(?!=)([^;\\s"',]{16,500})`,
    ['sess', 'sid', 'jwt'],
    { entropy: 3.5, allowlists: [PLACEHOLDERS, { patterns: ['^S-1-\\d'], stopwords: [], target: 'secret' }] },
  ),
  rule(
    'mysql-password-flag',
    `\\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlsh|mariadb|mariadb-dump|mariadb-admin)\\b${COMMAND_RUN}[ \\t]-p(["']?)([^\\s"'-][^\\s"']{3,199})\\1${LINE_END}`,
    ['mysql', 'mariadb'],
    { secretGroup: 2 },
  ),
  rule('sshpass-password', `\\bsshpass\\b${COMMAND_RUN}[ \\t]-p${SPACE}(["']?)([^\\s"'-][^\\s"']{3,199})\\1${LINE_END}`, ['sshpass'], { secretGroup: 2 }),
  rule(
    'registry-login-password',
    `\\b(?:docker|podman|nerdctl|buildah|skopeo|helm|oras|crane)(?:${GAP}[\\w.-]{1,40}){0,2}${GAP}login\\b${COMMAND_RUN}[ \\t](?:-p|--password)(?:=|${GAP})(["']?)([^\\s"'-][^\\s"']{3,199})\\1${LINE_END}`,
    ['login'],
    { secretGroup: 2 },
  ),
  rule(
    'cli-password-flag',
    `(?:^|\\s)--?(?!${ci('no-')})(?:[\\w-]{0,40}[-_])?${anyOf(['password', 'passwd', 'passphrase', 'pass', 'pwd', 'storepass', 'keypass', 'srcstorepass', 'deststorepass'])}(?:=|${GAP})(["']?)([^\\s"'-][^\\s"']{3,199})\\1${LINE_END}`,
    ['pass', 'pwd'],
    { secretGroup: 2, entropy: 1.5, allowlists: FREE_TEXT },
  ),
  rule(
    'cli-token-flag',
    `(?:^|\\s)--(?:[\\w-]{0,40}[-_])?${anyOf([
      'token',
      'api-key',
      'apikey',
      'auth-token',
      'access-token',
      'access-key',
      'secret-key',
      'secret-access-key',
      'client-secret',
      'bearer-token',
      'refresh-token',
    ])}(?:=|${GAP})(["']?)([A-Za-z0-9_\\-.+\\/=~]{16,200})\\1${LINE_END}`,
    ['token', 'key', 'secret'],
    { secretGroup: 2, entropy: 3.2 },
  ),
  rule('openssl-pass-argument', `-(?:passin|passout|pass)${GAP}(["']?)pass:([^\\s"']{4,200})\\1`, ['pass:'], { secretGroup: 2 }),
  rule(
    'powershell-secure-string',
    `${ci('convertto-securestring')}(?:${GAP}-(?:${ci('asplaintext')}|${ci('force')}|${ci('string')})){0,4}${GAP}(["'])((?:(?!\\1)[^\\n]){4,200})\\1`,
    ['convertto-securestring'],
    { secretGroup: 2 },
  ),
  rule(
    'curl-user-password',
    `\\b(?:curl|wget|xh)\\b${COMMAND_RUN}[ \\t](?:-u|--user|--proxy-user|-U|--http-user)(?:=|${SPACE})(["']?)[^\\s:"']{0,64}:([^\\s"']{4,200})\\1`,
    ['curl', 'wget', 'xh'],
    { secretGroup: 2, entropy: 1.5 },
  ),
  rule(
    'sql-password',
    `(?:${ci('password')}|${ci('identified')}(?:${SEP}{1,20}${ci('with')}${SEP}{1,20}\\w{1,64})?${SEP}{1,20}${ci('by')})${SEP}{0,20}(?:=${SEP}{0,20})?(?:${ci('password')}\\(${SEP}{0,20})?'((?:[^'\\\\\\n]|\\\\.|''){4,200})'`,
    ['password', 'identified'],
    { entropy: 1.5 },
  ),
  rule('mongo-auth', `\\.auth\\(${SPACE}(["'])[^"'\\n]{1,64}\\1${SPACE},${SPACE}(["'])((?:(?!\\2)[^\\n]){4,200})\\2`, ['.auth('], { secretGroup: 3 }),
  rule(
    'redis-auth',
    `(?:^|\\n|>)${SPACE}(?:(?:AUTH|auth)(?:${GAP}[^\\s"']{1,200})?|requirepass|masterauth|${ci('config')}${GAP}${ci('set')}${GAP}(?:requirepass|masterauth))${GAP}(["']?)([^\\s"']{4,200})\\1${SPACE}(?=\\r?\\n|$)`,
    ['auth', 'requirepass'],
    { secretGroup: 2, entropy: 1.5 },
  ),
  rule(
    'private-key-block',
    `-{4,5} ?${ci('begin')}[ A-Za-z0-9_-]{0,100}${ci('private key')}(?: ${ci('block')})? ?-{4,5}(?=[\\s\\S]{0,600}?[A-Za-z0-9+\\/]{16})(?:${KEY_LINE}|${KEY_CHUNK})*(?:${KEY_END_LINE}|${KEY_TAIL})?`,
    ['-----begin', '---- begin'],
    { secretGroup: 0, multiline: true, continuation: `(?:${KEY_LINE}|${KEY_CHUNK})*(?:${KEY_END_LINE}|${KEY_TAIL})?`, allowlists: [] },
  ),
  rule(
    'private-key-base64',
    `(?:${PEM_BEGIN.join('|')})(?=[A-Za-z0-9+\\/]{0,80}(?:${PEM_PRIVATE.join('|')}))[A-Za-z0-9+\\/]{1,200}(?:(?:\\r?\\n[ \\t]{0,20})?[A-Za-z0-9+\\/]{1,200}){0,400}={0,2}`,
    PEM_BEGIN.map(core => core.toLowerCase()),
    { secretGroup: 0, multiline: true, allowlists: [] },
  ),
  rule(
    'putty-private-key',
    'Private-Lines:[ \\t]{0,20}\\d{1,4}[ \\t]{0,20}\\r?\\n((?:[ \\t]{0,20}[A-Za-z0-9+\\/=]{1,200}[ \\t]{0,20}(?:\\r?\\n|$))*(?:[ \\t]{0,20}[A-Za-z0-9+\\/=]{1,200})?)',
    ['private-lines'],
    { multiline: true, allowlists: [] },
  ),
  rule('jwk-private-member', '"(?:d|p|q|dp|dq|qi|k)"\\s{0,20}:\\s{0,20}"([A-Za-z0-9_-]{16,4096})', ['kty'], { entropy: 3, multiline: true, allowlists: [] }),
  rule('rsa-private-parameters', '"(?:d|p|q|dp|dq|inverseq|D|P|Q|DP|DQ|InverseQ)"\\s{0,20}:\\s{0,20}"([A-Za-z0-9+\\/=_-]{16,4096})', ['inverseq'], {
    entropy: 3,
    multiline: true,
    allowlists: [],
  }),
  rule('rsa-private-parameters-xml', '<(D|P|Q|DP|DQ|InverseQ)>[ \\t\\r\\n]{0,40}([A-Za-z0-9+\\/=]{1,4096}(?:[ \\t\\r\\n]{1,40}[A-Za-z0-9+\\/=]{1,4096}){0,64})', ['inverseq'], {
    secretGroup: 2,
    entropy: 3,
    multiline: true,
    allowlists: [],
  }),
  rule('gpg-private-key-sexp', '\\((?:d|p|q|u)[ \\t\\r\\n]{1,20}#([0-9A-Fa-f \\t\\r\\n]{32,8192})', ['private-key'], { entropy: 2.5, multiline: true, allowlists: [] }),
  rule(
    'password-hash',
    '\\$[56]\\$(?:rounds=\\d{1,9}\\$)?[.\\/A-Za-z0-9]{1,16}\\$[.\\/A-Za-z0-9]{43,86}|\\$y\\$[.\\/A-Za-z0-9]{1,30}\\$[.\\/A-Za-z0-9]{1,86}\\$[.\\/A-Za-z0-9]{43}|\\$2[abxy]?\\$\\d{2}\\$[.\\/A-Za-z0-9]{53}|\\$1\\$[.\\/A-Za-z0-9]{1,8}\\$[.\\/A-Za-z0-9]{22}',
    ['$6$', '$5$', '$y$', '$2', '$1$'],
    { secretGroup: 0, allowlists: [] },
  ),
  rule('svn-simple-password', 'K 8\\r?\\npassword\\r?\\nV \\d{1,5}\\r?\\n([^\\r\\n]{1,1000})', ['password'], { multiline: true, allowlists: [] }),
]
