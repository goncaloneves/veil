import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { base64Encode } from '../src/core/encoding.ts'
import { compileRules, findRuleSpans } from '../src/core/rules.ts'
import { ruleSet } from '../src/rules/index.ts'
import { fake, fakeToken, keyHeader, seeded } from './helpers.ts'

const compiled = compileRules(ruleSet)
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const HEX = '0123456789abcdef'

function hits(text: string): { id: string; text: string }[] {
  return findRuleSpans(text, compiled).map(span => ({ id: span.label, text: text.slice(span.start, span.end) }))
}

function covers(text: string, value: string): boolean {
  const at = text.indexOf(value)
  return findRuleSpans(text, compiled).some(span => span.start <= at && at + value.length <= span.end)
}

function expectMasked(cases: readonly (readonly [string, string, string])[]): void {
  for (const [id, text, value] of cases) {
    const found = hits(text)
    assert.ok(
      found.some(hit => hit.id === id),
      `${id} not in ${JSON.stringify(found.map(hit => hit.id))} for ${JSON.stringify(text.slice(0, 120))}`,
    )
    if (value) assert.ok(covers(text, value), `${JSON.stringify(value)} not fully masked in ${JSON.stringify(text.slice(0, 120))}`)
  }
}

function expectClean(texts: readonly string[]): void {
  for (const text of texts) assert.deepEqual(hits(text), [], text)
}

describe('veil rules: tokens gitleaks misses', () => {
  const random = seeded(60)

  it('masks every Anthropic token family, OAuth access and refresh included', () => {
    const cases: [string, string, string][] = []
    for (const kind of ['api03', 'admin01', 'oat01', 'ort01', 'sid01']) {
      const token = fake.anthropic(random, kind)
      const short = `${token.slice(0, 50)}`
      cases.push(['anthropic-token', `{"claudeAiOauth":{"accessToken":"${token}"}}`, token])
      cases.push(['anthropic-token', `key ${short}`, short])
    }
    expectMasked(cases)
    expectClean([`${['sk', 'ant', 'api03'].join('-')}-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, `${['sk', 'ant', 'api03'].join('-')}-...`])
  })

  it('masks Google OAuth access and refresh tokens and client secrets', () => {
    const access = fake.googleAccess(random)
    const refresh = fake.googleRefresh(random)
    const client = `${['GOC', 'SPX-'].join('')}${fakeToken(random, 28)}`
    expectMasked([
      ['google-oauth-access-token', `$ gcloud auth print-access-token\n${access}\n`, access],
      ['google-oauth-refresh-token', `"refresh_token": "${refresh}",`, refresh],
      ['google-oauth-client-secret', `"client_secret": "${client}"`, client],
    ])
  })

  it('masks Supabase access tokens and secret keys', () => {
    const access = `${['sb', 'p_'].join('')}${fake.hex(random, 40)}`
    const secret = `${['sb', 'secret', ''].join('_')}${fakeToken(random, 32)}`
    expectMasked([
      ['supabase-token', access, access],
      ['supabase-token', `SUPABASE_KEY=${secret}`, secret],
    ])
  })
})

describe('veil rules: passwords in configs', () => {
  const random = seeded(61)
  const pw = fake.symbolPassword(random)
  const alnum = `${fakeToken(random, 10)}9q`

  it('masks a password with symbols in YAML, TOML, INI, properties, env, compose and systemd', () => {
    expectMasked([
      ['password-assignment', `db:\n  password: ${pw}\n`, pw],
      ['password-assignment', `password = "${pw}"`, pw],
      ['password-assignment', `[client]\npassword=${pw}\n`, pw],
      ['password-assignment', `spring.datasource.password=${pw}`, pw],
      ['password-assignment', `DB_PASSWORD='${pw}'`, pw],
      ['password-assignment', `    environment:\n      - POSTGRES_PASSWORD=${pw}\n`, pw],
      ['password-assignment', `Environment="DB_PASSWORD=${pw}"`, pw],
      ['password-assignment', `psk=${pw}`, pw],
      ['password-assignment', `pass_phrase = ${pw}`, pw],
      ['password-assignment', `SECRET_KEY = '${pw}'`, pw],
      ['password-assignment', `"PASSWORD": "${pw}",`, pw],
      ['password-assignment', `os.environ["DB_PASSWORD"] = "${pw}"`, pw],
      ['password-assignment', `$env:DB_PASS = "${pw}"`, pw],
    ])
  })

  it('masks XML elements and attributes, PHP define and connection strings', () => {
    expectMasked([
      ['password-xml-element', `<server><id>x</id><password>${alnum}</password></server>`, alnum],
      ['password-xml-element', `<db:Password>${pw}</db:Password>`, pw],
      ['password-xml-attribute', `<add key="ClearTextPassword" value="${alnum}" />`, alnum],
      ['password-argument', `define('DB_PASSWORD', '${pw}');`, pw],
      ['connection-string-password', `Server=db;Database=app;User Id=sa;Password=${pw};Encrypt=true`, pw],
      ['connection-string-password', `Driver={x};Pwd={${pw}};`, pw],
      ['url-query-password', `jdbc:mysql://h:3306/db?user=root&password=${alnum}&ssl=true`, alnum],
      ['jdbc-oracle-password', `jdbc:oracle:thin:scott/${alnum}@db:1521:orcl`, alnum],
    ])
  })

  it('leaves references, templates, placeholders, types, code and prose alone', () => {
    expectClean([
      'password: process.env.DB_PASSWORD',
      'password = ${DB_PASSWORD}',
      'password: ${{ secrets.DB_PASSWORD }}',
      'password: "{{ vault_db_password }}"',
      'PASSWORD=$(op read op://vault/db/password)',
      'PGPASSWORD=$DB_PASS psql',
      '<password>${env.MAVEN_PASS}</password>',
      'password: changeme',
      'password: "<password>"',
      'password: <your-password>',
      'password: ********',
      'password: [REDACTED]',
      'password: string',
      'password?: string | undefined',
      'password: Option<String>,',
      'password: Optional[str] = None',
      'password: z.string().min(8),',
      '"password": "Passwort"',
      '"password": "Contrase\u00f1a"',
      '"forgot_password": "Forgot password?"',
      'password_min_length: 12',
      'PASSWORD_RESET_URL=https://example.com/reset',
      'bypass = "localhost,127.0.0.1"',
      'const password = userPassword',
      'password = os.getenv("DB_PASSWORD")',
      'self.password = password',
      'password = password.trim()',
      '$pw = ConvertTo-SecureString $plain -AsPlainText',
      'secret: kv/data/app',
      'secretName: db-creds',
      'PWD=/home/dev/project',
      'PWD=C:\\Users\\dev\\project',
      'password = var.db_password',
      'password: YOUR_PASSWORD',
    ])
  })
})

describe('veil rules: Windows output, shells and XML', () => {
  const random = seeded(66)
  const pw = fake.symbolPassword(random)
  const token = fakeToken(random, 40)

  it('masks secret-named values in reg query, Get-ChildItem env: tables and Format-List', () => {
    expectMasked([
      ['windows-registry-value', `HKEY_CURRENT_USER\\Environment\r\n    API_TOKEN    REG_SZ    ${token}\r\n    Path    REG_EXPAND_SZ    C:\\bin\r\n`, token],
      ['windows-registry-value', `    DB_PASSWORD    REG_SZ    ${pw}`, pw],
      ['environment-table-value', `Name                           Value\r\n----                           -----\r\nGITHUB_TOKEN                   ${token}\r\nHOME                           C:\\Users\\dev\r\n`, token],
      ['environment-list-value', `Name  : OPENAI_API_KEY\r\nValue : ${token.slice(0, 20)}\r\n        ${token.slice(20)}\r\n`, token.slice(20)],
    ])
    expectClean(['    Path    REG_EXPAND_SZ    %USERPROFILE%\\bin', 'HOME                           C:\\Users\\dev', 'Name  : PATH\r\nValue : C:\\bin'])
  })

  it('masks fish, csh and fish_variables secrets', () => {
    expectMasked([
      ['shell-set-password', `set -gx DB_PASSWORD '${pw}'`, pw],
      ['shell-set-password', `setenv SMTP_PASS ${pw}`, pw],
      ['shell-set-password', `SETUVAR --export DB_PASSWORD:${pw}`, pw],
    ])
    expectClean(['set -gx DB_PASSWORD $argv[1]', 'set -x EDITOR vim'])
  })

  it('masks hex keys whose entropy is below the generic rule floor', () => {
    let hex = ''
    while (hex.length < 32) hex += fakeToken(random, 4, '0123456789abc')
    expectMasked([['hex-api-key', `api_key = "${hex}"`, hex]])
    expectClean([`"cacheKey": "${fake.hex(random, 32)}"`, `"key_id": "${fake.hex(random, 32)}"`, `public_key: ${fake.hex(random, 64)}`, `commit: ${fake.hex(random, 40)}`])
  })

  it('masks tokens in XML elements, where the value ends at <', () => {
    expectMasked([
      ['token-xml-element', `<apiKey>${token}</apiKey>`, token],
      ['token-xml-element', `<ns:accessToken>${token}</ns:accessToken>`, token],
    ])
    expectClean(['<tokenEndpoint>https://login.example.com/oauth2/token</tokenEndpoint>', '<secretName>db-creds</secretName>', '<apiKey>${API_KEY}</apiKey>'])
  })
})

describe('veil rules: headers, cookies and URLs', () => {
  const random = seeded(62)

  it('masks Authorization, Proxy-Authorization and API key headers in any context', () => {
    const bearer = fakeToken(random, 40)
    const basic = base64Encode(`ci:${fakeToken(random, 20)}`)
    const key = fakeToken(random, 32)
    expectMasked([
      ['authorization-header', `"headers": {"Authorization": "Bearer ${bearer}"}`, bearer],
      ['authorization-header', `> Authorization: Bearer ${bearer}`, bearer],
      ['authorization-header', `-H 'Proxy-Authorization: Basic ${basic}'`, basic],
      ['authorization-header', `\textraheader = AUTHORIZATION: basic ${basic}`, basic],
      ['authorization-header', `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20${bearer}`, bearer],
      ['authorization-header', `-Headers @{Authorization = "token ${bearer}"}`, bearer],
      ['api-key-header', `X-Api-Key: ${key}`, key],
      ['api-key-header', `"x-goog-api-key": "${key}"`, key],
    ])
    expectClean([
      'Authorization: Bearer ${TOKEN}',
      'Authorization: Bearer <token>',
      'const authorization = request.headers.authorization',
      'authorization: required for every endpoint',
      'X-Api-Key: <your-api-key>',
    ])
  })

  it('masks session cookies but not Windows SIDs', () => {
    const session = fakeToken(random, 40)
    expectMasked([
      ['session-cookie', `Set-Cookie: session=${session}; Path=/; HttpOnly`, session],
      ['session-cookie', `Cookie: theme=dark; connect.sid=${session}`, session],
      ['session-cookie', `PHPSESSID=${session}`, session],
    ])
    expectClean(['sid=S-1-5-21-3623811015-3361044348-30300820-1013', 'session_timeout=3600'])
  })

  it('masks URL credentials with an empty user, an @ in the password, or only a token', () => {
    const password = fakeToken(random, 20)
    const token = fakeToken(random, 40)
    expectMasked([
      ['url-credentials', `REDIS_URL=redis://:${password}@cache:6379/0`, password],
      ['url-credentials', `postgres://app:p@ss${password}@db/app`, `p@ss${password}`],
      ['url-token-userinfo', `url = https://${token}@github.com/org/repo.git`, token],
      ['url-query-token', `https://s3.example/x?X-Amz-Signature=${fake.hex(random, 64)}&a=1`, ''],
    ])
    expectClean([
      'postgres://user:password@localhost/db',
      'redis://default:${REDIS_PASS}@cache:6379',
      `https://${fake.hex(random, 32)}@o123.ingest.sentry.io/456`,
      'ssh://git@github.com/org/repo.git',
      'https://user@example.com/',
    ])
  })
})

describe('veil rules: command lines and history', () => {
  const random = seeded(63)
  const pw = `${fakeToken(random, 10)}7x`

  it('masks password flags, sshpass, registry logins, openssl, PowerShell and curl -u', () => {
    expectMasked([
      ['mysql-password-flag', `mysql -u root -p${pw} app`, pw],
      ['mysql-password-flag', `mysqldump -p'${pw}' app > a.sql`, pw],
      ['sshpass-password', `sshpass -p '${pw}' ssh deploy@host`, pw],
      ['registry-login-password', `docker login -u me -p ${pw} ghcr.io`, pw],
      ['cli-password-flag', `psql --password=${pw} -h db`, pw],
      ['cli-password-flag', `keytool -list -storepass ${pw}`, pw],
      ['cli-token-flag', `vault login --token ${fakeToken(random, 30)}`, ''],
      ['openssl-pass-argument', `openssl rsa -in k.pem -passin pass:${pw}`, pw],
      ['powershell-secure-string', `$p = ConvertTo-SecureString "${pw}" -AsPlainText -Force`, pw],
      ['powershell-secure-string', `ConvertTo-SecureString -String '${pw}' -AsPlainText -Force`, pw],
      ['curl-user-password', `curl -u admin:${pw} https://h/api`, pw],
    ])
    expectClean(['mkdir -p build/out', 'psql --password-stdin', 'docker login --password-stdin', 'openssl rsa -passin env:KEY_PASS', 'docker run -u 1000:1000 img', 'git push -u origin main'])
  })

  it('masks database history: SQL, mysql \\040 escapes, mongosh and redis', () => {
    expectMasked([
      ['sql-password', `ALTER USER app WITH PASSWORD '${pw}';`, pw],
      ['sql-password', `CREATE USER 'x'@'%' IDENTIFIED WITH mysql_native_password BY '${pw}';`, pw],
      ['sql-password', `CREATE\\040USER\\040x\\040IDENTIFIED\\040BY\\040'${pw}';`, pw],
      ['mongo-auth', `db.auth('admin', '${pw}')`, pw],
      ['redis-auth', `127.0.0.1:6379> AUTH ${pw}\nOK`, pw],
      ['redis-auth', `AUTH default ${pw}`, pw],
      ['redis-auth', `requirepass ${pw}`, pw],
      ['redis-auth', `CONFIG SET masterauth ${pw}`, pw],
    ])
    expectClean(['Auth is hard', 'The password is long.'])
  })
})

describe('veil rules: private keys', () => {
  const random = seeded(64)
  const lines = (count: number) => Array.from({ length: count }, () => fakeToken(random, 64, B64)).join('\n')

  it('masks a private key block that has no END line, to the end of its body', () => {
    const body = lines(4)
    const text = `$ head -n 5 key.pem\n${keyHeader('RSA')}\n${body}\n$ ls\n`
    expectMasked([['private-key-block', text, body]])
    assert.ok(text.slice(findRuleSpans(text, compiled)[0]?.end).startsWith('\n$ ls'))
  })

  it('masks PGP private key blocks with armor headers, and SSH2 blocks', () => {
    const body = lines(3)
    expectMasked([
      ['private-key-block', `${keyHeader('PGP', { block: true })}\nVersion: GnuPG v2\n\n${body}\n=${fakeToken(random, 4)}\n${keyHeader('PGP', { block: true, end: true })}`, body],
      ['private-key-block', `${keyHeader('SSH2 ENCRYPTED', { ssh2: true })}\nComment: "x"\n${body}\n`, body],
      ['private-key-block', `{"private_key": "${keyHeader()}\\n${body.replaceAll('\n', '\\n')}`, body.split('\n')[2] ?? ''],
    ])
    expectClean(['-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----'])
  })

  it('masks the private lines of a PuTTY key, and nothing public', () => {
    const publicLines = lines(2)
    const privateLines = lines(2)
    const text = `PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 2\n${publicLines}\nPrivate-Lines: 2\n${privateLines}\nPrivate-MAC: ${fake.hex(random, 64)}\n`
    expectMasked([['putty-private-key', text, privateLines]])
    assert.ok(!covers(text, publicLines))
  })

  it('masks private JWK members, RSA parameters and GnuPG key s-expressions', () => {
    const d = fakeToken(random, 43, `${B64.slice(0, 62)}-_`)
    const inverse = fakeToken(random, 172, B64)
    const hex = fakeToken(random, 128, HEX.toUpperCase())
    expectMasked([
      ['jwk-private-member', `{"kty":"EC","crv":"P-256","x":"${fakeToken(random, 43)}","d":"${d}"}`, d],
      ['jwk-private-member', `{\n  "kty": "oct",\n  "k": "${d}"\n}`, d],
      ['rsa-private-parameters', `{"d":"${inverse}","inverseQ":"${inverse.slice(0, 80)}"}`, inverse],
      ['rsa-private-parameters-xml', `<RSAKeyValue><D>${inverse}</D><InverseQ>${inverse.slice(0, 80)}</InverseQ></RSAKeyValue>`, inverse],
      ['gpg-private-key-sexp', `Key: (private-key (rsa (n #00${fake.hex(random, 128)}#)(e #010001#)(d #${hex}#)))`, hex],
    ])
    expectClean([`{"kty":"EC","crv":"P-256","x":"${fakeToken(random, 43)}","y":"${fakeToken(random, 43)}"}`, '{"d":"M10 10 L20 20 Z"}'])
  })

  it('masks crypt password hashes', () => {
    const hash = `$6$${fakeToken(random, 8)}$${fakeToken(random, 86, `${B64.slice(0, 62)}./`)}`
    expectMasked([['password-hash', `root:${hash}:19000:0:99999:7:::`, hash]])
  })
})

describe('veil rules: review findings', () => {
  const random = seeded(67)

  it('leaves minified comparisons and call chains alone', () => {
    expectClean([
      'if(a.password===b.passwordConfirmation)return',
      'a.password==b.password',
      "secret: crypto.randomBytes(32).toString('hex'),",
      'passphrase: Buffer.from(env.P, "utf8"),',
      'token = request.headers["x-token"]',
    ])
  })

  it('masks dotted literal passwords when they are quoted or inside an element', () => {
    const dotted = `${fakeToken(random, 3)}9.${fakeToken(random, 4)}2.${fakeToken(random, 4)}`
    expectMasked([
      ['cli-password-flag', `mysqladmin --password '${dotted}' status`, dotted],
      ['password-xml-element', `<password>${dotted}</password>`, dotted],
      ['password-assignment', `DB_PASSWORD="${dotted}"`, dotted],
    ])
  })

  it('masks a Google client secret that ends in a hyphen', () => {
    const client = `${['GOC', 'SPX-'].join('')}${fakeToken(random, 27)}-`
    expectMasked([['google-oauth-client-secret', `"client_secret": "${client}"`, client]])
  })

  it('masks key bodies collapsed onto one line or escaped twice, and a last line cut before an ellipsis', () => {
    const chunks = Array.from({ length: 3 }, () => fakeToken(random, 64, B64))
    const partial = fakeToken(random, 30, B64)
    expectMasked([
      ['private-key-block', `echo $KEY\n${keyHeader('RSA')} ${chunks.join(' ')} ${keyHeader('RSA', { end: true })}`, chunks[1] ?? ''],
      ['private-key-block', `"${keyHeader()}\\\\n${chunks.join('\\\\n')}\\\\n"`, chunks[2] ?? ''],
      ['private-key-block', `${keyHeader('EC')}\n${chunks[0]}\n${partial}\u2026`, partial],
      ['private-key-block', `${keyHeader('EC')} ${chunks[0]}\u2026`, chunks[0] ?? ''],
    ])
    expectClean([`${keyHeader()} is how a key file starts`])
  })

  it('never masks an existing placeholder again', () => {
    expectClean([
      'password: [veil:password-assignment#3fa2c1]',
      'DB_PASSWORD=[veil:DB_PASSWORD]',
      'redis://:[veil:url-credentials#9b1e44aa]@cache:6379',
      'Authorization: Bearer [veil:authorization-header#0a1b2c]',
      '<password>[veil:db/password]</password>',
    ])
  })

  it('applies none of the gitleaks global allowlists to veil rules', () => {
    const value = `${fakeToken(random, 4)}false${fakeToken(random, 6)}`
    expectMasked([['password-assignment', `password: "${value}"`, value]])
  })
})

describe('veil rules: verification findings', () => {
  const random = seeded(68)
  const lines = (count: number) => Array.from({ length: count }, () => fakeToken(random, 64, B64)).join('\n')

  it('masks armoured keys larger than one keyword window, END line included', () => {
    for (const count of [520, 631]) {
      const body = lines(count)
      const end = keyHeader('PGP', { block: true, end: true })
      const text = `${keyHeader('PGP', { block: true })}\nVersion: x\n\n${body}\n=${fakeToken(random, 4)}\n${end}\nafter\n`
      const spans = findRuleSpans(text, compiled).filter(span => span.label === 'private-key-block')
      const last = body.split('\n').pop() ?? ''
      assert.ok(spans.some(span => span.start <= text.indexOf(body) && text.indexOf(end) + end.length <= span.end), `${count} lines`)
      assert.ok(covers(text, last))
    }
  })

  it('masks base64 encoded PEM private keys, as kubectl shows tls.key, and not certificates', () => {
    const pem = `${keyHeader('RSA')}\n${lines(8)}\n${keyHeader('RSA', { end: true })}\n`
    const encoded = base64Encode(pem)
    const wrapped = (encoded.match(/.{1,76}/g) ?? []).join('\n')
    const certificate = base64Encode(`-----BEGIN ${['CERTIFI', 'CATE'].join('')}-----\n${lines(4)}\n`)
    expectMasked([
      ['private-key-base64', `data:\n  tls.crt: ${certificate}\n  tls.key: ${encoded}\n`, encoded],
      ['private-key-base64', wrapped, wrapped],
    ])
    assert.ok(!hits(`tls.crt: ${certificate}`).some(hit => hit.id === 'private-key-base64'))
  })

  it('leaves the description column of environment variable tables alone', () => {
    expectClean([
      'GITHUB_TOKEN    Token used to call the GitHub API (required)',
      'API_KEY         Your key from the dashboard',
      'DB_PASSWORD     Password of the database user',
      'AWS_SECRET_ACCESS_KEY    Secret key paired with the access key id',
    ])
    const token = fakeToken(random, 40)
    expectMasked([['environment-table-value', `GITHUB_TOKEN                   ${token}\r\n`, token]])
  })

  it('masks keys whose names only contain a non-secret word inside another word', () => {
    const secret = `${fake.hex(random, 16)}${fake.password(random)}`
    const hex = fake.hex(random, 32)
    for (const name of ['IDENTITY_TOKEN', 'IDENTITY_KEY', 'ESCROW_KEY']) {
      assert.ok(covers(`${name} = "${secret}"`, secret), name)
      assert.ok(covers(`${name}: ${hex}`, hex), name)
    }
    expectClean([`"stripeIdempotencyKey": "${fake.hex(random, 8)}-${fake.hex(random, 4)}-${fake.hex(random, 4)}-${fake.hex(random, 4)}-${fake.hex(random, 12)}"`])
  })
})

describe('veil rule allowlists for gitleaks rules', () => {
  const random = seeded(65)

  it('leaves idempotency, cache, pagination and site keys, and publishable keys, alone', () => {
    const uuid = `${fake.hex(random, 8)}-${fake.hex(random, 4)}-${fake.hex(random, 4)}-${fake.hex(random, 4)}-${fake.hex(random, 12)}`
    expectClean([
      `"idempotencyKey": "${uuid}"`,
      `idempotency_key: ${uuid}`,
      `"cacheKey": "v2-${fake.hex(random, 32)}"`,
      `"NextToken": "${fakeToken(random, 60)}"`,
      `"nextPageToken": "${fakeToken(random, 60)}"`,
      `RECAPTCHA_SITE_KEY=6L${fakeToken(random, 38)}`,
      `STRIPE_PUBLISHABLE_KEY=${['pk', 'live', ''].join('_')}${fakeToken(random, 24)}`,
      `publishableKey: "${['pk', 'test', ''].join('_')}${fakeToken(random, 24)}"`,
      `key: brave-tiger-${fake.hex(random, 4)}9`,
    ])
  })

  it('no longer exempts a value that merely contains true, false or null', () => {
    const secret = `${fake.hex(random, 10)}false${fake.password(random)}`
    expectMasked([['generic-api-key', `api_key = "${secret}"`, secret]])
  })

  it('checks stopwords only on values short enough for a word inside them to mean something', () => {
    const long = `${fakeToken(random, 40)}crud${fakeToken(random, 40)}1`
    assert.ok(covers(`api_key = "${long}"`, long))
  })

  it('still masks real keys under those rules', () => {
    const secret = `${fake.hex(random, 16)}${fake.password(random)}`
    expectMasked([
      ['generic-api-key', `api_key = "${secret}"`, secret],
      ['generic-api-key', `"storageKey": "${secret}"`, secret],
    ])
  })

  it("leaves a Supabase anon key alone but masks a service-role key", () => {
    const encode = (value: object) => base64Encode(JSON.stringify(value), true)
    const header = encode({ alg: 'HS256', typ: 'JWT' })
    const anon = `${header}.${encode({ iss: 'supabase', ref: fakeToken(random, 20), role: 'anon', iat: 1700000000 })}.${fakeToken(random, 43)}`
    const service = `${header}.${encode({ iss: 'supabase', ref: fakeToken(random, 20), role: 'service_role', iat: 1700000000 })}.${fakeToken(random, 43)}`
    assert.ok(!hits(`SUPABASE_ANON_KEY=${anon}`).some(hit => hit.id === 'jwt'))
    assert.ok(hits(`SUPABASE_SERVICE_ROLE_KEY=${service}`).some(hit => hit.id === 'jwt'))
  })
})
