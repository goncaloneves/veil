import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { DEFAULT_CONFIG } from '../src/config/config.ts'
import { base64Encode } from '../src/core/encoding.ts'
import { isSecretKey } from '../src/sources/env-policy.ts'
import { ENVIRONMENT_KEYS, LOCATION_KEYS, environmentSecrets, parseEnviron } from '../src/sources/environment.ts'
import { loadSecrets } from '../src/sources/load.ts'
import { fake, fakeToken, memoryFs, seeded } from './helpers.ts'

const random = seeded(303)
const token = (length = 32) => fakeToken(random, length)
const policy = { secretKeys: [], ignoreKeys: [] }

function block(source: string, start: string): string[] {
  const from = source.indexOf(start)
  const body = source.slice(from, source.indexOf(']),', from))
  return [...body.matchAll(/\$\.env\.get\('([A-Za-z0-9_]+)'\)/g)].map(match => match[1] ?? '')
}

describe('the process environment', () => {
  it('splits /proc/self/environ on NUL and keeps = inside values', () => {
    const value = `${token()}==`
    assert.deepEqual(parseEnviron(`A=1\0B_TOKEN=${value}\0EMPTY=\0BROKEN\0`), { A: '1', B_TOKEN: value, EMPTY: '' })
  })

  it('takes secret-named variables from a full environment and leaves system values alone', () => {
    const [jwt, github, pin] = [token(), fake.githubPat(random), '4821']
    const vars = {
      PWD: '/home/me/project',
      OLDPWD: '/home/me',
      PATH: `/usr/local/bin:/usr/bin:/home/me/.local/${token(40)}/bin`,
      HOSTNAME: fake.hex(random, 12),
      TERM_SESSION_ID: `w0t0p0:${token(8)}-${token(4)}-${token(4)}-${token(12)}`,
      INVOCATION_ID: fake.hex(random, 32),
      BUILD_HASH: token(40),
      GIT_COMMIT: fake.hex(random, 40),
      SSH_AUTH_SOCK: '/private/tmp/com.apple.launchd.x/Listeners',
      GOOGLE_APPLICATION_CREDENTIALS: '/home/me/keys/sa.json',
      MAX_THINKING_TOKENS: '31999',
      JWT_SIGNING_SECRET: jwt,
      GITHUB_TOKEN: github,
      ADMIN_PIN: pin,
      SHORT_PASS: 'abc',
    }
    const found = environmentSecrets(vars, policy)
    assert.deepEqual(found.map(secret => [secret.name, secret.strong === true]), [['JWT_SIGNING_SECRET', true], ['GITHUB_TOKEN', true], ['ADMIN_PIN', true]])
  })

  it('skips publishable and public values, and DSNs without a password', () => {
    const vars = {
      STRIPE_PUBLISHABLE_KEY: `pk_live_${token(40)}`,
      CLERK_KEY: `pk_test_${token(40)}`,
      SUPABASE_ANON_KEY: fake.jwt(random, 40),
      GOOGLE_CLIENT_ID: `${fake.hex(random, 12)}-${token(32).toLowerCase()}.apps.googleusercontent.com`,
      RECAPTCHA_SITE_KEY: token(40),
      JWT_PUBLIC_KEY: token(60),
      SENTRY_DSN: `https://${fake.hex(random, 32)}@o12345.ingest.sentry.io/678`,
      NEXT_PUBLIC_API_KEY: token(),
      NUXT_PUBLIC_TOKEN: token(),
    }
    assert.deepEqual(environmentSecrets(vars, policy), [])
    const legacy = token(32)
    const old = environmentSecrets({ SENTRY_DSN: `https://${fake.hex(random, 32)}:${legacy}@sentry.example/1` }, policy)
    assert.deepEqual(old.map(secret => secret.name), ['SENTRY_DSN', 'SENTRY_DSN.password'])
  })

  it('reads OTLP header lists and JSON-valued variables', () => {
    const [bearer, apiKey, dockerPass] = [token(), token(), token(16)]
    const auth = base64Encode(`me:${dockerPass}`)
    const found = environmentSecrets(
      {
        OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer%20${bearer},x-api-key=${apiKey},x-tenant=acme`,
        DOCKER_AUTH_CONFIG: JSON.stringify({ auths: { 'registry.example.com': { auth } } }),
      },
      policy,
    )
    assert.deepEqual(found.map(secret => secret.value).sort(), [`Bearer ${bearer}`, bearer, apiKey, JSON.stringify({ auths: { 'registry.example.com': { auth } } }), auth].sort())
  })

  it('counts KEY and TOKEN anywhere in a name, and strips version and stage suffixes', () => {
    const names = ['API_TOKEN_V2', 'STRIPE_KEY_LIVE', 'TOKEN_GITHUB', 'GITHUB_TOKEN_RO', 'API_KEY_OLD', 'NPM_TOKEN_PUBLISH', 'OCI_PASS_PHRASE', 'SSH_PRIVKEY', 'APP_PASSKEY']
    const found = environmentSecrets(Object.fromEntries(names.map(name => [name, token()])), policy)
    assert.deepEqual(found.map(secret => secret.name), names)
    assert.deepEqual(found.filter(secret => secret.strong).map(secret => secret.name), ['OCI_PASS_PHRASE', 'SSH_PRIVKEY', 'APP_PASSKEY'])
    assert.deepEqual(['SESSION_DRIVER', 'KEY_PREFIX', 'TOKEN_TTL_SECONDS', 'AWS_ACCESS_KEY_ID', 'PUBLIC_KEY_ID', 'NODE_ENV', 'OPENAI_KEY_ENV_VAR'].filter(isSecretKey), [])
  })

  it('treats ENV or VAR as a reference word only after the secret word, and keeps private GPG keys', () => {
    const secret = ['ENV_API_KEY', 'ENV_DB_PASSWORD', 'PROD_ENV_SECRET', 'envPassword', 'GPG_PRIVATE_KEY', 'GPG_SECRET_KEY', 'GPG_SIGNING_KEY', 'PGP_PRIVATE_KEY']
    const found = environmentSecrets(Object.fromEntries(secret.map(name => [name, token()])), policy)
    assert.deepEqual(found.map(item => item.name), secret)
    assert.deepEqual(['token_env', 'OPENAI_KEY_ENV_VAR', 'api_key_env_var', 'env_key', 'GPG_KEY', 'GPG_KEYS'].filter(name => environmentSecrets({ [name]: token() }, policy).length > 0), [])
  })

  it('treats header, URL and similar label names as non-secret, and wants a random value when KEY or TOKEN is not the last word', () => {
    const vars = { TOKEN_HEADER: 'Authorization', JWT_TOKEN_HEADER: 'X-Token', TOKEN_URL: 'https://auth.example/token', KEY_AUDIENCE: 'api.example', TOKEN_ISSUER: 'acme', API_KEY_PARAM: 'apikey', TOKEN_SCOPE: 'read:all', TOKEN_COOKIE_DOMAIN: 'example.com', KEY_ROTATION: 'monthly' }
    assert.deepEqual(environmentSecrets(vars, policy), [])
    const random = token()
    assert.deepEqual(environmentSecrets({ TOKEN_GITHUB: random }, policy).map(item => item.value), [random])
  })

  it('leaves fingerprints, PDO DSNs without a password, file URLs, terminal sessions and credential paths alone', () => {
    const vars = {
      GPG_KEY: fake.hex(random, 40).toUpperCase(),
      GPG_KEYS: `${fake.hex(random, 40)} ${fake.hex(random, 40)}`,
      DB_DSN: 'mysql:host=db;dbname=app;charset=utf8mb4',
      DATABASE_URL: 'file:./dev.db',
      WT_SESSION: `${fake.hex(random, 8)}-${fake.hex(random, 4)}-${fake.hex(random, 4)}-${fake.hex(random, 4)}-${fake.hex(random, 12)}`,
      GOOGLE_APPLICATION_CREDENTIALS: './gcp-key.json',
    }
    assert.deepEqual(environmentSecrets(vars, policy), [])
    const pdo = environmentSecrets({ DB_DSN: `mysql:host=db;dbname=app;password=${token(16)}` }, policy)
    assert.deepEqual(pdo.map(secret => secret.name), ['DB_DSN.password'])
  })

  it('treats TF_TOKEN_ and OP_SESSION_ variables as secret', () => {
    const found = environmentSecrets({ TF_TOKEN_app_terraform_io: token(), OP_SESSION_my: token() }, policy)
    assert.equal(found.length, 2)
  })

  it('loads every variable from /proc/self/environ, with literal reads taking precedence', async () => {
    const [fromProc, fromVars] = [token(), token()]
    const config = { ...DEFAULT_CONFIG, sources: { ...DEFAULT_CONFIG.sources, project: false, home: false, system: false } }
    const loaded = await loadSecrets(memoryFs({}), { home: '/home/me', root: '/repo', vars: { GITHUB_TOKEN: fromVars }, environ: `POSTGRES_ADMIN_PASSWORD=${fromProc}\0GITHUB_TOKEN=stale-${token(8)}\0HOME=/home/me\0` }, config)
    assert.deepEqual(loaded.secrets.map(secret => [secret.name, secret.value]), [['POSTGRES_ADMIN_PASSWORD', fromProc], ['GITHUB_TOKEN', fromVars]])
  })
})

describe('environment files and diagnostics', () => {
  const config = { ...DEFAULT_CONFIG, sources: { ...DEFAULT_CONFIG.sources, project: false, home: false, system: false } }

  it('reads the file named by a *_PASSWORD_FILE or *_TOKEN_FILE variable', async () => {
    const [password, tokenValue] = [token(), token()]
    const fs = memoryFs({ '/run/app/db-password': `${password}\n`, '/run/app/api-token': tokenValue })
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: { POSTGRES_PASSWORD_FILE: '/run/app/db-password', API_TOKEN_FILE: '/run/app/api-token', CONFIG_FILE: '/etc/app.conf' } }, config)
    assert.deepEqual(loaded.secrets.map(secret => [secret.name, secret.value]), [['POSTGRES_PASSWORD_FILE', password], ['API_TOKEN_FILE', tokenValue]])
  })

  it('never follows a *_KEY_FILE variable to a public key', async () => {
    const fs = memoryFs({ '/keys/id.pub': `ssh-ed25519 ${token(68)} me`, '/keys/deploy.pem': fake.privateKey(random) })
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: { SSH_KEY_FILE: '/keys/id.pub', PUBLIC_KEY_FILE: '/keys/deploy.pem', DEPLOY_KEY_FILE: '/keys/deploy.pem' } }, config)
    assert.deepEqual(loaded.files.map(file => file.path), ['/keys/deploy.pem'])
  })

  it('warns when /proc/self/environ could not be read, and notes when it read empty', async () => {
    const failed = await loadSecrets(memoryFs({}), { home: '/home/me', root: '/repo', vars: {}, environ: null }, config)
    assert.match(failed.warnings.join('\n'), /could not read \/proc\/self\/environ/)
    const empty = await loadSecrets(memoryFs({}), { home: '/home/me', root: '/repo', vars: {}, environ: '' }, config)
    assert.deepEqual(empty.errors.map(error => [error.path, error.quiet]), [['/proc/self/environ', true]])
  })
})

describe('the Claude Code hooks module', () => {
  const source = readFileSync(new URL('../hooks/register.ts', import.meta.url), 'utf8')

  it('reads every location variable the loader uses, by literal name', () => {
    assert.deepEqual(block(source, 'locations: await settled([').sort(), [...LOCATION_KEYS].sort())
  })

  it('gives every hook that gates text or a tool call a .catch', () => {
    const registrations = source.split('\n  on(').slice(1)
    const gating = registrations.filter(hook => /^'(?:tool\.call|prompt\.submit|prompt\.mention|session\.append|session\.send|session\.receive|command\.run)'/.test(hook) && !hook.startsWith("'command.run', { command: 'veil' }"))
    assert.ok(gating.some(hook => hook.startsWith("'tool.call', { tool: 'Edit' }")))
    assert.equal(gating.length, 10)
    for (const hook of gating) assert.match(hook, /\.catch\(\s*\(\$, e, next\) =>/, hook.slice(0, 60))
  })

  it('reads every known secret variable by literal name, with no digits the validator could miss', () => {
    assert.deepEqual(block(source, 'vars: await settled([').sort(), [...ENVIRONMENT_KEYS].sort())
    assert.ok(ENVIRONMENT_KEYS.every(name => /^[A-Za-z_]+$/.test(name)))
  })
})
