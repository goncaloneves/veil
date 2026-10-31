import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { DEFAULT_CONFIG, parseConfig } from '../src/config/config.ts'
import { base64Encode } from '../src/core/encoding.ts'
import {
  parseAwsCredentials,
  parseDockerConfig,
  parseGhHosts,
  parseGitCredentials,
  parseKubeConfig,
  parseNetrc,
  parseNpmrc,
  parsePgpass,
} from '../src/sources/credentials.ts'
import { privateKeyBlocks } from '../src/sources/keys.ts'
import { parseDotenv } from '../src/sources/dotenv.ts'
import { envSecrets, isSecretKey, keyWords, urlPassword } from '../src/sources/env-policy.ts'
import { isEnvFileName, loadSecrets } from '../src/sources/load.ts'
import { fake, memoryFs, seeded } from './helpers.ts'

const policy = { secretKeys: [], ignoreKeys: [] }

describe('parseDotenv', () => {
  it('reads plain, exported, quoted and commented values', () => {
    const entries = parseDotenv(`# comment
PLAIN=value one # inline comment
export EXPORTED=exported_value
DOUBLE="has \\"quotes\\" and \\n newline"
SINGLE='keeps \\n as is'
EMPTY=
`)
    assert.deepEqual(entries, [
      { key: 'PLAIN', value: 'value one' },
      { key: 'EXPORTED', value: 'exported_value' },
      { key: 'DOUBLE', value: 'has "quotes" and \n newline' },
      { key: 'SINGLE', value: 'keeps \\n as is', literal: true },
      { key: 'EMPTY', value: '' },
    ])
  })

  it('reads a multi-line quoted private key whole', () => {
    const key = fake.privateKey(seeded(1))
    const entries = parseDotenv(`BEFORE=1\nSSH_PRIVATE_KEY="${key}"\nAFTER=2`)
    assert.deepEqual(entries.map(entry => entry.key), ['BEFORE', 'SSH_PRIVATE_KEY', 'AFTER'])
    assert.equal(entries[1]?.value, key)
  })
})

describe('env policy', () => {
  it('treats secret-looking names as secret', () => {
    assert.ok(isSecretKey('STRIPE_SECRET_KEY'))
    assert.ok(isSecretKey('github-token'))
    assert.ok(isSecretKey('DB_PASSWORD'))
    assert.ok(!isSecretKey('NODE_ENV'))
    assert.ok(!isSecretKey('KEYBOARD_LAYOUT'))
    assert.ok(!isSecretKey('SSH_KEY_PATH'))
    assert.ok(!isSecretKey('SESSION_DRIVER'))
  })

  it('finds the password in a connection URL', () => {
    assert.equal(urlPassword('postgres://app:p%40ss@db:5432/app'), 'p@ss')
    assert.equal(urlPassword('https://example.com/path'), undefined)
  })

  it('masks secret names, URL credentials and random-looking values, and skips the rest', () => {
    const random = seeded(2)
    const token = fake.hex(random, 40)
    const password = fake.password(random)
    const entries = parseDotenv(
      [
        `API_TOKEN=${token}`,
        `DATABASE_URL=postgres://app:${password}@localhost:5432/app`,
        'NODE_ENV=development',
        'APP_NAME=my-application',
        `NEXT_PUBLIC_KEY=${fake.hex(random, 32)}`,
        `SOME_VALUE=${fake.password(random)}${fake.password(random)}`,
        'SHORT_KEY=abc',
      ].join('\n'),
    )
    const names = envSecrets(entries, '.env', policy).map(secret => secret.name)
    assert.deepEqual(names, ['API_TOKEN', 'DATABASE_URL', 'DATABASE_URL.password', 'SOME_VALUE'])
  })

  it('does not take ordinary settings for secrets', () => {
    const entries = parseDotenv(
      [
        'SESSION_DRIVER=database',
        'COOKIE_DOMAIN=localhost',
        'AUTH_URL=http://localhost:3000',
        'AUTH_PROVIDER=keycloak',
        'SSH_KEY_PATH=/home/me/.ssh/id_rsa',
        'TOKEN_TTL_SECONDS=86400000',
        'KEY_PREFIX=myapp:cache',
        'SESSION_COOKIE=true',
        'CACHE_KEY=users_by_id',
      ].join('\n'),
    )
    assert.deepEqual(envSecrets(entries, '.env', policy), [])
  })

  it('finds secrets under many naming styles, including weak values behind strong names', () => {
    const random = seeded(6)
    const entries = parseDotenv(
      [
        `DB_PW=${fake.password(random)}`,
        `SECRETKEY=${fake.password(random)}`,
        `dbPassword=${fake.password(random)}`,
        `REDIS_PASSWORD2=${fake.password(random)}`,
        'DB_PASSWORD=postgres',
        'JWT_SECRET=changeme-in-prod',
        `APP_KEY=base64:${fake.password(random)}`,
        `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0000/B0000/${fake.password(random)}abcd`,
      ].join('\n'),
    )
    assert.deepEqual(
      envSecrets(entries, '.env', policy).map(secret => secret.name),
      ['DB_PW', 'SECRETKEY', 'dbPassword', 'REDIS_PASSWORD2', 'DB_PASSWORD', 'JWT_SECRET', 'APP_KEY', 'SLACK_WEBHOOK_URL'],
    )
  })

  it('treats a strong word inside a longer name as weak, so settings stay readable', () => {
    const random = seeded(9)
    const entries = parseDotenv(
      [
        'AWS_SECRETS_MANAGER_REGION=us-east-1',
        'PASSWORD_HASH_ALGORITHM=argon2id',
        'SECRETS_ENDPOINT=http://localhost:4566',
        'PASSWORD_RESET_URL=https://app.example.com/reset',
        'PASSWORD_MIN_LENGTH=12345678',
        'PIN_ATTEMPTS_MAX=10000000',
        `AWS_SECRET_ACCESS_KEY=${fake.password(random)}${fake.password(random)}`,
        `API_TOKEN=${fake.hex(random, 22)}`,
      ].join('\n'),
    )
    assert.deepEqual(envSecrets(entries, '.env', policy).map(secret => secret.name), ['AWS_SECRET_ACCESS_KEY', 'API_TOKEN'])
  })

  it('keeps short mixed secrets under weak names and ignores stage suffixes', () => {
    const entries = parseDotenv('ADMIN_TOKEN=x7k2m9q4\nLICENSE_KEY=a1b2-c3d4-e5f6-g7h8\nDB_PASSWORD_PROD=correct-horse-battery-staple\nCACHE_KEY=k8s-cache')
    assert.deepEqual(envSecrets(entries, '.env', policy).map(secret => secret.name), ['ADMIN_TOKEN', 'LICENSE_KEY', 'DB_PASSWORD_PROD'])
  })

  it('masks numeric values and plain words behind strong names', () => {
    const entries = parseDotenv('MYSQL_ROOT_PASSWORD=48213977\nVOICEMAIL_PASSCODE=99887766\nBACKUP_OTP=12345678\nADMIN_PASSWORD=letmeinplease\nFEATURE_SECRET=false')
    assert.deepEqual(envSecrets(entries, '.env', policy).map(secret => secret.name), ['MYSQL_ROOT_PASSWORD', 'VOICEMAIL_PASSCODE', 'BACKUP_OTP', 'ADMIN_PASSWORD'])
  })

  it('splits names on camelCase and drops digit suffixes', () => {
    assert.deepEqual(keyWords('dbPassword2'), ['DB', 'PASSWORD'])
    assert.deepEqual(keyWords('REDIS_PASSWORD2'), ['REDIS', 'PASSWORD'])
  })

  it('honours secret_keys and ignore_keys', () => {
    const entries = parseDotenv('SENTRY_DSN=https://abc@sentry.example/1\nSESSION_SECRET=supersecretvalue')
    const names = envSecrets(entries, '.env', { secretKeys: ['*_DSN'], ignoreKeys: ['SESSION_*'] }).map(s => s.name)
    assert.deepEqual(names, ['SENTRY_DSN'])
  })
})

describe('credential files', () => {
  const random = seeded(3)

  it('reads AWS credentials per profile', () => {
    const secret = fake.hex(random, 40)
    const found = parseAwsCredentials(`[default]\naws_access_key_id = ${fake.awsKeyId(random)}\naws_secret_access_key = ${secret}\n[profile ci]\naws_session_token=${secret}x`, 'aws')
    assert.deepEqual(found.map(s => s.name), ['aws/default/aws_secret_access_key', 'aws/ci/aws_session_token'])
    assert.equal(found[0]?.value, secret)
    assert.ok(found.every(s => s.strong))
  })

  it('reads netrc, pgpass and git credentials', () => {
    assert.deepEqual(parseNetrc('machine api.example.com\n  login me\n  password hunter2hunter2', 'n').map(s => [s.name, s.value]), [['netrc/api.example.com', 'hunter2hunter2']])
    assert.deepEqual(parseNetrc('# my hosts\nmachine h login me password abcd#efgh1234', 'n').map(s => s.value), ['abcd#efgh1234'])
    assert.deepEqual(parseGitCredentials('https://tokenasusername1234@github.com', 'g').map(s => [s.name, s.value]), [['git-credentials/github.com', 'tokenasusername1234']])
    assert.deepEqual(parsePgpass('db:5432:app:me:pa\\:ss\\:word', 'p').map(s => [s.name, s.value]), [['pgpass/db/me', 'pa:ss:word']])
    assert.deepEqual(parseGitCredentials('https://me:tok%2Fen@github.com', 'g').map(s => [s.name, s.value]), [['git-credentials/github.com', 'tok/en']])
  })

  it('reads npm tokens and decodes _password', () => {
    const found = parseNpmrc(`//registry.npmjs.org/:_authToken=npm_${fake.password(random)}\n//r.example/:_password=${base64Encode('plainpassword')}\n//x/:_authToken=\${NPM_TOKEN}`, 'npmrc')
    assert.deepEqual(found.map(s => s.name), ['npmrc///registry.npmjs.org/:_authToken', 'npmrc///r.example/:_password', 'npmrc///r.example/:_password.decoded'])
    assert.equal(found[2]?.value, 'plainpassword')
  })

  it('reads docker auth and decodes the password', () => {
    const found = parseDockerConfig(JSON.stringify({ auths: { 'ghcr.io': { auth: base64Encode('me:registrypassword') } }, credsStore: 'osxkeychain' }), 'docker')
    assert.deepEqual(found.map(s => [s.name, s.value]), [
      ['docker/ghcr.io/auth', base64Encode('me:registrypassword')],
      ['docker/ghcr.io/password', 'registrypassword'],
    ])
  })

  it('reads gh and kube tokens', () => {
    const token = fake.githubPat(random)
    assert.deepEqual(parseGhHosts(`github.com:\n    oauth_token: ${token}\n    user: me\n`, 'gh').map(s => [s.name, s.value]), [['gh/github.com', token]])
    const kube = parseKubeConfig('users:\n- name: admin\n  user:\n    token: kubetokenvalue123\n', 'kube')
    assert.deepEqual(kube.map(s => [s.name, s.value]), [['kube/admin/token', 'kubetokenvalue123']])
  })

  it('reads private key blocks', () => {
    const key = fake.privateKey(random)
    assert.deepEqual(privateKeyBlocks(`noise\n${key}\n`, 'ssh/id', 'f').map(s => s.value), [key])
  })
})

describe('loadSecrets', () => {
  it('finds env files in the project, skipping templates, hidden and vendored folders', async () => {
    const random = seeded(4)
    const token = fake.hex(random, 40)
    const fs = memoryFs({
      '/repo/.env': `API_TOKEN=${token}`,
      '/repo/.env.example': 'API_TOKEN=changeme_changeme',
      '/repo/apps/web/.env.local': `WEB_SECRET=${fake.hex(random, 32)}`,
      '/repo/node_modules/pkg/.env': `VENDOR_SECRET=${fake.hex(random, 32)}`,
      '/repo/.claude/worktrees/a/.env': `WORKTREE_SECRET=${fake.hex(random, 32)}`,
      '/repo/apps/web/src/deep/.env': `TOO_DEEP_SECRET=${fake.hex(random, 32)}`,
    })
    const config = { ...DEFAULT_CONFIG, sources: { ...DEFAULT_CONFIG.sources, home: false, environment: false } }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, config)
    assert.deepEqual(loaded.secrets.map(s => s.name).sort(), ['API_TOKEN', 'WEB_SECRET'])
    assert.deepEqual(loaded.files.map(f => f.path).sort(), ['/repo/.env', '/repo/apps/web/.env.local'])
  })

  it('reads configured files with a wildcard, home credentials and the environment', async () => {
    const random = seeded(5)
    const fs = memoryFs({
      '/home/me/.config/app/staging.env': `STAGING_TOKEN=${fake.hex(random, 40)}`,
      '/home/me/.config/app/notes.txt': 'NOT_READ=1',
      '/home/me/.ssh/id_ed25519': fake.privateKey(random),
      '/home/me/.ssh/id_ed25519.pub': 'ssh-ed25519 AAAA me',
      '/home/me/.ssh/config': 'Host x',
      '/home/me/.aws/credentials': `[default]\naws_secret_access_key=${fake.hex(random, 40)}`,
    })
    const { config } = parseConfig('[sources]\nproject = false\nfiles = ["~/.config/app/*.env"]')
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: { GITHUB_TOKEN: fake.githubPat(random), OTHER: 'x' } }, config)
    assert.deepEqual(loaded.files.map(f => f.kind), ['dotenv', 'aws', 'ssh', 'environment'])
    assert.deepEqual(loaded.secrets.map(s => s.name), ['STAGING_TOKEN', 'aws/default/aws_secret_access_key', 'ssh/id_ed25519', 'GITHUB_TOKEN'])
  })

  it('reads symlinked env files and keys, and .env files under a deep working folder', async () => {
    const random = seeded(7)
    const base = memoryFs({
      '/repo/.env': `LINKED_SECRET=${fake.hex(random, 32)}`,
      '/repo/a/b/c/d/.env': `DEEP_SECRET=${fake.hex(random, 32)}`,
      '/home/me/.ssh/id_rsa': fake.privateKey(random),
    })
    const fs = {
      ...base,
      list: async (dir: string) =>
        (await base.list(dir)).map(entry => (entry.name === '.env' || entry.name === 'id_rsa' ? { ...entry, kind: 'other' as const, isLink: true } : entry)),
    }
    const config = { ...DEFAULT_CONFIG, sources: { ...DEFAULT_CONFIG.sources, environment: false } }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', cwd: '/repo/a/b/c/d', vars: {} }, config)
    assert.deepEqual(loaded.secrets.map(s => s.name).sort(), ['DEEP_SECRET', 'LINKED_SECRET', 'ssh/id_rsa'])
  })

  it('never opens a named pipe, a socket or a link to one', async () => {
    const random = seeded(8)
    const base = memoryFs({ '/repo/.env': `PIPE_SECRET=${fake.hex(random, 32)}`, '/repo/.env.local': `LINKED_PIPE=${fake.hex(random, 32)}` })
    let reads = 0
    const fs = {
      ...base,
      read: async (path: string) => {
        reads++
        return base.read(path)
      },
      list: async (dir: string) =>
        (await base.list(dir)).map(entry =>
          entry.name === '.env' ? { ...entry, kind: 'other' as const } : entry.name === '.env.local' ? { ...entry, kind: 'other' as const, isLink: true } : entry,
        ),
      kindOf: async (path: string) => (path.startsWith('/repo/.env') ? ('other' as const) : base.kindOf?.(path) ?? 'other'),
    }
    const config = { ...DEFAULT_CONFIG, sources: { ...DEFAULT_CONFIG.sources, home: false, system: false, environment: false } }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, config)
    assert.deepEqual(loaded.secrets, [])
    assert.equal(reads, 0)
  })

  it('knows which names are env files', () => {
    for (const name of ['.env', '.env.local', '.env.production', '.envrc', 'staging.env']) assert.ok(isEnvFileName(name), name)
    for (const name of ['.env.example', '.env.sample', '.env.template', 'env.ts', '.environment']) assert.ok(!isEnvFileName(name), name)
  })
})
