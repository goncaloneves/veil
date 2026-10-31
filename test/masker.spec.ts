import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ENCODINGS } from '../src/config/config.ts'
import { base64Encode } from '../src/core/encoding.ts'
import { MaskTimeout, Masker } from '../src/core/masker.ts'
import { emptyRuleSet } from '../src/core/rules.ts'
import type { Secret } from '../src/core/types.ts'
import { gitleaks } from '../src/rules/gitleaks.ts'
import { ruleSet } from '../src/rules/index.ts'
import { fake, fakeToken, seeded } from './helpers.ts'

function masker(secrets: Secret[], rules = false, salt = 'test-salt'): Masker {
  return new Masker({ secrets, ruleSet: rules ? gitleaks : emptyRuleSet(), minLength: 8, encodings: ENCODINGS, salt })
}

describe('Masker with known values', () => {
  const random = seeded(10)
  const token = fake.hex(random, 40)
  const password = fake.password(random)

  it('replaces every occurrence with a named placeholder', () => {
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }])
    const out = m.mask(`a ${token} b ${token}`)
    assert.equal(out.text, 'a [veil:API_TOKEN] b [veil:API_TOKEN]')
    assert.equal(out.hits.length, 2)
  })

  it('catches base64, URL and JSON encoded forms with their own labels', () => {
    const value = `${password}/+=:"x`
    const m = masker([{ name: 'SECRET', value, source: '/r/.env' }])
    assert.equal(m.mask(base64Encode(value)).text, '[veil:SECRET~base64]')
    assert.equal(m.mask(encodeURIComponent(value)).text, '[veil:SECRET~url]')
    assert.equal(m.mask(JSON.stringify({ v: value })).text, '{"v":"[veil:SECRET~json]"}')
  })

  it('catches single lines of a multi-line key printed on their own', () => {
    const key = fake.privateKey(random)
    const m = masker([{ name: 'ssh/id', value: key, source: '/h/.ssh/id' }])
    const line = key.split('\n')[2] ?? ''
    assert.equal(m.mask(`leaked: ${line}`).text, 'leaked: [veil:ssh/id~line3]')
    assert.equal(m.mask(key).text, '[veil:ssh/id]')
  })

  it('never masks values shorter than min_length', () => {
    const m = masker([{ name: 'PIN', value: '1234', source: '/r/.env' }])
    assert.equal(m.mask('pin 1234').text, 'pin 1234')
  })

  it('prefers the longer value when one holds the other', () => {
    const m = masker([
      { name: 'URL', value: `postgres://app:${password}@db/app`, source: '/r/.env' },
      { name: 'URL.password', value: password, source: '/r/.env' },
    ])
    assert.equal(m.mask(`url postgres://app:${password}@db/app and ${password}`).text, 'url [veil:URL] and [veil:URL.password]')
  })

  it('masks the whole stretch when two secrets overlap, leaving no tail visible', () => {
    const a = 'abcdefgh12345678'
    const b = '12345678zzzzzzzz'
    const m = masker([
      { name: 'A', value: a, source: '/r/.env' },
      { name: 'B', value: b, source: '/r/.env' },
    ])
    const out = m.mask('x abcdefgh12345678zzzzzzzz y')
    assert.match(out.text, /^x \[veil:A~joined#[0-9a-f]+\] y$/)
    assert.equal(m.restore(out.text).text, 'x abcdefgh12345678zzzzzzzz y')
  })

  it('labels every known value up front, the same in every session, so a resumed session can restore it', () => {
    const secrets = [{ name: 'API_TOKEN', value: token, source: '/r/.env' }]
    const fresh = masker(secrets, false, 'another-salt')
    assert.equal(fresh.vault.text('API_TOKEN'), token)
    assert.equal(fresh.vault.source('API_TOKEN'), '/r/.env')
    assert.equal(fresh.restore('[veil:API_TOKEN]').text, token)
  })

  it('tells same-named values apart by the file they come from', () => {
    const m = masker([
      { name: 'TOKEN', value: token, source: '/r/.env' },
      { name: 'TOKEN', value: `${token}x`, source: '/r/.env.test' },
    ])
    assert.equal(m.mask(`${token}x ${token}`).text, '[veil:TOKEN@.env.test] [veil:TOKEN]')
  })

  it('is idempotent on placeholders it made', () => {
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }], true)
    const once = m.mask(`token=${token}`).text
    assert.equal(m.mask(once).text, once)
  })

  it('still masks a secret wrapped to look like a placeholder', () => {
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }], true)
    const pat = fake.githubPat(random)
    assert.ok(!m.mask(`[veil:${token}]`).text.includes(token))
    assert.ok(!m.mask(`[veil:${pat}]`).text.includes(pat))
  })

  it('leaves placeholders from another session alone, even when no rule or value matches them now', () => {
    const m = new Masker({ secrets: [], ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'test-salt' })
    for (const text of [
      'DATABASE_URL=postgres://app:[veil:url-credentials#3fa2c1]@db/app',
      'password: [veil:DB_PASSWORD]',
      'Authorization: Bearer [veil:authorization-header#0a1b2c3d]',
    ]) {
      assert.equal(m.mask(text).text, text)
    }
  })

  it('never re-masks a placeholder that a rule value runs into or out of', () => {
    const random = seeded(31)
    const known = new Masker({ secrets: [{ name: 'DB_PASSWORD', value: fake.password(random), source: '/r/.env' }], ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'test-salt' })
    const unknown = new Masker({ secrets: [], ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'test-salt' })
    for (const m of [known, unknown]) {
      for (const text of [
        'password=[veil:DB_PASSWORD];',
        'password=[veil:DB_PASSWORD]x',
        'PGPASSWORD=[veil:DB_PASSWORD]&&psql',
        'password=[veil:DB_PASSWORD]\\n',
        'secret: [veil:DB_PASSWORD]/[veil:DB_PASSWORD]',
      ]) {
        assert.equal(m.mask(text).text, text)
      }
    }
  })

  it('still masks a known connection string wrapped to look like a placeholder', () => {
    const url = `postgres://app:${password}@db/app`
    const m = masker([{ name: 'DATABASE_URL', value: url, source: '/r/.env' }])
    assert.equal(m.mask(`[veil:${url}]`).text, '[veil:[veil:DATABASE_URL]]')
  })

  it('restores placeholders it knows and leaves unknown ones alone', () => {
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }])
    const restored = m.restore('A=[veil:API_TOKEN] B=[veil:NOT_KNOWN]')
    assert.equal(restored.text, `A=${token} B=[veil:NOT_KNOWN]`)
    assert.deepEqual(restored.restored, ['API_TOKEN'])
    assert.deepEqual(restored.unknown, ['NOT_KNOWN'])
  })

  it('keeps masking a rotated value under a retired label, and gives the new value the name', () => {
    const fresh = fake.hex(seeded(15), 40)
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }])
    m.setSecrets([{ name: 'API_TOKEN', value: fresh, source: '/r/.env' }])
    assert.equal(m.mask(fresh).text, '[veil:API_TOKEN]')
    const old = m.mask(token).text
    assert.match(old, /^\[veil:API_TOKEN~previous#[0-9a-f]+\]$/)
    assert.equal(m.vault.isCurrent('API_TOKEN'), true)
    assert.equal(m.vault.isCurrent(old.slice(6, -1)), false)
  })

  it('takes new secrets without losing the vault', () => {
    const m = masker([])
    m.setSecrets([{ name: 'LATE', value: token, source: '/r/.env' }])
    assert.equal(m.mask(token).text, '[veil:LATE]')
    assert.ok(m.holds(token))
  })

  it('counts what it masked per label', () => {
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }])
    m.mask(`${token} ${token}`)
    assert.deepEqual(m.vault.stats(), [{ label: 'API_TOKEN', kind: 'known', count: 2 }])
  })
})

describe('Masker with pattern rules', () => {
  const random = seeded(11)

  it('masks well-known token formats it has never seen in a file', () => {
    const m = masker([], true)
    const pat = fake.githubPat(random)
    const out = m.mask(`export GH=${pat}`)
    assert.match(out.text, /^export GH=\[veil:github-pat#[0-9a-f]{6}\]$/)
    assert.equal(m.restore(out.text).text, `export GH=${pat}`)
  })

  it('masks private key blocks', () => {
    const key = fake.privateKey(random)
    const out = masker([], true).mask(`key:\n${key}\n`)
    assert.ok(!out.text.includes(key.split('\n')[1] ?? 'missing'))
    assert.equal(out.hits[0]?.kind, 'rule')
  })

  it('gives rule hits salted labels that differ between sessions', () => {
    const pat = fake.githubPat(random)
    assert.notEqual(masker([], true, 'one').mask(pat).text, masker([], true, 'two').mask(pat).text)
  })

  it('leaves ordinary code and prose alone', () => {
    const text = [
      'const user = await db.users.findFirst({ where: { id } })',
      'The key insight is that tokens are counted per request.',
      'commit 4f9c2a1b8e7d6c5b4a39281706f5e4d3c2b1a090',
      'uuid: 123e4567-e89b-12d3-a456-426614174000',
      'password: process.env.DB_PASSWORD',
      'api_key = ${API_KEY}',
    ].join('\n')
    assert.equal(masker([], true).mask(text).text, text)
  })
})

describe('Masker across separators', () => {
  const random = seeded(16)
  const entries = [
    `GITHUB_TOKEN=${fake.githubPat(random)}`,
    `AWS_ACCESS_KEY_ID=${fake.awsKeyId(random)}`,
    `ANTHROPIC_API_KEY=${fake.anthropic(random, 'oat01')}`,
    `API_KEY=${fake.hex(random, 16)}${fake.password(random)}`,
    `REDIS_PASSWORD=${fake.symbolPassword(random)}`,
    `SMTP_PASS=${fake.symbolPassword(random)}`,
    `SLACK_TOKEN=${fake.slackBot(random)}`,
    `SESSION_JWT=${fake.jwt(random, 40)}`,
    `DATABASE_URL=postgres://app:${fake.password(random)}@db:5432/app`,
  ]
  const values = entries.map(entry => entry.slice(entry.indexOf('=') + 1).replace(/^postgres:\/\/app:|@db:5432\/app$/g, ''))

  for (const [name, separator] of [
    ['newlines', '\n'],
    ['NUL bytes, as /proc/<pid>/environ and find -print0 print them', '\0'],
    ['CRLF', '\r\n'],
    ['lone carriage returns', '\r'],
  ] as const) {
    it(`masks every pattern-matched value in an environment separated by ${name}`, () => {
      const m = new Masker({ secrets: [], ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'sep-salt' })
      const out = m.mask(`${entries.join(separator)}${separator}`).text
      for (const value of values) assert.ok(!out.includes(value), `${value.slice(0, 12)} leaked: ${JSON.stringify(out.slice(0, 300))}`)
    })
  }

  it('masks a known value next to a NUL and keeps every offset', () => {
    const token = fake.hex(random, 40)
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }])
    const out = m.mask(`A=1\0API_TOKEN=${token}\0B=2`)
    assert.equal(out.text, 'A=1\0API_TOKEN=[veil:API_TOKEN]\0B=2')
    assert.deepEqual(out.hits.map(hit => [hit.start, hit.end]), [[14, 54]])
  })
})

const MARGIN = 350

describe('Masker performance', () => {
  it('stays fast on large ordinary output', () => {
    const random = seeded(12)
    const secrets = Array.from({ length: 50 }, (_, i) => ({ name: `S${i}`, value: fake.hex(random, 40), source: '/r/.env' }))
    const m = masker(secrets, true)
    const line = 'export function handler(request: Request): Response { return new Response(JSON.stringify({ ok: true })) }\n'
    const started = performance.now()
    m.mask(line.repeat(Math.ceil(1_000_000 / line.length)))
    const elapsed = performance.now() - started
    assert.ok(elapsed < 3000, `masking 1 MB took ${Math.round(elapsed)} ms`)
  })

  it('stays bounded on text built to make the rules backtrack', () => {
    const random = seeded(13)
    const words = ['cohere', 'okta', 'access', 'token', 'secret', 'api', 'key', 'auth', 'password']
    const lines: string[] = []
    while (lines.join('\n').length < 300_000) {
      lines.push(`${words.map(word => `${word}_${fakeToken(random, 24)}`).join('.')} = ${fakeToken(random, 60)}`)
    }
    const text = lines.join('\n')
    const m = new Masker({ secrets: [], ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'test-salt' })
    const started = performance.now()
    try {
      m.mask(text, { deadline: Date.now() + 1000 })
    } catch (error) {
      assert.ok(error instanceof MaskTimeout)
    }
    const elapsed = performance.now() - started
    assert.ok(elapsed < 1000 + MARGIN, `took ${Math.round(elapsed)} ms for a 1000 ms deadline`)
  })

  it('checks the deadline while it filters tens of thousands of placeholders and hits', () => {
    const random = seeded(19)
    const token = fake.hex(random, 40)
    const m = masker([{ name: 'API_TOKEN', value: token, source: '/r/.env' }])
    const text = `[veil:API_TOKEN] ${token} `.repeat(30_000)
    const started = performance.now()
    try {
      const out = m.mask(text, { deadline: Date.now() + 1000 })
      assert.equal(out.hits.length, 30_000)
    } catch (error) {
      assert.ok(error instanceof MaskTimeout)
    }
    assert.ok(performance.now() - started < 1000 + MARGIN)
  })

  it('gives up with MaskTimeout once its deadline passes', () => {
    const random = seeded(14)
    const text = Array.from({ length: 5000 }, () => `api_key = "${fakeToken(random, 40)}"`).join('\n')
    assert.throws(() => masker([], true).mask(text, { deadline: Date.now() - 1 }), MaskTimeout)
  })

  it('fails closed when the known-value search passes its deadline', () => {
    const random = seeded(17)
    const secrets = Array.from({ length: 50 }, (_, i) => ({ name: `S${i}`, value: fake.hex(random, 40), source: '/r/.env' }))
    assert.throws(() => masker(secrets).mask('nothing secret here', { deadline: Date.now() - 1 }), MaskTimeout)
  })

  it('searches thousands of known values in one pass', () => {
    const random = seeded(18)
    const secrets = Array.from({ length: 10_000 }, (_, i) => ({ name: `K${i}`, value: fakeToken(random, 32), source: '/r/.env' }))
    const m = masker(secrets)
    const text = secrets.slice(0, 6000).map(secret => `${secret.name}=${secret.value}`).join('\n')
    const started = performance.now()
    const out = m.mask(text, { deadline: Date.now() + 3000 })
    const elapsed = performance.now() - started
    assert.equal(out.hits.length, 6000)
    assert.ok(elapsed < 1500, `masking ${Math.round(text.length / 1000)} KB took ${Math.round(elapsed)} ms`)
  })

  it('merges tens of thousands of hits in linear time', () => {
    const m = masker([{ name: 'HOST', value: 'abcdefgh', source: '/r/.env' }])
    const started = performance.now()
    const out = m.mask('abcdefgh '.repeat(60_000))
    assert.equal(out.hits.length, 60_000)
    assert.ok(performance.now() - started < 1500)
  })
})
