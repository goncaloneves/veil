import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ENCODINGS } from '../src/config/config.ts'
import { looksRandomShort, scopeOf } from '../src/core/known.ts'
import { Masker } from '../src/core/masker.ts'
import { emptyRuleSet } from '../src/core/rules.ts'
import type { Secret } from '../src/core/types.ts'
import { LOWER, fakeToken, seeded } from './helpers.ts'

function masker(secrets: Secret[], minLength = 8): Masker {
  return new Masker({ secrets, ruleSet: emptyRuleSet(), minLength, encodings: ENCODINGS, salt: 'short-salt' })
}

describe('short secret tiers', () => {
  const random = seeded(40)
  const word = fakeToken(random, 5, LOWER)
  const strong: Secret = { name: 'DB_PASSWORD', value: word, source: '/r/.env', strong: true }
  const mixed = `${fakeToken(random, 2, 'ABCDEFGH')}${fakeToken(random, 1, '23456789')}${fakeToken(random, 1, 'jkmnpq')}${fakeToken(random, 1, '23456789')}${fakeToken(random, 1, 'RSTUVW')}`

  it('picks a tier from length, shape and strength', () => {
    assert.equal(scopeOf({ ...strong, value: `${fakeToken(random, 6, LOWER)}9!Kq` }, 8), 'anywhere')
    assert.equal(scopeOf({ ...strong, value: fakeToken(random, 8, LOWER) }, 8), 'context')
    assert.equal(scopeOf({ ...strong, value: fakeToken(random, 8, LOWER).toUpperCase() }, 8), 'context')
    assert.equal(scopeOf({ ...strong, value: fakeToken(random, 9, LOWER) }, 8), 'anywhere')
    assert.equal(scopeOf({ ...strong, value: fakeToken(random, 20, LOWER) }, 8), 'anywhere')
    assert.equal(scopeOf(strong, 8), 'context')
    assert.equal(scopeOf({ ...strong, strong: false }, 8), undefined)
    assert.equal(scopeOf({ name: 'X', value: mixed, source: '/r/.env' }, 8), 'token')
    assert.equal(scopeOf({ name: 'X', value: mixed, source: '/r/.env', strong: true }, 8), 'either')
    assert.equal(scopeOf({ ...strong, value: 'abc' }, 8), undefined)
    assert.equal(scopeOf({ ...strong, value: 'true' }, 8), undefined)
    assert.equal(scopeOf({ ...strong, value: fakeToken(random, 10, LOWER) }, 12), 'context')
    assert.equal(scopeOf({ name: 'X', value: mixed, source: '/r/.env' }, 4), 'anywhere')
  })

  it('treats mixed character classes as random-looking, but not words, versions, slugs or numbers', () => {
    assert.ok(looksRandomShort(mixed))
    assert.ok(looksRandomShort('k9!xQ2'))
    for (const value of ['Hunter', 'hunter2', 'abc123', '123456', 'v1.2.3', '2.10.4', 'k8s-v1', 'API_V2', 'aaB3B3', 'two words']) {
      assert.ok(!looksRandomShort(value), value)
    }
  })

  it('masks a long default-word password in base64, where a Kubernetes secret shows it, but not in prose', () => {
    const m = masker([{ name: 'ADMIN_PASSWORD', value: 'sunshine', source: '/r/.env', strong: true }])
    assert.equal(m.mask(`data:\n  admin: ${Buffer.from('sunshine').toString('base64')}`).text, 'data:\n  admin: [veil:ADMIN_PASSWORD~base64]')
    assert.equal(m.mask('ADMIN_PASSWORD=sunshine').text, 'ADMIN_PASSWORD=[veil:ADMIN_PASSWORD]')
    assert.equal(m.mask('a sunshine day').text, 'a sunshine day')
  })

  it('never masks a short strong value in free prose', () => {
    const m = masker([strong])
    for (const text of [
      `the ${word} is here`,
      word,
      `${word}s and more`,
      `x${word} y`,
      `password is ${word}`,
      `name = ${word}`,
      `user=${word}`,
      `DB_PASSWORD=${word}x`,
      `https://${word}.example.com/a`,
      `-u ${word}`,
      `# ${word}: a heading`,
    ]) {
      assert.equal(m.mask(text).text, text, text)
    }
  })

  it('masks a short strong value in PGPASSWORD=... and in a URL', () => {
    const m = masker([strong])
    assert.equal(m.mask(`PGPASSWORD=${word} psql -h db`).text, 'PGPASSWORD=[veil:DB_PASSWORD] psql -h db')
    assert.equal(m.mask(`postgres://app:${word}@db:5432/app`).text, 'postgres://app:[veil:DB_PASSWORD]@db:5432/app')
    assert.equal(m.mask(`redis://:${word}@cache:6379`).text, 'redis://:[veil:DB_PASSWORD]@cache:6379')
  })

  it('masks a short strong value in every assignment form', () => {
    const m = masker([strong])
    const forms = [
      `DB_PASSWORD: ${word}`,
      `"password": "${word}"`,
      `password = "${word}"`,
      `'password' => '${word}',`,
      `--password ${word}`,
      `--password=${word}`,
      `mysql -u root -p${word} app`,
      `mysql -p'${word}' app`,
      `sshpass -p ${word} ssh host`,
      `docker login -u me -p ${word}`,
      `curl -u admin:${word} https://h`,
      `Server=db;Password=${word};Database=x`,
      `jdbc:mysql://h/db?user=a&password=${word}&ssl=1`,
      `export DB_PASSWORD=${word}`,
      `$env:DB_PASSWORD="${word}"`,
      `$env:DB_PASSWORD = '${word}'`,
      `set -x DB_PASSWORD ${word}`,
      `set -gx DB_PASSWORD ${word}`,
      `setenv DB_PASSWORD ${word}`,
      `<password>${word}</password>`,
      `<add key="ClearTextPassword" value="${word}" />`,
      `define('DB_PASSWORD', '${word}');`,
      `ALTER USER app WITH PASSWORD '${word}';`,
      `CREATE USER x IDENTIFIED BY '${word}';`,
      `CREATE\\040USER\\040x\\040IDENTIFIED\\040BY\\040'${word}';`,
      `AUTH ${word}`,
      `requirepass ${word}`,
      `$p = ConvertTo-SecureString "${word}" -AsPlainText -Force`,
      `Environment="DB_PASSWORD=${word}"`,
      `  - POSTGRES_PASSWORD=${word}`,
      `A=1\0DB_PASSWORD=${word}\0B=2`,
      `DB_PASSWORD=${word}\r\nNEXT=1`,
    ]
    for (const text of forms) {
      const out = m.mask(text)
      assert.ok(!out.text.includes(word), `${JSON.stringify(text)} -> ${JSON.stringify(out.text)}`)
      assert.ok(out.text.includes('[veil:DB_PASSWORD]'), text)
    }
  })

  it("accepts the secret's own name as the key, even when it is not a credential word", () => {
    const m = masker([{ name: 'MYAPP_SEED', value: word, source: '/r/.env', strong: true }])
    assert.equal(m.mask(`MYAPP_SEED=${word}`).text, 'MYAPP_SEED=[veil:MYAPP_SEED]')
    assert.equal(m.mask(`OTHER_SEED=${word}`).text, `OTHER_SEED=${word}`)
  })

  it('masks a random-looking value shorter than min_length everywhere, but only as a whole token', () => {
    const m = masker([{ name: 'SHORT_KEY', value: mixed, source: '/r/.env' }])
    assert.equal(m.mask(`id ${mixed}.`).text, 'id [veil:SHORT_KEY].')
    assert.equal(m.mask(`{"k":"${mixed}"}`).text, '{"k":"[veil:SHORT_KEY]"}')
    assert.equal(m.mask(`/api/${mixed}/x`).text, '/api/[veil:SHORT_KEY]/x')
    for (const text of [`x${mixed}`, `${mixed}2`, `${mixed}_suffix`, `pre_${mixed}`]) assert.equal(m.mask(text).text, text, text)
  })

  it('masks a strong random-looking short value glued to a flag', () => {
    const m = masker([{ name: 'DB_PASSWORD', value: mixed, source: '/r/.env', strong: true }])
    assert.equal(m.mask(`mysql -p${mixed}`).text, 'mysql -p[veil:DB_PASSWORD]')
    assert.equal(m.mask(`see ${mixed}`).text, 'see [veil:DB_PASSWORD]')
  })

  it('leaves a short value that is neither strong nor random-looking alone', () => {
    const m = masker([{ name: 'API_KEY', value: word, source: '/r/.env' }])
    assert.equal(m.mask(`API_KEY=${word}`).text, `API_KEY=${word}`)
  })

  it('restores short values from the same vault labels as other known values', () => {
    const m = masker([strong])
    assert.equal(m.vault.text('DB_PASSWORD'), word)
    assert.equal(m.restore('PGPASSWORD=[veil:DB_PASSWORD]').text, `PGPASSWORD=${word}`)
  })

  it('keeps plain-word default passwords to assignments, so they never mask prose or image tags', () => {
    const m = masker([
      { name: 'POSTGRES_PASSWORD', value: 'postgres', source: '/r/compose.yml', strong: true },
      { name: 'DB_PASSWORD', value: 'password', source: '/r/application.properties', strong: true },
    ])
    for (const text of ['image: postgres:16', 'Enter your password:', 'psql -U postgres -h db', 'the password field']) assert.equal(m.mask(text).text, text, text)
    assert.equal(m.mask('POSTGRES_PASSWORD=postgres').text, 'POSTGRES_PASSWORD=[veil:POSTGRES_PASSWORD]')
    assert.equal(m.mask('spring.datasource.password=password').text, 'spring.datasource.password=[veil:DB_PASSWORD]')
  })

  it('masks a proven password that only looks like a word everywhere, with every encoding', () => {
    for (const value of ['Summer2024!', 'Password1', 'Welcome123', 'hunter22', 'admin123', 'Dragon2025.', 'correct-horse', 'mysecretpw']) {
      for (const strength of [true, false]) {
        const m = masker([{ name: 'DB_PASSWORD', value, source: '/r/.env', strong: strength }])
        const out = m.mask(`printenv DB_PASSWORD\n${value}\nlog: "${value}" ${btoa(value)}`).text
        assert.ok(!out.includes(value) && !out.includes(btoa(value)), `${value} ${strength}: ${out}`)
      }
    }
  })

  it('gives assignment-only values their JSON and URL forms', () => {
    const value = `${fakeToken(random, 2, LOWER)}@${fakeToken(random, 2, LOWER)}"`
    const m = masker([{ name: 'DB_PASSWORD', value, source: '/r/.env', strong: true }])
    const url = `postgres://app:${encodeURIComponent(value)}@db/app`
    assert.equal(m.mask(url).text, 'postgres://app:[veil:DB_PASSWORD~url]@db/app')
    assert.equal(m.mask(JSON.stringify({ password: value })).text, '{"password":"[veil:DB_PASSWORD~json]"}')
  })

  it('reads AWS SSM parameter names and Dockerfile ENV lines as assignments', () => {
    const m = masker([strong])
    assert.ok(!m.mask(`{"Name": "/prod/db/password", "Type": "SecureString", "Value": "${word}"}`).text.includes(word))
    assert.ok(!m.mask(`ENV DB_PASSWORD ${word}`).text.includes(word))
    assert.equal(m.mask(`RUN echo ${word}`).text, `RUN echo ${word}`)
  })

  it('merges the scopes of one value loaded twice, whatever the order', () => {
    const plain = { name: 'SHORT_KEY', value: mixed, source: '/r/.env' }
    const proven = { name: 'DB_PASSWORD', value: mixed, source: '/r/.env.local', strong: true }
    for (const secrets of [[plain, proven], [proven, plain]]) {
      const m = masker(secrets)
      assert.ok(!m.mask(`mysql -p${mixed}`).text.includes(mixed))
      assert.ok(!m.mask(`see ${mixed} here`).text.includes(mixed))
    }
  })

  it('masks a short value under a sibling name key, in netrc, pgpass, redis-cli -a and PowerShell listings', () => {
    const m = masker([strong])
    const forms = [
      `{"name":"DB_PASSWORD","value":"${word}"}`,
      `env:\n  - name: DB_PASSWORD\n    value: ${word}\n`,
      `env:\n  - name: DB_PASSWORD\n    value: "${word}"\n`,
      `Name  : DB_PASSWORD\r\nValue : ${word}\r\n`,
      `machine db.example.com login app password ${word}`,
      `machine db.example.com\n  login app\n  password ${word}\n`,
      `db.example.com:5432:app:app:${word}`,
      `redis-cli -h cache -a ${word} ping`,
      `DB_PASSWORD                    ${word}\r\nHOME                           C:\\Users\\dev`,
      `DB_PASSWORD=${word}.`,
      `DB_PASSWORD=\x1b[01;31m\x1b[K${word}\x1b[m\x1b[K`,
    ]
    for (const text of forms) {
      const out = m.mask(text).text
      assert.ok(!out.includes(word), `${JSON.stringify(text)} -> ${JSON.stringify(out)}`)
    }
    for (const text of [`{"name":"HOST","value":"${word}"}`, `my password ${word} is weak`, `the ${word}.`, `a:b:c:d:${word}x`]) {
      assert.equal(m.mask(text).text, text, text)
    }
  })

  it('masks a token-scope value split by grep colour codes', () => {
    const m = masker([{ name: 'SHORT_KEY', value: mixed, source: '/r/.env' }])
    assert.ok(!m.mask(`KEY=\x1b[01;31m\x1b[K${mixed}\x1b[m\x1b[K`).text.includes(mixed))
  })

  it('stays fast with many short context values over 1 MB', () => {
    const secrets = Array.from({ length: 2000 }, (_, i) => ({
      name: `P${i}`,
      value: fakeToken(random, 4 + (i % 4), LOWER),
      source: '/r/.env',
      strong: true,
    }))
    const words = secrets.slice(0, 200).map(secret => secret.value)
    const text = Array.from({ length: 30_000 }, (_, i) => `the ${words[i % 200]} of x = ${words[(i * 7) % 200]} and PASSWORD=${words[(i * 3) % 200]}\n`).join('')
    const m = masker(secrets)
    const started = performance.now()
    const out = m.mask(text, { deadline: Date.now() + 3000 })
    const elapsed = performance.now() - started
    assert.equal(out.hits.length, 30_000)
    assert.ok(elapsed < 2000, `masking took ${Math.round(elapsed)} ms`)
  })
})
