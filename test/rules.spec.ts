import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { compileRules, findRuleSpans } from '../src/core/rules.ts'
import type { RuleSet } from '../src/core/types.ts'
import { gitleaks } from '../src/rules/gitleaks.ts'
import { ruleSet } from '../src/rules/index.ts'
import { convertGitleaks, defang } from '../scripts/lib/gitleaks.ts'
import { re2ToJs } from '../scripts/lib/re2.ts'
import { fake, seeded } from './helpers.ts'

describe('re2ToJs', () => {
  it('expands a leading (?i) into case classes', () => {
    const re = new RegExp(re2ToJs('(?i)token'))
    assert.ok(re.test('TOKEN') && re.test('Token') && re.test('token'))
  })

  it('scopes (?i:...) and (?-i:...) like RE2', () => {
    const re = new RegExp(`^${re2ToJs('a(?i:bc)d(?i)e(?-i:F)g')}$`)
    assert.ok(re.test('aBCdEFG'))
    assert.ok(!re.test('ABCdEFG'))
    assert.ok(!re.test('aBCdEfG'))
  })

  it('adds the other case to letter ranges and single letters in classes', () => {
    const re = new RegExp(`^${re2ToJs('(?i)[a-c_x-]+')}$`)
    assert.ok(re.test('aBc_X-'))
    assert.ok(!re.test('d'))
  })

  it('keeps a trailing hyphen literal after adding ranges', () => {
    const re = new RegExp(`^${re2ToJs('(?i)[a-z0-9_-]{3}')}$`)
    assert.ok(re.test('A_-'))
    assert.ok(!re.test('A^-'))
  })

  it('turns (?s:.) into a dot that matches newlines', () => {
    assert.ok(new RegExp(re2ToJs('a(?s:.)b')).test('a\nb'))
    assert.ok(!new RegExp(re2ToJs('a.b')).test('a\nb'))
  })

  it('makes . exclude only newlines, as RE2 does', () => {
    assert.ok(new RegExp(re2ToJs('a.b')).test('a\rb'))
    assert.ok(!new RegExp(re2ToJs('a.b')).test('a\nb'))
  })

  it('converts \\z, \\A, named groups and POSIX classes', () => {
    assert.equal(re2ToJs('\\Aab\\z'), '^ab$')
    assert.equal(re2ToJs('(?P<k>x)'), '(?<k>x)')
    assert.ok(new RegExp(`^${re2ToJs('[[:alpha:]]+')}$`).test('Abc'))
  })
})

describe('defang', () => {
  it('rewrites long literal runs so no key-shaped text is left, matching exactly the same strings', () => {
    const random = seeded(21)
    const literal = fake.hex(random, 39)
    const pattern = `^(?:${literal}|x[a-z]{2})$`
    const safe = defang(pattern)
    assert.ok(!safe.includes(literal))
    assert.ok(new RegExp(safe).test(literal))
    assert.ok(!new RegExp(safe).test(`${literal}0`))
    assert.ok(new RegExp(safe).test('xab'))
  })

  it('leaves escapes and short runs alone', () => {
    assert.equal(defang('\\dabc[a-z]{3}'), '\\dabc[a-z]{3}')
  })
})

describe('gitleaks conversion', () => {
  it('converts rules, skips path-only ones and keeps allowlists', () => {
    const toml = `
[allowlist]
regexes = ['''^placeholder$''']
paths = ['''\\.png$''']
[[rules]]
id = "demo-token"
regex = '''(?i)demo_([a-z0-9]{12})'''
keywords = ["demo_"]
entropy = 2.0
[[rules.allowlists]]
regexTarget = "match"
regexes = ['''example''']
[[rules]]
id = "path-only"
path = '''\\.p12$'''
[[rules]]
id = "path-scoped"
regex = '''x'''
path = '''\\.tf$'''
`
    const { ruleSet, skipped } = convertGitleaks(toml, 'v0')
    assert.deepEqual(ruleSet.rules.map(rule => rule.id), ['demo-token'])
    assert.deepEqual(skipped.map(skip => skip.id), ['path-only', 'path-scoped'])
    assert.equal(ruleSet.allowlists.length, 1)
    assert.equal(ruleSet.rules[0]?.allowlists[0]?.target, 'match')
  })

  it('the shipped rule set compiles completely', () => {
    const compiled = compileRules(gitleaks)
    assert.deepEqual(compiled.failed, [])
    assert.ok(compiled.rules.length >= 200, `only ${compiled.rules.length} rules`)
    assert.match(gitleaks.version, /^v\d+\.\d+\.\d+$/)
  })
})

describe('rule matching', () => {
  const demo: RuleSet = {
    version: 'test',
    allowlists: [{ patterns: ['^demo_allowedvalue$'], stopwords: [], target: 'secret' }],
    rules: [
      {
        id: 'demo',
        pattern: 'demo_([a-z0-9]{13,14})',
        keywords: ['demo_'],
        secretGroup: 0,
        entropy: 2,
        allowlists: [{ patterns: [], stopwords: ['notreal'], target: 'secret' }],
      },
    ],
  }

  it('masks the secret group, not the whole match', () => {
    const spans = findRuleSpans('x demo_k3y9q2w8e7r6t1 y', compileRules(demo))
    assert.deepEqual(spans, [{ start: 7, end: 21, label: 'demo' }])
  })

  it('skips text without the keyword, low entropy, stopwords and allowlisted secrets', () => {
    const compiled = compileRules(demo)
    assert.deepEqual(findRuleSpans('k3y9q2w8e7r6t1', compiled), [])
    assert.deepEqual(findRuleSpans('demo_aaaaaaaaaaaaaa', compiled), [])
    assert.deepEqual(findRuleSpans('demo_notreal12345a', compiled), [])
  })

  it('masks only the password inside a URL, and skips templates and examples', () => {
    const random = seeded(22)
    const password = fake.password(random)
    const compiled = compileRules(ruleSet)
    const text = `DB=postgres://app:${password}@db:5432/app`
    const spans = findRuleSpans(text, compiled).filter(span => span.label === 'url-credentials')
    assert.deepEqual(spans.map(span => text.slice(span.start, span.end)), [password])
    for (const safe of ['postgres://user:password@localhost/db', 'redis://default:${REDIS_PASS}@cache:6379', 'https://user:<token>@example.com']) {
      assert.deepEqual(findRuleSpans(safe, compiled).filter(span => span.label === 'url-credentials'), [], safe)
    }
  })

  it('finds a long token that crosses a window edge on a very long line', () => {
    const random = seeded(23)
    const jwt = fake.jwt(random)
    const compiled = compileRules(ruleSet)
    for (const at of [3500, 4000, 12_000, 16_000, 16_300]) {
      const line = `${'{"k":"v",'.repeat(Math.ceil(at / 9)).slice(0, at)}"token":"${jwt}",${'"x":1,'.repeat(4000)}`
      const hit = findRuleSpans(line, compiled).find(span => span.label === 'jwt')
      assert.ok(hit, `no jwt hit at ${at}`)
      assert.equal(line.slice(hit.start, hit.end), jwt)
    }
  })

  it('finds a 6 KB token anywhere on a 50 KB line', () => {
    const random = seeded(25)
    const jwt = fake.jwt(random, 4500)
    const compiled = compileRules(ruleSet)
    for (let at = 0; at < 44_000; at += 2_750) {
      const line = `${'a'.repeat(at)} ${jwt} ${'b'.repeat(50_000 - at)}`
      const hit = findRuleSpans(line, compiled).find(span => span.label === 'jwt')
      assert.equal(hit && line.slice(hit.start, hit.end), jwt, `missed at ${at}`)
    }
  })

  it('finds a value that runs from a long line onto the next', () => {
    const random = seeded(26)
    const secret = `${fake.hex(random, 12)}${fake.password(random)}`
    const text = `${'x'.repeat(10_000)} password:\n    ${secret}\nnext: 1\n`
    assert.ok(findRuleSpans(text, compileRules(ruleSet)).some(span => text.slice(span.start, span.end).includes(secret)))
  })

  it('finds a value written on the line after its key', () => {
    const random = seeded(24)
    const secret = `${fake.hex(random, 12)}${fake.password(random)}`
    const yaml = `db:\n  password:\n    ${secret}\nother: 1\n`
    const labels = findRuleSpans(yaml, compileRules(ruleSet)).map(span => yaml.slice(span.start, span.end))
    assert.ok(labels.some(text => text.includes(secret)), JSON.stringify(labels))
  })

  it('can turn rules off by id', () => {
    assert.equal(compileRules(demo, ['demo']).rules.length, 0)
  })

  it('finds real-world formats with the shipped rules', () => {
    const random = seeded(20)
    const compiled = compileRules(gitleaks)
    const cases: [string, string][] = [
      ['github-pat', `token: ${fake.githubPat(random)}`],
      ['aws-access-token', `id=${fake.awsKeyId(random)}`],
      ['slack-bot-token', `SLACK=${fake.slackBot(random)}`],
      ['private-key', fake.privateKey(random)],
      ['generic-api-key', `api_key = "${fake.hex(random, 16)}${fake.password(random)}"`],
    ]
    for (const [id, text] of cases) {
      const labels = findRuleSpans(text, compiled).map(span => span.label)
      assert.ok(labels.includes(id), `${id} not found in rule hits ${JSON.stringify(labels)}`)
    }
  })
})
