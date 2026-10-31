import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ENCODINGS } from '../src/config/config.ts'
import { base64Cores, base64Encode, utf8Encode } from '../src/core/encoding.ts'
import { Masker } from '../src/core/masker.ts'
import { emptyRuleSet } from '../src/core/rules.ts'
import type { Secret } from '../src/core/types.ts'
import { ruleSet } from '../src/rules/index.ts'
import { fake, fakeToken, keyHeader, seeded, utf16le, utf16leBase64 } from './helpers.ts'

function known(secrets: Secret[]): Masker {
  return new Masker({ secrets, ruleSet: emptyRuleSet(), minLength: 8, encodings: ENCODINGS, salt: 'enc-salt' })
}

function withRules(secrets: Secret[] = []): Masker {
  return new Masker({ secrets, ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'enc-salt' })
}

function hidden(masker: Masker, text: string, value: string): string {
  const out = masker.mask(text).text
  assert.ok(out !== text, `nothing masked in ${JSON.stringify(text.slice(0, 80))}`)
  for (let at = 0; at + 12 <= value.length; at += 4) assert.ok(!out.includes(value.slice(at, at + 12)), `${JSON.stringify(out)} still shows part of the value`)
  return out
}

describe('base64 forms', () => {
  const random = seeded(50)
  const pat = `${['github', 'pat'].join('_')}_${fakeToken(random, 82)}`

  it('finds base64 wrapped at 76 columns, as GNU base64 prints it', () => {
    const m = known([{ name: 'GH_TOKEN', value: pat, source: '/r/.env' }])
    const wrapped = (base64Encode(pat).match(/.{1,76}/g) ?? []).join('\n')
    const out = m.mask(`$ echo -n $GH_TOKEN | base64\n${wrapped}\n$ `).text
    assert.equal(out, '$ echo -n $GH_TOKEN | base64\n[veil:GH_TOKEN~base64]\n$ ')
  })

  it('finds the value at byte offsets 0, 1 and 2 inside a larger base64 blob', () => {
    const m = known([{ name: 'API_TOKEN', value: pat, source: '/r/.env' }])
    for (const prefix of ['', 'A', 'AB', 'ABC=', 'KEY=x\nAPI_TOKEN=']) {
      const blob = base64Encode(`${prefix}${pat}\nOTHER=1\n`)
      const out = m.mask(`data:\n  .env: ${blob}\n`)
      assert.ok(out.hits.some(hit => hit.label.startsWith('API_TOKEN~base64')), `offset ${prefix.length}`)
      for (const core of base64Cores(utf8Encode(pat))) assert.ok(!out.text.includes(core.slice(4, 24)), `offset ${prefix.length}`)
    }
  })

  it('finds a Basic credential whose user name is not a multiple of three bytes long', () => {
    const password = fake.password(random)
    const m = known([{ name: 'REGISTRY_PASSWORD', value: password, source: '/r/.env' }])
    for (const user of ['dev', 'ops1', 'admin']) {
      const header = `Authorization: Basic ${base64Encode(`${user}:${password}`)}`
      assert.ok(m.mask(header).hits.some(hit => hit.label.startsWith('REGISTRY_PASSWORD~base64')), user)
    }
  })
})

describe('Windows encodings', () => {
  const random = seeded(51)
  const value = `${fakeToken(random, 12)}/+= !'()*&<>`
  const plain = fakeToken(random, 32)

  it('finds UTF-16LE text, as Git Bash shows a file PowerShell wrote', () => {
    const m = known([{ name: 'API_TOKEN', value: plain, source: '/r/.env' }])
    const out = m.mask(utf16le(`API_TOKEN=${plain}\r\n`))
    assert.ok(!out.text.includes(utf16le(plain).slice(0, 24)))
    assert.equal(out.hits[0]?.label, 'API_TOKEN')
  })

  it('runs the pattern rules over UTF-16LE text too', () => {
    const pat = fake.githubPat(random)
    const out = withRules().mask(utf16le(`GITHUB_TOKEN=${pat}\r\n`))
    assert.equal(out.hits.length, 1)
    assert.ok(!out.text.includes(utf16le(pat).slice(8, 32)))
  })

  it('finds a value inside a PowerShell -EncodedCommand', () => {
    const m = known([{ name: 'API_TOKEN', value: plain, source: '/r/.env' }])
    for (const lead of ['', 'x', '$env:API_TOKEN = "']) {
      const command = `powershell -EncodedCommand ${utf16leBase64(`${lead}${plain}"; Invoke-Thing`)}`
      assert.ok(m.mask(command).hits.some(hit => hit.label.startsWith('API_TOKEN~utf16')), JSON.stringify(lead))
    }
  })

  it('finds a value in a regedit export written as hex(2) bytes, wrapped or not', () => {
    const m = known([{ name: 'API_TOKEN', value: plain, source: '/r/.env' }])
    const bytes = [...plain].flatMap(char => [char.charCodeAt(0).toString(16).padStart(2, '0'), '00'])
    const line = `"API_TOKEN"=hex(2):${bytes.join(',')},00,00`
    const wrapped = `"API_TOKEN"=hex(2):${bytes.slice(0, 20).join(',')},\\\r\n  ${bytes.slice(20).join(',')},00,00`
    for (const text of [line, wrapped]) {
      const out = m.mask(text)
      assert.ok(out.hits.some(hit => hit.label.startsWith('API_TOKEN~utf16')), text.slice(0, 60))
      assert.ok(!out.text.includes(bytes.slice(24, 40).join(',')))
    }
  })

  it('finds lowercase, strict RFC 3986 and form URL encodings', () => {
    const m = known([{ name: 'SECRET', value, source: '/r/.env' }])
    const strict = encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
    for (const text of [strict, strict.replace(/%[0-9A-F]{2}/g, escape => escape.toLowerCase()), strict.replaceAll('%20', '+'), strict.replaceAll('%2F', '/')]) {
      const out = m.mask(`q=${text}&x=1`)
      assert.ok(out.hits.some(hit => hit.label.startsWith('SECRET~url')), text)
    }
  })

  it('finds PowerShell and PHP JSON escapes', () => {
    const m = known([{ name: 'SECRET', value, source: '/r/.env' }])
    const powershell = JSON.stringify(value).slice(1, -1).replace(/[<>&']/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`)
    const php = JSON.stringify(value).slice(1, -1).replaceAll('/', '\\/')
    for (const text of [powershell, php]) assert.ok(m.mask(`{"v":"${text}"}`).hits.some(hit => hit.label.startsWith('SECRET~json')), text)
  })

  it("finds a value written with '' doubling, '\\'' quoting, cmd ^ escapes and shell or PowerShell backslash and backtick escapes", () => {
    const m = known([{ name: 'SECRET', value, source: '/r/.env' }])
    const forms = [
      `'${value.replaceAll("'", "''")}'`,
      `'${value.replaceAll("'", "'\\''")}'`,
      `set X=${value.replace(/[&|<>^]/g, '^$&')}`,
      `"${value.replace(/["$`\\]/g, '\\$&')}"`,
      `"${value.replace(/[$"`]/g, '`$&')}"`,
    ]
    for (const text of forms) assert.ok(m.mask(text).hits.some(hit => hit.label.startsWith('SECRET~escaped') || hit.label === 'SECRET'), text)
  })

  it('finds a non-ASCII value in NFD and after a code page turned its accents into replacement characters', () => {
    const accented = `${fakeToken(random, 6)}\u00e4\u00f6${fakeToken(random, 6)}\u00e9`
    const m = known([{ name: 'SECRET', value: accented, source: '/r/.env' }])
    for (const text of [accented.normalize('NFD'), accented.replace(/[^\x00-\x7f]/g, '\ufffd'), accented.replace(/[^\x00-\x7f]/g, '?')]) {
      assert.ok(m.mask(`v=${text}`).hits.length > 0, JSON.stringify(text))
    }
  })

  it('masks a key printed with CRLF line endings, short last line included', () => {
    const key = `${fake.privateKey(random).replace(/\n-----END/, `\n${fakeToken(random, 9)}\n-----END`)}`
    const m = known([{ name: 'ssh/id', value: key, source: '/h/.ssh/id' }])
    const crlf = key.replaceAll('\n', '\r\n')
    const out = m.mask(`cat id\r\n${crlf}\r\n$ `).text
    assert.equal(out, 'cat id\r\n[veil:ssh/id~unwrapped]\r\n$ ')
  })

  it('masks a value Format-List wrapped onto an indented line', () => {
    const m = known([{ name: 'API_TOKEN', value: plain, source: '/r/.env' }])
    const out = m.mask(`Name  : API_TOKEN\r\nValue : ${plain.slice(0, 20)}\r\n        ${plain.slice(20)}\r\n`).text
    assert.equal(out, 'Name  : API_TOKEN\r\nValue : [veil:API_TOKEN]\r\n')
  })

  it('finds a value with the URL encoding of ~ that Java and PHP use', () => {
    const tilde = `${fakeToken(random, 12)}~${fakeToken(random, 6)} x`
    const m = known([{ name: 'SECRET', value: tilde, source: '/r/.env' }])
    for (const form of [encodeURIComponent(tilde).replaceAll('~', '%7E').replaceAll('%20', '+'), encodeURIComponent(tilde).replaceAll('~', '%7e')]) {
      assert.ok(m.mask(`q=${form}`).hits.some(hit => hit.label.startsWith('SECRET~url')), form)
    }
  })

  it('does not turn armour header lines of a key into needles', () => {
    const key = `${keyHeader('PGP', { block: true })}\nVersion: GnuPG v2\nComment: build key\n\n${fakeToken(random, 64)}\n${fakeToken(random, 64)}\n${keyHeader('PGP', { block: true, end: true })}`
    const m = known([{ name: 'gpg/key', value: key, source: '/h/key.asc' }])
    for (const text of ['Version: GnuPG v2', 'Comment: build key']) assert.equal(m.mask(text).text, text)
  })
})

describe('JSON escapes', () => {
  const random = seeded(53)

  it('finds a known value behind any JSON escape style', () => {
    const value = `${fakeToken(random, 10)}+&'\u00e9/${fakeToken(random, 6)}`
    const m = known([{ name: 'SECRET', value, source: '/r/.env' }])
    const escape = (char: string, upper = false) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')[upper ? 'toUpperCase' : 'toLowerCase']()}`
    const dotnet = value.replace(/[+&'\u00e9]/g, char => escape(char, true))
    const go = value.replace(/[&]/g, char => escape(char))
    const python = value.replace(/\u00e9/g, char => escape(char))
    const slashes = value.replaceAll('/', '\\/')
    for (const text of [dotnet, go, python, slashes]) {
      const out = m.mask(`{"v":"${text}"}`)
      assert.equal(out.hits.length, 1, text)
      assert.equal(out.text.startsWith('{"v":"[veil:SECRET'), true, out.text)
    }
  })

  it('runs the rules over JSON inside JSON and escaped URLs', () => {
    const bearer = fakeToken(random, 40)
    const password = fake.password(random)
    const nested = JSON.stringify({ body: JSON.stringify({ authorization: `Bearer ${bearer}` }) })
    assert.ok(!withRules().mask(nested).text.includes(bearer))
    const escaped = `{"url":"postgres:\\/\\/app:${password}@db\\/app"}`
    assert.ok(!withRules().mask(escaped).text.includes(password))
  })
})

describe('colour codes written as escapes', () => {
  const random = seeded(55)

  it('masks a token behind ANSI codes escaped inside JSON or written for echo -e', () => {
    const key = fake.awsKeyId(random)
    const password = `${fakeToken(random, 12)}x9`
    for (const text of [
      `{"log":"\\u001b[1;32m${key}\\u001b[0m"}`,
      `{"log":"\\u001b[1mmysql -u root -p${password} app\\u001b[0m"}`,
      `echo -e "\\033[32m${key}\\033[0m"`,
      `printf '\\x1b[31m${key}\\x1b[0m'`,
    ]) {
      const out = withRules().mask(text).text
      assert.ok(!out.includes(key) && !out.includes(password), out)
    }
  })
})

describe('Format-List wrapping for rules', () => {
  const random = seeded(54)

  it('catches a token Format-List wrapped onto lines indented to the value column', () => {
    const pat = fake.githubPat(random)
    const jwt = fake.jwt(random, 80)
    for (const token of [pat, jwt]) {
      const text = `Name  : TOKEN\r\nValue : ${token.slice(0, 20)}\r\n        ${token.slice(20, 50)}\r\n        ${token.slice(50)}\r\n`
      const out = withRules().mask(text).text
      assert.ok(!out.includes(token.slice(20, 50)), out)
    }
  })
})

describe('text views', () => {
  const random = seeded(52)

  it('masks a known value split by terminal colour codes', () => {
    const value = fakeToken(random, 32)
    const m = known([{ name: 'API_TOKEN', value, source: '/r/.env' }])
    const colored = `API_TOKEN=${value.slice(0, 10)}\x1b[01;31m\x1b[K${value.slice(10, 20)}\x1b[m\x1b[K${value.slice(20)}`
    hidden(m, colored, value)
  })

  it('runs the pattern rules over text with colour codes', () => {
    const pat = fake.githubPat(random)
    const out = withRules().mask(`token \x1b[1;32m${pat.slice(0, 6)}\x1b[0m${pat.slice(6)}`)
    assert.ok(!out.text.includes(pat.slice(6)))
  })
})
