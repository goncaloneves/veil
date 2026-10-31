import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { fake, seeded } from './helpers.ts'

const cli = new URL('../src/cli/main.ts', import.meta.url).pathname
const dir = mkdtempSync(join(tmpdir(), 'veil-cli-'))
const random = seeded(30)
const token = fake.hex(random, 40)
writeFileSync(join(dir, '.env'), `API_TOKEN=${token}\nNODE_ENV=development\n`)

after(() => rmSync(dir, { recursive: true, force: true }))

function veil(args: string[], input?: string) {
  const env: Record<string, string> = { PATH: process.env.PATH ?? '', HOME: dir, XDG_CONFIG_HOME: join(dir, 'xdg') }
  return spawnSync(process.execPath, [cli, ...args], { cwd: dir, input, encoding: 'utf8', env })
}

describe('veil cli', () => {
  it('scan masks stdin and exits 1 when it masked something', () => {
    const result = veil(['scan'], `token ${token} env development`)
    assert.equal(result.stdout, 'token [veil:API_TOKEN] env development')
    assert.equal(result.status, 1)
  })

  it('scan exits 0 on clean input', () => {
    const result = veil(['scan'], 'nothing secret here')
    assert.equal(result.stdout, 'nothing secret here')
    assert.equal(result.status, 0)
  })

  it('scan --json reports labels and offsets, never values', () => {
    const result = veil(['scan', '--json'], `x ${token}`)
    assert.ok(!result.stdout.includes(token))
    assert.deepEqual(JSON.parse(result.stdout), [{ file: '-', hits: [{ start: 2, end: 42, label: 'API_TOKEN', kind: 'known' }] }])
  })

  it('sources lists names, never values', () => {
    const result = veil(['sources'])
    assert.match(result.stdout, /\.env \(dotenv\): API_TOKEN/)
    assert.ok(!result.stdout.includes(token))
  })

  it('config init writes a starter file once', () => {
    assert.match(veil(['config', 'init']).stdout, /Created .*veil\/config\.toml/)
    assert.match(veil(['config', 'init']).stdout, /already exists/)
    assert.match(veil(['config', 'path']).stdout, /veil\/config\.toml/)
  })

  it('prints help and rejects unknown commands', () => {
    assert.match(veil(['--help']).stdout, /Usage:/)
    assert.equal(veil(['bogus']).status, 2)
  })
})
