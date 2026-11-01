import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, describe, it } from 'node:test'
import { fake, seeded } from './helpers.ts'

const cli = fileURLToPath(new URL('../src/cli/main.ts', import.meta.url))
const dir = mkdtempSync(join(tmpdir(), 'veil-cli-'))
const random = seeded(30)
const token = fake.hex(random, 40)
writeFileSync(join(dir, '.env'), `API_TOKEN=${token}\nNODE_ENV=development\n`)

after(() => rmSync(dir, { recursive: true, force: true }))

function env(): Record<string, string> {
  const out: Record<string, string> = { PATH: process.env.PATH ?? '', HOME: dir, USERPROFILE: dir, APPDATA: join(dir, 'appdata'), XDG_CONFIG_HOME: join(dir, 'xdg') }
  for (const key of ['SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP']) {
    const value = process.env[key]
    if (value !== undefined) out[key] = value
  }
  return out
}

function veil(args: string[], input?: string) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: dir, input, encoding: 'utf8', env: env() })
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

  it('scan reads UTF-16 files and stdin, as Windows PowerShell writes them', () => {
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`token ${token}\r\n`, 'utf16le')])
    writeFileSync(join(dir, 'ps-out.txt'), utf16)
    const file = veil(['scan', join(dir, 'ps-out.txt')])
    assert.equal(file.stdout, 'token [veil:API_TOKEN]\r\n')
    assert.equal(file.status, 1)
    const piped = spawnSync(process.execPath, [cli, 'scan'], { cwd: dir, input: utf16, env: env() })
    assert.equal(piped.stdout.toString('utf8'), 'token [veil:API_TOKEN]\r\n')
  })

  it('sources lists names under every file they come from, never values', () => {
    writeFileSync(join(dir, '.env.local'), `API_TOKEN=${token}\n`)
    const result = veil(['sources'])
    rmSync(join(dir, '.env.local'))
    assert.match(result.stdout, /\.env \(dotenv\): API_TOKEN/)
    assert.match(result.stdout, /\.env\.local \(dotenv\): API_TOKEN/)
    assert.ok(!result.stdout.includes(token))
  })

  it('config init writes a starter file once', () => {
    assert.match(veil(['config', 'init']).stdout, /Created .*veil[\\/]config\.toml/)
    assert.match(veil(['config', 'init']).stdout, /already exists/)
    assert.match(veil(['config', 'path']).stdout, /veil[\\/]config\.toml/)
    const ignored = spawnSync(process.execPath, [cli, 'config', 'path'], { cwd: dir, encoding: 'utf8', env: { ...env(), VEIL_CONFIG: 'relative.toml' } })
    assert.match(ignored.stderr, /VEIL_CONFIG=relative\.toml was ignored/)
    assert.doesNotMatch(ignored.stdout, /relative\.toml/)
  })

  it('init installs an agent adapter from a local bundle into that agent folder', () => {
    const bundle = join(dir, 'bundle.js')
    writeFileSync(bundle, 'export default {}\n')
    const result = veil(['init', 'opencode', '--from', bundle])
    assert.equal(result.status, 0, result.stderr)
    assert.equal(readFileSync(join(dir, 'xdg', 'opencode', 'plugins', 'veil.js'), 'utf8'), 'export default {}\n')
    assert.equal(veil(['init', 'cursor']).status, 2)
  })

  it('refuses ambiguous init and proxy arguments instead of guessing', () => {
    assert.equal(veil(['init', '--from', join(dir, 'bundle.js')]).status, 2)
    assert.equal(veil(['init', 'pi', 'opencode', '--dry-run']).status, 2)
    assert.equal(veil(['init', 'kilo', '--from', '--dry-run']).status, 2)
    assert.equal(veil(['proxy', '--root', join(dir, 'missing')]).status, 2)
    const credentials = veil(['proxy', '--route', 'work=https://user:pw@llm.example.com'])
    assert.equal(credentials.status, 2)
    assert.ok(!credentials.stderr.includes('pw@'))
    assert.equal(veil(['proxy', '--route', 'work=ftp://llm.example.com']).status, 2)
    assert.equal(veil(['proxy', '--bogus']).status, 2)
    assert.equal(veil(['scan', '--bogus'], '').status, 2)
    assert.equal(veil(['init', 'kilo', '--from=']).status, 2)
    const unnamed = veil(['proxy', '--route', 'work'])
    assert.equal(unnamed.status, 2)
    assert.match(unnamed.stderr, /has no =url/)
  })

  it('documents every command it has, and installs each plugin where the docs say', () => {
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
    const help = veil(['--help']).stdout
    const listed = [...readme.matchAll(/^\| `veil ([a-z]+)[^`]*` \|/gm)].map(match => match[1] ?? '')
    const helped = [...help.replace(/\r\n/g, '\n').matchAll(/^  veil ([a-z]+)/gm)].map(match => match[1] ?? '').filter(command => command !== 'version')
    assert.ok(listed.length >= 6)
    assert.deepEqual(listed.sort(), helped.sort())
    for (const doc of ['../INSTALL.md', '../docs/HARNESSES.md']) {
      const text = readFileSync(new URL(doc, import.meta.url), 'utf8').replace(/\r\n/g, '\n')
      const lines = [...text.matchAll(/^veil init (pi|opencode|kilo) +# (?:[A-Za-z ]+: )?~\/(\S+)$/gm)]
      assert.equal(lines.length, 3, doc)
      for (const match of lines) {
        const out = veil(['init', match[1] ?? '', '--dry-run']).stdout
        const expected = (match[2] ?? '').replace(/^\.config\//, 'xdg/')
        assert.ok(out.includes(join(dir, ...expected.split('/'))), `${doc}: ${match[0]} → ${out}`)
      }
    }
  })

  it('prints help for a command asked with --help, but still rejects an unknown one', () => {
    const scan = veil(['scan', '--help'])
    assert.equal(scan.status, 0)
    assert.match(scan.stdout, /Usage:/)
    assert.equal(veil(['bogus', '--help']).status, 2)
  })

  it('reads relative paths from the folder the proxy starts in, and loads secrets from --root', async () => {
    const root = join(dir, 'proxy-root')
    mkdirSync(root, { recursive: true })
    const child = spawn(process.execPath, [cli, 'proxy', '--port', '0', '--root', root], { cwd: dir, env: env() })
    const first = await new Promise<string>((resolve, reject) => {
      let out = ''
      child.stdout.on('data', chunk => {
        out += chunk
        if (out.includes('\n')) resolve(out.split('\n')[0] ?? '')
      })
      child.on('error', reject)
      setTimeout(() => resolve(out), 10_000)
    })
    child.kill('SIGINT')
    assert.match(first, /veil proxy on http:\/\/127\.0\.0\.1:\d+ for /)
    assert.match(first, /for ~[\\/]proxy-root; start your agent in /)
    assert.ok(first.endsWith(basename(dir)), first)
  })

  it('prints help and rejects unknown commands', () => {
    assert.match(veil(['--help']).stdout, /Usage:/)
    assert.equal(veil(['bogus']).status, 2)
  })
})
