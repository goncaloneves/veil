import type { On } from 'claude-code'
import { describe, expect, mock, test } from 'claude-code/testing'

const HEX = '0123456789abcdef'

function fakeHex(seed: number, length: number): string {
  let state = seed >>> 0
  let out = ''
  for (let i = 0; i < length; i++) {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    out += HEX[((t ^ (t >>> 14)) >>> 0) % 16]
  }
  return out
}

const TOKEN = fakeHex(7, 40)
const PASSWORD = fakeHex(11, 24)

const CONFIG = '/home/me/.config/veil/config.toml'

const LINKS: Record<string, string> = {}

const FILES: Record<string, string> = {
  '/home/me/.config/veil/config.toml': '[sources]\nhome = false\nenvironment = false\n',
  '/repo/.env': `API_TOKEN=${TOKEN}\nDATABASE_URL=postgres://app:${PASSWORD}@db:5432/app\nNODE_ENV=development\n`,
  '/repo/src/config.ts': `export const token = '${TOKEN}'\n`,
  '/repo/README.md': '# a project\n',
}

function children(path: string): { name: string; kind: 'file' | 'dir'; size: number; mtimeMs: number; isLink: boolean }[] {
  const prefix = path.endsWith('/') ? path : `${path}/`
  const names = new Map<string, 'file' | 'dir'>()
  for (const file of Object.keys(FILES)) {
    if (!file.startsWith(prefix)) continue
    const rest = file.slice(prefix.length)
    const slash = rest.indexOf('/')
    names.set(slash === -1 ? rest : rest.slice(0, slash), slash === -1 ? 'file' : 'dir')
  }
  return [...names].map(([name, kind]) => ({ name, kind, size: 0, mtimeMs: 0, isLink: false }))
}

function world(on: On, extraConfig = ''): void {
  mock.env(on, { HOME: '/home/me' })
  on('fs.read', (_$, e) => ({ value: e.path === CONFIG ? `${FILES[CONFIG]}${extraConfig}` : (FILES[LINKS[e.path] ?? e.path] ?? '') }))
  on('fs.stat', (_$, e) => {
    const kind = e.path in FILES ? 'file' : children(e.path).length > 0 ? 'dir' : undefined
    if (kind === undefined) throw new Error(`ENOENT: no such file or directory, stat '${e.path}'`)
    return { value: { kind, size: 0, mtimeMs: 0, isLink: e.path in LINKS, realPath: LINKS[e.path] ?? e.path } }
  })
  on('fs.exists', (_$, e) => ({ value: e.path in FILES || children(e.path).length > 0 }))
  on('fs.list', (_$, e) => ({ value: children(e.path) }))
  on('session.root', () => ({ value: '/repo' }))
  on('session.cwd', () => ({ value: '/repo' }))
  on('command.register', () => ({ value: { command: 'veil' } }))
  on('ui.log', () => ({ value: undefined }))
  on('session.start', (_$, e) => ({ cwd: e.cwd }))
}

const START = { cwd: '/repo', surface: 'terminal', isInteractive: true } as const

describe('veil in a Claude Code session', () => {
  test('masks a secret from .env in a tool result before it is stored and sent', async ($, on) => {
    world(on)
    const session = mock.session(on)
    await $.session.start(START)
    await $.session.append({
      message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: `API_TOKEN=${TOKEN}` }] },
      door: 'tool-result',
      origin: { kind: 'tool', tool: 'Bash' },
      uuid: 'row-1',
    })
    const stored = JSON.stringify(session.appended())
    expect(stored.includes(TOKEN)).toBe(false)
    expect(stored.includes('API_TOKEN=[veil:API_TOKEN]')).toBe(true)
  })

  test('masks a connection string and its password in the model text blocks', async ($, on) => {
    world(on)
    const session = mock.session(on)
    await $.session.start(START)
    await $.session.append({
      message: { type: 'assistant', role: 'assistant', content: [{ type: 'text', text: `the password is ${PASSWORD}` }] },
      door: 'response',
      origin: { kind: 'model', model: 'test' },
      uuid: 'row-2',
    })
    const stored = JSON.stringify(session.appended())
    expect(stored.includes(PASSWORD)).toBe(false)
    expect(stored.includes('[veil:DATABASE_URL.password]')).toBe(true)
  })

  test('masks a typed prompt before the turn starts', async ($, on) => {
    world(on)
    let seen = ''
    on('prompt.submit', (_$, e) => {
      seen = e.text
      return { text: e.text }
    })
    await $.session.start(START)
    await $.prompt.submit({ text: `use ${TOKEN} please`, wait: false, origin: { kind: 'composer' } })
    expect(seen).toBe('use [veil:API_TOKEN] please')
  })

  test('restores a placeholder only into its own file or a file that already holds the value, and refuses the rest', async ($, on) => {
    world(on)
    const written: Record<string, string> = {}
    on('tool.call', (_$, e) => {
      if (e.tool === 'Edit') written[e.file_path] = e.new_string
      if (e.tool === 'Write') written[e.file_path] = e.content
      return { result: {} }
    })
    await $.session.start(START)
    await $.tool.call({ tool: 'Edit', file_path: '/repo/src/config.ts', old_string: "'[veil:API_TOKEN]'", new_string: "'[veil:API_TOKEN]' as const" })
    await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' })
    const exfil = await $.tool.call({ tool: 'Write', file_path: '/tmp/exfil.env', content: 'API_TOKEN=[veil:API_TOKEN]' })
    const other = await $.tool.call({ tool: 'Write', file_path: '/repo/public/leak.env', content: '[veil:API_TOKEN]' })
    const unknown = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: 'X=[veil:generic-api-key#0a1b2c]' })
    expect(written['/repo/src/config.ts']).toBe(`'${TOKEN}' as const`)
    expect(written['/repo/.env']).toBe(`API_TOKEN=${TOKEN}\n`)
    expect(written['/tmp/exfil.env']).toBe(undefined)
    expect(written['/repo/public/leak.env']).toBe(undefined)
    expect(String(exfil.deny ?? exfil.text ?? '').includes('does not already hold it')).toBe(true)
    expect(String(other.deny ?? other.text ?? '').includes('does not already hold it')).toBe(true)
    expect(String(unknown.deny ?? unknown.text ?? '').includes('cannot resolve')).toBe(true)
  })

  test('refuses to restore through a source that was swapped for a link after the session started', async ($, on) => {
    world(on)
    const written: Record<string, string> = {}
    on('tool.call', (_$, e) => {
      if (e.tool === 'Write') written[e.file_path] = e.content
      return { result: {} }
    })
    await $.session.start(START)
    LINKS['/repo/.env'] = '/repo/README.md'
    try {
      const swapped = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' })
      expect(written['/repo/.env']).toBe(undefined)
      expect(typeof swapped.deny).toBe('string')
    } finally {
      delete LINKS['/repo/.env']
    }
  })

  test('picks up a secret added to .env after the session started when the file is read', async ($, on) => {
    world(on)
    const added = fakeHex(13, 32)
    const before = FILES['/repo/.env'] ?? ''
    on('tool.call', (_$, e) => (e.tool === 'Read' ? { result: { file: { content: FILES['/repo/.env'] } } } : { result: {} }))
    await $.session.start(START)
    FILES['/repo/.env'] = `${before}SIGNING_SECRET=${added}\n`
    try {
      const read = await $.tool.call({ tool: 'Read', file_path: '/repo/.env' })
      const record = JSON.stringify(read)
      expect(record.includes(added)).toBe(false)
      expect(record.includes('[veil:SIGNING_SECRET]')).toBe(true)
    } finally {
      FILES['/repo/.env'] = before
    }
  })

  test('refuses an MCP tool call that names a file and holds a placeholder, and lets others through', async ($, on) => {
    world(on)
    const ran: string[] = []
    on('tool.call', (_$, e) => {
      ran.push(e.tool)
      return { result: {} }
    })
    await $.session.start(START)
    const refused = await $.tool.call({ tool: 'mcp__files__write_file', path: '/repo/.env', content: 'K=[veil:API_TOKEN]' } as never)
    const allowed = await $.tool.call({ tool: 'mcp__search__query', query: 'how to rotate [veil:API_TOKEN]' } as never)
    expect(typeof refused.deny).toBe('string')
    expect(String(refused.deny).includes('cannot write real values through mcp__files__write_file')).toBe(true)
    expect(allowed.deny).toBe(undefined)
    expect(ran).toEqual(['mcp__search__query'])
  })

  test("masks a failed tool's error before the transcript keeps it", async ($, on) => {
    world(on)
    on('tool.call', () => ({ isError: true, result: `Error: Exit code 3\nAPI_TOKEN=${TOKEN}`, text: `Error: Exit code 3\nAPI_TOKEN=${TOKEN}` }))
    await $.session.start(START)
    const ran = await $.tool.call({ tool: 'Bash', command: 'cat secrets; exit 3' })
    const record = JSON.stringify(ran)
    expect(record.includes(TOKEN)).toBe(false)
    expect(record.includes('API_TOKEN=[veil:API_TOKEN]')).toBe(true)
  })

  test('refuses an @-mention of a file that holds secrets, and lets other mentions through', async ($, on) => {
    world(on)
    on('prompt.mention', () => ({ type: null }))
    await $.session.start(START)
    const env = await $.prompt.mention({ mention: '@.env', path: '/repo/.env' })
    const code = await $.prompt.mention({ mention: '@src/config.ts', path: '/repo/src/config.ts' })
    const clean = await $.prompt.mention({ mention: '@README.md', path: '/repo/README.md' })
    expect(typeof env.deny).toBe('string')
    expect(typeof code.deny).toBe('string')
    expect(clean.deny).toBe(undefined)
  })

  test('still masks a secret wrapped to look like a placeholder', async ($, on) => {
    world(on)
    const session = mock.session(on)
    await $.session.start(START)
    await $.session.append({
      message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: 't9', content: `[veil:${TOKEN}]` }] },
      door: 'tool-result',
      origin: { kind: 'tool', tool: 'Bash' },
      uuid: 'row-9',
    })
    expect(JSON.stringify(session.appended()).includes(TOKEN)).toBe(false)
  })

  test("masks a tool's own result record, which the screen and the transcript keep", async ($, on) => {
    world(on)
    on('tool.call', () => ({ result: { stdout: `API_TOKEN=${TOKEN}`, stderr: '', interrupted: false } }))
    await $.session.start(START)
    const ran = await $.tool.call({ tool: 'Bash', command: 'cat secrets' })
    const record = JSON.stringify(ran.result)
    expect(record.includes(TOKEN)).toBe(false)
    expect(record.includes('API_TOKEN=[veil:API_TOKEN]')).toBe(true)
  })

  test('masks the system prompt and adds its note', async ($, on) => {
    world(on)
    on('prompt.compose', () => ({ sections: [{ id: 'memory', text: `notes: ${TOKEN}`, scope: 'session' }] }))
    await $.session.start(START)
    const result = await $.prompt.compose({ model: 'm', promptModel: 'm', surfaces: [], tools: [], outputStyle: null, traits: [] })
    expect(result.sections[0]?.text).toBe('notes: [veil:API_TOKEN]')
    expect(result.sections[result.sections.length - 1]?.id).toBe('veil:note')
  })

  test('never mode refuses an edit that would replace a secret with its placeholder', async ($, on) => {
    world(on, '[restore]\nmode = "never"\n')
    let written: string | undefined
    on('tool.call', (_$, e) => {
      if (e.tool === 'Write') written = e.content
      return { result: {} }
    })
    await $.session.start(START)
    const ran = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]' })
    expect(written).toBe(undefined)
    expect(String(ran.deny ?? ran.text ?? '').includes('never')).toBe(true)
  })

  test('/veil reports names and counts, never values', async ($, on) => {
    world(on)
    await $.session.start(START)
    const result = await $.command.run({ command: 'veil', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 80 } })
    const text = result.text ?? ''
    expect(text.includes('masking 3 known values')).toBe(true)
    expect(text.includes('/repo/.env (dotenv): 3 values')).toBe(true)
    expect(text.includes(TOKEN)).toBe(false)
  })
})

function sourcesWorld(on: On, env: Record<string, string>, files: Record<string, string>, cwd: string, logged: string[] = []): void {
  mock.env(on, env)
  const list = (path: string) => {
    const prefix = path.endsWith('/') || path.endsWith('\\') ? path : `${path}${path.includes('\\') ? '\\' : '/'}`
    const names = new Map<string, 'file' | 'dir'>()
    for (const file of Object.keys(files)) {
      if (!file.startsWith(prefix)) continue
      const rest = file.slice(prefix.length)
      const cut = rest.search(/[\\/]/)
      names.set(cut === -1 ? rest : rest.slice(0, cut), cut === -1 ? 'file' : 'dir')
    }
    return [...names].map(([name, kind]) => ({ name, kind, size: 0, mtimeMs: 0, isLink: false }))
  }
  on('fs.read', (_$, e) => ({ value: files[e.path] ?? '' }))
  on('fs.stat', (_$, e) => ({ value: { kind: e.path in files ? 'file' : list(e.path).length > 0 ? 'dir' : 'other', size: 0, mtimeMs: 0, isLink: false, realPath: e.path } }))
  on('fs.exists', (_$, e) => ({ value: e.path in files || list(e.path).length > 0 }))
  on('fs.list', (_$, e) => ({ value: list(e.path) }))
  on('session.root', () => ({ value: cwd }))
  on('session.cwd', () => ({ value: cwd }))
  on('command.register', () => ({ value: { command: 'veil' } }))
  on('ui.log', (_$, e) => {
    logged.push(e.text)
    return { value: undefined }
  })
  on('session.start', (_$, e) => ({ cwd: e.cwd }))
}

describe('veil sources in a Claude Code session', () => {
  test('on Linux, masks any secret-named variable from /proc/self/environ', async ($, on) => {
    const secret = fakeHex(23, 32)
    sourcesWorld(on, { HOME: '/home/me' }, { '/proc/self/environ': `PATH=/usr/bin\0POSTGRES_ADMIN_PASSWORD=${secret}\0HOME=/home/me\0` }, '/repo')
    const session = mock.session(on)
    await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })
    await $.session.append({
      message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: `POSTGRES_ADMIN_PASSWORD=${secret}` }] },
      door: 'tool-result',
      origin: { kind: 'tool', tool: 'Bash' },
      uuid: 'row-env',
    })
    const stored = JSON.stringify(session.appended())
    expect(stored.includes(secret)).toBe(false)
    expect(stored.includes('[veil:POSTGRES_ADMIN_PASSWORD]')).toBe(true)
  })

  test('on Windows, prefers USERPROFILE over HOME and reads the gh token from %APPDATA%', async ($, on) => {
    const ghToken = fakeHex(29, 40)
    const stale = fakeHex(31, 40)
    sourcesWorld(
      on,
      { HOME: '/h', USERPROFILE: '/Users/me', APPDATA: '/Users/me/AppData/Roaming', OS: 'Windows_NT' },
      { '/Users/me/AppData/Roaming/GitHub CLI/hosts.yml': `github.com:\n    oauth_token: ${ghToken}\n`, '/h/.config/gh/hosts.yml': `github.com:\n    oauth_token: ${stale}\n` },
      '/repo',
    )
    await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })
    const result = await $.command.run({ command: 'veil', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 80 } })
    expect(result.text?.includes('~/AppData/Roaming/GitHub CLI/hosts.yml (gh): 1 value')).toBe(true)
    expect(result.text?.includes('/h/')).toBe(false)
  })
})

describe('veil platform detection in a Claude Code session', () => {
  test('detects macOS from /System/Library even without ~/Library/Application Support', async ($, on) => {
    const netlify = fakeHex(37, 40)
    sourcesWorld(on, { HOME: '/home/me' }, { '/System/Library/CoreServices/x': '', '/home/me/Library/Preferences/netlify/config.json': JSON.stringify({ users: { u: { auth: { token: netlify } } } }) }, '/repo')
    await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })
    const result = await $.command.run({ command: 'veil', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 80 } })
    expect(result.text?.includes('~/Library/Preferences/netlify/config.json (netlify): 1 value')).toBe(true)
  })

  test('notes in the debug log when /proc/self/environ reads empty on Linux', async ($, on) => {
    const logged: string[] = []
    sourcesWorld(on, { HOME: '/home/me' }, {}, '/repo', logged)
    await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })
    expect(logged.some(line => line.includes('could not read /proc/self/environ'))).toBe(true)
  })
})
