import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { VeilSession, type AdapterFs } from '../src/adapters/claude-code/session.ts'
import { CLAUDE_TOOLS, checkInput } from '../src/restore.ts'
import { fake, memoryFs, seeded } from './helpers.ts'

const random = seeded(40)
const TOKEN = fake.hex(random, 40)

function adapterFs(files: Record<string, string>, links: Record<string, string> = {}): AdapterFs {
  const rooted = (path: string) => (path.startsWith('/') ? path : `/${path}`)
  const fs = memoryFs(Object.fromEntries(Object.entries(files).map(([path, text]) => [rooted(path), text])))
  return {
    read: path => fs.read(rooted(path)),
    list: dir => fs.list(rooted(dir)),
    exists: path => fs.exists(rooted(path)),
    kindOf: path => fs.kindOf(rooted(path)),
    realPath: async path => links[path] ?? (path in files ? path : undefined),
  }
}

async function session(extra = '', links: Record<string, string> = {}): Promise<VeilSession> {
  const veil = new VeilSession()
  await veil.start(
    adapterFs(
      {
        '/home/me/.config/veil/config.toml': `[sources]\nhome = false\nenvironment = false\n${extra}`,
        '/repo/.env': `API_TOKEN=${TOKEN}\n`,
      },
      links,
    ),
    { home: '/home/me', root: '/repo', cwd: '/repo', platform: 'linux', vars: {} },
  )
  return veil
}

const at = (content: string, realPath?: string) => ({ content, realPath })

async function checkEdit(veil: VeilSession, path: string, fields: Record<string, string>, target: { content: string; realPath?: string | undefined }) {
  const checked = await checkInput({ file_path: path, ...fields }, { veil, tools: CLAUDE_TOOLS, probe: async () => target }, 'Edit')
  if ('deny' in checked) return checked
  const { file_path: _, ...out } = checked.input as Record<string, string>
  return { fields: out }
}

describe('VeilSession', () => {
  it('masks secrets anywhere in a tool result, including under data, and leaves media alone', async () => {
    const veil = await session()
    const result = { data: { apiKey: TOKEN }, list: [`x ${TOKEN}`], image: { type: 'image', source: { data: TOKEN } } }
    const masked = veil.maskValue(result) as typeof result
    assert.equal(masked.data.apiKey, '[veil:API_TOKEN]')
    assert.equal(masked.list[0], 'x [veil:API_TOKEN]')
    assert.equal(masked.image, result.image)
  })

  it('returns the same object when nothing needed masking', async () => {
    const veil = await session()
    const result = { stdout: 'clean', nested: { ok: true } }
    assert.equal(veil.maskValue(result), result)
  })

  it('restores into the value own file or a file holding it, and refuses everything else', async () => {
    const veil = await session()
    assert.deepEqual(await checkEdit(veil, '/repo/.env', { content: 'API_TOKEN=[veil:API_TOKEN]' }, at('', '/repo/.env')), { fields: { content: `API_TOKEN=${TOKEN}` } })
    assert.deepEqual(await checkEdit(veil, '/repo/src/a.ts', { new_string: '[veil:API_TOKEN]' }, at(`k = '${TOKEN}'`, '/repo/src/a.ts')), { fields: { new_string: TOKEN } })
    for (const path of ['/tmp/exfil.env', '/repo/public/leak.env', '/repo/.env.example.local', '/repo/docs/.envrc']) {
      assert.ok('deny' in await checkEdit(veil, path, { content: '[veil:API_TOKEN]' }, at('', path)), path)
    }
  })

  it('restores into the own file only when it still lands where it did at load', async () => {
    const veil = await session()
    assert.ok('fields' in await checkEdit(veil, './.env', { content: '[veil:API_TOKEN]' }, at('', '/repo/.env')))
    assert.ok('deny' in await checkEdit(veil, '/repo/.env', { content: '[veil:API_TOKEN]' }, at('', '/repo/public/config.js')))
    assert.ok('deny' in await checkEdit(veil, '/repo/.env', { content: '[veil:API_TOKEN]' }, at('')))
  })

  it('never restores into a source that was already a link to somewhere else at load, unless that target is the file edited', async () => {
    const veil = await session('', { '/repo/.env': '/vault/app.env' })
    assert.ok('deny' in await checkEdit(veil, '/repo/.env', { content: '[veil:API_TOKEN]' }, at('', '/repo/.env')))
    assert.ok('fields' in await checkEdit(veil, '/repo/.env', { content: '[veil:API_TOKEN]' }, at('', '/vault/app.env')))
  })

  it('never treats the environment as a file a placeholder may be restored into', async () => {
    const value = fake.hex(seeded(42), 40)
    const veil = new VeilSession()
    await veil.start(
      adapterFs({ '/home/me/.config/veil/config.toml': '[sources]\nhome = false\n', '/repo/environment': 'notes\n' }),
      { home: '/home/me', root: '/repo', cwd: '/repo', platform: 'linux', vars: { OPENAI_API_KEY: value } },
    )
    const masked = veil.mask(value)
    assert.match(masked, /^\[veil:/)
    assert.ok('deny' in await checkEdit(veil, 'environment', { content: `K=${masked}` }, at('notes\n', '/repo/environment')))
  })

  it('escapes a restored value for JSON when the edit is JSON text, and keeps its formatting', async () => {
    const veil = await session()
    const content = '{\n  "token": "[veil:API_TOKEN]"\n}\n'
    assert.deepEqual(await checkEdit(veil, '/repo/.env', { content }, at('', '/repo/.env')), { fields: { content: `{\n  "token": "${TOKEN}"\n}\n` } })
  })

  it('matches Windows spellings of a source path', async () => {
    const veil = new VeilSession()
    await veil.start(
      adapterFs({
        'C:/Users/me/.config/veil/config.toml': '[sources]\nhome = false\nenvironment = false\n',
        'C:/repo/.env': `API_TOKEN=${TOKEN}\n`,
      }),
      { home: 'C:/Users/me', root: 'C:/repo', cwd: 'C:/repo', platform: 'win32', vars: {} },
    )
    assert.equal(veil.isSource('c:\\REPO\\.env'), true)
    assert.equal(veil.isSource('C:\\repo\\.env.local'), true)
    assert.equal(veil.isSource('C:\\repo\\src\\a.ts'), false)
    assert.ok('fields' in await checkEdit(veil, 'c:\\repo\\.env', { content: '[veil:API_TOKEN]' }, at('', 'C:\\Repo\\.env')))
  })

  it('refuses a placeholder it cannot resolve, unless the file already holds that exact text', async () => {
    const veil = await session()
    assert.ok('deny' in await checkEdit(veil, '/repo/.env', { content: '[veil:github-pat#0a1b2c]' }, at('', '/repo/.env')))
    assert.ok('deny' in await checkEdit(veil, '/repo/.env.local', { content: 'API_KEY=[veil:API_KEY@.env.local]' }, at('API_KEY=real', '/repo/.env.local')))
    const readme = '# docs\nshows [veil:DATABASE_URL]\n'
    assert.deepEqual(await checkEdit(veil, '/repo/README.md', { old_string: 'shows [veil:DATABASE_URL]', new_string: 'now shows [veil:DATABASE_URL]' }, at(readme, '/repo/README.md')), {
      fields: { old_string: 'shows [veil:DATABASE_URL]', new_string: 'now shows [veil:DATABASE_URL]' },
    })
  })

  it('in never mode refuses edits that would write a placeholder over real content', async () => {
    const veil = await session('[restore]\nmode = "never"\n')
    const checked = await checkEdit(veil, '/repo/.env', { content: 'API_TOKEN=[veil:API_TOKEN]' }, at(`API_TOKEN=${TOKEN}`, '/repo/.env'))
    assert.ok('deny' in checked && checked.deny.includes('never'))
  })

  it('still restores a rotated-out value into a file that holds it', async () => {
    const veil = await session()
    const fresh = fake.hex(seeded(41), 40)
    veil.masker.setSecrets([{ name: 'API_TOKEN', value: fresh, source: '/repo/.env' }])
    const old = veil.mask(TOKEN)
    assert.match(old, /~previous#/)
    assert.deepEqual(await checkEdit(veil, '/repo/legacy.ts', { new_string: old }, at(`k = '${TOKEN}'`, '/repo/legacy.ts')), { fields: { new_string: TOKEN } })
    assert.ok('deny' in await checkEdit(veil, '/repo/.env', { content: old }, at(`API_TOKEN=${fresh}`, '/repo/.env')))
  })

  it('skips only payloads that are base64 from start to end', async () => {
    const veil = await session()
    const blob = 'QUJD'.repeat(300_000)
    assert.equal(veil.maskValue(blob), blob)
    const mixed = `${'QUJD'.repeat(300_000)} token ${TOKEN}`
    assert.ok(!(veil.maskValue(mixed) as string).includes(TOKEN))
  })

  it('asks for a source refresh on a read of a secret file, and otherwise at most every 15 seconds', async () => {
    const veil = await session()
    assert.equal(veil.refreshDue('/repo/.env'), true)
    assert.equal(veil.refreshDue('/repo/src/a.ts'), false)
    assert.equal(veil.refreshDue(), false)
    assert.equal(new VeilSession().refreshDue('/repo/.env'), false)
  })

  it('withholds instead of throwing when masking fails', async () => {
    const veil = await session()
    assert.equal(veil.holdsSecret(`token ${TOKEN}`), true)
    assert.equal(veil.holdsSecret('nothing here'), false)
  })
})
