import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { VeilSession } from '../src/adapters/claude-code/session.ts'
import { fake, memoryFs, seeded } from './helpers.ts'

const random = seeded(40)
const TOKEN = fake.hex(random, 40)

async function session(extra = ''): Promise<VeilSession> {
  const veil = new VeilSession()
  await veil.start(
    memoryFs({
      '/home/me/.config/veil/config.toml': `[sources]\nhome = false\nenvironment = false\n${extra}`,
      '/repo/.env': `API_TOKEN=${TOKEN}\n`,
    }),
    { home: '/home/me', root: '/repo', cwd: '/repo', platform: 'linux', vars: {} },
  )
  return veil
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
    assert.deepEqual(veil.checkEdit('/repo/.env', { content: 'API_TOKEN=[veil:API_TOKEN]' }, ''), { fields: { content: `API_TOKEN=${TOKEN}` } })
    assert.deepEqual(veil.checkEdit('/repo/src/a.ts', { new_string: '[veil:API_TOKEN]' }, `k = '${TOKEN}'`), { fields: { new_string: TOKEN } })
    for (const path of ['/tmp/exfil.env', '/repo/public/leak.env', '/repo/.env.example.local', '/repo/docs/.envrc']) {
      assert.ok('deny' in veil.checkEdit(path, { content: '[veil:API_TOKEN]' }, ''), path)
    }
  })

  it('refuses a placeholder it cannot resolve, unless the file already holds that exact text', async () => {
    const veil = await session()
    assert.ok('deny' in veil.checkEdit('/repo/.env', { content: '[veil:github-pat#0a1b2c]' }, ''))
    assert.ok('deny' in veil.checkEdit('/repo/.env.local', { content: 'API_KEY=[veil:API_KEY@.env.local]' }, 'API_KEY=real'))
    const readme = '# docs\nshows [veil:DATABASE_URL]\n'
    assert.deepEqual(veil.checkEdit('/repo/README.md', { old_string: 'shows [veil:DATABASE_URL]', new_string: 'now shows [veil:DATABASE_URL]' }, readme), {
      fields: { old_string: 'shows [veil:DATABASE_URL]', new_string: 'now shows [veil:DATABASE_URL]' },
    })
  })

  it('in never mode refuses edits that would write a placeholder over real content', async () => {
    const veil = await session('[restore]\nmode = "never"\n')
    const checked = veil.checkEdit('/repo/.env', { content: 'API_TOKEN=[veil:API_TOKEN]' }, `API_TOKEN=${TOKEN}`)
    assert.ok('deny' in checked && checked.deny.includes('never'))
  })

  it('still restores a rotated-out value into a file that holds it', async () => {
    const veil = await session()
    const fresh = fake.hex(seeded(41), 40)
    veil.masker.setSecrets([{ name: 'API_TOKEN', value: fresh, source: '/repo/.env' }])
    const old = veil.mask(TOKEN)
    assert.match(old, /~previous#/)
    assert.deepEqual(veil.checkEdit('/repo/legacy.ts', { new_string: old }, `k = '${TOKEN}'`), { fields: { new_string: TOKEN } })
    assert.ok('deny' in veil.checkEdit('/repo/.env', { content: old }, `API_TOKEN=${fresh}`))
  })

  it('skips only payloads that are base64 from start to end', async () => {
    const veil = await session()
    const blob = 'QUJD'.repeat(300_000)
    assert.equal(veil.maskValue(blob), blob)
    const mixed = `${'QUJD'.repeat(300_000)} token ${TOKEN}`
    assert.ok(!(veil.maskValue(mixed) as string).includes(TOKEN))
  })

  it('withholds instead of throwing when masking fails', async () => {
    const veil = await session()
    assert.equal(veil.holdsSecret(`token ${TOKEN}`), true)
    assert.equal(veil.holdsSecret('nothing here'), false)
  })
})
