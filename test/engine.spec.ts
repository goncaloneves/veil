import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { DEFAULT_CONFIG, parseConfig, weakenings } from '../src/config/config.ts'
import { loadConfig } from '../src/engine.ts'
import { memoryFs } from './helpers.ts'

const host = { home: '/home/me', root: '/repo', cwd: '/repo', platform: 'linux', vars: {} }

describe('loadConfig', () => {
  it('ignores a relative VEIL_CONFIG or one inside the project, and says so', async () => {
    const fs = memoryFs({ '/repo/veil.toml': '[rules]\ngitleaks = false', '/home/me/.config/veil/config.toml': '' })
    for (const veilConfig of ['veil.toml', '/repo/veil.toml', '/tmp/../repo/veil.toml', '/repo/./sub/../veil.toml']) {
      const loaded = await loadConfig(fs, { ...host, veilConfig })
      assert.equal(loaded.config.rules.gitleaks, true)
      assert.match(loaded.warnings[0] ?? '', /VEIL_CONFIG=.* was ignored/)
    }
  })

  it('takes an absolute VEIL_CONFIG outside the project, and warns about what it weakens', async () => {
    const fs = memoryFs({ '/etc/veil.toml': '[rules]\ngitleaks = false\n[restore]\nmode = "always"' })
    const loaded = await loadConfig(fs, { ...host, veilConfig: '/etc/veil.toml' })
    assert.equal(loaded.config.rules.gitleaks, false)
    assert.deepEqual(loaded.warnings, ['config: the gitleaks pattern rules are off', 'config: placeholders are restored into any file'])
  })

  it('warns when the config path exists but is not a regular file', async () => {
    const base = memoryFs({ '/home/me/.config/veil/config.toml': '[restore]\nmode = "never"' })
    const fs = { ...base, kindOf: async () => 'other' as const }
    const loaded = await loadConfig(fs, host)
    assert.equal(loaded.config.restore.mode, 'holding')
    assert.match(loaded.warnings.join('\n'), /is not a regular file/)
  })
})

describe('weakenings', () => {
  it('is empty for the defaults and names every weaker setting', () => {
    assert.deepEqual(weakenings(DEFAULT_CONFIG), [])
    const { config } = parseConfig('[sources]\nhome = false\n[mask]\nmin_length = 12\nencodings = ["json"]')
    assert.deepEqual(weakenings(config), [
      'the credentials in your home folder are not read',
      'values shorter than 12 characters are not masked',
      'encoded forms not matched: base64, url, lines',
    ])
  })
})
