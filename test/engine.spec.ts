import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { DEFAULT_CONFIG, parseConfig, weakenings } from '../src/config/config.ts'
import { loadConfig, maskerSettings, type VeilState } from '../src/engine.ts'
import { ruleSet } from '../src/rules/index.ts'
import { memoryFs, pathFs } from './helpers.ts'

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

describe('config location guards', () => {
  it('accepts an absolute Windows VEIL_CONFIG outside the project', async () => {
    const fs = pathFs({ 'D:\\veil\\config.toml': '[rules]\ngitleaks = false' }, { platform: 'win32' })
    const loaded = await loadConfig(fs, { home: 'C:\\Users\\me', root: 'C:\\repo', cwd: 'C:\\repo', platform: 'win32', vars: {}, veilConfig: 'D:\\veil\\config.toml' })
    assert.equal(loaded.config.rules.gitleaks, false)
  })

  it('rejects a VEIL_CONFIG inside the project spelled in another case or reached through a link', async () => {
    const fs = pathFs({ '/repo/veil.toml': '[rules]\ngitleaks = false', '/etc/link.toml': '[rules]\ngitleaks = false' }, { platform: 'darwin' })
    const cased = await loadConfig(fs, { ...host, platform: 'darwin', veilConfig: '/REPO/VEIL.TOML' })
    assert.equal(cased.config.rules.gitleaks, true)
    const linked = await loadConfig({ ...fs, realPath: async path => (path === '/etc/link.toml' ? '/repo/veil.toml' : path) }, { ...host, veilConfig: '/etc/link.toml' })
    assert.equal(linked.config.rules.gitleaks, true)
    assert.match(linked.warnings[0] ?? '', /VEIL_CONFIG=\/etc\/link.toml was ignored/)
  })

  it('accepts a system VEIL_CONFIG when the session starts at / or in the home folder', async () => {
    const fs = memoryFs({ '/etc/veil/config.toml': '[rules]\ngitleaks = false' })
    for (const root of ['/', '/home/me']) {
      const loaded = await loadConfig(fs, { ...host, root, cwd: root, veilConfig: '/etc/veil/config.toml' })
      assert.equal(loaded.config.rules.gitleaks, false, root)
    }
  })

  it('knows the home folder when the session starts there under its real path', async () => {
    const files = { '/home/me/xdg/veil/config.toml': '[rules]\ngitleaks = false' }
    const base = memoryFs(files)
    const fs = { ...base, realPath: async (path: string) => (path.startsWith('/home/me') ? `/private${path}` : path) }
    const loaded = await loadConfig(fs, { ...host, root: '/private/home/me', cwd: '/private/home/me', xdgConfigHome: '/home/me/xdg' })
    assert.deepEqual(loaded.warnings, ['config: the gitleaks pattern rules are off'])
  })

  it('ignores an XDG_CONFIG_HOME inside the project or relative, and says when VEIL_CONFIG is missing', async () => {
    const fs = memoryFs({ '/repo/.config/veil/config.toml': '[rules]\ngitleaks = false', '/home/me/.config/veil/config.toml': '' })
    for (const xdgConfigHome of ['/repo/.config', '.config']) {
      const loaded = await loadConfig(fs, { ...host, xdgConfigHome })
      assert.equal(loaded.config.rules.gitleaks, true)
      assert.match(loaded.warnings[0] ?? '', /XDG_CONFIG_HOME=.* was ignored/)
      assert.equal(loaded.path, '/home/me/.config/veil/config.toml')
    }
    const missing = await loadConfig(fs, { ...host, veilConfig: '/etc/nothing.toml' })
    assert.deepEqual(missing.warnings, ['VEIL_CONFIG=/etc/nothing.toml does not exist; using the defaults'])
  })
})

describe('weakenings', () => {
  it('is empty for the defaults and names every weaker setting', () => {
    assert.deepEqual(weakenings(DEFAULT_CONFIG), [])
    const { config } = parseConfig('[sources]\nhome = false\nsystem = false\n[mask]\nmin_length = 12\nencodings = ["json"]')
    assert.deepEqual(weakenings(config), [
      'the credentials in your home folder are not read',
      'secret files outside your home folder, such as /run/secrets, are not read',
      'values shorter than 12 characters are masked at most as whole tokens or where they are assigned',
      'encoded forms not matched: base64, url, lines',
    ])
  })
})

describe('maskerSettings', () => {
  it('drops only the gitleaks rules when they are turned off, and keeps veil own rules', () => {
    const state: VeilState = {
      config: { ...DEFAULT_CONFIG, rules: { ...DEFAULT_CONFIG.rules, gitleaks: false } },
      warnings: [],
      loaded: { secrets: [], files: [], errors: [], warnings: [] },
      sourcePaths: new Set(),
    }
    const rules = maskerSettings(state, ruleSet).ruleSet.rules
    assert.ok(rules.length > 0)
    assert.ok(rules.every(rule => rule.own))
    assert.equal(rules.length, ruleSet.rules.filter(rule => rule.own).length)
  })
})
