import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { DEFAULT_CONFIG, STARTER_CONFIG, configPaths, parseConfig } from '../src/config/config.ts'

describe('config', () => {
  it('the starter config parses to the defaults', () => {
    const { config, warnings } = parseConfig(STARTER_CONFIG)
    assert.deepEqual(config, DEFAULT_CONFIG)
    assert.deepEqual(warnings, [])
  })

  it('reads every setting', () => {
    const { config, warnings } = parseConfig(`
[sources]
project = false
project_depth = 4
home = false
environment = false
files = ["~/.config/app/*.env"]
[env]
secret_keys = ["*_DSN"]
ignore_keys = ["SENTRY_ENVIRONMENT"]
[rules]
gitleaks = false
disable = ["generic-api-key"]
[mask]
min_length = 12
encodings = ["json"]
[restore]
mode = "never"
`)
    assert.deepEqual(warnings, [])
    assert.deepEqual(config, {
      sources: { project: false, projectDepth: 4, home: false, environment: false, files: ['~/.config/app/*.env'] },
      env: { secretKeys: ['*_DSN'], ignoreKeys: ['SENTRY_ENVIRONMENT'] },
      rules: { gitleaks: false, disable: ['generic-api-key'] },
      mask: { minLength: 12, encodings: ['json'] },
      restore: { mode: 'never' },
    })
  })

  it('keeps the default and warns on an invalid value, so masking never turns off by mistake', () => {
    const { config, warnings } = parseConfig('[mask]\nmin_length = 2\n[restore]\nmode = "sometimes"\n[sources]\nhome = "yes"')
    assert.equal(config.mask.minLength, DEFAULT_CONFIG.mask.minLength)
    assert.equal(config.restore.mode, 'holding')
    assert.equal(config.sources.home, true)
    assert.equal(warnings.length, 3)
  })

  it('warns on unknown sections and keys', () => {
    const { warnings } = parseConfig('[mask]\nlength = 3\n[extra]\na = 1')
    assert.deepEqual(warnings, ['unknown key mask.length', 'unknown section [extra]'])
  })

  it('looks in VEIL_CONFIG, then XDG, then Application Support on macOS', () => {
    assert.deepEqual(configPaths({ home: '/h', platform: 'linux', veilConfig: '/x/v.toml' }), ['/x/v.toml'])
    assert.deepEqual(configPaths({ home: '/h', platform: 'linux' }), ['/h/.config/veil/config.toml'])
    assert.deepEqual(configPaths({ home: '/h', platform: 'darwin', xdgConfigHome: '/xdg' }), [
      '/xdg/veil/config.toml',
      '/h/Library/Application Support/veil/config.toml',
    ])
  })
})
