import assert from 'node:assert/strict'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import { createHash } from 'node:crypto'
import { adapterBundle, adapterPath, bundleName, checksumFor, type Fetch } from '../src/cli/install.ts'

describe('adapter install', () => {
  it('puts each adapter where its agent loads global plugins', () => {
    const home = join('/home', 'me')
    assert.equal(adapterPath('pi', {}, home), join(home, '.pi', 'agent', 'extensions', 'veil.js'))
    assert.equal(adapterPath('pi', { PI_CODING_AGENT_DIR: '/opt/pi' }, home), join('/opt/pi', 'extensions', 'veil.js'))
    assert.equal(adapterPath('opencode', {}, home), join(home, '.config', 'opencode', 'plugins', 'veil.js'))
    assert.equal(adapterPath('kilo', { XDG_CONFIG_HOME: '/xdg' }, home), join('/xdg', 'kilo', 'plugin', 'veil.js'))
    assert.equal(bundleName('kilo'), 'veil-opencode.js')
    assert.equal(adapterPath('pi', { PI_CODING_AGENT_DIR: '~/pi' }, home), join(home, 'pi', 'extensions', 'veil.js'))
    assert.equal(adapterPath('opencode', { XDG_CONFIG_HOME: '~/cfg' }, home), join(home, 'cfg', 'opencode', 'plugins', 'veil.js'))
  })

  it('installs a downloaded bundle only when it matches its published checksum', async () => {
    const bundle = Buffer.from('export default function () {}\n')
    const hash = createHash('sha256').update(bundle).digest('hex')
    const serve = (files: Record<string, string | Buffer | number>): Fetch => async url => {
      const name = url.slice(url.lastIndexOf('/') + 1)
      const file = files[name]
      if (file === undefined || typeof file === 'number') return { ok: false, status: typeof file === 'number' ? file : 404, arrayBuffer: async () => new ArrayBuffer(0) }
      const bytes = Buffer.from(file)
      return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer }
    }
    assert.deepEqual(await adapterBundle('pi', '1.2.3', undefined, serve({ 'veil-pi.js': bundle, SHA256SUMS: `${hash}  veil-pi.js\n` })), bundle)
    await assert.rejects(adapterBundle('pi', '1.2.3', undefined, serve({ 'veil-pi.js': bundle, SHA256SUMS: `${'0'.repeat(64)}  veil-pi.js\n` })), /does not match/)
    await assert.rejects(adapterBundle('pi', '1.2.3', undefined, serve({ 'veil-pi.js': bundle, SHA256SUMS: `${hash}  veil-opencode.js\n` })), /does not match/)
    await assert.rejects(adapterBundle('pi', '1.2.3', undefined, serve({ 'veil-pi.js': bundle, SHA256SUMS: 404 })), /HTTP 404/)
  })

  it('reads a checksum line in text or binary mode, and nothing else', () => {
    const sums = `${'a'.repeat(64)}  veil-pi.js\n${'B'.repeat(64)} *veil-opencode.js\n`
    assert.equal(checksumFor(sums, 'veil-pi.js'), 'a'.repeat(64))
    assert.equal(checksumFor(sums, 'veil-opencode.js'), 'b'.repeat(64))
    assert.equal(checksumFor(sums, 'veil-linux-x64'), undefined)
  })
})
