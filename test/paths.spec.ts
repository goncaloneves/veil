import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { basename, dirname, isAbsolutePath, isInside, joinPath, normalizePath, pathKey, samePath } from '../src/core/paths.ts'

describe('paths', () => {
  it('normalizes POSIX and Windows paths to one slash form', () => {
    assert.equal(normalizePath('/tmp/../repo/./a//b'), '/repo/a/b')
    assert.equal(normalizePath('c:\\Users\\dev\\..\\me\\.env'), 'C:/Users/me/.env')
    assert.equal(normalizePath('\\\\server\\share\\.env'), '//server/share/.env')
  })

  it('knows absolute paths on both families', () => {
    assert.equal(isAbsolutePath('/etc/passwd'), true)
    assert.equal(isAbsolutePath('C:\\Users'), true)
    assert.equal(isAbsolutePath('D:/x'), true)
    assert.equal(isAbsolutePath('x/y'), false)
    assert.equal(isAbsolutePath('C:relative'), false)
  })

  it('compares case-insensitively only where the file system does', () => {
    assert.equal(samePath('/Repo/.ENV', '/repo/.env', 'darwin'), true)
    assert.equal(samePath('C:\\Repo\\.ENV', 'c:/repo/.env', 'win32'), true)
    assert.equal(samePath('/Repo/.ENV', '/repo/.env', 'linux'), false)
    assert.equal(pathKey('c:\\A\\B', 'win32'), 'c:/a/b')
  })

  it('tells whether a path is inside a directory without prefix tricks', () => {
    assert.equal(isInside('c:\\proj\\veil.toml', 'C:/proj', 'win32'), true)
    assert.equal(isInside('/repo/sub/../veil.toml', '/repo', 'linux'), true)
    assert.equal(isInside('/repo-evil/veil.toml', '/repo', 'linux'), false)
    assert.equal(isInside('/repo', '/repo/', 'linux'), true)
    assert.equal(isInside('/anything', '/', 'linux'), true)
  })

  it('splits and joins either separator', () => {
    assert.equal(basename('C:\\a\\b\\.env.local'), '.env.local')
    assert.equal(basename('/a/b/'), 'b')
    assert.equal(dirname('C:\\a\\b\\.env'), 'C:/a/b')
    assert.equal(dirname('/x'), '/')
    assert.equal(dirname('x'), '.')
    assert.equal(joinPath('C:\\a\\', '.env'), 'C:\\a\\.env')
    assert.equal(joinPath('/a', '.env'), '/a/.env')
  })
})
