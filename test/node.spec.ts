import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { nodeProbe, projectRoot } from '../src/node/fs.ts'

const root = mkdtempSync(join(tmpdir(), 'veil-node-'))
mkdirSync(join(root, '.git'))
mkdirSync(join(root, 'sub'))
writeFileSync(join(root, '.env'), 'API_TOKEN=x\n')

after(() => rmSync(root, { recursive: true, force: true }))

describe('node probe', () => {
  it('reads relative paths from the agent folder and never outside the project', async () => {
    const probe = nodeProbe(join(root, 'sub'), root)
    assert.deepEqual(await probe('.env'), { content: '' })
    assert.equal((await probe('../.env'))?.content, 'API_TOKEN=x\n')
    assert.equal(await probe('../../outside.txt'), undefined)
  })

  it('finds the git root above a subfolder', async () => {
    assert.equal(await projectRoot(join(root, 'sub')), await projectRoot(root))
  })
})
