import { access, mkdir, open, readdir, realpath, stat, writeFile } from 'node:fs/promises'
import { homedir, platform } from 'node:os'
import { dirname } from 'node:path'
import { readText } from '../core/text.ts'
import type { VeilHost } from '../engine.ts'
import { MAX_TEXT, type FsKind, type SourceFs } from '../sources/load.ts'

const CHUNK = 64 * 1024

export async function readCapped(path: string, limit = MAX_TEXT): Promise<Buffer> {
  const handle = await open(path, 'r')
  try {
    const chunks: Buffer[] = []
    let total = 0
    for (;;) {
      const chunk = Buffer.alloc(Math.min(CHUNK, limit + 1 - total))
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null)
      if (bytesRead === 0) break
      chunks.push(chunk.subarray(0, bytesRead))
      total += bytesRead
      if (total > limit) throw Object.assign(new Error(`larger than ${limit / 1024 / 1024} MiB`), { code: 'EFBIG' })
    }
    return Buffer.concat(chunks, total)
  } finally {
    await handle.close()
  }
}

async function readTail(path: string, bytes: number): Promise<string> {
  const handle = await open(path, 'r')
  try {
    const size = (await handle.stat()).size
    const length = Math.min(bytes, size)
    const buffer = Buffer.alloc(length)
    const { bytesRead } = await handle.read(buffer, 0, length, size - length)
    return buffer.subarray(0, bytesRead).toString('utf8')
  } finally {
    await handle.close()
  }
}

function kindOf(info: { isFile(): boolean; isDirectory(): boolean }): FsKind {
  return info.isFile() ? 'file' : info.isDirectory() ? 'dir' : 'other'
}

export const nodeFs: SourceFs = {
  read: async path => {
    const bytes = await readCapped(path)
    return readText(async () => bytes.toString('utf8'), async () => bytes.toString('base64'))
  },
  list: async dir =>
    (await readdir(dir, { withFileTypes: true })).map(entry => ({
      name: entry.name,
      kind: entry.isFile() ? 'file' : entry.isDirectory() ? 'dir' : 'other',
      isLink: entry.isSymbolicLink(),
    })),
  kindOf: async path => kindOf(await stat(path)),
  exists: path =>
    access(path).then(
      () => true,
      () => false,
    ),
  realPath: path => realpath(path).catch(() => undefined),
  stat: async path => {
    const info = await stat(path)
    return { kind: kindOf(info), size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs, ino: info.ino, realPath: await realpath(path).catch(() => undefined) }
  },
  readTail,
}

export function nodeHost(root = process.cwd(), cwd = process.cwd()): VeilHost {
  const os = platform()
  const home = (os === 'win32' ? (process.env.USERPROFILE ?? process.env.HOME) : (process.env.HOME ?? process.env.USERPROFILE)) ?? homedir()
  return {
    home,
    root,
    cwd,
    platform: os,
    vars: { ...process.env },
    veilConfig: process.env.VEIL_CONFIG,
    xdgConfigHome: process.env.XDG_CONFIG_HOME,
  }
}

export async function writeNewFile(path: string, text: string): Promise<boolean> {
  if (await nodeFs.exists(path)) return false
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, text, { mode: 0o600 })
  return true
}
