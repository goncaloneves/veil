import { access, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { homedir, platform } from 'node:os'
import { dirname } from 'node:path'
import type { VeilHost } from '../engine.ts'
import { ENVIRONMENT_KEYS, type SourceFs } from '../sources/load.ts'

export const nodeFs: SourceFs = {
  read: path => readFile(path, 'utf8'),
  list: async dir =>
    (await readdir(dir, { withFileTypes: true })).map(entry => ({
      name: entry.name,
      kind: entry.isFile() ? 'file' : entry.isDirectory() ? 'dir' : 'other',
      isLink: entry.isSymbolicLink(),
    })),
  kindOf: async path => {
    const info = await stat(path)
    return info.isFile() ? 'file' : info.isDirectory() ? 'dir' : 'other'
  },
  exists: path =>
    access(path).then(
      () => true,
      () => false,
    ),
}

export function nodeHost(root = process.cwd(), cwd = process.cwd()): VeilHost {
  const vars: Record<string, string | undefined> = {}
  for (const key of ENVIRONMENT_KEYS) vars[key] = process.env[key]
  return {
    home: process.env.HOME ?? homedir(),
    root,
    cwd,
    platform: platform(),
    vars,
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
