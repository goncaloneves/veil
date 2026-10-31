import { realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { nodeFs, nodeHost } from '../cli/node-host.ts'
import type { VeilHost } from '../engine.ts'
import type { Probe } from '../restore.ts'
import type { SessionFs } from '../session.ts'

const PROBE_LIMIT = 16 * 1024 * 1024

export const nodeSessionFs: SessionFs = {
  ...nodeFs,
  realPath: path => nodeFs.realPath?.(path) ?? Promise.resolve(undefined),
}

export async function projectRoot(cwd: string): Promise<string> {
  for (let dir = resolve(cwd); ; dir = dirname(dir)) {
    if (await stat(join(dir, '.git')).then(() => true, () => false)) return dir
    if (dirname(dir) === dir) return resolve(cwd)
  }
}

export function nodeProbe(base: string, root: string = base): Probe {
  return async path => {
    const full = isAbsolute(path) ? path : resolve(base, path)
    if (!isAbsolute(path)) {
      const inside = relative(resolve(root), full)
      if (inside.startsWith('..') || isAbsolute(inside)) return undefined
    }
    const info = await stat(full).catch((error: NodeJS.ErrnoException) => (error.code === 'ENOENT' ? null : undefined))
    if (info === null) return { content: '' }
    if (info === undefined || !info.isFile() || info.size > PROBE_LIMIT) return undefined
    const content = await nodeFs.read(full).catch(() => undefined)
    if (content === undefined) return undefined
    return { content, realPath: await realpath(full).catch(() => undefined) }
  }
}

export type AdapterDeps = {
  readonly fs: SessionFs
  readonly host: (root: string, cwd: string) => VeilHost
  readonly probe: (base: string, root?: string) => Probe
  readonly root: (cwd: string) => Promise<string>
}

export const nodeDeps: AdapterDeps = { fs: nodeSessionFs, host: nodeHost, probe: nodeProbe, root: projectRoot }
