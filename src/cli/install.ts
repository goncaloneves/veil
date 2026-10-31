import { createHash } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { expandHome } from '../core/paths.ts'

export type AdapterTarget = 'pi' | 'opencode' | 'kilo'

export const ADAPTER_TARGETS: readonly AdapterTarget[] = ['pi', 'opencode', 'kilo']

const RELEASES = 'https://github.com/goncaloneves/veil/releases/download'

export function bundleName(target: AdapterTarget): string {
  return target === 'pi' ? 'veil-pi.js' : 'veil-opencode.js'
}

export function adapterPath(target: AdapterTarget, env: Readonly<Record<string, string | undefined>>, home: string): string {
  const config = env.XDG_CONFIG_HOME ? expandHome(env.XDG_CONFIG_HOME, home) : join(home, '.config')
  if (target === 'pi') return join(env.PI_CODING_AGENT_DIR ? expandHome(env.PI_CODING_AGENT_DIR, home) : join(home, '.pi', 'agent'), 'extensions', 'veil.js')
  if (target === 'opencode') return join(config, 'opencode', 'plugins', 'veil.js')
  return join(config, 'kilo', 'plugin', 'veil.js')
}

export function checksumFor(sums: string, name: string): string | undefined {
  for (const line of sums.split(/\r?\n/)) {
    const [hash, file] = line.trim().split(/\s+/)
    if (hash && file?.replace(/^\*/, '') === name) return hash.toLowerCase()
  }
  return undefined
}

export type Fetch = (url: string, init: { redirect: 'follow' }) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>

async function download(url: string, get: Fetch): Promise<Buffer> {
  const response = await get(url, { redirect: 'follow' })
  if (!response.ok) throw new Error(`could not download ${url}: HTTP ${response.status}`)
  return Buffer.from(await response.arrayBuffer())
}

export async function adapterBundle(target: AdapterTarget, version: string, from?: string, get: Fetch = fetch): Promise<Buffer> {
  if (from !== undefined) return readFile(from)
  const name = bundleName(target)
  const base = `${RELEASES}/v${version}`
  const [bundle, sums] = await Promise.all([download(`${base}/${name}`, get), download(`${base}/SHA256SUMS`, get)])
  const expected = checksumFor(sums.toString('utf8'), name)
  const actual = createHash('sha256').update(bundle).digest('hex')
  if (expected === undefined || expected !== actual) throw new Error(`${name} does not match the checksum published with v${version}; nothing was installed`)
  return bundle
}

export async function writeAdapter(path: string, bundle: Buffer): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.${process.pid}.tmp`
  await writeFile(temporary, bundle, { mode: 0o644 })
  await rename(temporary, path)
}
