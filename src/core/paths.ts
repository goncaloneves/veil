export function toSlashes(path: string): string {
  return path.replace(/\\/g, '/')
}

export function isAbsolutePath(path: string): boolean {
  return /^(?:[A-Za-z]:)?[\\/]/.test(path)
}

export function normalizePath(path: string): string {
  const slashed = toSlashes(path)
  const drive = slashed.match(/^([A-Za-z]):/)?.[1]
  const rest = drive ? slashed.slice(2) : slashed
  const parts: string[] = []
  for (const part of rest.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') parts.pop()
    else parts.push(part)
  }
  const body = `/${parts.join('/')}`
  if (drive) return `${drive.toUpperCase()}:${body}`
  return /^\/\/[^/]/.test(slashed) ? `/${body}` : body
}

export function caseInsensitive(platform: string): boolean {
  return platform === 'darwin' || platform === 'win32'
}

export function pathKey(path: string, platform: string): string {
  const normal = normalizePath(path)
  return caseInsensitive(platform) ? normal.toLowerCase() : normal
}

export function samePath(a: string, b: string, platform: string): boolean {
  return pathKey(a, platform) === pathKey(b, platform)
}

export function isInside(path: string, dir: string, platform: string): boolean {
  const target = pathKey(path, platform)
  const base = pathKey(dir, platform)
  return target === base || target.startsWith(base.endsWith('/') ? base : `${base}/`)
}

export function basename(path: string): string {
  const slashed = toSlashes(path).replace(/\/+$/, '')
  return slashed.slice(slashed.lastIndexOf('/') + 1)
}

export function dirname(path: string): string {
  const slashed = toSlashes(path).replace(/\/+$/, '')
  const cut = slashed.lastIndexOf('/')
  return cut <= 0 ? (slashed.startsWith('/') ? '/' : '.') : slashed.slice(0, cut)
}

export function joinPath(dir: string, name: string): string {
  return /[\\/]$/.test(dir) ? `${dir}${name}` : `${dir}/${name}`
}
