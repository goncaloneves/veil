export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export function decodeUri(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

export function globRegExp(glob: string, options: { readonly segment?: boolean; readonly caseInsensitive?: boolean } = {}): RegExp {
  const any = options.segment ? '[^/\\\\]' : '.'
  const body = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, `${any}*`).replace(/\?/g, any)
  return new RegExp(`^${body}$`, options.caseInsensitive ? 'i' : '')
}
