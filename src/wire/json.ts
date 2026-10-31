type RawJson = {
  readonly rawJSON?: (text: string) => unknown
  readonly isRawJSON?: (value: unknown) => boolean
}

const JSON_RAW = JSON as unknown as RawJson

export function isRawJson(value: unknown): boolean {
  return JSON_RAW.isRawJSON?.(value) ?? false
}

export function parseJson(text: string): unknown {
  const raw = JSON_RAW.rawJSON
  if (raw === undefined) return JSON.parse(text)
  return JSON.parse(text, function (this: unknown, _key: string, value: unknown, context?: { source?: string }) {
    if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value) && typeof context?.source === 'string') return raw(context.source)
    return value
  } as (key: string, value: unknown) => unknown)
}
