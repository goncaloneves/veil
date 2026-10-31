import { once } from 'node:events'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import * as zlib from 'node:zlib'
import { MaskTimeout } from '../core/timeout.ts'
import { GEMINI_TOOLS, type Restorer } from '../restore.ts'
import type { Veil } from '../session.ts'
import { parseJson } from '../wire/json.ts'
import { dialectOf, maskPayload, wantsNote } from '../wire/request.ts'
import { restoreNdjson, restoreSse, restoreToolCalls } from '../wire/response.ts'

export const DEFAULT_PORT = 8345

export const DEFAULT_ROUTES: Readonly<Record<string, string>> = {
  openai: 'https://api.openai.com',
  codex: 'https://chatgpt.com/backend-api/codex',
  anthropic: 'https://api.anthropic.com',
  xai: 'https://api.x.ai',
  gemini: 'https://generativelanguage.googleapis.com',
  openrouter: 'https://openrouter.ai/api',
  deepseek: 'https://api.deepseek.com',
  groq: 'https://api.groq.com/openai',
  mistral: 'https://api.mistral.ai',
  together: 'https://api.together.xyz',
  fireworks: 'https://api.fireworks.ai/inference',
  cerebras: 'https://api.cerebras.ai',
  moonshot: 'https://api.moonshot.ai',
  zai: 'https://api.z.ai/api/paas',
  ollama: 'http://127.0.0.1:11434',
  lmstudio: 'http://127.0.0.1:1234',
}

export type ProxyOptions = {
  readonly port: number
  readonly routes: Readonly<Record<string, string>>
  readonly veil: Veil
  readonly restorer: Restorer
  readonly beforeRequest?: () => Promise<void>
  readonly log?: (line: string) => void
}

const MAX_BODY = 64 * 1024 * 1024
const DROP_REQUEST = new Set([
  'host', 'content-length', 'content-encoding', 'accept-encoding', 'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'expect',
])
const DROP_RESPONSE = new Set(['content-length', 'content-encoding', 'transfer-encoding', 'connection', 'keep-alive'])
const BINARY_MEDIA = /^(?:image\/(?!svg)|audio\/|video\/|application\/pdf\b)/i
const REDIRECTS = new Set([301, 302, 303, 307, 308])

export class Refusal extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function allowedHost(host: string | undefined, port: number): boolean {
  if (host === undefined) return false
  return [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`].includes(host.toLowerCase())
}

function readBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    request.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > MAX_BODY) {
        reject(new Refusal(413, 'veil proxy takes request bodies up to 64 MiB'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => resolve(Buffer.concat(chunks)))
    request.on('error', reject)
  })
}

export function decompress(raw: Buffer, encoding: string): Buffer {
  const steps = encoding
    .split(',')
    .map(step => step.trim().toLowerCase())
    .filter(step => step !== '' && step !== 'identity')
  let body = raw
  try {
    for (const step of steps.reverse()) {
      if (step === 'gzip' || step === 'x-gzip') body = zlib.gunzipSync(body, { maxOutputLength: MAX_BODY })
      else if (step === 'deflate') body = zlib.inflateSync(body, { maxOutputLength: MAX_BODY })
      else if (step === 'br') body = zlib.brotliDecompressSync(body, { maxOutputLength: MAX_BODY })
      else if (step === 'zstd' && typeof zlib.zstdDecompressSync === 'function') body = zlib.zstdDecompressSync(body, { maxOutputLength: MAX_BODY })
      else throw new Refusal(415, `veil proxy cannot read a body sent with content-encoding ${step}, so it did not forward it`)
    }
  } catch (error) {
    if (error instanceof Refusal) throw error
    throw new Refusal(415, 'veil proxy could not unpack this request body, so it did not forward it')
  }
  return body
}

function utf8(raw: Buffer): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(raw)
  } catch {
    return undefined
  }
}

function boundaryOf(contentType: string): string | undefined {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i)
  return match?.[1] ?? match?.[2]
}

function maskPart(part: Buffer, mask: (text: string) => string): Buffer {
  const split = part.indexOf('\r\n\r\n')
  if (split < 0) {
    const text = utf8(part)
    return text === undefined ? part : Buffer.from(mask(text))
  }
  const headers = part.subarray(0, split + 4).toString('latin1')
  const body = part.subarray(split + 4)
  const text = utf8(body)
  if (text === undefined) {
    const type = headers.match(/content-type:\s*([^\r\n]+)/i)?.[1] ?? ''
    if (BINARY_MEDIA.test(type)) return part
    throw new Refusal(415, 'veil proxy cannot check a binary upload that is not an image, audio, video or PDF, so it did not forward it')
  }
  return Buffer.concat([Buffer.from(mask(headers), 'latin1'), Buffer.from(mask(text))])
}

function maskMultipart(raw: Buffer, boundary: string, mask: (text: string) => string): Buffer {
  const marker = Buffer.from(`--${boundary}`)
  const out: Buffer[] = []
  let at = 0
  for (;;) {
    const next = raw.indexOf(marker, at)
    if (next < 0) {
      out.push(maskPart(raw.subarray(at), mask))
      break
    }
    out.push(maskPart(raw.subarray(at, next), mask), marker)
    at = next + marker.length
  }
  return Buffer.concat(out)
}

export function maskBody(raw: Buffer, contentType: string, path: string, veil: Veil, scope: string): Buffer {
  if (raw.length === 0) return raw
  const options = { strict: true, scope }
  const mask = (text: string) => String(veil.maskValue(text, undefined, options))
  const boundary = /^multipart\//i.test(contentType) ? boundaryOf(contentType) : undefined
  if (boundary !== undefined) return maskMultipart(raw, boundary, mask)
  const text = utf8(raw)
  if (text === undefined) {
    if (BINARY_MEDIA.test(contentType)) return raw
    throw new Refusal(415, 'veil proxy cannot check a binary body that is not an image, audio, video or PDF, so it did not forward it')
  }
  const body = text.replace(/^﻿/, '')
  if (/^\s*[[{]/.test(body)) {
    let parsed: unknown
    try {
      parsed = parseJson(body)
    } catch {
      parsed = undefined
    }
    if (parsed !== undefined) {
      const masked = maskPayload(veil, parsed, dialectOf(path), { note: wantsNote(path), scope })
      return masked === parsed ? raw : Buffer.from(JSON.stringify(masked))
    }
  }
  const masked = mask(text)
  return masked === text ? raw : Buffer.from(masked)
}

function fail(response: ServerResponse, status: number, message: string): void {
  if (response.headersSent) {
    response.destroy()
    return
  }
  response.writeHead(status, { 'content-type': 'application/json' })
  response.end(JSON.stringify({ error: { type: 'veil_proxy_error', message } }))
}

function isJson(type: string): boolean {
  return /\bjson\b/i.test(type)
}

async function* decoded(body: ReadableStream<Uint8Array>): AsyncGenerator<string> {
  const decoder = new TextDecoder()
  for await (const chunk of Readable.fromWeb(body as never)) yield decoder.decode(chunk as Uint8Array, { stream: true })
  const tail = decoder.decode()
  if (tail !== '') yield tail
}

async function write(response: ServerResponse, piece: string | Uint8Array): Promise<void> {
  if (response.destroyed) return
  if (!response.write(piece)) await Promise.race([once(response, 'drain'), once(response, 'close')])
}

async function handle(options: ProxyOptions, request: IncomingMessage, response: ServerResponse, abort: AbortController): Promise<void> {
  if (!allowedHost(request.headers.host, request.socket.localPort ?? options.port)) return fail(response, 403, 'veil proxy answers only on localhost')
  if (request.headers.origin !== undefined || request.headers['sec-fetch-site'] !== undefined) return fail(response, 403, 'veil proxy does not answer browser requests')
  if (request.headers.upgrade !== undefined) return fail(response, 501, 'veil proxy does not relay WebSockets; use HTTP')
  const url = new URL(request.url ?? '/', 'http://127.0.0.1')
  const [, name = '', ...rest] = url.pathname.split('/')
  const upstream = Object.hasOwn(options.routes, name) ? options.routes[name] : undefined
  if (upstream === undefined) return fail(response, 404, `unknown route /${name}; routes: ${Object.keys(options.routes).map(route => `/${route}`).join(', ')}`)
  const path = `/${rest.join('/')}`
  await options.beforeRequest?.()
  const raw = decompress(await readBody(request), String(request.headers['content-encoding'] ?? ''))
  const body = maskBody(raw, String(request.headers['content-type'] ?? ''), path, options.veil, name)
  const headers = new Headers()
  for (const [key, value] of Object.entries(request.headers)) {
    if (value === undefined || DROP_REQUEST.has(key.toLowerCase())) continue
    for (const item of Array.isArray(value) ? value : [value]) headers.append(key, item)
  }
  headers.set('accept-encoding', 'identity')
  const method = request.method ?? 'GET'
  const answer = await fetch(`${upstream.replace(/\/+$/, '')}${path}${url.search}`, {
    method,
    headers,
    redirect: 'manual',
    signal: abort.signal,
    ...(method === 'GET' || method === 'HEAD' ? {} : { body: new Uint8Array(body) }),
  })
  if (REDIRECTS.has(answer.status)) {
    await answer.body?.cancel()
    return fail(response, 502, `the upstream answered with a redirect (${answer.status}); veil proxy does not follow redirects, so nothing was re-sent`)
  }
  const outHeaders: Record<string, string> = {}
  answer.headers.forEach((value, key) => {
    if (!DROP_RESPONSE.has(key.toLowerCase())) outHeaders[key] = value
  })
  const type = answer.headers.get('content-type') ?? ''
  const dialect = dialectOf(path)
  const restorer = dialect === 'gemini' ? { ...options.restorer, tools: new Set([...options.restorer.tools, ...GEMINI_TOOLS]) } : options.restorer
  if (!answer.body) {
    response.writeHead(answer.status, outHeaders)
    response.end()
    return
  }
  if (/text\/event-stream/i.test(type) || /ndjson/i.test(type)) {
    response.writeHead(answer.status, outHeaders)
    const pieces = /ndjson/i.test(type) ? restoreNdjson(decoded(answer.body), restorer) : restoreSse(decoded(answer.body), dialect, restorer)
    for await (const piece of pieces) {
      if (response.destroyed) break
      await write(response, piece)
    }
    response.end()
    return
  }
  if (isJson(type)) {
    const text = await answer.text()
    let out = text
    try {
      const parsed: unknown = parseJson(text)
      const restored = await restoreToolCalls(parsed, restorer)
      if (restored !== parsed) out = JSON.stringify(restored)
    } catch {}
    response.writeHead(answer.status, outHeaders)
    response.end(out)
    return
  }
  response.writeHead(answer.status, outHeaders)
  for await (const chunk of Readable.fromWeb(answer.body as never)) {
    if (response.destroyed) break
    await write(response, chunk as Uint8Array)
  }
  response.end()
}

function codeOf(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined
  const own = (error as NodeJS.ErrnoException).code
  if (typeof own === 'string') return own
  const nested = error instanceof AggregateError ? error.errors : []
  return [error.cause, ...nested].map(codeOf).find(code => code !== undefined)
}

function describe(error: unknown): string {
  if (!(error instanceof Error)) return 'unknown error'
  const cause = error.cause instanceof Error ? error.cause : undefined
  return [error.name, cause?.name, codeOf(error)].filter(Boolean).join(', ')
}

export function startProxy(options: ProxyOptions): Promise<Server> {
  const server = createServer((request, response) => {
    const abort = new AbortController()
    response.on('close', () => {
      if (!response.writableFinished) abort.abort()
    })
    handle(options, request, response, abort).catch(error => {
      if (abort.signal.aborted) return
      if (error instanceof Refusal) return fail(response, error.status, error.message)
      if (error instanceof MaskTimeout) return fail(response, 503, 'veil proxy could not check this request for secrets in time, so it did not forward it')
      options.log?.(`veil proxy: a request failed (${describe(error)})`)
      fail(response, 502, 'veil proxy could not complete this request')
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(options.port, '127.0.0.1', () => resolve(server))
  })
}
