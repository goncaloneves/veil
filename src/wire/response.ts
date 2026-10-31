import { restoreArguments, restoreInput, type Restorer } from '../restore.ts'
import type { Dialect } from './request.ts'

type Json = Record<string, unknown>

function record(value: unknown): Json | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : undefined
}

function nameOf(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

async function restoreField(value: unknown, restorer: Restorer, tool: string | undefined): Promise<unknown> {
  return typeof value === 'string' ? restoreArguments(value, restorer, tool) : restoreInput(value, restorer, tool)
}

export async function restoreToolCalls(value: unknown, restorer: Restorer): Promise<unknown> {
  if (Array.isArray(value)) {
    const out = await Promise.all(value.map(item => restoreToolCalls(item, restorer)))
    return out.every((item, index) => item === value[index]) ? value : out
  }
  const top = record(value)
  if (!top) return value
  const swaps: [string, Promise<unknown>][] = []
  const fn = record(top.function)
  if (fn && 'arguments' in fn) swaps.push(['function', restoreField(fn.arguments, restorer, nameOf(fn.name)).then(args => (args === fn.arguments ? fn : { ...fn, arguments: args }))])
  const call = record(top.functionCall)
  if (call && 'args' in call) swaps.push(['functionCall', restoreInput(call.args, restorer, nameOf(call.name)).then(args => (args === call.args ? call : { ...call, args }))])
  const legacy = record(top.function_call)
  if (legacy && typeof legacy.arguments === 'string') swaps.push(['function_call', restoreArguments(legacy.arguments, restorer, nameOf(legacy.name)).then(args => (args === legacy.arguments ? legacy : { ...legacy, arguments: args }))])
  if (top.type === 'tool_use' && 'input' in top) swaps.push(['input', restoreInput(top.input, restorer, nameOf(top.name))])
  if (top.type === 'function_call' && typeof top.arguments === 'string') swaps.push(['arguments', restoreArguments(top.arguments, restorer, nameOf(top.name))])
  if (top.type === 'custom_tool_call' && typeof top.input === 'string') swaps.push(['input', restoreArguments(top.input, restorer, nameOf(top.name))])
  const handled = new Set(swaps.map(([key]) => key))
  for (const [key, item] of Object.entries(top)) {
    if (!handled.has(key) && item !== null && typeof item === 'object') swaps.push([key, restoreToolCalls(item, restorer)])
  }
  let changed = false
  const out: Json = { ...top }
  for (const [key, pending] of swaps) {
    const next = await pending
    if (next !== top[key]) changed = true
    out[key] = next
  }
  return changed ? out : value
}

export type SseEvent = { readonly raw: string; readonly event?: string; readonly data?: string }

export function parseSse(raw: string): SseEvent {
  let event: string | undefined
  const data: string[] = []
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith('event:')) event = line.slice(6).trim()
    else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''))
  }
  return { raw, ...(event === undefined ? {} : { event }), ...(data.length > 0 ? { data: data.join('\n') } : {}) }
}

function sse(event: string | undefined, data: unknown): string {
  return `${event === undefined ? '' : `event: ${event}\n`}data: ${typeof data === 'string' ? data : JSON.stringify(data)}\n\n`
}

export type StreamStep = (event: SseEvent) => Promise<string>

function json(data: string | undefined): Json | undefined {
  if (data === undefined) return undefined
  try {
    return record(JSON.parse(data))
  } catch {
    return undefined
  }
}

function chatStream(restorer: Restorer): { step: StreamStep; end: () => Promise<string> } {
  const calls = new Map<string, { choice: number; index: number; name: string | undefined; held: boolean; args: string }>()
  let template: Json = {}
  const flush = async (choice?: number): Promise<string> => {
    let out = ''
    for (const [key, call] of [...calls]) {
      if (choice !== undefined && call.choice !== choice) continue
      calls.delete(key)
      if (!call.held || call.args === '') continue
      const args = await restoreArguments(call.args, restorer, call.name)
      out += sse(undefined, { ...template, choices: [{ index: call.choice, delta: { tool_calls: [{ index: call.index, function: { arguments: args } }] }, finish_reason: null }] })
    }
    return out
  }
  const step: StreamStep = async event => {
    if (event.data === '[DONE]') return `${await flush()}${event.raw}`
    const chunk = json(event.data)
    if (!chunk || !Array.isArray(chunk.choices)) return event.raw
    template = Object.fromEntries(Object.entries(chunk).filter(([key]) => key !== 'choices' && key !== 'usage'))
    let changed = false
    const finishing: Json[] = []
    const choices = chunk.choices.map(raw => {
      const choice = record(raw)
      if (!choice) return raw
      const at = typeof choice.index === 'number' ? choice.index : 0
      const delta = record(choice.delta)
      let next: Json = choice
      if (delta && Array.isArray(delta.tool_calls)) {
        const stripped = delta.tool_calls.map(item => {
          const call = record(item)
          const fn = record(call?.function)
          if (!call || !fn) return item
          const index = typeof call.index === 'number' ? call.index : 0
          const key = `${at}:${index}`
          const name = nameOf(fn.name)
          const entry = calls.get(key) ?? { choice: at, index, name, held: name === undefined || restorer.tools.has(name), args: '' }
          let released = ''
          if (name !== undefined && entry.name === undefined) {
            entry.name = name
            entry.held = restorer.tools.has(name)
            if (!entry.held) {
              released = entry.args
              entry.args = ''
            }
          }
          calls.set(key, entry)
          if (released !== '') {
            changed = true
            return { ...call, function: { ...fn, arguments: `${released}${typeof fn.arguments === 'string' ? fn.arguments : ''}` } }
          }
          if (!entry.held || typeof fn.arguments !== 'string') return item
          entry.args += fn.arguments
          changed = true
          const { arguments: _, ...rest } = fn
          return { ...call, function: rest }
        })
        next = { ...choice, delta: { ...delta, tool_calls: stripped } }
      }
      const held = [...calls.values()].some(call => call.choice === at && call.held && call.args !== '')
      if (choice.finish_reason !== null && choice.finish_reason !== undefined && held) {
        finishing.push({ index: at, delta: {}, finish_reason: choice.finish_reason })
        next = { ...next, finish_reason: null }
        changed = true
      }
      return next
    })
    if (!changed) return event.raw
    let out = sse(event.event, { ...chunk, choices, ...(finishing.length > 0 ? { usage: undefined } : {}) })
    for (const done of finishing) out += await flush(done.index as number)
    if (finishing.length > 0) out += sse(event.event, { ...template, choices: finishing, ...('usage' in chunk ? { usage: chunk.usage } : {}) })
    return out
  }
  return { step, end: () => flush() }
}

function anthropicStream(restorer: Restorer): { step: StreamStep; end: () => Promise<string> } {
  const pending = new Map<number, { name: string | undefined; args: string }>()
  const step: StreamStep = async event => {
    const data = json(event.data)
    if (!data) return event.raw
    const index = typeof data.index === 'number' ? data.index : -1
    const block = record(data.content_block)
    if (data.type === 'content_block_start' && block?.type === 'tool_use' && restorer.tools.has(nameOf(block.name) ?? '')) {
      pending.set(index, { name: nameOf(block.name), args: '' })
      return event.raw
    }
    const delta = record(data.delta)
    const held = pending.get(index)
    if (data.type === 'content_block_delta' && delta?.type === 'input_json_delta' && held) {
      held.args += typeof delta.partial_json === 'string' ? delta.partial_json : ''
      return ''
    }
    if (data.type === 'content_block_stop' && held) {
      pending.delete(index)
      if (held.args === '') return event.raw
      const restored = await restoreArguments(held.args, restorer, held.name)
      return `${sse('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json: restored } })}${event.raw}`
    }
    return event.raw
  }
  const end = async () => {
    let out = ''
    for (const [index, held] of pending) if (held.args !== '') out += sse('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json: held.args } })
    pending.clear()
    return out
  }
  return { step, end }
}

const RESPONSES_DELTAS = new Set(['response.function_call_arguments.delta', 'response.custom_tool_call_input.delta'])

function responsesStream(restorer: Restorer): { step: StreamStep; end: () => Promise<string> } {
  const names = new Map<string, string | undefined>()
  const buffers = new Map<string, { text: string; last: Json | undefined; event: string | undefined }>()
  const restored = new Map<string, string>()
  const restoreItem = async (item: Json): Promise<Json> => {
    const id = typeof item.id === 'string' ? item.id : undefined
    const field = item.type === 'function_call' ? 'arguments' : item.type === 'custom_tool_call' ? 'input' : undefined
    if (!field || typeof item[field] !== 'string') return (await restoreToolCalls(item, restorer)) as Json
    const known = id !== undefined ? restored.get(id) : undefined
    const value = known ?? (await restoreArguments(item[field] as string, restorer, nameOf(item.name)))
    if (id !== undefined) restored.set(id, value)
    return value === item[field] ? item : { ...item, [field]: value }
  }
  const step: StreamStep = async event => {
    const data = json(event.data)
    if (!data || typeof data.type !== 'string') return event.raw
    const type = data.type
    const added = record(data.item)
    if (type === 'response.output_item.added' && added && typeof added.id === 'string') names.set(added.id, nameOf(added.name))
    const id = typeof data.item_id === 'string' ? data.item_id : undefined
    const held = id !== undefined && (!names.has(id) || restorer.tools.has(names.get(id) ?? ''))
    if (RESPONSES_DELTAS.has(type) && id !== undefined && held) {
      const entry = buffers.get(id) ?? { text: '', last: undefined, event: event.event }
      entry.text += typeof data.delta === 'string' ? data.delta : ''
      entry.last = data
      buffers.set(id, entry)
      return ''
    }
    const doneField = type === 'response.function_call_arguments.done' ? 'arguments' : type === 'response.custom_tool_call_input.done' ? 'input' : undefined
    if (doneField && id !== undefined && held) {
      const entry = buffers.get(id)
      buffers.delete(id)
      const original = typeof data[doneField] === 'string' ? (data[doneField] as string) : (entry?.text ?? '')
      const value = restored.get(id) ?? (await restoreArguments(original, restorer, names.get(id)))
      restored.set(id, value)
      const deltaType = type.replace(/\.done$/, '.delta')
      const delta = entry?.last ? { ...entry.last, delta: value } : { type: deltaType, item_id: id, output_index: data.output_index, delta: value }
      const doneEvent = value === original ? event.raw : sse(event.event, { ...data, [doneField]: value })
      return `${value === '' ? '' : sse(entry?.event ?? event.event, delta)}${doneEvent}`
    }
    if (type === 'response.output_item.done') {
      const item = record(data.item)
      if (!item) return event.raw
      const next = await restoreItem(item)
      return next === item ? event.raw : sse(event.event, { ...data, item: next })
    }
    const response = record(data.response)
    if (response && Array.isArray(response.output)) {
      const output = await Promise.all(response.output.map(item => (record(item) ? restoreItem(item as Json) : item)))
      if (output.every((item, index) => item === (response.output as unknown[])[index])) return event.raw
      return sse(event.event, { ...data, response: { ...response, output } })
    }
    return event.raw
  }
  const end = async () => {
    let out = ''
    for (const [, entry] of buffers) if (entry.last) out += sse(entry.event, { ...entry.last, delta: entry.text })
    buffers.clear()
    return out
  }
  return { step, end }
}

function wholeEventStream(restorer: Restorer): { step: StreamStep; end: () => Promise<string> } {
  const step: StreamStep = async event => {
    if (event.data === undefined) return event.raw
    let parsed: unknown
    try {
      parsed = JSON.parse(event.data)
    } catch {
      return event.raw
    }
    const next = await restoreToolCalls(parsed, restorer)
    return next === parsed ? event.raw : sse(event.event, next)
  }
  return { step, end: async () => '' }
}

export function sseRestorer(dialect: Dialect, restorer: Restorer): { step: StreamStep; end: () => Promise<string> } {
  if (dialect === 'openai-chat') return chatStream(restorer)
  if (dialect === 'anthropic') return anthropicStream(restorer)
  if (dialect === 'openai-responses') return responsesStream(restorer)
  return wholeEventStream(restorer)
}

export async function* splitEvents(chunks: AsyncIterable<string>): AsyncGenerator<string> {
  let buffer = ''
  for await (const chunk of chunks) {
    buffer += chunk
    for (;;) {
      const match = /\r?\n\r?\n/.exec(buffer)
      if (!match) break
      yield buffer.slice(0, match.index + match[0].length)
      buffer = buffer.slice(match.index + match[0].length)
    }
  }
  if (buffer !== '') yield buffer
}

export async function* splitLines(chunks: AsyncIterable<string>): AsyncGenerator<string> {
  let buffer = ''
  for await (const chunk of chunks) {
    buffer += chunk
    for (;;) {
      const at = buffer.indexOf('\n')
      if (at < 0) break
      yield buffer.slice(0, at + 1)
      buffer = buffer.slice(at + 1)
    }
  }
  if (buffer !== '') yield buffer
}

export async function* restoreSse(chunks: AsyncIterable<string>, dialect: Dialect, restorer: Restorer): AsyncGenerator<string> {
  const machine = sseRestorer(dialect, restorer)
  for await (const raw of splitEvents(chunks)) {
    const out = await machine.step(parseSse(raw))
    if (out !== '') yield out
  }
  const tail = await machine.end()
  if (tail !== '') yield tail
}

export async function* restoreNdjson(chunks: AsyncIterable<string>, restorer: Restorer): AsyncGenerator<string> {
  for await (const line of splitLines(chunks)) {
    const body = line.trim()
    if (body === '') {
      yield line
      continue
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(body)
    } catch {
      yield line
      continue
    }
    const next = await restoreToolCalls(parsed, restorer)
    yield next === parsed ? line : `${JSON.stringify(next)}\n`
  }
}
