import { NOTE, type Skip, type Veil } from '../session.ts'

export type Dialect = 'openai-chat' | 'openai-responses' | 'anthropic' | 'gemini' | 'ollama' | 'bedrock' | 'pi' | 'json'

export const REQUEST_SKIP: Skip = {
  keys: new Set([
    'model', 'role', 'type', 'id', 'tool_call_id', 'tool_use_id', 'call_id', 'item_id', 'object', 'status', 'authorization_token',
    'finish_reason', 'stop_reason', 'signature', 'encrypted_content', 'media_type', 'mime_type', 'mimeType', 'detail',
    'reasoning_effort', 'service_tier', 'previous_response_id', 'prompt_cache_key', 'thoughtSignature', 'textSignature',
    'thinkingSignature', 'toolCallId', 'toolName', 'api', 'provider', 'responseId', 'stopReason', 'sessionID', 'messageID',
    'callID', 'mime', 'hash', 'snapshot', 'cachedContent',
  ]),
  types: new Set(['image', 'image_url', 'input_image', 'input_audio', 'audio', 'thinking', 'redacted_thinking', 'reasoning', 'base64']),
  free: new Set(['input', 'arguments', 'args', 'partialArgs', 'output', 'response', 'details', 'structuredContent', 'metadata', 'result']),
  schema: new Set(['tools', 'functions', 'tool_choice', 'response_format', 'parameters', 'input_schema', 'inputSchema', 'generationConfig', 'safetySettings', 'format']),
  media: true,
}

export const MEDIA_ONLY: Skip = { media: true }

export const SAVED_SKIP: Skip = { ...REQUEST_SKIP, types: new Set([...(REQUEST_SKIP.types ?? []), 'toolCall', 'tool_use', 'function_call', 'custom_tool_call']) }

export function dialectOf(path: string): Dialect {
  const bare = path.split('?')[0] ?? ''
  if (/\/chat\/completions$/.test(bare) || /\/completions$/.test(bare)) return 'openai-chat'
  if (/\/responses(?:\/compact)?$/.test(bare)) return 'openai-responses'
  if (/\/messages(?:\/count_tokens)?$/.test(bare)) return 'anthropic'
  if (/:(?:stream)?[gG]enerateContent$/.test(bare) || /:countTokens$/.test(bare)) return 'gemini'
  if (/\/api\/(?:chat|generate)$/.test(bare)) return 'ollama'
  return 'json'
}

const API_DIALECTS: Readonly<Record<string, Dialect>> = {
  'openai-completions': 'openai-chat',
  'mistral-conversations': 'openai-chat',
  'openai-responses': 'openai-responses',
  'azure-openai-responses': 'openai-responses',
  'openai-codex-responses': 'openai-responses',
  'anthropic-messages': 'anthropic',
  'google-generative-ai': 'gemini',
  'google-vertex': 'gemini',
  'bedrock-converse-stream': 'bedrock',
  'pi-messages': 'pi',
}

export function dialectOfPayload(payload: unknown, api?: string): Dialect {
  const known = api === undefined ? undefined : API_DIALECTS[api]
  if (known) return known
  const top = record(payload)
  if (!top) return 'json'
  if (Array.isArray(top.contents)) return 'gemini'
  if ('input' in top || 'instructions' in top) return 'openai-responses'
  if (Array.isArray(top.messages) && ('system' in top || 'anthropic_version' in top)) return 'anthropic'
  if (Array.isArray(top.messages)) return 'openai-chat'
  return 'json'
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined
}

function instructionWith(current: unknown, note: string): unknown {
  if (typeof current === 'string' && current !== '') return `${current}\n\n${note}`
  if (Array.isArray(current)) return [...current, { text: note }]
  const content = record(current)
  const parts = Array.isArray(content?.parts) ? content.parts : []
  return { ...content, parts: [...parts, { text: note }] }
}

function noteFirst(messages: readonly unknown[], note: string): unknown[] {
  const first = record(messages[0])
  if (first && (first.role === 'system' || first.role === 'developer')) {
    if (typeof first.content === 'string') return [{ ...first, content: `${first.content}\n\n${note}` }, ...messages.slice(1)]
    if (Array.isArray(first.content)) return [{ ...first, content: [...first.content, { type: 'text', text: note }] }, ...messages.slice(1)]
  }
  return [{ role: 'system', content: note }, ...messages]
}

export function withNote(body: unknown, dialect: Dialect, note: string): unknown {
  const top = record(body)
  if (!top) return body
  switch (dialect) {
    case 'openai-chat': {
      if (!Array.isArray(top.messages)) return body
      return { ...top, messages: noteFirst(top.messages, note) }
    }
    case 'openai-responses': {
      const instructions = typeof top.instructions === 'string' && top.instructions !== '' ? `${top.instructions}\n\n${note}` : note
      return { ...top, instructions }
    }
    case 'anthropic': {
      if (!Array.isArray(top.messages)) return body
      if (Array.isArray(top.system)) return { ...top, system: [...top.system, { type: 'text', text: note }] }
      const system = typeof top.system === 'string' && top.system !== '' ? `${top.system}\n\n${note}` : note
      return { ...top, system }
    }
    case 'gemini': {
      if (!Array.isArray(top.contents) || 'cachedContent' in top || 'cached_content' in top) return body
      const config = record(top.config)
      if (config) {
        if ('cachedContent' in config) return body
        return { ...top, config: { ...config, systemInstruction: instructionWith(config.systemInstruction, note) } }
      }
      const key = 'systemInstruction' in top || !('system_instruction' in top) ? 'systemInstruction' : 'system_instruction'
      return { ...top, [key]: instructionWith(top[key], note) }
    }
    case 'pi': {
      const context = record(top.context)
      if (!context) return body
      const systemPrompt = typeof context.systemPrompt === 'string' && context.systemPrompt !== '' ? `${context.systemPrompt}\n\n${note}` : note
      return { ...top, context: { ...context, systemPrompt } }
    }
    case 'bedrock': {
      if (!Array.isArray(top.messages)) return body
      return { ...top, system: [...(Array.isArray(top.system) ? top.system : []), { text: note }] }
    }
    case 'ollama': {
      if (Array.isArray(top.messages)) return { ...top, messages: noteFirst(top.messages, note) }
      return body
    }
    default:
      return body
  }
}

export type PayloadOptions = { readonly note?: boolean; readonly scope?: string; readonly strict?: boolean }

export function maskPayload(veil: Veil, payload: unknown, dialect: Dialect, options: PayloadOptions = {}): unknown {
  const masked = veil.maskValue(payload, REQUEST_SKIP, { strict: options.strict ?? true, ...(options.scope === undefined ? {} : { scope: options.scope }) })
  return options.note === false ? masked : withNote(masked, dialect, NOTE)
}

export function wantsNote(path: string): boolean {
  return !/:countTokens$/.test(path.split("?")[0] ?? "")
}
