import assert from 'node:assert/strict'
import { createServer, request as httpRequest, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { gzipSync, zstdCompressSync } from 'node:zlib'
import { after, before, describe, it } from 'node:test'
import { dialectOf } from '../src/wire/request.ts'
import { PROXY_TOOLS, restoreArguments } from '../src/restore.ts'
import { startProxy } from '../src/proxy/server.ts'
import { Veil, type SessionFs } from '../src/session.ts'
import { fake, memoryFs, seeded } from './helpers.ts'

const random = seeded(60)
const TOKEN = fake.hex(random, 40)
const ENV = `API_TOKEN=${TOKEN}\n`

const FILES: Record<string, string> = {
  '/home/me/.config/veil/config.toml': '[sources]\nhome = false\nenvironment = false\n',
  '/repo/.env': ENV,
  '/repo/src/config.ts': `export const token = '${TOKEN}'\n`,
  '/repo/public/app.js': 'console.log(1)\n',
}

function sessionFs(): SessionFs {
  const fs = memoryFs(FILES)
  return { ...fs, realPath: async path => (path in FILES ? path : undefined) }
}

type Canned = { type: string; body: string; status?: number; headers?: Record<string, string>; slow?: boolean }
let upstreamClosed = false
let canned: Canned = { type: 'application/json', body: '{}' }
let received: { path: string; headers: Record<string, unknown>; body: string } | undefined

let upstream: Server
let proxy: Server
let veil: Veil
let proxyPort = 0

function send(path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; type: string; text: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.isBuffer(body) ? body : typeof body === 'string' ? body : JSON.stringify(body)
    const req = httpRequest(
      { host: '127.0.0.1', port: proxyPort, path, method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer test-key', ...headers } },
      res => {
        const chunks: Buffer[] = []
        res.on('data', chunk => chunks.push(chunk))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, type: String(res.headers['content-type'] ?? ''), text: Buffer.concat(chunks).toString('utf8') }))
      },
    )
    req.on('error', reject)
    req.end(data)
  })
}

function sse(events: readonly (readonly [string | undefined, unknown])[]): string {
  return events.map(([event, data]) => `${event ? `event: ${event}\n` : ''}data: ${typeof data === 'string' ? data : JSON.stringify(data)}\n\n`).join('')
}

function events(text: string): { event?: string; data: string }[] {
  return text
    .split(/\n\n/)
    .filter(Boolean)
    .map(block => {
      const event = block.match(/^event: (.*)$/m)?.[1]
      const data = block
        .split('\n')
        .filter(line => line.startsWith('data: '))
        .map(line => line.slice(6))
        .join('\n')
      return event === undefined ? { data } : { event, data }
    })
}

before(async () => {
  upstream = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk))
    req.on('end', () => {
      received = { path: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks).toString('utf8') }
      res.writeHead(canned.status ?? 200, { 'content-type': canned.type, ...canned.headers })
      const body = canned.body
      if (canned.slow) {
        res.on('close', () => {
          upstreamClosed = true
        })
        let sent = 0
        const timer = setInterval(() => {
          if (sent++ > 40) {
            clearInterval(timer)
            res.end()
            return
          }
          res.write(body)
        }, 20)
        res.on('close', () => clearInterval(timer))
        return
      }
      const half = Math.floor(body.length / 2)
      res.write(body.slice(0, half))
      setTimeout(() => res.end(body.slice(half)), 5)
    })
  })
  await new Promise<void>(done => upstream.listen(0, '127.0.0.1', done))
  const upstreamPort = (upstream.address() as AddressInfo).port
  veil = new Veil({ budgetMs: 30_000, cache: true })
  await veil.start(sessionFs(), { home: '/home/me', root: '/repo', cwd: '/repo', platform: 'linux', vars: {} })
  proxy = await startProxy({
    port: 0,
    routes: { test: `http://127.0.0.1:${upstreamPort}`, local: `http://127.0.0.1:${upstreamPort}` },
    veil,
    restorer: {
      veil,
      tools: PROXY_TOOLS,
      probe: async path => {
        const full = path.startsWith('/') ? path : `/repo/${path}`
        return full in FILES ? { content: FILES[full] ?? '', realPath: full } : { content: '' }
      },
    },
  })
  proxyPort = (proxy.address() as AddressInfo).port
})

after(async () => {
  await new Promise(done => proxy.close(done))
  await new Promise(done => upstream.close(done))
})

describe('veil proxy', () => {
  it('knows each API from its path', () => {
    assert.equal(dialectOf('/v1/chat/completions'), 'openai-chat')
    assert.equal(dialectOf('/v1/responses'), 'openai-responses')
    assert.equal(dialectOf('/v1/messages?beta=true'), 'anthropic')
    assert.equal(dialectOf('/v1beta/models/gemini-3-pro:streamGenerateContent'), 'gemini')
    assert.equal(dialectOf('/api/chat'), 'ollama')
    assert.equal(dialectOf('/v1/embeddings'), 'json')
  })

  it('masks an OpenAI chat request, adds the note, and leaves ids, models and images alone', async () => {
    canned = { type: 'application/json', body: JSON.stringify({ choices: [{ index: 0, message: { role: 'assistant', content: 'ok' } }] }) }
    const image = `data:image/png;base64,${Buffer.from(TOKEN).toString('base64')}`
    await send('/test/v1/chat/completions', {
      model: 'gpt-test',
      messages: [
        { role: 'user', content: [{ type: 'text', text: `use ${TOKEN}` }, { type: 'image_url', image_url: { url: image } }] },
        { role: 'assistant', tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'Write', arguments: JSON.stringify({ file_path: '/repo/.env', content: ENV }) } }] },
        { role: 'tool', tool_call_id: 'call_1', content: `wrote ${TOKEN}` },
      ],
    })
    const body = JSON.parse(received?.body ?? '{}')
    assert.equal(received?.path, '/v1/chat/completions')
    assert.equal(received?.headers.authorization, 'Bearer test-key')
    assert.ok(!received?.body.includes(TOKEN))
    assert.equal(body.model, 'gpt-test')
    assert.equal(body.messages[0].role, 'system')
    assert.match(body.messages[0].content, /veil/)
    assert.equal(body.messages[1].content[0].text, 'use [veil:API_TOKEN]')
    assert.equal(body.messages[1].content[1].image_url.url, image)
    assert.equal(body.messages[2].tool_calls[0].id, 'call_1')
    assert.match(body.messages[2].tool_calls[0].function.arguments, /\[veil:API_TOKEN\]/)
    assert.equal(body.messages[3].content, 'wrote [veil:API_TOKEN]')
  })

  it('masks an Anthropic request and keeps signed thinking as it was', async () => {
    canned = { type: 'application/json', body: JSON.stringify({ content: [{ type: 'text', text: 'ok' }] }) }
    const thinking = { type: 'thinking', thinking: 'plan', signature: 'sig' }
    await send('/test/v1/messages', {
      model: 'claude-test',
      system: 'be brief',
      messages: [
        { role: 'user', content: `the key is ${TOKEN}` },
        { role: 'assistant', content: [thinking, { type: 'tool_use', id: 'toolu_1', name: 'Bash', input: { command: `echo ${TOKEN}` } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: TOKEN }] },
      ],
    })
    const body = JSON.parse(received?.body ?? '{}')
    assert.ok(!received?.body.includes(TOKEN))
    assert.match(body.system, /^be brief\n\n.*veil/s)
    assert.deepEqual(body.messages[1].content[0], thinking)
    assert.equal(body.messages[1].content[1].input.command, 'echo [veil:API_TOKEN]')
  })

  it('restores tool call arguments only for the value own file or a file holding it', async () => {
    const calls = [
      { file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' },
      { file_path: '/repo/public/app.js', content: 'const t = "[veil:API_TOKEN]"' },
      { command: 'curl -H "x: [veil:API_TOKEN]"' },
    ]
    canned = {
      type: 'application/json',
      body: JSON.stringify({
        choices: [{ index: 0, message: { role: 'assistant', tool_calls: calls.map((args, i) => ({ id: `c${i}`, type: 'function', function: { name: 'write', arguments: JSON.stringify(args) } })) } }],
      }),
    }
    const answer = JSON.parse((await send('/test/v1/chat/completions', { model: 'm', messages: [] })).text)
    const args = answer.choices[0].message.tool_calls.map((call: { function: { arguments: string } }) => JSON.parse(call.function.arguments))
    assert.equal(args[0].content, ENV)
    assert.equal(args[1].content, 'const t = "[veil:API_TOKEN]"')
    assert.equal(args[2].command, 'curl -H "x: [veil:API_TOKEN]"')
  })

  it('restores OpenAI chat tool calls streamed in pieces, and leaves text deltas alone', async () => {
    const args = JSON.stringify({ file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' })
    const base = { id: 'x', object: 'chat.completion.chunk', created: 1, model: 'm' }
    canned = {
      type: 'text/event-stream',
      body: sse([
        [undefined, { ...base, choices: [{ index: 0, delta: { content: 'see [veil:API_TOKEN]' }, finish_reason: null }] }],
        [undefined, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'c1', type: 'function', function: { name: 'Write', arguments: args.slice(0, 20) } }] }, finish_reason: null }] }],
        [undefined, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args.slice(20) } }] }, finish_reason: null }] }],
        [undefined, { ...base, choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] }],
        [undefined, '[DONE]'],
      ]),
    }
    const answer = await send('/test/v1/chat/completions', { model: 'm', stream: true, messages: [] })
    let text = ''
    let joined = ''
    let finishedAfterArgs = false
    for (const { data } of events(answer.text)) {
      if (data === '[DONE]') continue
      const choice = JSON.parse(data).choices[0]
      text += choice.delta.content ?? ''
      joined += choice.delta.tool_calls?.[0]?.function?.arguments ?? ''
      if (choice.finish_reason === 'tool_calls') finishedAfterArgs = joined !== ''
    }
    assert.equal(text, 'see [veil:API_TOKEN]')
    assert.equal(JSON.parse(joined).content, ENV)
    assert.equal(finishedAfterArgs, true)
    assert.match(answer.text, /data: \[DONE\]\n\n$/)
  })

  it('restores Anthropic tool_use input streamed as JSON deltas', async () => {
    const args = JSON.stringify({ file_path: '/repo/src/config.ts', old_string: "'[veil:API_TOKEN]'", new_string: "'[veil:API_TOKEN]' as const" })
    canned = {
      type: 'text/event-stream',
      body: sse([
        ['message_start', { type: 'message_start', message: { id: 'm', content: [] } }],
        ['content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 't', name: 'Edit', input: {} } }],
        ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: args.slice(0, 15) } }],
        ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: args.slice(15) } }],
        ['content_block_stop', { type: 'content_block_stop', index: 0 }],
        ['message_stop', { type: 'message_stop' }],
      ]),
    }
    const answer = await send('/test/v1/messages', { model: 'm', stream: true, messages: [] })
    const parsed = events(answer.text)
    const deltas = parsed.filter(item => item.event === 'content_block_delta').map(item => JSON.parse(item.data).delta.partial_json as string)
    assert.equal(deltas.length, 1)
    const input = JSON.parse(deltas.join(''))
    assert.equal(input.new_string, `'${TOKEN}' as const`)
    assert.deepEqual(parsed.map(item => item.event), ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_stop'])
  })

  it('restores Responses API function calls and apply_patch input, in deltas, done events and the completed response', async () => {
    const args = JSON.stringify({ file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' })
    const patch = '*** Begin Patch\n*** Update File: /repo/.env\n@@\n-API_TOKEN=[veil:API_TOKEN]\n+API_TOKEN=[veil:API_TOKEN]\n+DEBUG=1\n*** Update File: /repo/public/app.js\n+x = "[veil:API_TOKEN]"\n*** End Patch'
    canned = {
      type: 'text/event-stream',
      body: sse([
        ['response.output_item.added', { type: 'response.output_item.added', output_index: 0, item: { id: 'fc_1', type: 'function_call', name: 'write', arguments: '' }, sequence_number: 1 }],
        ['response.function_call_arguments.delta', { type: 'response.function_call_arguments.delta', item_id: 'fc_1', output_index: 0, delta: args.slice(0, 10), sequence_number: 2 }],
        ['response.function_call_arguments.delta', { type: 'response.function_call_arguments.delta', item_id: 'fc_1', output_index: 0, delta: args.slice(10), sequence_number: 3 }],
        ['response.function_call_arguments.done', { type: 'response.function_call_arguments.done', item_id: 'fc_1', output_index: 0, arguments: args, sequence_number: 4 }],
        ['response.output_item.done', { type: 'response.output_item.done', output_index: 0, item: { id: 'fc_1', type: 'function_call', name: 'write', arguments: args }, sequence_number: 5 }],
        ['response.output_item.added', { type: 'response.output_item.added', output_index: 1, item: { id: 'ct_1', type: 'custom_tool_call', name: 'apply_patch', input: '' }, sequence_number: 5 }],
        ['response.custom_tool_call_input.delta', { type: 'response.custom_tool_call_input.delta', item_id: 'ct_1', output_index: 1, delta: patch, sequence_number: 6 }],
        ['response.custom_tool_call_input.done', { type: 'response.custom_tool_call_input.done', item_id: 'ct_1', output_index: 1, input: patch, sequence_number: 7 }],
        ['response.completed', { type: 'response.completed', response: { output: [{ id: 'fc_1', type: 'function_call', name: 'write', arguments: args }, { id: 'ct_1', type: 'custom_tool_call', name: 'apply_patch', input: patch }] }, sequence_number: 8 }],
      ]),
    }
    const answer = await send('/test/v1/responses', { model: 'm', stream: true, input: 'hi' })
    const parsed = events(answer.text).map(item => JSON.parse(item.data))
    const deltas = parsed.filter(item => item.type === 'response.function_call_arguments.delta')
    assert.equal(deltas.length, 1)
    assert.equal(JSON.parse(deltas[0].delta).content, ENV)
    assert.equal(JSON.parse(parsed.find(item => item.type === 'response.function_call_arguments.done').arguments).content, ENV)
    assert.equal(JSON.parse(parsed.find(item => item.type === 'response.output_item.done').item.arguments).content, ENV)
    const done = parsed.find(item => item.type === 'response.custom_tool_call_input.done').input as string
    assert.ok(done.includes(`-API_TOKEN=${TOKEN}\n+API_TOKEN=${TOKEN}\n+DEBUG=1`))
    assert.ok(done.includes('x = "[veil:API_TOKEN]"'))
    const completed = parsed.find(item => item.type === 'response.completed').response.output
    assert.equal(JSON.parse(completed[0].arguments).content, ENV)
    assert.equal(completed[1].input, done)
  })

  it('restores Gemini function calls in a server-sent stream and Ollama tool calls in NDJSON', async () => {
    const args = { file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' }
    canned = { type: 'text/event-stream', body: sse([[undefined, { candidates: [{ content: { role: 'model', parts: [{ functionCall: { name: 'write_file', args } }] } }] }]]) }
    const gemini = await send('/test/v1beta/models/g:streamGenerateContent?alt=sse', { contents: [{ role: 'user', parts: [{ text: TOKEN }] }] })
    assert.equal(JSON.parse(events(gemini.text)[0]?.data ?? '{}').candidates[0].content.parts[0].functionCall.args.content, ENV)
    const sent = JSON.parse(received?.body ?? '{}')
    assert.equal(sent.contents[0].parts[0].text, '[veil:API_TOKEN]')
    assert.match(sent.systemInstruction.parts[0].text, /veil/)
    canned = { type: 'application/x-ndjson', body: `${JSON.stringify({ message: { role: 'assistant', content: '', tool_calls: [{ function: { name: 'write', arguments: args } }] }, done: false })}\n${JSON.stringify({ done: true })}\n` }
    const ollama = await send('/test/api/chat', { model: 'm', messages: [{ role: 'user', content: TOKEN }] })
    const lines = ollama.text.trim().split('\n').map(line => JSON.parse(line))
    assert.equal(lines[0].message.tool_calls[0].function.arguments.content, ENV)
    assert.equal(lines[1].done, true)
  })

  it('refuses other hosts, browsers and unknown routes', async () => {
    assert.equal((await send('/test/v1/chat/completions', {}, { host: 'evil.example:80' })).status, 403)
    assert.equal((await send('/test/v1/chat/completions', {}, { origin: 'https://evil.example' })).status, 403)
    const unknown = await send('/nope/v1/chat/completions', {})
    assert.equal(unknown.status, 404)
    assert.match(unknown.text, /\/test/)
  })

  it('reads gzip and zstd request bodies, masks them, and refuses encodings it cannot read', async () => {
    canned = { type: 'application/json', body: '{}' }
    const message = { model: 'm', messages: [{ role: 'user', content: TOKEN }] }
    for (const [encoding, pack] of [['gzip', gzipSync], ['zstd', zstdCompressSync]] as const) {
      const answer = await send('/test/v1/chat/completions', pack(Buffer.from(JSON.stringify(message))), { 'content-encoding': encoding })
      assert.equal(answer.status, 200, encoding)
      assert.equal(received?.headers['content-encoding'], undefined)
      assert.ok(!received?.body.includes(TOKEN))
      assert.match(received?.body ?? '', /\[veil:API_TOKEN\]/)
    }
    received = undefined
    const refused = await send('/test/v1/chat/completions', Buffer.from(JSON.stringify(message)), { 'content-encoding': 'compress' })
    assert.equal(refused.status, 415)
    assert.equal(received, undefined)
  })

  it('refuses WebSocket upgrades so clients fall back to HTTP', async () => {
    const answer = await send('/test/v1/responses', {}, { connection: 'Upgrade', upgrade: 'websocket' })
    assert.equal(answer.status, 501)
  })

  it('re-masks text it already sent once it learns a new secret, and never shares masked text across routes', async () => {
    const later = fake.hex(seeded(61), 40)
    const old = `earlier output ${later}`
    canned = { type: 'application/json', body: '{}' }
    await send('/test/v1/chat/completions', { model: 'm', messages: [{ role: 'user', content: old }] })
    FILES['/repo/.env'] = `${ENV}LATER_TOKEN=${later}\n`
    try {
      await veil.refreshSources(sessionFs())
      await send('/test/v1/chat/completions', { model: 'm', messages: [{ role: 'user', content: old }] })
      assert.equal(JSON.parse(received?.body ?? '{}').messages[1].content, 'earlier output [veil:LATER_TOKEN]')
      await send('/local/v1/chat/completions', { model: 'm', messages: [{ role: 'user', content: old }] })
      assert.equal(JSON.parse(received?.body ?? '{}').messages[1].content, 'earlier output [veil:LATER_TOKEN]')
    } finally {
      FILES['/repo/.env'] = ENV
      await veil.refreshSources(sessionFs())
    }
  })

  it('masks text that only looks like a data URL, and keeps real media data URLs whole', async () => {
    canned = { type: 'application/json', body: '{}' }
    const image = `data:image/png;base64,${Buffer.from(TOKEN).toString('base64')}`
    await send('/test/v1/chat/completions', {
      model: 'm',
      messages: [
        { role: 'tool', tool_call_id: 'c1', content: `data: {"token":"${TOKEN}"}` },
        { role: 'user', content: [{ type: 'image_url', image_url: { url: image } }, { type: 'text', text: `data:text/plain;base64,${TOKEN}` }] },
      ],
    })
    const body = JSON.parse(received?.body ?? '{}')
    assert.ok(!received?.body.includes(TOKEN))
    assert.equal(body.messages[2].content[0].image_url.url, image)
  })

  it('masks every string inside tool inputs, outputs and descriptions, whatever its key is called', async () => {
    canned = { type: 'application/json', body: '{}' }
    await send('/test/v1/messages', {
      model: 'm',
      tools: [{ name: 'db', description: `connect with ${TOKEN}`, input_schema: { type: 'object', properties: { mode: { type: 'string', enum: ['read', 'write'] } } } }],
      messages: [
        { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_1', name: 'db', input: { name: TOKEN, id: TOKEN, options: { type: TOKEN } } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: TOKEN }] },
      ],
    })
    const body = JSON.parse(received?.body ?? '{}')
    assert.ok(!received?.body.includes(TOKEN))
    assert.deepEqual(body.tools[0].input_schema.properties.mode.enum, ['read', 'write'])
    assert.equal(body.messages[0].content[0].id, 'toolu_1')
    await send('/test/v1beta/models/g:generateContent', { contents: [{ role: 'user', parts: [{ functionResponse: { name: 'f', id: 'call-1', response: { id: TOKEN, provider: TOKEN } } }] }, { role: 'model', parts: [{ text: 'ok' }] }] })
    assert.ok(!received?.body.includes(TOKEN))
    await send('/test/v1/chat/completions', { model: 'm', messages: [{ role: 'assistant', content: 'ok', reasoning: `I saw ${TOKEN}` }] })
    assert.ok(!received?.body.includes(TOKEN))
  })

  it('masks every text body, multipart text parts included, and refuses binary it cannot check', async () => {
    canned = { type: 'application/json', body: '{}' }
    const boundary = 'veil-test-boundary'
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00, 0x01])
    const multipart = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename=".env"\r\nContent-Type: text/plain\r\n\r\n${ENV}\r\n`),
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="a.png"\r\nContent-Type: image/png\r\n\r\n`),
      png,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ])
    assert.equal((await send('/test/v1/files', multipart, { 'content-type': `multipart/form-data; boundary=${boundary}` })).status, 200)
    assert.ok(!received?.body.includes(TOKEN))
    assert.match(received?.body ?? '', /API_TOKEN=\[veil:API_TOKEN\]/)
    for (const type of ['application/x-ndjson', 'application/octet-stream', 'text/plain']) {
      await send('/test/v1/batch', `{"input":"${TOKEN}"}\n{"input":"x"}\n`, { 'content-type': type })
      assert.ok(!received?.body.includes(TOKEN), type)
    }
    received = undefined
    assert.equal((await send('/test/v1/files', Buffer.from([0xff, 0xfe, 0x00, 0x9f]), { 'content-type': 'application/zip' })).status, 415)
    assert.equal(received, undefined)
    assert.equal((await send('/test/v1/audio', png, { 'content-type': 'image/png' })).status, 200)
  })

  it('turns an upstream redirect into an error, so the body is never re-sent elsewhere', async () => {
    canned = { type: 'application/json', body: '{}', status: 307, headers: { location: 'https://elsewhere.example/v1' } }
    const answer = await send('/test/v1/chat/completions', { model: 'm', messages: [] })
    canned = { type: 'application/json', body: '{}' }
    assert.equal(answer.status, 502)
    assert.ok(!answer.text.includes('elsewhere'))
  })

  it('sends a whole tool call in one chunk as id and name first, then the arguments, then the finish', async () => {
    const args = JSON.stringify({ file_path: '/repo/.env', content: 'API_TOKEN=[veil:API_TOKEN]\n' })
    canned = {
      type: 'text/event-stream',
      body: sse([
        [undefined, { id: 'x', choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'c1', type: 'function', function: { name: 'write', arguments: args } }] }, finish_reason: 'tool_calls' }] }],
        [undefined, '[DONE]'],
      ]),
    }
    const answer = await send('/test/v1/chat/completions', { model: 'm', stream: true, messages: [] })
    const chunks = events(answer.text).filter(item => item.data !== '[DONE]').map(item => JSON.parse(item.data).choices[0])
    assert.equal(chunks[0].delta.tool_calls[0].id, 'c1')
    assert.equal(chunks[0].finish_reason, null)
    assert.equal(JSON.parse(chunks[1].delta.tool_calls[0].function.arguments).content, ENV)
    assert.equal(chunks[2].finish_reason, 'tool_calls')
  })

  it('passes other tool calls through as they stream, without holding them', async () => {
    const args = JSON.stringify({ command: 'echo [veil:API_TOKEN]' })
    canned = {
      type: 'text/event-stream',
      body: sse([
        [undefined, { id: 'x', choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'c1', type: 'function', function: { name: 'Bash', arguments: args.slice(0, 5) } }] }, finish_reason: null }] }],
        [undefined, { id: 'x', choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args.slice(5) } }] }, finish_reason: 'tool_calls' }] }],
        [undefined, '[DONE]'],
      ]),
    }
    const answer = await send('/test/v1/chat/completions', { model: 'm', stream: true, messages: [] })
    const chunks = events(answer.text).filter(item => item.data !== '[DONE]').map(item => JSON.parse(item.data).choices[0])
    assert.equal(chunks.length, 2)
    assert.equal(chunks[0].delta.tool_calls[0].function.arguments, args.slice(0, 5))
    assert.ok(!answer.text.includes(TOKEN))
  })

  it('cancels the upstream request when the client goes away', async () => {
    upstreamClosed = false
    canned = { type: 'text/event-stream', body: 'data: {}\n\n'.repeat(5), slow: true }
    await new Promise<void>(done => {
      const req = httpRequest({ host: '127.0.0.1', port: proxyPort, path: '/test/v1/chat/completions', method: 'POST', headers: { 'content-type': 'application/json' } }, res => {
        res.once('data', () => {
          req.destroy()
          setTimeout(done, 150)
        })
      })
      req.on('error', () => undefined)
      req.end('{}')
    })
    canned = { type: 'application/json', body: '{}' }
    assert.equal(upstreamClosed, true)
  })

  it('takes requests that ask for 100-continue, and keeps the note out of requests that cannot hold one', async () => {
    canned = { type: 'application/json', body: '{}' }
    assert.equal((await send('/test/v1/chat/completions', { model: 'm', messages: [] }, { expect: '100-continue' })).status, 200)
    await send('/test/v1beta/models/g:countTokens', { contents: [{ role: 'user', parts: [{ text: 'hi' }] }] })
    assert.equal(JSON.parse(received?.body ?? '{}').systemInstruction, undefined)
    await send('/test/v1beta/models/g:generateContent', { cachedContent: 'cachedContents/abc', contents: [{ role: 'user', parts: [{ text: 'hi' }] }] })
    assert.equal(JSON.parse(received?.body ?? '{}').systemInstruction, undefined)
    await send('/test/api/generate', { model: 'm', prompt: 'hi' })
    assert.equal(JSON.parse(received?.body ?? '{}').system, undefined)
  })

  it('refuses a request it cannot check in time instead of forwarding it gutted, and unknown routes such as __proto__', async () => {
    const slow = new Veil({ budgetMs: -1 })
    await slow.start(sessionFs(), { home: '/home/me', root: '/repo', cwd: '/repo', platform: 'linux', vars: {} })
    const server = await startProxy({ port: 0, routes: { test: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}` }, veil: slow, restorer: { veil: slow, tools: PROXY_TOOLS, probe: async () => ({ content: '' }) } })
    const port = (server.address() as AddressInfo).port
    try {
      received = undefined
      const answer = await new Promise<number>((resolve, reject) => {
        const req = httpRequest({ host: '127.0.0.1', port, path: '/test/v1/chat/completions', method: 'POST', headers: { 'content-type': 'application/json' } }, res => {
          res.resume()
          resolve(res.statusCode ?? 0)
        })
        req.on('error', reject)
        req.end(JSON.stringify({ model: 'm', messages: [{ role: 'user', content: `long ${TOKEN}` }] }))
      })
      assert.equal(answer, 503)
      assert.equal(received, undefined)
    } finally {
      await new Promise(done => server.close(done))
    }
    assert.equal((await send('/__proto__/v1/chat/completions', {})).status, 404)
  })

  it('passes a 304 through, and refuses any request a browser marks as cross-site', async () => {
    canned = { type: 'application/json', body: '', status: 304 }
    assert.equal((await send('/test/v1/models', {})).status, 304)
    canned = { type: 'application/json', body: '{}' }
    assert.equal((await send('/test/v1/chat/completions', {}, { 'sec-fetch-site': 'cross-site' })).status, 403)
  })

  it('masks secrets in tool schemas but keeps schema keywords, and keeps a Responses conversation encrypted parts intact', async () => {
    canned = { type: 'application/json', body: '{}' }
    const dsn = `postgres://app:${TOKEN}@db/app`
    await send('/test/v1/responses', {
      model: 'm',
      tools: [{ type: 'function', name: 'q', parameters: { type: 'object', properties: { url: { type: 'string', default: dsn, enum: [dsn, 'none'], examples: [dsn], pattern: '^post' } }, required: ['url'] } }],
      input: [
        { type: 'reasoning', id: 'rs_1', encrypted_content: `gAAA${TOKEN}` },
        { type: 'function_call', id: 'fc_1', call_id: `call_${TOKEN}`, name: 'q', arguments: JSON.stringify({ url: dsn }) },
        { type: 'function_call_output', call_id: `call_${TOKEN}`, output: dsn },
      ],
    })
    const body = JSON.parse(received?.body ?? '{}')
    const url = body.tools[0].parameters.properties.url
    assert.ok(!JSON.stringify(body.tools).includes(TOKEN))
    assert.equal(url.pattern, '^post')
    assert.deepEqual(body.tools[0].parameters.required, ['url'])
    assert.equal(body.input[0].encrypted_content, `gAAA${TOKEN}`)
    assert.equal(body.input[1].call_id, `call_${TOKEN}`)
    assert.ok(!body.input[1].arguments.includes(TOKEN))
    assert.ok(!body.input[2].output.includes(TOKEN))
  })

  it('leaves raw base64 images alone, keeps the MCP connector token, and masks a message name', async () => {
    canned = { type: 'application/json', body: '{}' }
    const image = Buffer.from(`${'x'.repeat(200)}${TOKEN}`).toString('base64')
    await send('/test/v1beta/models/g:generateContent', { contents: [{ role: 'user', parts: [{ inlineData: { mimeType: 'image/png', data: image } }, { text: TOKEN }] }] })
    const gemini = JSON.parse(received?.body ?? '{}')
    assert.equal(gemini.contents[0].parts[0].inlineData.data, image)
    assert.equal(gemini.contents[0].parts[1].text, '[veil:API_TOKEN]')
    await send('/test/api/chat', { model: 'm', messages: [{ role: 'user', content: 'see', images: [image] }] })
    assert.equal(JSON.parse(received?.body ?? '{}').messages[1].images[0], image)
    await send('/test/v1/messages', { model: 'm', mcp_servers: [{ type: 'url', url: 'https://mcp.example', name: 'x', authorization_token: TOKEN }], messages: [{ role: 'user', content: 'hi' }] })
    assert.equal(JSON.parse(received?.body ?? '{}').mcp_servers[0].authorization_token, TOKEN)
    await send('/test/v1/chat/completions', { model: 'm', messages: [{ role: 'user', name: TOKEN, content: 'hi' }] })
    assert.ok(!received?.body.includes(TOKEN))
  })

  it('releases arguments it held when a late tool name turns out not to write files', async () => {
    const args = JSON.stringify({ command: 'ls' })
    canned = {
      type: 'text/event-stream',
      body: sse([
        [undefined, { id: 'x', choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'c1', type: 'function', function: { arguments: args.slice(0, 4) } }] }, finish_reason: null }] }],
        [undefined, { id: 'x', choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: 'Bash', arguments: args.slice(4) } }] }, finish_reason: 'tool_calls' }] }],
        [undefined, '[DONE]'],
      ]),
    }
    const answer = await send('/test/v1/chat/completions', { model: 'm', stream: true, messages: [] })
    const joined = events(answer.text)
      .filter(item => item.data !== '[DONE]')
      .map(item => JSON.parse(item.data).choices[0].delta.tool_calls?.[0]?.function?.arguments ?? '')
      .join('')
    assert.equal(joined, args)
  })

  it('never logs a request URL, whatever went wrong upstream', async () => {
    const lines: string[] = []
    const server = await startProxy({ port: 0, routes: { dead: 'http://127.0.0.1:1' }, veil, restorer: { veil, tools: PROXY_TOOLS, probe: async () => ({ content: '' }) }, log: line => lines.push(line) })
    const port = (server.address() as AddressInfo).port
    try {
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest({ host: '127.0.0.1', port, path: '/dead/v1/models?key=FAKEKEY123', method: 'GET' }, res => {
          res.resume()
          resolve(res.statusCode ?? 0)
        })
        req.on('error', reject)
        req.end()
      })
      assert.equal(status, 502)
      assert.ok(lines.length > 0)
      assert.ok(lines.every(line => !line.includes('FAKEKEY123') && !line.includes('127.0.0.1:1')), lines.join('\n'))
    } finally {
      await new Promise(done => server.close(done))
    }
  })

  it('keeps integers beyond double precision and __proto__ keys exactly as sent', async () => {
    canned = { type: 'application/json', body: '{}' }
    await send('/test/v1/chat/completions', `{"model":"m","seed":12345678901234567890,"metadata":{"__proto__":"${TOKEN}"},"messages":[{"role":"user","content":"${TOKEN}"}]}`)
    assert.match(received?.body ?? '', /"seed":12345678901234567890/)
    assert.match(received?.body ?? '', /"__proto__":"\[veil:API_TOKEN\]"/)
    assert.ok(!received?.body.includes(TOKEN))
  })

  it('restores Gemini CLI replace edits only on Gemini requests, and masks SVG data URLs as text', async () => {
    const args = { file_path: '/repo/.env', old_string: 'API_TOKEN=[veil:API_TOKEN]', new_string: 'API_TOKEN=[veil:API_TOKEN]\nX=1' }
    canned = { type: 'application/json', body: JSON.stringify({ candidates: [{ content: { parts: [{ functionCall: { name: 'replace', args } }] } }] }) }
    const gemini = JSON.parse((await send('/test/v1beta/models/g:generateContent', { contents: [{ role: 'user', parts: [{ text: 'x' }] }] })).text)
    assert.equal(gemini.candidates[0].content.parts[0].functionCall.args.new_string, `${ENV.trim()}\nX=1`)
    canned = { type: 'application/json', body: JSON.stringify({ choices: [{ index: 0, message: { tool_calls: [{ id: 'c', type: 'function', function: { name: 'replace', arguments: JSON.stringify(args) } }] } }] }) }
    const chat = JSON.parse((await send('/test/v1/chat/completions', { model: 'm', messages: [] })).text)
    assert.equal(JSON.parse(chat.choices[0].message.tool_calls[0].function.arguments).new_string, args.new_string)
    canned = { type: 'application/json', body: '{}' }
    const svg = `data:image/svg+xml;base64,${Buffer.from(`<svg><text>${TOKEN}</text></svg>`).toString('base64')}`
    await send('/test/v1/chat/completions', { model: 'm', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: svg } }, { type: 'text', text: `<svg>${TOKEN}</svg>` }] }] })
    assert.ok(!received?.body.includes(TOKEN))
  })

  it('restores freeform patch arguments that are not JSON', async () => {
    const restorer = { veil, tools: PROXY_TOOLS, probe: async (path: string) => (path in FILES ? { content: FILES[path] ?? '', realPath: path } : { content: '' }) }
    const out = await restoreArguments('*** Begin Patch\n*** Update File: /repo/.env\n-API_TOKEN=[veil:API_TOKEN]\n*** End Patch', restorer, 'apply_patch')
    assert.ok(out.includes(`-API_TOKEN=${TOKEN}`))
  })
})
