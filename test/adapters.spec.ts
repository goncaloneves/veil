import assert from 'node:assert/strict'
import { posix } from 'node:path'
import { describe, it } from 'node:test'
import { opencodePlugin } from '../src/adapters/opencode/index.ts'
import { piExtension, type PiContext, type PiOptions, type ShellOps } from '../src/adapters/pi/index.ts'
import type { AdapterDeps } from '../src/node/fs.ts'
import { NOTE } from '../src/session.ts'
import { fake, memoryFs, seeded } from './helpers.ts'

const TOKEN = fake.hex(seeded(70), 40)
const ENV = `API_TOKEN=${TOKEN}\n`

const FILES: Record<string, string> = {
  '/home/me/.config/veil/config.toml': '[sources]\nhome = false\nenvironment = false\n',
  '/repo/.env': ENV,
  '/repo/public/app.js': 'console.log(1)\n',
}

const deps: AdapterDeps = {
  fs: { ...memoryFs(FILES), realPath: async path => (path in FILES ? path : undefined) },
  host: (root, cwd) => ({ home: '/home/me', root, cwd, platform: 'linux', vars: {} }),
  probe: base => async path => {
    const full = posix.resolve(base, path)
    return full in FILES ? { content: FILES[full] ?? '', realPath: full } : { content: '' }
  },
  root: async cwd => (cwd.startsWith('/repo') ? '/repo' : cwd),
}

function pi(options: PiOptions = {}, ctx: PiContext = { cwd: '/repo', model: { api: 'anthropic-messages' } }) {
  const handlers = new Map<string, (event: any, ctx: PiContext) => unknown>()
  piExtension(deps, options)({ on: (event, handler) => handlers.set(event, handler) })
  return async (event: string, payload: unknown) => (handlers.get(event) as (event: unknown, ctx: PiContext) => Promise<unknown>)(payload, ctx)
}

describe('pi extension', () => {
  it('masks the typed prompt', async () => {
    const emit = pi()
    assert.deepEqual(await emit('input', { text: `use ${TOKEN}` }), { action: 'transform', text: 'use [veil:API_TOKEN]' })
    assert.deepEqual(await emit('input', { text: 'plain' }), { action: 'continue' })
  })

  it('restores edits into the value own file, including edits sent as a JSON string, and blocks the rest', async () => {
    const emit = pi()
    const edit = { path: '/repo/.env', edits: [{ oldText: 'API_TOKEN=[veil:API_TOKEN]', newText: 'API_TOKEN=[veil:API_TOKEN]\nDEBUG=1' }] }
    assert.equal(await emit('tool_call', { toolName: 'edit', input: edit }), undefined)
    assert.deepEqual(edit.edits[0], { oldText: `API_TOKEN=${TOKEN}`, newText: `API_TOKEN=${TOKEN}\nDEBUG=1` })
    const encoded = { path: '/repo/.env', edits: JSON.stringify([{ oldText: 'API_TOKEN=[veil:API_TOKEN]', newText: 'X=[veil:API_TOKEN]' }]) }
    await emit('tool_call', { toolName: 'edit', input: encoded })
    assert.deepEqual(JSON.parse(encoded.edits), [{ oldText: `API_TOKEN=${TOKEN}`, newText: `X=${TOKEN}` }])
    const blocked = (await emit('tool_call', { toolName: 'write', input: { path: '/repo/public/app.js', content: '[veil:API_TOKEN]' } })) as { block: boolean; reason: string }
    assert.equal(blocked.block, true)
    assert.match(blocked.reason, /does not already hold it/)
    const read = { path: '/repo/.env', content: '[veil:API_TOKEN]' }
    assert.equal(await emit('tool_call', { toolName: 'read', input: read }), undefined)
    assert.equal(read.content, '[veil:API_TOKEN]')
    const shell = { command: 'echo [veil:API_TOKEN]' }
    assert.equal(await emit('tool_call', { toolName: 'bash', input: shell }), undefined)
    assert.equal(shell.command, 'echo [veil:API_TOKEN]')
  })

  it('masks tool results, saved messages and the provider payload, and adds the note', async () => {
    const emit = pi()
    const result = (await emit('tool_result', { input: { command: 'cat .env' }, content: [{ type: 'text', text: ENV }], details: { stdout: ENV } })) as { content: { text: string }[]; details: { stdout: string } }
    assert.equal(result.content[0]?.text, 'API_TOKEN=[veil:API_TOKEN]\n')
    assert.equal(result.details.stdout, 'API_TOKEN=[veil:API_TOKEN]\n')
    assert.equal(await emit('tool_result', { input: {}, content: [{ type: 'text', text: 'clean' }] }), undefined)
    const saved = (await emit('message_end', { message: { role: 'user', content: [{ type: 'text', text: TOKEN }] } })) as { message: { content: { text: string }[] } }
    assert.equal(saved.message.content[0]?.text, '[veil:API_TOKEN]')
    const thinking = { type: 'thinking', thinking: 'plan', thinkingSignature: 'sig' }
    const payload = (await emit('before_provider_request', { payload: { model: 'm', system: 'be brief', messages: [{ role: 'user', content: [thinking, { type: 'text', text: TOKEN }] }] } })) as { system: string; messages: { content: unknown[] }[] }
    assert.match(payload.system, /^be brief\n\n/)
    assert.ok(payload.system.endsWith(NOTE))
    assert.deepEqual(payload.messages[0]?.content[0], thinking)
    assert.deepEqual(payload.messages[0]?.content[1], { type: 'text', text: '[veil:API_TOKEN]' })
  })
})

describe('pi extension, beyond the model request', () => {
  it('refuses a third-party tool that names a file and carries a placeholder, and leaves read tools alone', async () => {
    const emit = pi()
    const blocked = (await emit('tool_call', { toolName: 'mcp__pastebin__write', input: { path: '.env', content: '[veil:API_TOKEN]' } })) as { block: boolean; reason: string }
    assert.equal(blocked.block, true)
    assert.match(blocked.reason, /cannot write real values through mcp__pastebin__write/)
    assert.equal(await emit('tool_call', { toolName: 'grep', input: { path: '/repo', pattern: '[veil:API_TOKEN]' } }), undefined)
  })

  it('masks what compaction and tree summaries send, in place', async () => {
    const emit = pi()
    const preparation = { messagesToSummarize: [{ role: 'user', content: [{ type: 'text', text: ENV }] }], turnPrefixMessages: [{ role: 'toolResult', toolCallId: 't', content: [{ type: 'text', text: TOKEN }], details: { name: TOKEN } }], previousSummary: `earlier ${TOKEN}`, firstKeptEntryId: 'e1' }
    const messages = preparation.messagesToSummarize
    await emit('session_before_compact', { preparation })
    assert.equal(preparation.messagesToSummarize, messages)
    assert.ok(!JSON.stringify(preparation).includes(TOKEN))
    assert.equal(preparation.firstKeptEntryId, 'e1')
    const entries = [{ type: 'message', message: { role: 'user', content: TOKEN } }]
    await emit('session_before_tree', { preparation: { entriesToSummarize: entries } })
    assert.ok(!JSON.stringify(entries).includes(TOKEN))
  })

  it('masks the output of the user own shell commands, line by line', async () => {
    const local: ShellOps = {
      exec: async (_command, _cwd, options) => {
        options.onData(Buffer.from(`API_TOKEN=${TOKEN.slice(0, 10)}`))
        options.onData(Buffer.from(`${TOKEN.slice(10)}\nok`))
        return { exitCode: 0 }
      },
    }
    const emit = pi({ localShell: async () => local })
    const handled = (await emit('user_bash', { command: 'cat .env', cwd: '/repo' })) as { operations: ShellOps }
    const chunks: string[] = []
    await handled.operations.exec('cat .env', '/repo', { onData: data => chunks.push(data.toString()) })
    assert.equal(chunks.join(''), 'API_TOKEN=[veil:API_TOKEN]\nok')
  })

  it('checks relative paths from Pi own folder, refuses names Pi would rewrite, and keeps saved tool calls as written', async () => {
    const sub = pi({}, { cwd: '/repo/sub', model: { api: 'anthropic-messages' } })
    const here = (await sub('tool_call', { toolName: 'write', input: { path: '.env', content: 'K=[veil:API_TOKEN]' } })) as { block: boolean }
    assert.equal(here.block, true)
    const up = { path: '../.env', content: 'API_TOKEN=[veil:API_TOKEN]' }
    assert.equal(await sub('tool_call', { toolName: 'write', input: up }), undefined)
    assert.equal(up.content, ENV.trim())
    for (const path of ['@scope/.env', '.env\u00a0', 'a\u3000b', '~/.env', 'file:///repo/.env']) {
      const blocked = (await sub('tool_call', { toolName: 'write', input: { path, content: '[veil:API_TOKEN]' } })) as { block: boolean; reason: string }
      assert.equal(blocked.block, true, JSON.stringify(path))
    }
    const emit = pi()
    const call = { type: 'toolCall', id: 't1', name: 'bash', arguments: { command: `echo ${TOKEN}` } }
    const saved = (await emit('message_end', { message: { role: 'assistant', content: [{ type: 'text', text: TOKEN }, call] } })) as { message: { content: unknown[] } }
    assert.deepEqual(saved.message.content[0], { type: 'text', text: '[veil:API_TOKEN]' })
    assert.equal(saved.message.content[1], call)
  })

  it('withholds instead of sending the original payload when masking fails in any way', async () => {
    let deep: Record<string, unknown> = { text: TOKEN }
    for (let i = 0; i < 3000; i++) deep = { next: deep }
    const payload = (await pi()('before_provider_request', { payload: { model: 'm', system: 's', messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: [{ type: 'text', text: JSON.stringify({ ok: true }) }], extra: deep }] }] } })) as unknown
    assert.ok(!JSON.stringify(payload).includes(TOKEN))
  })

  it('withholds instead of sending the original payload when masking runs out of time', async () => {
    const emit = pi({ budgetMs: -1 })
    const payload = (await emit('before_provider_request', { payload: { model: 'm', system: 's', messages: [{ role: 'user', content: TOKEN }] } })) as { messages: { content: string }[] }
    assert.ok(!JSON.stringify(payload).includes(TOKEN))
    assert.match(payload.messages[0]?.content ?? '', /withheld/)
  })

  it('puts the note where @google/genai reads it, and loads the project root from a subfolder', async () => {
    const emit = pi({}, { cwd: '/repo/packages/app', model: { api: 'google-generative-ai' } })
    const payload = (await emit('before_provider_request', { payload: { model: 'g', contents: [{ role: 'user', parts: [{ text: TOKEN }] }], config: { systemInstruction: 'be brief' } } })) as { contents: { parts: { text: string }[] }[]; config: { systemInstruction: string } }
    assert.equal(payload.contents[0]?.parts[0]?.text, '[veil:API_TOKEN]')
    assert.ok(payload.config.systemInstruction.startsWith('be brief\n\n'))
    assert.ok(payload.config.systemInstruction.endsWith(NOTE))
  })
})

describe('opencode plugin', () => {
  it('masks any shape of tool result, refuses third-party file writes with placeholders, and roots a worktree of / at the project', async () => {
    const hooks = await opencodePlugin(deps)({ directory: '/repo/sub', worktree: '/' })
    const picture = Buffer.from(`${'x'.repeat(300)}${TOKEN}`).toString('base64')
    const attachment = { type: 'file', mime: 'image/png', url: `data:image/png;base64,${picture}` }
    const withFile = { title: 'read', output: 'ok', metadata: { attachments: [attachment] } }
    await hooks['tool.execute.after']({ tool: 'read', args: {} }, withFile)
    assert.equal((withFile.metadata as { attachments: unknown[] }).attachments[0], attachment)
    const mcp = { content: [{ type: 'text', text: ENV }], structuredContent: { key: TOKEN }, metadata: { truncated: false } }
    await hooks['tool.execute.after']({ tool: 'github_get_file', args: {} }, mcp)
    assert.ok(!JSON.stringify(mcp).includes(TOKEN))
    await assert.rejects(hooks['tool.execute.before']({ tool: 'filesystem_write_file' }, { args: { path: '/repo/.env', content: '[veil:API_TOKEN]' } }), /cannot write real values/)
    await hooks['tool.execute.before']({ tool: 'grep' }, { args: { path: '/repo', pattern: '[veil:API_TOKEN]' } })
    const output = { title: 'cat', output: ENV, metadata: {} }
    await hooks['tool.execute.after']({ tool: 'bash', args: {} }, output)
    assert.equal(output.output, 'API_TOKEN=[veil:API_TOKEN]\n')
  })

  it('masks prompts, tool output, history and the system prompt, and restores edits only where allowed', async () => {
    const hooks = await opencodePlugin(deps)({ directory: '/repo', worktree: '/repo' })
    const prompt = { parts: [{ id: 'p1', type: 'text', text: `key ${TOKEN}` }] }
    await hooks['chat.message']({}, prompt)
    assert.equal(prompt.parts[0]?.text, 'key [veil:API_TOKEN]')
    assert.equal(prompt.parts[0]?.id, 'p1')

    const args: Record<string, unknown> = { filePath: '.env', oldString: 'API_TOKEN=[veil:API_TOKEN]', newString: 'API_TOKEN=[veil:API_TOKEN]\nDEBUG=1' }
    await hooks['tool.execute.before']({ tool: 'edit' }, { args })
    assert.equal(args.newString, `API_TOKEN=${TOKEN}\nDEBUG=1`)
    await assert.rejects(hooks['tool.execute.before']({ tool: 'write' }, { args: { filePath: '/repo/public/app.js', content: '[veil:API_TOKEN]' } }), /does not already hold it/)
    const patch = { patchText: '*** Begin Patch\n*** Update File: .env\n-API_TOKEN=[veil:API_TOKEN]\n+API_TOKEN=[veil:API_TOKEN]\n*** End Patch' }
    await hooks['tool.execute.before']({ tool: 'apply_patch' }, { args: patch })
    assert.ok(patch.patchText.includes(`+API_TOKEN=${TOKEN}`))

    const output = { title: 'cat .env', output: ENV, metadata: { preview: ENV, exit: 0, name: TOKEN, id: TOKEN } }
    await hooks['tool.execute.after']({ tool: 'bash', args: { command: 'cat .env' } }, output)
    assert.equal(output.output, 'API_TOKEN=[veil:API_TOKEN]\n')
    assert.deepEqual(output.metadata, { preview: 'API_TOKEN=[veil:API_TOKEN]\n', exit: 0, name: '[veil:API_TOKEN]', id: '[veil:API_TOKEN]' })

    const history = { messages: [{ info: { id: 'm1' }, parts: [{ type: 'tool', callID: 'c1', state: { status: 'completed', input: { filePath: '.env', content: ENV }, output: ENV } }] }] }
    await hooks['experimental.chat.messages.transform']({}, history)
    assert.ok(!JSON.stringify(history).includes(TOKEN))
    assert.equal(history.messages[0]?.parts[0]?.callID, 'c1')

    const system = { system: [`You are helpful. Token ${TOKEN}`] }
    await hooks['experimental.chat.system.transform']({}, system)
    assert.deepEqual(system.system, ['You are helpful. Token [veil:API_TOKEN]', NOTE])
  })
})
