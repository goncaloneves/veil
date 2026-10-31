import { nodeDeps, type AdapterDeps } from '../../node/fs.ts'
import { OPENCODE_TOOLS, checkInput, hasPlaceholder, namesFile, unrestorable } from '../../restore.ts'
import { NOTE, Veil } from '../../session.ts'
import { MEDIA_ONLY, REQUEST_SKIP } from '../../wire/request.ts'

const READ_TOOLS = new Set(['read', 'grep', 'glob', 'bash', 'webfetch', 'websearch', 'lsp', 'todowrite', 'task', 'skill', 'question'])

export type OpencodeInput = { readonly directory: string; readonly worktree?: string }

type Part = Record<string, unknown>

export type OpencodeHooks = {
  readonly 'chat.message': (input: unknown, output: { parts: Part[] }) => Promise<void>
  readonly 'tool.execute.before': (input: { tool: string }, output: { args: Record<string, unknown> }) => Promise<void>
  readonly 'tool.execute.after': (input: { tool: string; args?: unknown }, output: Record<string, unknown>) => Promise<void>
  readonly 'experimental.chat.messages.transform': (input: unknown, output: { messages: { info: unknown; parts: Part[] }[] }) => Promise<void>
  readonly 'experimental.chat.system.transform': (input: unknown, output: { system: string[] }) => Promise<void>
}

function maskParts(veil: Veil, parts: Part[]): void {
  const masked = veil.maskValue(parts, REQUEST_SKIP) as Part[]
  if (masked === parts) return
  masked.forEach((part, index) => {
    const original = parts[index]
    if (original && part !== original) Object.assign(original, part)
  })
}

function pathOf(args: unknown): string | undefined {
  const top = args !== null && typeof args === 'object' ? (args as Record<string, unknown>) : undefined
  const path = top?.filePath ?? top?.path
  return typeof path === 'string' ? path : undefined
}

export function opencodePlugin(deps: AdapterDeps): (input: OpencodeInput) => Promise<OpencodeHooks> {
  return async input => {
    const cwd = input.directory
    const worktree = input.worktree && input.worktree !== '/' ? input.worktree : await deps.root(cwd)
    const veil = new Veil({ budgetMs: 10_000, cache: true })
    await veil.start(deps.fs, deps.host(worktree, cwd))
    const restorer = { veil, probe: deps.probe(cwd, worktree), tools: OPENCODE_TOOLS }
    return {
      'chat.message': async (_input, output) => maskParts(veil, output.parts),
      'tool.execute.before': async (call, output) => {
        if (!hasPlaceholder(output.args)) return
        if (!OPENCODE_TOOLS.has(call.tool)) {
          if (namesFile(output.args) && !READ_TOOLS.has(call.tool)) throw new Error(unrestorable(call.tool))
          return
        }
        const checked = await checkInput(output.args, restorer, call.tool)
        if ('deny' in checked) throw new Error(checked.deny)
        Object.assign(output.args, checked.input)
      },
      'tool.execute.after': async (call, output) => {
        if (veil.refreshDue(pathOf(call.args))) await veil.refreshSources(deps.fs).catch(() => undefined)
        for (const [key, value] of Object.entries(output)) output[key] = typeof value === 'string' ? veil.mask(value) : veil.maskValue(value, MEDIA_ONLY)
      },
      'experimental.chat.messages.transform': async (_input, output) => {
        for (const message of output.messages) maskParts(veil, message.parts)
      },
      'experimental.chat.system.transform': async (_input, output) => {
        const system = output.system.map(text => veil.mask(text))
        output.system.splice(0, output.system.length, ...system, NOTE)
      },
    }
  }
}

export default { id: 'veil', server: opencodePlugin(nodeDeps) }
