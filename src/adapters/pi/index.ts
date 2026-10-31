import { nodeDeps, type AdapterDeps } from '../../node/fs.ts'
import { PI_TOOLS, checkInput, hasPlaceholder, namesFile, targetPathOf, unrestorable } from '../../restore.ts'
import { Veil, replaceItems, type StartLog } from '../../session.ts'
import { MEDIA_ONLY, REQUEST_SKIP, SAVED_SKIP, dialectOfPayload, maskPayload } from '../../wire/request.ts'

const READ_TOOLS = new Set(['read', 'grep', 'find', 'ls', 'bash'])
const PI_PACKAGE = '@earendil-works/pi-coding-agent'
const PI_REWRITTEN = /^@|^~(?:[\\/]|$)|^file:|[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/

export type PiContext = {
  readonly cwd: string
  readonly model?: { readonly api?: string } | undefined
  readonly ui?: { readonly notify?: (message: string, level: string) => void } | undefined
}

type Handler = (event: any, ctx: PiContext) => unknown

export type PiApi = { on(event: string, handler: Handler): void; getSettings?: () => { readonly shellPath?: string } | undefined }

export type ShellOps = {
  exec: (command: string, cwd: string, options: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number; env?: NodeJS.ProcessEnv }) => Promise<{ exitCode: number | null }>
}

export type PiOptions = { readonly localShell?: (shellPath: string | undefined) => Promise<ShellOps | undefined>; readonly budgetMs?: number }

type Started = { readonly veil: Veil; readonly log: StartLog; readonly root: string }

function pathOf(input: unknown): string | undefined {
  const top = input !== null && typeof input === 'object' ? (input as Record<string, unknown>) : undefined
  return typeof top?.path === 'string' ? top.path : undefined
}

async function piShell(shellPath: string | undefined): Promise<ShellOps | undefined> {
  const name = PI_PACKAGE
  const pi = (await import(name).catch(() => undefined)) as { createLocalBashOperations?: (options?: { shellPath?: string }) => ShellOps } | undefined
  return pi?.createLocalBashOperations?.(shellPath === undefined ? undefined : { shellPath })
}

function maskedShell(local: ShellOps, veil: Veil): ShellOps {
  return {
    exec: async (command, cwd, options) => {
      const decoder = new TextDecoder()
      let pending = ''
      const emit = (text: string) => {
        if (text !== '') options.onData(Buffer.from(veil.mask(text)))
      }
      const result = await local.exec(command, cwd, {
        ...options,
        onData: data => {
          pending += decoder.decode(data, { stream: true })
          const cut = pending.lastIndexOf('\n')
          if (cut < 0) return
          emit(pending.slice(0, cut + 1))
          pending = pending.slice(cut + 1)
        },
      })
      emit(pending + decoder.decode())
      return result
    },
  }
}

export function piExtension(deps: AdapterDeps, options: PiOptions = {}): (pi: PiApi) => void {
  const localShell = options.localShell ?? piShell
  return pi => {
    const sessions = new Map<string, Promise<Started>>()
    const session = (cwd: string): Promise<Started> => {
      let started = sessions.get(cwd)
      if (!started) {
        started = (async () => {
          const root = await deps.root(cwd)
          const veil = new Veil({ budgetMs: options.budgetMs ?? 10_000, cache: true })
          const log = await veil.start(deps.fs, deps.host(root, cwd))
          return { veil, log, root }
        })()
        sessions.set(cwd, started)
      }
      return started
    }

    pi.on('session_start', async (_event, ctx) => {
      const { log } = await session(ctx.cwd)
      for (const line of log.transcript) ctx.ui?.notify?.(line, 'warning')
    })

    pi.on('input', async (event: { text: string }, ctx) => {
      const { veil } = await session(ctx.cwd)
      const text = veil.mask(event.text)
      return text === event.text ? { action: 'continue' } : { action: 'transform', text }
    })

    pi.on('tool_call', async (event: { toolName: string; input: Record<string, unknown> }, ctx) => {
      if (!hasPlaceholder(event.input)) return undefined
      if (!PI_TOOLS.has(event.toolName)) return namesFile(event.input) && !READ_TOOLS.has(event.toolName) ? { block: true, reason: unrestorable(event.toolName) } : undefined
      const path = targetPathOf(event.input)
      if (path !== undefined && PI_REWRITTEN.test(path)) return { block: true, reason: `veil keeps placeholders out of ${path}, because Pi would rewrite that file name before writing it.` }
      const { veil, root } = await session(ctx.cwd)
      const checked = await checkInput(event.input, { veil, probe: deps.probe(ctx.cwd, root), tools: PI_TOOLS }, event.toolName)
      if ('deny' in checked) return { block: true, reason: checked.deny }
      Object.assign(event.input, checked.input)
      return undefined
    })

    pi.on('tool_result', async (event: { input: unknown; content: unknown; details?: unknown; structuredContent?: unknown }, ctx) => {
      const { veil } = await session(ctx.cwd)
      if (veil.refreshDue(pathOf(event.input))) await veil.refreshSources(deps.fs).catch(() => undefined)
      const content = veil.maskValue(event.content, MEDIA_ONLY)
      const details = veil.maskValue(event.details, MEDIA_ONLY)
      const structured = veil.maskValue(event.structuredContent, MEDIA_ONLY)
      if (content === event.content && details === event.details && structured === event.structuredContent) return undefined
      return {
        content,
        ...(event.details === undefined ? {} : { details }),
        ...(event.structuredContent === undefined ? {} : { structuredContent: structured }),
      }
    })

    pi.on('message_end', async (event: { message: unknown }, ctx) => {
      const { veil } = await session(ctx.cwd)
      const [message] = veil.maskValue([event.message], SAVED_SKIP) as unknown[]
      return message === event.message ? undefined : { message }
    })

    pi.on('session_before_compact', async (event: { preparation: { messagesToSummarize?: unknown[]; turnPrefixMessages?: unknown[]; previousSummary?: string } }, ctx) => {
      const { veil } = await session(ctx.cwd)
      const preparation = event.preparation
      for (const items of [preparation.messagesToSummarize, preparation.turnPrefixMessages]) if (items) replaceItems(items, veil.maskValue(items, REQUEST_SKIP))
      if (typeof preparation.previousSummary === 'string') preparation.previousSummary = veil.mask(preparation.previousSummary)
      return undefined
    })

    pi.on('session_before_tree', async (event: { preparation: { entriesToSummarize?: unknown[] } }, ctx) => {
      const { veil } = await session(ctx.cwd)
      const entries = event.preparation.entriesToSummarize
      if (entries) replaceItems(entries, veil.maskValue(entries, REQUEST_SKIP))
      return undefined
    })

    pi.on('user_bash', async (_event, ctx) => {
      const { veil } = await session(ctx.cwd)
      const local = await localShell(pi.getSettings?.()?.shellPath)
      if (!local) {
        ctx.ui?.notify?.('veil could not wrap shell commands in this Pi version, so their output is saved unmasked', 'warning')
        return undefined
      }
      return { operations: maskedShell(local, veil) }
    })

    pi.on('before_provider_request', async (event: { payload: unknown }, ctx) => {
      const { veil } = await session(ctx.cwd)
      const dialect = dialectOfPayload(event.payload, ctx.model?.api)
      try {
        return maskPayload(veil, event.payload, dialect)
      } catch {
        return maskPayload(veil, event.payload, dialect, { strict: false })
      }
    })
  }
}

export default piExtension(nodeDeps)
