import type { Register } from 'claude-code'
import { DROP_REASON, NOTE, NOTE_ID, VeilSession, WITHHELD, isMediaPath, type Block } from '../src/adapters/claude-code/session.ts'

export const register: Register = on => {
  const veil = new VeilSession()

  on('session.start', async ($, e, next) => {
    const result = await next(e)
    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE')) ?? ''
    const cwd = await $.session.cwd()
    const root = await $.session.root().catch(() => cwd)
    const darwin = home !== '' && (await $.fs.exists(`${home}/Library/Application Support`).catch(() => false))
    const log = await veil.start(
      {
        read: path => $.fs.read(path).then(String),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
      },
      {
        home,
        root,
        cwd,
        platform: darwin ? 'darwin' : 'linux',
        veilConfig: await $.env.get('VEIL_CONFIG'),
        xdgConfigHome: await $.env.get('XDG_CONFIG_HOME'),
        vars: {
          ANTHROPIC_API_KEY: await $.env.get('ANTHROPIC_API_KEY'),
          ANTHROPIC_AUTH_TOKEN: await $.env.get('ANTHROPIC_AUTH_TOKEN'),
          CLAUDE_CODE_OAUTH_TOKEN: await $.env.get('CLAUDE_CODE_OAUTH_TOKEN'),
          OPENAI_API_KEY: await $.env.get('OPENAI_API_KEY'),
          AZURE_OPENAI_API_KEY: await $.env.get('AZURE_OPENAI_API_KEY'),
          GEMINI_API_KEY: await $.env.get('GEMINI_API_KEY'),
          GOOGLE_API_KEY: await $.env.get('GOOGLE_API_KEY'),
          MISTRAL_API_KEY: await $.env.get('MISTRAL_API_KEY'),
          GROQ_API_KEY: await $.env.get('GROQ_API_KEY'),
          XAI_API_KEY: await $.env.get('XAI_API_KEY'),
          DEEPSEEK_API_KEY: await $.env.get('DEEPSEEK_API_KEY'),
          OPENROUTER_API_KEY: await $.env.get('OPENROUTER_API_KEY'),
          TOGETHER_API_KEY: await $.env.get('TOGETHER_API_KEY'),
          FIREWORKS_API_KEY: await $.env.get('FIREWORKS_API_KEY'),
          COHERE_API_KEY: await $.env.get('COHERE_API_KEY'),
          PERPLEXITY_API_KEY: await $.env.get('PERPLEXITY_API_KEY'),
          HF_TOKEN: await $.env.get('HF_TOKEN'),
          HUGGINGFACE_TOKEN: await $.env.get('HUGGINGFACE_TOKEN'),
          REPLICATE_API_TOKEN: await $.env.get('REPLICATE_API_TOKEN'),
          GITHUB_TOKEN: await $.env.get('GITHUB_TOKEN'),
          GH_TOKEN: await $.env.get('GH_TOKEN'),
          GITLAB_TOKEN: await $.env.get('GITLAB_TOKEN'),
          NPM_TOKEN: await $.env.get('NPM_TOKEN'),
          NODE_AUTH_TOKEN: await $.env.get('NODE_AUTH_TOKEN'),
          AWS_SECRET_ACCESS_KEY: await $.env.get('AWS_SECRET_ACCESS_KEY'),
          AWS_SESSION_TOKEN: await $.env.get('AWS_SESSION_TOKEN'),
          DIGITALOCEAN_ACCESS_TOKEN: await $.env.get('DIGITALOCEAN_ACCESS_TOKEN'),
          CLOUDFLARE_API_TOKEN: await $.env.get('CLOUDFLARE_API_TOKEN'),
          VERCEL_TOKEN: await $.env.get('VERCEL_TOKEN'),
          NETLIFY_AUTH_TOKEN: await $.env.get('NETLIFY_AUTH_TOKEN'),
          FLY_API_TOKEN: await $.env.get('FLY_API_TOKEN'),
          STRIPE_SECRET_KEY: await $.env.get('STRIPE_SECRET_KEY'),
          SLACK_BOT_TOKEN: await $.env.get('SLACK_BOT_TOKEN'),
          SLACK_TOKEN: await $.env.get('SLACK_TOKEN'),
          SENTRY_AUTH_TOKEN: await $.env.get('SENTRY_AUTH_TOKEN'),
          DATABASE_URL: await $.env.get('DATABASE_URL'),
          REDIS_URL: await $.env.get('REDIS_URL'),
        },
      },
    )
    for (const line of log.transcript) $.ui.log(line)
    for (const line of log.debug) $.ui.log(line, { to: 'debug' })
    await $.command.register({ name: 'veil', description: 'Show what veil masks in this session', argumentHint: '[reload]' })
    return result
  })

  on('prompt.submit', async ($, e, next) => {
    if (e.command || (e.isMeta && e.turnId === undefined)) return next(e)
    const context = e.context?.map(item => veil.mask(item))
    return next({ ...e, text: veil.mask(e.text), ...(context ? { context } : {}) })
  }).catch(($, e, next) => (next.called ? next(e) : { drop: DROP_REASON }))

  on('prompt.mention', async ($, e, next) => {
    const holds = `${e.path} holds secrets. Ask Claude to read it with its Read tool, so veil can mask them.`
    if (veil.isSource(e.path)) return { deny: holds }
    if (isMediaPath(e.path)) return next(e)
    const own = await $.fs.stat(e.path, { resolve: true }).catch(() => undefined)
    const real = own?.realPath && own.realPath !== e.path ? await $.fs.stat(own.realPath).catch(() => undefined) : own
    const text = real?.kind === 'file' ? await $.fs.read(e.path).then(String, () => undefined) : undefined
    if (text === undefined) return { deny: `veil could not check ${e.path} for secrets. Ask Claude to read it with its Read tool instead.` }
    return veil.holdsSecret(text) ? { deny: holds } : next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: DROP_REASON }))

  on('command.run', { command: 'veil' }, async ($, e) => {
    const notes: string[] = []
    if (e.args.trim() === 'reload') {
      const log = await veil.reload({
        read: path => $.fs.read(path).then(String),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
      })
      notes.push('veil: reloaded the config and your secret files', ...log.transcript)
      for (const line of log.debug) $.ui.log(line, { to: 'debug' })
    }
    const manifest = await $.fs.read(`${$.plugin.root}/.claude-plugin/plugin.json`).then(String, () => '')
    return { text: [...notes, veil.report(manifest, (await $.env.get('HOME')) ?? '')].join('\n') }
  })

  on('command.run', async ($, e, next) => (e.command === 'veil' || !e.args ? next(e) : next({ ...e, args: veil.mask(e.args) }))).catch(
    ($, e, next) => (next.called ? next(e) : { text: DROP_REASON }),
  )

  on('skill.prompt', async ($, e, next) => {
    const result = await next(e)
    return { ...result, text: veil.mask(result.text) }
  }).catch(() => ({ text: WITHHELD }))

  on('session.append', async ($, e, next) => {
    const content = veil.maskBlocks(e.message.content as Block[])
    return content ? next({ ...e, message: { ...e.message, content: content as typeof e.message.content } }) : next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : next({ ...e, message: { ...e.message, content: veil.withheld(e.message.content as Block[]) as typeof e.message.content } }),
  )

  on('session.send', async ($, e, next) => next({ ...e, text: veil.mask(e.text) })).catch(($, e, next) =>
    next.called ? next(e) : { isDelivered: false, reason: DROP_REASON },
  )

  on('session.receive', async ($, e, next) => next({ ...e, text: veil.mask(e.text) })).catch(($, e, next) =>
    next.called ? next(e) : { consumed: DROP_REASON },
  )

  on('prompt.attachment', async ($, e, next) => {
    const result = await next(e)
    return typeof result.text === 'string' ? { ...result, text: veil.mask(result.text) } : result
  }).catch(() => ({ text: WITHHELD }))

  on('prompt.context', async ($, e, next) => {
    const result = await next(e)
    return { ...result, blocks: result.blocks.map(block => ({ ...block, text: veil.mask(block.text) })) }
  }).catch(async ($, e, next) => {
    const result = await next(e)
    return { ...result, blocks: result.blocks.map(block => ({ ...block, text: WITHHELD })) }
  })

  on('prompt.compose', async ($, e, next) => {
    const result = await next(e)
    const sections = result.sections.map(section => ({ ...section, text: veil.mask(section.text) }))
    return { ...result, sections: [...sections, { id: NOTE_ID, text: NOTE, scope: 'session' as const }] }
  }).catch(async ($, e, next) => {
    const result = await next(e)
    const sections = result.sections.map(section => (section.scope === 'session' ? { ...section, text: WITHHELD } : section))
    return { ...result, sections: [...sections, { id: NOTE_ID, text: NOTE, scope: 'session' as const }] }
  })

  on('tool.call', async ($, e, next) => {
    const result = await next(e)
    if (result.deny !== undefined) return result
    if (result.isError) {
      const raw = result.text ?? (typeof result.result === 'string' ? result.result : JSON.stringify(result.result ?? ''))
      const masked = veil.mask(raw)
      return masked === raw && veil.maskValue(result.result) === result.result ? result : { deny: masked }
    }
    const masked = veil.maskValue(result.result)
    if (masked === result.result) return result
    return { result: masked as typeof result.result, ...(result.context ? { context: result.context } : {}) }
  }).catch(($, e, next) => (next.called ? { deny: WITHHELD } : next(e)))

  on('tool.call', { tool: 'Edit' }, async ($, e, next) => {
    let fields = { old_string: e.old_string, new_string: e.new_string }
    if (veil.hasPlaceholder([e.old_string, e.new_string])) {
      const content = await $.fs.read(e.file_path).then(String, () => '')
      const checked = veil.checkEdit(e.file_path, fields, content)
      if ('deny' in checked) return { deny: checked.deny }
      fields = checked.fields
    }
    const result = await next({ ...e, ...fields })
    if (veil.isSource(e.file_path)) {
      await veil.refreshSources({
        read: path => $.fs.read(path).then(String),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
      })
    }
    return result
  })

  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    let fields = { content: e.content }
    if (veil.hasPlaceholder([e.content])) {
      const content = await $.fs.read(e.file_path).then(String, () => '')
      const checked = veil.checkEdit(e.file_path, fields, content)
      if ('deny' in checked) return { deny: checked.deny }
      fields = checked.fields
    }
    const result = await next({ ...e, ...fields })
    if (veil.isSource(e.file_path)) {
      await veil.refreshSources({
        read: path => $.fs.read(path).then(String),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
      })
    }
    return result
  })

  on('tool.call', { tool: 'NotebookEdit' }, async ($, e, next) => {
    if (!veil.hasPlaceholder([e.new_source])) return next(e)
    const content = await $.fs.read(e.notebook_path).then(String, () => '')
    const checked = veil.checkEdit(e.notebook_path, { new_source: e.new_source }, content)
    if ('deny' in checked) return { deny: checked.deny }
    return next({ ...e, ...checked.fields })
  })
}
