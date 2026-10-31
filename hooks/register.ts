import type { Register } from 'claude-code'
import { DROP_REASON, NOTE, NOTE_ID, VeilSession, WITHHELD, isMediaPath, type Block } from '../src/adapters/claude-code/session.ts'
import { readText } from '../src/core/text.ts'
import { CLAUDE_TOOLS, checkInput, hasPlaceholder, namesFile, unrestorable } from '../src/restore.ts'
import { settled } from '../src/session.ts'

export const register: Register = on => {
  const veil = new VeilSession()

  on('session.start', async ($, e, next) => {
    const result = await next(e)
    const cwd = await $.session.cwd()
    const root = await $.session.root().catch(() => cwd)
    const userProfile = await $.env.get('USERPROFILE')
    const windows = (await $.env.get('OS')) === 'Windows_NT' || /^[A-Za-z]:[\\/]/.test(cwd)
    const home = (windows ? (userProfile ?? (await $.env.get('HOME'))) : ((await $.env.get('HOME')) ?? userProfile)) ?? ''
    const darwin = !windows && ((await $.fs.exists('/System/Library').catch(() => false)) || (home !== '' && (await $.fs.exists(`${home}/Library/Application Support`).catch(() => false))))
    const platform = windows ? 'win32' : darwin ? 'darwin' : 'linux'
    const log = await veil.start(
      {
        read: path => readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
        realPath: path => $.fs.stat(path, { resolve: true }).then(stat => stat.realPath),
        stat: path => $.fs.stat(path, { resolve: true }).then(stat => ({ kind: stat.kind, size: stat.size, mtimeMs: stat.mtimeMs, realPath: stat.realPath })),
      },
      {
        home,
        root,
        cwd,
        platform,
        veilConfig: await $.env.get('VEIL_CONFIG'),
        xdgConfigHome: await $.env.get('XDG_CONFIG_HOME'),
        environ: platform === 'linux' ? await $.fs.read('/proc/self/environ').then(String, () => null) : undefined,
        vars: await settled([
          ['ANTHROPIC_API_KEY', $.env.get('ANTHROPIC_API_KEY')],
          ['ANTHROPIC_AUTH_TOKEN', $.env.get('ANTHROPIC_AUTH_TOKEN')],
          ['CLAUDE_CODE_OAUTH_TOKEN', $.env.get('CLAUDE_CODE_OAUTH_TOKEN')],
          ['OPENAI_API_KEY', $.env.get('OPENAI_API_KEY')],
          ['AZURE_OPENAI_API_KEY', $.env.get('AZURE_OPENAI_API_KEY')],
          ['GEMINI_API_KEY', $.env.get('GEMINI_API_KEY')],
          ['GOOGLE_API_KEY', $.env.get('GOOGLE_API_KEY')],
          ['MISTRAL_API_KEY', $.env.get('MISTRAL_API_KEY')],
          ['GROQ_API_KEY', $.env.get('GROQ_API_KEY')],
          ['XAI_API_KEY', $.env.get('XAI_API_KEY')],
          ['DEEPSEEK_API_KEY', $.env.get('DEEPSEEK_API_KEY')],
          ['OPENROUTER_API_KEY', $.env.get('OPENROUTER_API_KEY')],
          ['TOGETHER_API_KEY', $.env.get('TOGETHER_API_KEY')],
          ['FIREWORKS_API_KEY', $.env.get('FIREWORKS_API_KEY')],
          ['COHERE_API_KEY', $.env.get('COHERE_API_KEY')],
          ['PERPLEXITY_API_KEY', $.env.get('PERPLEXITY_API_KEY')],
          ['VOYAGE_API_KEY', $.env.get('VOYAGE_API_KEY')],
          ['ELEVENLABS_API_KEY', $.env.get('ELEVENLABS_API_KEY')],
          ['DEEPGRAM_API_KEY', $.env.get('DEEPGRAM_API_KEY')],
          ['ASSEMBLYAI_API_KEY', $.env.get('ASSEMBLYAI_API_KEY')],
          ['CEREBRAS_API_KEY', $.env.get('CEREBRAS_API_KEY')],
          ['LANGSMITH_API_KEY', $.env.get('LANGSMITH_API_KEY')],
          ['LANGCHAIN_API_KEY', $.env.get('LANGCHAIN_API_KEY')],
          ['TAVILY_API_KEY', $.env.get('TAVILY_API_KEY')],
          ['EXA_API_KEY', $.env.get('EXA_API_KEY')],
          ['FIRECRAWL_API_KEY', $.env.get('FIRECRAWL_API_KEY')],
          ['PINECONE_API_KEY', $.env.get('PINECONE_API_KEY')],
          ['HF_TOKEN', $.env.get('HF_TOKEN')],
          ['HUGGINGFACE_TOKEN', $.env.get('HUGGINGFACE_TOKEN')],
          ['HUGGING_FACE_HUB_TOKEN', $.env.get('HUGGING_FACE_HUB_TOKEN')],
          ['REPLICATE_API_TOKEN', $.env.get('REPLICATE_API_TOKEN')],
          ['GITHUB_TOKEN', $.env.get('GITHUB_TOKEN')],
          ['GH_TOKEN', $.env.get('GH_TOKEN')],
          ['GITHUB_PAT', $.env.get('GITHUB_PAT')],
          ['GH_ENTERPRISE_TOKEN', $.env.get('GH_ENTERPRISE_TOKEN')],
          ['GITHUB_ENTERPRISE_TOKEN', $.env.get('GITHUB_ENTERPRISE_TOKEN')],
          ['HOMEBREW_GITHUB_API_TOKEN', $.env.get('HOMEBREW_GITHUB_API_TOKEN')],
          ['GITLAB_TOKEN', $.env.get('GITLAB_TOKEN')],
          ['GITLAB_PRIVATE_TOKEN', $.env.get('GITLAB_PRIVATE_TOKEN')],
          ['GIT_TOKEN', $.env.get('GIT_TOKEN')],
          ['GIT_PASSWORD', $.env.get('GIT_PASSWORD')],
          ['BITBUCKET_TOKEN', $.env.get('BITBUCKET_TOKEN')],
          ['NPM_TOKEN', $.env.get('NPM_TOKEN')],
          ['NODE_AUTH_TOKEN', $.env.get('NODE_AUTH_TOKEN')],
          ['YARN_NPM_AUTH_TOKEN', $.env.get('YARN_NPM_AUTH_TOKEN')],
          ['CARGO_REGISTRY_TOKEN', $.env.get('CARGO_REGISTRY_TOKEN')],
          ['GEM_HOST_API_KEY', $.env.get('GEM_HOST_API_KEY')],
          ['NUGET_API_KEY', $.env.get('NUGET_API_KEY')],
          ['TWINE_PASSWORD', $.env.get('TWINE_PASSWORD')],
          ['POETRY_PYPI_TOKEN_PYPI', $.env.get('POETRY_PYPI_TOKEN_PYPI')],
          ['VSCE_PAT', $.env.get('VSCE_PAT')],
          ['DOCKER_PASSWORD', $.env.get('DOCKER_PASSWORD')],
          ['DOCKERHUB_TOKEN', $.env.get('DOCKERHUB_TOKEN')],
          ['DOCKER_AUTH_CONFIG', $.env.get('DOCKER_AUTH_CONFIG')],
          ['AWS_SECRET_ACCESS_KEY', $.env.get('AWS_SECRET_ACCESS_KEY')],
          ['AWS_SESSION_TOKEN', $.env.get('AWS_SESSION_TOKEN')],
          ['AWS_BEARER_TOKEN_BEDROCK', $.env.get('AWS_BEARER_TOKEN_BEDROCK')],
          ['AZURE_CLIENT_SECRET', $.env.get('AZURE_CLIENT_SECRET')],
          ['ARM_CLIENT_SECRET', $.env.get('ARM_CLIENT_SECRET')],
          ['ARM_ACCESS_KEY', $.env.get('ARM_ACCESS_KEY')],
          ['AZURE_STORAGE_KEY', $.env.get('AZURE_STORAGE_KEY')],
          ['AZURE_STORAGE_CONNECTION_STRING', $.env.get('AZURE_STORAGE_CONNECTION_STRING')],
          ['AZURE_STORAGE_SAS_TOKEN', $.env.get('AZURE_STORAGE_SAS_TOKEN')],
          ['AZURE_DEVOPS_EXT_PAT', $.env.get('AZURE_DEVOPS_EXT_PAT')],
          ['SYSTEM_ACCESSTOKEN', $.env.get('SYSTEM_ACCESSTOKEN')],
          ['GOOGLE_CREDENTIALS', $.env.get('GOOGLE_CREDENTIALS')],
          ['GOOGLE_CLIENT_SECRET', $.env.get('GOOGLE_CLIENT_SECRET')],
          ['CLOUDSDK_AUTH_ACCESS_TOKEN', $.env.get('CLOUDSDK_AUTH_ACCESS_TOKEN')],
          ['GOOGLE_OAUTH_ACCESS_TOKEN', $.env.get('GOOGLE_OAUTH_ACCESS_TOKEN')],
          ['DIGITALOCEAN_ACCESS_TOKEN', $.env.get('DIGITALOCEAN_ACCESS_TOKEN')],
          ['DIGITALOCEAN_TOKEN', $.env.get('DIGITALOCEAN_TOKEN')],
          ['CLOUDFLARE_API_TOKEN', $.env.get('CLOUDFLARE_API_TOKEN')],
          ['CLOUDFLARE_API_KEY', $.env.get('CLOUDFLARE_API_KEY')],
          ['CF_API_TOKEN', $.env.get('CF_API_TOKEN')],
          ['VERCEL_TOKEN', $.env.get('VERCEL_TOKEN')],
          ['NETLIFY_AUTH_TOKEN', $.env.get('NETLIFY_AUTH_TOKEN')],
          ['FLY_API_TOKEN', $.env.get('FLY_API_TOKEN')],
          ['RAILWAY_TOKEN', $.env.get('RAILWAY_TOKEN')],
          ['RAILWAY_API_TOKEN', $.env.get('RAILWAY_API_TOKEN')],
          ['RENDER_API_KEY', $.env.get('RENDER_API_KEY')],
          ['HEROKU_API_KEY', $.env.get('HEROKU_API_KEY')],
          ['HCLOUD_TOKEN', $.env.get('HCLOUD_TOKEN')],
          ['LINODE_TOKEN', $.env.get('LINODE_TOKEN')],
          ['LINODE_CLI_TOKEN', $.env.get('LINODE_CLI_TOKEN')],
          ['SCW_SECRET_KEY', $.env.get('SCW_SECRET_KEY')],
          ['VULTR_API_KEY', $.env.get('VULTR_API_KEY')],
          ['SUPABASE_ACCESS_TOKEN', $.env.get('SUPABASE_ACCESS_TOKEN')],
          ['SUPABASE_SERVICE_ROLE_KEY', $.env.get('SUPABASE_SERVICE_ROLE_KEY')],
          ['SUPABASE_DB_PASSWORD', $.env.get('SUPABASE_DB_PASSWORD')],
          ['FIREBASE_TOKEN', $.env.get('FIREBASE_TOKEN')],
          ['NEON_API_KEY', $.env.get('NEON_API_KEY')],
          ['TURSO_AUTH_TOKEN', $.env.get('TURSO_AUTH_TOKEN')],
          ['PLANETSCALE_SERVICE_TOKEN', $.env.get('PLANETSCALE_SERVICE_TOKEN')],
          ['UPSTASH_REDIS_REST_TOKEN', $.env.get('UPSTASH_REDIS_REST_TOKEN')],
          ['KV_REST_API_TOKEN', $.env.get('KV_REST_API_TOKEN')],
          ['VAULT_TOKEN', $.env.get('VAULT_TOKEN')],
          ['VAULT_SECRET_ID', $.env.get('VAULT_SECRET_ID')],
          ['CONSUL_HTTP_TOKEN', $.env.get('CONSUL_HTTP_TOKEN')],
          ['NOMAD_TOKEN', $.env.get('NOMAD_TOKEN')],
          ['TFE_TOKEN', $.env.get('TFE_TOKEN')],
          ['PULUMI_ACCESS_TOKEN', $.env.get('PULUMI_ACCESS_TOKEN')],
          ['PULUMI_CONFIG_PASSPHRASE', $.env.get('PULUMI_CONFIG_PASSPHRASE')],
          ['SOPS_AGE_KEY', $.env.get('SOPS_AGE_KEY')],
          ['OP_SERVICE_ACCOUNT_TOKEN', $.env.get('OP_SERVICE_ACCOUNT_TOKEN')],
          ['OP_CONNECT_TOKEN', $.env.get('OP_CONNECT_TOKEN')],
          ['BW_SESSION', $.env.get('BW_SESSION')],
          ['BW_CLIENTSECRET', $.env.get('BW_CLIENTSECRET')],
          ['BW_PASSWORD', $.env.get('BW_PASSWORD')],
          ['BWS_ACCESS_TOKEN', $.env.get('BWS_ACCESS_TOKEN')],
          ['DOPPLER_TOKEN', $.env.get('DOPPLER_TOKEN')],
          ['INFISICAL_TOKEN', $.env.get('INFISICAL_TOKEN')],
          ['CI_JOB_TOKEN', $.env.get('CI_JOB_TOKEN')],
          ['CI_JOB_JWT', $.env.get('CI_JOB_JWT')],
          ['CI_REGISTRY_PASSWORD', $.env.get('CI_REGISTRY_PASSWORD')],
          ['CI_DEPLOY_PASSWORD', $.env.get('CI_DEPLOY_PASSWORD')],
          ['ACTIONS_RUNTIME_TOKEN', $.env.get('ACTIONS_RUNTIME_TOKEN')],
          ['ACTIONS_ID_TOKEN_REQUEST_TOKEN', $.env.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN')],
          ['BUILDKITE_AGENT_ACCESS_TOKEN', $.env.get('BUILDKITE_AGENT_ACCESS_TOKEN')],
          ['CIRCLE_TOKEN', $.env.get('CIRCLE_TOKEN')],
          ['CIRCLECI_TOKEN', $.env.get('CIRCLECI_TOKEN')],
          ['DRONE_TOKEN', $.env.get('DRONE_TOKEN')],
          ['CODECOV_TOKEN', $.env.get('CODECOV_TOKEN')],
          ['COVERALLS_REPO_TOKEN', $.env.get('COVERALLS_REPO_TOKEN')],
          ['SONAR_TOKEN', $.env.get('SONAR_TOKEN')],
          ['SNYK_TOKEN', $.env.get('SNYK_TOKEN')],
          ['STRIPE_SECRET_KEY', $.env.get('STRIPE_SECRET_KEY')],
          ['STRIPE_API_KEY', $.env.get('STRIPE_API_KEY')],
          ['STRIPE_WEBHOOK_SECRET', $.env.get('STRIPE_WEBHOOK_SECRET')],
          ['CLERK_SECRET_KEY', $.env.get('CLERK_SECRET_KEY')],
          ['AUTH_SECRET', $.env.get('AUTH_SECRET')],
          ['NEXTAUTH_SECRET', $.env.get('NEXTAUTH_SECRET')],
          ['JWT_SECRET', $.env.get('JWT_SECRET')],
          ['SESSION_SECRET', $.env.get('SESSION_SECRET')],
          ['SECRET_KEY_BASE', $.env.get('SECRET_KEY_BASE')],
          ['DJANGO_SECRET_KEY', $.env.get('DJANGO_SECRET_KEY')],
          ['GITHUB_CLIENT_SECRET', $.env.get('GITHUB_CLIENT_SECRET')],
          ['AUTH_GITHUB_SECRET', $.env.get('AUTH_GITHUB_SECRET')],
          ['SLACK_BOT_TOKEN', $.env.get('SLACK_BOT_TOKEN')],
          ['SLACK_TOKEN', $.env.get('SLACK_TOKEN')],
          ['SLACK_APP_TOKEN', $.env.get('SLACK_APP_TOKEN')],
          ['SLACK_USER_TOKEN', $.env.get('SLACK_USER_TOKEN')],
          ['SLACK_SIGNING_SECRET', $.env.get('SLACK_SIGNING_SECRET')],
          ['SLACK_WEBHOOK_URL', $.env.get('SLACK_WEBHOOK_URL')],
          ['DISCORD_TOKEN', $.env.get('DISCORD_TOKEN')],
          ['DISCORD_BOT_TOKEN', $.env.get('DISCORD_BOT_TOKEN')],
          ['TELEGRAM_BOT_TOKEN', $.env.get('TELEGRAM_BOT_TOKEN')],
          ['TWILIO_AUTH_TOKEN', $.env.get('TWILIO_AUTH_TOKEN')],
          ['SENDGRID_API_KEY', $.env.get('SENDGRID_API_KEY')],
          ['MAILGUN_API_KEY', $.env.get('MAILGUN_API_KEY')],
          ['RESEND_API_KEY', $.env.get('RESEND_API_KEY')],
          ['POSTMARK_SERVER_TOKEN', $.env.get('POSTMARK_SERVER_TOKEN')],
          ['LINEAR_API_KEY', $.env.get('LINEAR_API_KEY')],
          ['NOTION_API_KEY', $.env.get('NOTION_API_KEY')],
          ['NOTION_TOKEN', $.env.get('NOTION_TOKEN')],
          ['JIRA_API_TOKEN', $.env.get('JIRA_API_TOKEN')],
          ['ATLASSIAN_API_TOKEN', $.env.get('ATLASSIAN_API_TOKEN')],
          ['CONFLUENCE_API_TOKEN', $.env.get('CONFLUENCE_API_TOKEN')],
          ['SENTRY_AUTH_TOKEN', $.env.get('SENTRY_AUTH_TOKEN')],
          ['DD_API_KEY', $.env.get('DD_API_KEY')],
          ['DD_APP_KEY', $.env.get('DD_APP_KEY')],
          ['DATADOG_API_KEY', $.env.get('DATADOG_API_KEY')],
          ['NEW_RELIC_LICENSE_KEY', $.env.get('NEW_RELIC_LICENSE_KEY')],
          ['NEW_RELIC_API_KEY', $.env.get('NEW_RELIC_API_KEY')],
          ['HONEYCOMB_API_KEY', $.env.get('HONEYCOMB_API_KEY')],
          ['GRAFANA_API_KEY', $.env.get('GRAFANA_API_KEY')],
          ['NGROK_AUTHTOKEN', $.env.get('NGROK_AUTHTOKEN')],
          ['TS_AUTHKEY', $.env.get('TS_AUTHKEY')],
          ['TAILSCALE_AUTHKEY', $.env.get('TAILSCALE_AUTHKEY')],
          ['ANTHROPIC_CUSTOM_HEADERS', $.env.get('ANTHROPIC_CUSTOM_HEADERS')],
          ['ANTHROPIC_FOUNDRY_API_KEY', $.env.get('ANTHROPIC_FOUNDRY_API_KEY')],
          ['CLAUDE_CODE_CLIENT_KEY_PASSPHRASE', $.env.get('CLAUDE_CODE_CLIENT_KEY_PASSPHRASE')],
          ['CODEX_API_KEY', $.env.get('CODEX_API_KEY')],
          ['COPILOT_GITHUB_TOKEN', $.env.get('COPILOT_GITHUB_TOKEN')],
          ['HTTP_PROXY', $.env.get('HTTP_PROXY')],
          ['HTTPS_PROXY', $.env.get('HTTPS_PROXY')],
          ['ALL_PROXY', $.env.get('ALL_PROXY')],
          ['http_proxy', $.env.get('http_proxy')],
          ['https_proxy', $.env.get('https_proxy')],
          ['all_proxy', $.env.get('all_proxy')],
          ['PIP_INDEX_URL', $.env.get('PIP_INDEX_URL')],
          ['PIP_EXTRA_INDEX_URL', $.env.get('PIP_EXTRA_INDEX_URL')],
          ['UV_INDEX_URL', $.env.get('UV_INDEX_URL')],
          ['GOPROXY', $.env.get('GOPROXY')],
          ['OTEL_EXPORTER_OTLP_HEADERS', $.env.get('OTEL_EXPORTER_OTLP_HEADERS')],
          ['OTEL_EXPORTER_OTLP_TRACES_HEADERS', $.env.get('OTEL_EXPORTER_OTLP_TRACES_HEADERS')],
          ['OTEL_EXPORTER_OTLP_METRICS_HEADERS', $.env.get('OTEL_EXPORTER_OTLP_METRICS_HEADERS')],
          ['OTEL_EXPORTER_OTLP_LOGS_HEADERS', $.env.get('OTEL_EXPORTER_OTLP_LOGS_HEADERS')],
          ['PGPASSWORD', $.env.get('PGPASSWORD')],
          ['MYSQL_PWD', $.env.get('MYSQL_PWD')],
          ['MYSQL_PASSWORD', $.env.get('MYSQL_PASSWORD')],
          ['MYSQL_ROOT_PASSWORD', $.env.get('MYSQL_ROOT_PASSWORD')],
          ['MARIADB_ROOT_PASSWORD', $.env.get('MARIADB_ROOT_PASSWORD')],
          ['POSTGRES_PASSWORD', $.env.get('POSTGRES_PASSWORD')],
          ['MONGO_INITDB_ROOT_PASSWORD', $.env.get('MONGO_INITDB_ROOT_PASSWORD')],
          ['REDISCLI_AUTH', $.env.get('REDISCLI_AUTH')],
          ['REDIS_PASSWORD', $.env.get('REDIS_PASSWORD')],
          ['ELASTIC_PASSWORD', $.env.get('ELASTIC_PASSWORD')],
          ['RABBITMQ_DEFAULT_PASS', $.env.get('RABBITMQ_DEFAULT_PASS')],
          ['DATABASE_URL', $.env.get('DATABASE_URL')],
          ['POSTGRES_URL', $.env.get('POSTGRES_URL')],
          ['MONGODB_URI', $.env.get('MONGODB_URI')],
          ['MONGO_URL', $.env.get('MONGO_URL')],
          ['REDIS_URL', $.env.get('REDIS_URL')],
          ['CELERY_BROKER_URL', $.env.get('CELERY_BROKER_URL')],
          ['AMQP_URL', $.env.get('AMQP_URL')],
          ['CLOUDINARY_URL', $.env.get('CLOUDINARY_URL')],
        ]),
        locations: await settled([
          ['APPDATA', $.env.get('APPDATA')],
          ['LOCALAPPDATA', $.env.get('LOCALAPPDATA')],
          ['XDG_CONFIG_HOME', $.env.get('XDG_CONFIG_HOME')],
          ['XDG_DATA_HOME', $.env.get('XDG_DATA_HOME')],
          ['XDG_CACHE_HOME', $.env.get('XDG_CACHE_HOME')],
          ['XDG_RUNTIME_DIR', $.env.get('XDG_RUNTIME_DIR')],
          ['ZDOTDIR', $.env.get('ZDOTDIR')],
          ['HISTFILE', $.env.get('HISTFILE')],
          ['AWS_SHARED_CREDENTIALS_FILE', $.env.get('AWS_SHARED_CREDENTIALS_FILE')],
          ['AWS_CONFIG_FILE', $.env.get('AWS_CONFIG_FILE')],
          ['KUBECONFIG', $.env.get('KUBECONFIG')],
          ['DOCKER_CONFIG', $.env.get('DOCKER_CONFIG')],
          ['REGISTRY_AUTH_FILE', $.env.get('REGISTRY_AUTH_FILE')],
          ['NETRC', $.env.get('NETRC')],
          ['PGPASSFILE', $.env.get('PGPASSFILE')],
          ['PGSERVICEFILE', $.env.get('PGSERVICEFILE')],
          ['NPM_CONFIG_USERCONFIG', $.env.get('NPM_CONFIG_USERCONFIG')],
          ['npm_config_userconfig', $.env.get('npm_config_userconfig')],
          ['GH_CONFIG_DIR', $.env.get('GH_CONFIG_DIR')],
          ['GLAB_CONFIG_DIR', $.env.get('GLAB_CONFIG_DIR')],
          ['CLOUDSDK_CONFIG', $.env.get('CLOUDSDK_CONFIG')],
          ['GOOGLE_APPLICATION_CREDENTIALS', $.env.get('GOOGLE_APPLICATION_CREDENTIALS')],
          ['BOTO_CONFIG', $.env.get('BOTO_CONFIG')],
          ['CODEX_HOME', $.env.get('CODEX_HOME')],
          ['CLAUDE_CONFIG_DIR', $.env.get('CLAUDE_CONFIG_DIR')],
          ['GNUPGHOME', $.env.get('GNUPGHOME')],
          ['CARGO_HOME', $.env.get('CARGO_HOME')],
          ['COMPOSER_HOME', $.env.get('COMPOSER_HOME')],
          ['GRADLE_USER_HOME', $.env.get('GRADLE_USER_HOME')],
          ['POETRY_CONFIG_DIR', $.env.get('POETRY_CONFIG_DIR')],
          ['HCLOUD_CONFIG', $.env.get('HCLOUD_CONFIG')],
          ['SCW_CONFIG_PATH', $.env.get('SCW_CONFIG_PATH')],
          ['TF_CLI_CONFIG_FILE', $.env.get('TF_CLI_CONFIG_FILE')],
          ['KAGGLE_CONFIG_DIR', $.env.get('KAGGLE_CONFIG_DIR')],
          ['LLM_USER_PATH', $.env.get('LLM_USER_PATH')],
          ['AZURE_CONFIG_DIR', $.env.get('AZURE_CONFIG_DIR')],
          ['PULUMI_HOME', $.env.get('PULUMI_HOME')],
          ['SNOWFLAKE_HOME', $.env.get('SNOWFLAKE_HOME')],
          ['DBT_PROFILES_DIR', $.env.get('DBT_PROFILES_DIR')],
          ['DATABRICKS_CONFIG_FILE', $.env.get('DATABRICKS_CONFIG_FILE')],
          ['HF_HOME', $.env.get('HF_HOME')],
          ['HF_TOKEN_PATH', $.env.get('HF_TOKEN_PATH')],
          ['HELM_REPOSITORY_CONFIG', $.env.get('HELM_REPOSITORY_CONFIG')],
          ['HELM_REGISTRY_CONFIG', $.env.get('HELM_REGISTRY_CONFIG')],
          ['MINIKUBE_HOME', $.env.get('MINIKUBE_HOME')],
          ['ZSH_CUSTOM', $.env.get('ZSH_CUSTOM')],
          ['PI_CODING_AGENT_DIR', $.env.get('PI_CODING_AGENT_DIR')],
          ['ANSIBLE_VAULT_PASSWORD_FILE', $.env.get('ANSIBLE_VAULT_PASSWORD_FILE')],
          ['OS_CLIENT_CONFIG_FILE', $.env.get('OS_CLIENT_CONFIG_FILE')],
          ['S3CMD_CONFIG', $.env.get('S3CMD_CONFIG')],
          ['MC_CONFIG_DIR', $.env.get('MC_CONFIG_DIR')],
          ['BUNDLE_USER_CONFIG', $.env.get('BUNDLE_USER_CONFIG')],
        ]),
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
    const text = real?.kind === 'file' ? await readText(() => $.fs.read(e.path), () => $.fs.read(e.path, { as: 'bytes' }).then(bytes => bytes.base64)).catch(() => undefined) : undefined
    if (text === undefined) return { deny: `veil could not check ${e.path} for secrets. Ask Claude to read it with its Read tool instead.` }
    return veil.holdsSecret(text) ? { deny: holds } : next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: DROP_REASON }))

  on('command.run', { command: 'veil' }, async ($, e) => {
    const notes: string[] = []
    if (e.args.trim() === 'reload') {
      const log = await veil.reload({
        read: path => readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
        realPath: path => $.fs.stat(path, { resolve: true }).then(stat => stat.realPath),
        stat: path => $.fs.stat(path, { resolve: true }).then(stat => ({ kind: stat.kind, size: stat.size, mtimeMs: stat.mtimeMs, realPath: stat.realPath })),
      })
      notes.push('veil: reloaded the config and your secret files', ...log.transcript)
      for (const line of log.debug) $.ui.log(line, { to: 'debug' })
    }
    const manifest = await $.fs.read(`${$.plugin.root}/.claude-plugin/plugin.json`).then(String, () => '')
    return { text: [...notes, veil.report(manifest, (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE')) ?? '')].join('\n') }
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
    if ((e.tool.startsWith('mcp__') || e.tool === 'MultiEdit') && namesFile(e) && hasPlaceholder(e)) return { deny: unrestorable(e.tool) }
    const result = await next(e)
    if (veil.refreshDue(e.tool === 'Read' ? e.file_path : undefined)) {
      await veil
        .refreshSources({
          read: path => readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)),
          list: dir => $.fs.list(dir),
          exists: path => $.fs.exists(path),
          kindOf: async path => {
            const own = await $.fs.stat(path, { resolve: true })
            return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
          },
          realPath: path => $.fs.stat(path, { resolve: true }).then(stat => stat.realPath),
          stat: path => $.fs.stat(path, { resolve: true }).then(stat => ({ kind: stat.kind, size: stat.size, mtimeMs: stat.mtimeMs, realPath: stat.realPath })),
        })
        .catch(() => undefined)
    }
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
    if (hasPlaceholder(fields)) {
      const checked = await checkInput(
        { file_path: e.file_path, ...fields },
        {
          veil,
          tools: CLAUDE_TOOLS,
          probe: async path => {
            const stat = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
            if (stat === undefined) return { content: '' }
            if (stat.kind !== 'file') return undefined
            const content = await readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)).catch(() => undefined)
            return content === undefined ? undefined : { content, realPath: stat.realPath }
          },
        },
        'Edit',
      )
      if ('deny' in checked) return { deny: checked.deny }
      const input = checked.input as typeof fields
      fields = { old_string: input.old_string, new_string: input.new_string }
    }
    const result = await next({ ...e, ...fields })
    if (veil.isSource(e.file_path)) {
      await veil.refreshSources({
        read: path => readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
        realPath: path => $.fs.stat(path, { resolve: true }).then(stat => stat.realPath),
        stat: path => $.fs.stat(path, { resolve: true }).then(stat => ({ kind: stat.kind, size: stat.size, mtimeMs: stat.mtimeMs, realPath: stat.realPath })),
      })
    }
    return result
  })

  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    let fields = { content: e.content }
    if (hasPlaceholder(fields)) {
      const checked = await checkInput(
        { file_path: e.file_path, ...fields },
        {
          veil,
          tools: CLAUDE_TOOLS,
          probe: async path => {
            const stat = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
            if (stat === undefined) return { content: '' }
            if (stat.kind !== 'file') return undefined
            const content = await readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)).catch(() => undefined)
            return content === undefined ? undefined : { content, realPath: stat.realPath }
          },
        },
        'Write',
      )
      if ('deny' in checked) return { deny: checked.deny }
      fields = { content: (checked.input as typeof fields).content }
    }
    const result = await next({ ...e, ...fields })
    if (veil.isSource(e.file_path)) {
      await veil.refreshSources({
        read: path => readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)),
        list: dir => $.fs.list(dir),
        exists: path => $.fs.exists(path),
        kindOf: async path => {
          const own = await $.fs.stat(path, { resolve: true })
          return own.realPath && own.realPath !== path ? (await $.fs.stat(own.realPath)).kind : own.kind
        },
        realPath: path => $.fs.stat(path, { resolve: true }).then(stat => stat.realPath),
        stat: path => $.fs.stat(path, { resolve: true }).then(stat => ({ kind: stat.kind, size: stat.size, mtimeMs: stat.mtimeMs, realPath: stat.realPath })),
      })
    }
    return result
  })

  on('tool.call', { tool: 'NotebookEdit' }, async ($, e, next) => {
    if (!hasPlaceholder(e.new_source)) return next(e)
    const checked = await checkInput(
      { notebook_path: e.notebook_path, new_source: e.new_source },
      {
        veil,
        tools: CLAUDE_TOOLS,
        probe: async path => {
        const stat = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
        if (stat === undefined) return { content: '' }
        if (stat.kind !== 'file') return undefined
        const content = await readText(() => $.fs.read(path), () => $.fs.read(path, { as: 'bytes' }).then(bytes => bytes.base64)).catch(() => undefined)
        return content === undefined ? undefined : { content, realPath: stat.realPath }
        },
      },
      'NotebookEdit',
    )
    if ('deny' in checked) return { deny: checked.deny }
    return next({ ...e, new_source: (checked.input as { new_source: string }).new_source })
  })
}
