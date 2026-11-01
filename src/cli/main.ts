#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { readFile, stat } from 'node:fs/promises'
import type { AddressInfo } from 'node:net'
import { resolve } from 'node:path'
import { parseArgs } from 'node:util'
import pkg from '../../package.json' with { type: 'json' }
import { STARTER_CONFIG } from '../config/config.ts'
import { Masker } from '../core/masker.ts'
import { decodeBytes, looksMisdecoded, readText } from '../core/text.ts'
import { configCandidates, loadState, maskerSettings, type VeilHost, type VeilState } from '../engine.ts'
import { report, shortPath } from '../report.ts'
import { ruleSet } from '../rules/index.ts'
import { PROXY_TOOLS } from '../restore.ts'
import { Veil } from '../session.ts'
import { nodeProbe, nodeSessionFs, projectRoot } from '../node/fs.ts'
import { DEFAULT_PORT, DEFAULT_ROUTES, startProxy } from '../proxy/server.ts'
import { ADAPTER_TARGETS, adapterBundle, adapterPath, bundleName, writeAdapter } from './install.ts'
import { nodeFs, nodeHost, writeNewFile } from './node-host.ts'
import { atLeast } from './versions.ts'

const HELP = `veil ${pkg.version}: masks your secrets before your coding agent's model sees them

Usage:
  veil scan [file ...]      print files (or stdin) with secrets masked
  veil sources              list the secret files veil reads and the names of their values, never the values
  veil config [path|show|init]
                            print the config file's path, the settings in effect, or create one
  veil doctor               check the setup: config, sources, rules, and the Claude Code version and plugin
  veil proxy [--port 8345] [--root dir] [--route name=url ...]
                            mask what an agent sends to its model, through a local proxy
  veil init [claude|pi|opencode|kilo] [--dry-run] [--from file]
                            install veil into an agent (Claude Code when none is named)
  veil version              print the version

Options for scan:
  --json                    print the hits (labels and offsets, never values) as JSON
  --no-known                pattern rules only
  --no-rules                known values only

https://github.com/goncaloneves/veil`

const MARKETPLACE = 'goncaloneves/veil'
const CLAUDE_MINIMUM = [2, 1, 287] as const

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
  const bytes = Buffer.concat(chunks)
  const text = bytes.toString('utf8')
  if (text.startsWith('\uFEFF')) return text.slice(1)
  return looksMisdecoded(text) ? decodeBytes(new Uint8Array(bytes)) : text
}

function readInput(file: string): Promise<string> {
  return readText(
    () => readFile(file, 'utf8'),
    () => readFile(file).then(bytes => bytes.toString('base64')),
  )
}

async function state(host: VeilHost): Promise<VeilState> {
  return loadState(nodeFs, host)
}

function masker(current: VeilState, options: { known: boolean; rules: boolean }): Masker {
  const settings = maskerSettings(current, ruleSet)
  return new Masker({
    ...settings,
    secrets: options.known ? settings.secrets : [],
    ruleSet: options.rules ? settings.ruleSet : { version: 'off', rules: [], allowlists: [] },
    salt: crypto.randomUUID(),
  })
}

async function scan(args: readonly string[]): Promise<number> {
  const { values, positionals: files } = parseArgs({ args: [...args], options: { json: { type: 'boolean' }, 'no-known': { type: 'boolean' }, 'no-rules': { type: 'boolean' } }, allowPositionals: true, strict: true })
  const host = nodeHost()
  const current = await state(host)
  const instance = masker(current, { known: values['no-known'] !== true, rules: values['no-rules'] !== true })
  const inputs = files.length > 0 ? await Promise.all(files.map(async file => ({ file, text: await readInput(file) }))) : [{ file: '-', text: await readStdin() }]
  let found = 0
  const results = inputs.map(({ file, text }) => {
    const masked = instance.mask(text)
    found += masked.hits.length
    return { file, masked }
  })
  if (values.json === true) {
    const json = results.map(({ file, masked }) => ({ file, hits: masked.hits.map(({ start, end, label, kind }) => ({ start, end, label, kind })) }))
    process.stdout.write(`${JSON.stringify(json, null, 2)}\n`)
  } else for (const { masked } of results) process.stdout.write(masked.text)
  return found > 0 ? 1 : 0
}

async function sources(): Promise<number> {
  const host = nodeHost()
  const current = await state(host)
  if (current.loaded.files.length === 0) console.log('No secret files found.')
  for (const file of current.loaded.files) {
    const names = current.loaded.secrets.filter(secret => (secret.sources ?? [secret.source]).includes(file.path)).map(secret => secret.name)
    console.log(`${shortPath(file.path, host.home)} (${file.kind}): ${names.length > 0 ? names.join(', ') : 'no values'}`)
  }
  for (const error of current.loaded.errors) console.error(`could not read ${shortPath(error.path, host.home)}: ${error.message}`)
  for (const warning of current.warnings) console.error(`warning: ${warning}`)
  return 0
}

async function config(action: string | undefined): Promise<number> {
  const host = nodeHost()
  const { paths, notes } = await configCandidates(nodeFs, host)
  const target = paths[0] ?? `${host.home}/.config/veil/config.toml`
  if (action === 'path' || action === undefined) {
    for (const note of notes) console.error(`warning: ${note}`)
    const current = await state(host)
    console.log(current.configPath ?? `${target} (${(await nodeFs.exists(target).catch(() => false)) ? 'not a regular file' : 'not created'}; defaults in effect)`)
    return 0
  }
  if (action === 'show') {
    const current = await state(host)
    console.log(JSON.stringify(current.config, null, 2))
    for (const warning of current.warnings) console.error(`warning: ${warning}`)
    return 0
  }
  if (action === 'init') {
    for (const note of notes) console.error(`warning: ${note}`)
    console.log((await writeNewFile(target, STARTER_CONFIG)) ? `Created ${target}` : `${target} already exists`)
    return 0
  }
  console.error(`unknown config action "${action}"`)
  return 2
}

const WINDOWS = process.platform === 'win32'

function run(command: string, args: readonly string[]): { ok: boolean; out: string } {
  const result = WINDOWS ? spawnSync('cmd.exe', ['/d', '/s', '/c', command, ...args], { encoding: 'utf8' }) : spawnSync(command, args, { encoding: 'utf8' })
  return { ok: result.status === 0, out: `${result.stdout ?? ''}${result.stderr ?? ''}` }
}

function locate(command: string): string {
  const found = WINDOWS ? run('where', [command]) : run('sh', ['-c', `command -v ${command}`])
  return found.ok ? (found.out.split(/\r?\n/)[0] ?? '').trim() : 'unknown location'
}

async function doctor(): Promise<number> {
  const host = nodeHost()
  const current = await state(host)
  const instance = masker(current, { known: true, rules: true })
  console.log(report(instance, current, { version: pkg.version, home: host.home }).split('\n').filter(line => !line.startsWith('masked this session')).join('\n'))
  let problems = current.warnings.length
  const version = run('claude', ['--version'])
  if (!version.ok) {
    console.log('claude code: not found on PATH')
    return 1
  }
  const found = version.out.match(/\d+\.\d+\.\d+/)?.[0] ?? 'unknown'
  const where = locate('claude')
  if (atLeast(found, CLAUDE_MINIMUM)) console.log(`claude code: ${found} (${where})`)
  else {
    problems++
    console.log(`claude code: ${found} at ${where} is older than ${CLAUDE_MINIMUM.join('.')}, which veil needs; update it or put a newer claude first on PATH`)
  }
  const plugins = run('claude', ['plugin', 'list'])
  console.log(`plugin: ${/veil@veil/.test(plugins.out) ? 'installed' : 'not installed (run: veil init)'}`)
  return problems > 0 ? 1 : 0
}

async function init(args: readonly string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args: [...args], options: { 'dry-run': { type: 'boolean' }, from: { type: 'string' } }, allowPositionals: true, strict: true })
  if (positionals.length > 1) {
    console.error(`veil init takes one agent at a time; got ${positionals.join(', ')}`)
    return 2
  }
  const target = positionals[0] ?? 'claude'
  const dryRun = values['dry-run'] === true
  if (values.from === '') {
    console.error('--from needs the path of an adapter bundle')
    return 2
  }
  if (target === 'claude' && values.from !== undefined) {
    console.error(`--from installs a local adapter bundle, so it needs ${ADAPTER_TARGETS.slice(0, -1).join(', ')} or ${ADAPTER_TARGETS.at(-1)} as the agent`)
    return 2
  }
  if (target !== 'claude') {
    const adapter = ADAPTER_TARGETS.find(name => name === target)
    if (!adapter) {
      console.error(`veil init takes claude, ${ADAPTER_TARGETS.slice(0, -1).join(', ')} or ${ADAPTER_TARGETS.at(-1)}; got "${target}"`)
      return 2
    }
    const path = adapterPath(adapter, process.env, nodeHost().home)
    const from = values.from
    console.log(`${from ? `copy ${from}, without a checksum` : `download ${bundleName(adapter)} v${pkg.version}`} → ${path}`)
    if (dryRun) return 0
    await writeAdapter(path, await adapterBundle(adapter, pkg.version, from))
    console.log(`Done. Start a new ${adapter === 'pi' ? 'Pi' : adapter === 'kilo' ? 'Kilo Code' : 'opencode'} session to load veil.`)
    return 0
  }
  const steps: [string, string[]][] = [
    ['claude', ['plugin', 'marketplace', 'add', MARKETPLACE]],
    ['claude', ['plugin', 'install', 'veil@veil']],
  ]
  for (const [command, rest] of steps) {
    console.log(`$ ${command} ${rest.join(' ')}`)
    if (dryRun) continue
    const result = run(command, rest)
    process.stdout.write(result.out)
    if (!result.ok && !/already/i.test(result.out)) return 1
  }
  if (!dryRun) console.log('Done. Start a new Claude Code session, or run /reload-plugins in an open one.')
  return 0
}


const BASE_URLS: readonly [string, string][] = [
  ['ANTHROPIC_BASE_URL', 'anthropic'],
  ['OPENAI_BASE_URL', 'openai/v1'],
  ['GOOGLE_GEMINI_BASE_URL', 'gemini'],
  ['GROK_BASE_URL', 'xai/v1'],
]

const HARNESS_GUIDE = 'https://github.com/goncaloneves/veil/blob/main/docs/HARNESSES.md'

function routeTarget(target: string): string | undefined {
  try {
    const url = new URL(target)
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.username === '' && url.password === '' && url.search === '' && url.hash === '' ? target : undefined
  } catch {
    return undefined
  }
}

async function proxy(args: readonly string[]): Promise<number> {
  const { values } = parseArgs({ args: [...args], options: { port: { type: 'string' }, root: { type: 'string' }, route: { type: 'string', multiple: true } }, strict: true })
  const port = Number(values.port ?? DEFAULT_PORT)
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    console.error('--port takes a number from 0 to 65535')
    return 2
  }
  const routes: Record<string, string> = { ...DEFAULT_ROUTES }
  for (const spec of values.route ?? []) {
    const cut = spec.indexOf('=')
    const name = spec.slice(0, cut)
    const target = routeTarget(spec.slice(cut + 1))
    if (cut < 1 || !/^[a-z0-9][a-z0-9-]*$/.test(name) || target === undefined) {
      console.error(`--route takes name=url with an http or https URL and no credentials, such as work=https://llm.example.com/api; ${cut < 0 ? 'this one has no =url' : cut === 0 ? 'this one has no name' : `check the route named "${spec.slice(0, cut)}"`}`)
      return 2
    }
    routes[name] = target
  }
  const base = process.cwd()
  const root = values.root === undefined ? await projectRoot(base) : resolve(values.root)
  if (!(await stat(root).then(info => info.isDirectory(), () => false))) {
    console.error(`--root ${root} is not a folder`)
    return 2
  }
  const host = nodeHost(root, root)
  const veil = new Veil({ budgetMs: 5_000, cache: true })
  const log = await veil.start(nodeSessionFs, host)
  for (const line of log.transcript) console.error(line)
  const server = await startProxy({
    port,
    routes,
    veil,
    restorer: { veil, probe: nodeProbe(base, root), tools: PROXY_TOOLS },
    beforeRequest: async () => {
      if (veil.refreshDue()) await veil.refreshSources(nodeSessionFs).catch(() => undefined)
    },
    log: line => console.error(line),
  })
  const address = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  console.log(`veil proxy on ${address} for ${shortPath(root, host.home)}; start your agent in ${shortPath(base, host.home)}`)
  console.log('Point your agent at a route. Some agents read these:')
  for (const [name, route] of BASE_URLS) console.log(`  ${name}=${address}/${route}`)
  console.log(`routes: ${Object.keys(routes).map(name => `/${name}`).join(' ')}`)
  console.log(`setup for each agent: ${HARNESS_GUIDE}`)
  await new Promise<void>(done => {
    const stop = () => server.close(() => done())
    process.once('SIGINT', stop)
    process.once('SIGTERM', stop)
  })
  return 0
}

const COMMANDS = new Set(['scan', 'sources', 'config', 'doctor', 'init', 'proxy', 'version'])

async function main(argv: readonly string[]): Promise<number> {
  const [command, ...rest] = argv
  if (command !== undefined && COMMANDS.has(command) && (rest.includes('--help') || rest.includes('-h'))) {
    console.log(HELP)
    return 0
  }
  switch (command) {
    case 'scan':
      return scan(rest)
    case 'sources':
      return sources()
    case 'config':
      return config(rest[0])
    case 'doctor':
      return doctor()
    case 'init':
      return await init(rest)
    case 'proxy':
      return proxy(rest)
    case 'version':
    case '--version':
    case '-v':
      console.log(pkg.version)
      return 0
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP)
      return 0
    default:
      console.error(`unknown command "${command}"\n\n${HELP}`)
      return 2
  }
}

process.exitCode = await main(process.argv.slice(2)).catch(error => {
  console.error(error instanceof Error ? error.message : String(error))
  return 2
})
