#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import pkg from '../../package.json' with { type: 'json' }
import { STARTER_CONFIG, configPaths } from '../config/config.ts'
import { Masker } from '../core/masker.ts'
import { loadState, maskerSettings, type VeilHost, type VeilState } from '../engine.ts'
import { report, shortPath } from '../report.ts'
import { ruleSet } from '../rules/index.ts'
import { nodeFs, nodeHost, writeNewFile } from './node-host.ts'
import { atLeast } from './versions.ts'

const HELP = `veil ${pkg.version}: masks your secrets before your coding agent's model sees them

Usage:
  veil scan [file ...]      print files (or stdin) with secrets masked
  veil sources              list the secret files veil reads (names and counts, never values)
  veil config [path|show|init]
                            print the config file's path, the settings in effect, or create one
  veil doctor               check the setup: config, sources, rules, agent integrations
  veil init [--dry-run]     install the Claude Code plugin from the veil marketplace
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
  return Buffer.concat(chunks).toString('utf8')
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
  const files = args.filter(arg => !arg.startsWith('--'))
  const host = nodeHost()
  const current = await state(host)
  const instance = masker(current, { known: !args.includes('--no-known'), rules: !args.includes('--no-rules') })
  const inputs = files.length > 0 ? await Promise.all(files.map(async file => ({ file, text: await readFile(file, 'utf8') }))) : [{ file: '-', text: await readStdin() }]
  let found = 0
  const results = inputs.map(({ file, text }) => {
    const masked = instance.mask(text)
    found += masked.hits.length
    return { file, masked }
  })
  if (args.includes('--json')) {
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
    const names = current.loaded.secrets.filter(secret => secret.source === file.path).map(secret => secret.name)
    console.log(`${shortPath(file.path, host.home)} (${file.kind}): ${names.length > 0 ? names.join(', ') : 'no values'}`)
  }
  for (const error of current.loaded.errors) console.error(`could not read ${shortPath(error.path, host.home)}: ${error.message}`)
  for (const warning of current.warnings) console.error(`warning: ${warning}`)
  return 0
}

async function config(action: string | undefined): Promise<number> {
  const host = nodeHost()
  const paths = configPaths({ home: host.home, platform: host.platform, veilConfig: host.veilConfig, xdgConfigHome: host.xdgConfigHome })
  if (action === 'path' || action === undefined) {
    const current = await state(host)
    console.log(current.configPath ?? `${paths[0]} (not created; defaults in effect)`)
    return 0
  }
  if (action === 'show') {
    const current = await state(host)
    console.log(JSON.stringify(current.config, null, 2))
    for (const warning of current.warnings) console.error(`warning: ${warning}`)
    return 0
  }
  if (action === 'init') {
    const target = paths[0] ?? `${host.home}/.config/veil/config.toml`
    console.log((await writeNewFile(target, STARTER_CONFIG)) ? `Created ${target}` : `${target} already exists`)
    return 0
  }
  console.error(`unknown config action "${action}"`)
  return 2
}

function run(command: string, args: readonly string[]): { ok: boolean; out: string } {
  const result = spawnSync(command, args, { encoding: 'utf8' })
  return { ok: result.status === 0, out: `${result.stdout ?? ''}${result.stderr ?? ''}` }
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
  const where = run('sh', ['-c', 'command -v claude']).out.trim()
  if (atLeast(found, CLAUDE_MINIMUM)) console.log(`claude code: ${found} (${where})`)
  else {
    problems++
    console.log(`claude code: ${found} at ${where} is older than ${CLAUDE_MINIMUM.join('.')}, which veil needs; update it or put a newer claude first on PATH`)
  }
  const plugins = run('claude', ['plugin', 'list'])
  console.log(`plugin: ${/veil@veil/.test(plugins.out) ? 'installed' : 'not installed (run: veil init)'}`)
  return problems > 0 ? 1 : 0
}

function init(args: readonly string[]): number {
  const steps: [string, string[]][] = [
    ['claude', ['plugin', 'marketplace', 'add', MARKETPLACE]],
    ['claude', ['plugin', 'install', 'veil@veil']],
  ]
  for (const [command, rest] of steps) {
    console.log(`$ ${command} ${rest.join(' ')}`)
    if (args.includes('--dry-run')) continue
    const result = run(command, rest)
    process.stdout.write(result.out)
    if (!result.ok && !/already/i.test(result.out)) return 1
  }
  if (!args.includes('--dry-run')) console.log('Done. Start a new Claude Code session, or run /reload-plugins in an open one.')
  return 0
}

async function main(argv: readonly string[]): Promise<number> {
  const [command, ...rest] = argv
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
      return init(rest)
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
