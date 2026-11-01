import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'
import { DEFAULT_CONFIG } from '../src/config/config.ts'
import { CONTEXT_MIN, LINE_MIN, TOKEN_MIN } from '../src/core/known.ts'
import { DEFAULT_PORT, DEFAULT_ROUTES } from '../src/proxy/server.ts'
import { CLAUDE_TOOLS, GEMINI_TOOLS, PROXY_TOOLS } from '../src/restore.ts'
import { KNOWN_ONLY_LENGTH, REFRESH_MS } from '../src/session.ts'
import { MAX_TEXT } from '../src/sources/load.ts'

const root = fileURLToPath(new URL('..', import.meta.url))
const DOCS = ['README.md', 'INSTALL.md', 'SECURITY.md', 'CONTRIBUTING.md', 'AGENTS.md', 'CHANGELOG.md', 'docs/HARNESSES.md', 'docs/ARCHITECTURE.md']
const read = (path: string) => readFileSync(join(root, path), 'utf8')
const doc = Object.fromEntries(DOCS.map(path => [path, read(path)]))
const cli = read('src/cli/main.ts')

function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s/g, '-')
}

function anchors(text: string): Set<string> {
  return new Set([...text.matchAll(/^#{1,6}\s+(.+)$/gm)].map(match => slug(match[1] ?? '')))
}

function section(text: string, heading: string): string {
  const start = text.indexOf(`\n### ${heading}\n`)
  assert.ok(start >= 0, heading)
  const end = text.indexOf('\n### ', start + 1)
  return text.slice(start, end < 0 ? undefined : end)
}

describe('the docs', () => {
  it('link only to files and headings that exist', () => {
    for (const [path, text] of Object.entries(doc)) {
      const targets = [...text.matchAll(/\]\(([^)\s]+)\)|(?:href|src|srcset)="([^"]+)"/g)].map(match => match[1] ?? match[2] ?? '')
      for (const target of targets) {
        if (/^(?:https?:|mailto:)/.test(target)) continue
        const [file = '', anchor] = target.split('#')
        const full = file === '' ? join(root, path) : join(root, dirname(path), file)
        assert.ok(existsSync(full), `${path} links to ${target}`)
        if (anchor !== undefined) assert.ok(anchors(readFileSync(full, 'utf8')).has(anchor), `${path} links to #${anchor} in ${file || path}`)
      }
    }
  })

  it('list exactly the proxy routes veil has, with their upstreams', () => {
    const rows = [...doc['docs/HARNESSES.md']!.matchAll(/^\| ((?:`\/[a-z]+`(?:, )?)+) \| (.+) \|$/gm)]
    const listed = rows.flatMap(row => [...(row[1] ?? '').matchAll(/`\/([a-z]+)`/g)].map(match => match[1] ?? ''))
    assert.deepEqual(listed.sort(), Object.keys(DEFAULT_ROUTES).sort())
    for (const row of rows) {
      const upstream = row[2]?.match(/^`(https?:\/\/[^`]+)`/)?.[1]
      if (upstream) assert.equal(DEFAULT_ROUTES[(row[1] ?? '').slice(2, -1)], upstream)
    }
  })

  it('point every agent at a route veil has, on its port', () => {
    for (const [path, text] of Object.entries(doc)) {
      for (const match of text.matchAll(/(?:127\.0\.0\.1:(\d+)|`P)\/([a-z]+)/g)) {
        if (match[1] !== undefined) assert.equal(Number(match[1]), DEFAULT_PORT, path)
        assert.ok(match[2] && match[2] in DEFAULT_ROUTES, `${path}: /${match[2]}`)
      }
    }
  })

  it('name only file tools veil really restores into', () => {
    const harnesses = doc['docs/HARNESSES.md']!
    const named = harnesses.slice(harnesses.indexOf('by their exact names'), harnesses.indexOf("and Gemini CLI's `replace`"))
    const tools = [...named.matchAll(/`([A-Za-z_]+)`/g)].map(match => match[1] ?? '')
    assert.ok(tools.length >= 8)
    for (const tool of tools) assert.ok(PROXY_TOOLS.has(tool), tool)
    assert.ok(GEMINI_TOOLS.has('replace') && !PROXY_TOOLS.has('replace'))
    for (const tool of ['Edit', 'Write', 'NotebookEdit']) assert.ok(CLAUDE_TOOLS.has(tool), tool)
    assert.match(doc['README.md']!, /Claude Code's own Edit, Write and NotebookEdit tools/)
  })

  it('quote the masking thresholds the code uses', () => {
    const readme = doc['README.md']!
    const minLength = DEFAULT_CONFIG.mask.minLength
    assert.equal(readme.split(`Values of ${minLength} characters or more are masked everywhere`).length, 3)
    assert.equal(readme.split(`a random-looking ${TOKEN_MIN} or ${minLength - 1}`).length, 2)
    assert.match(readme, new RegExp(`looks random \\(${TOKEN_MIN} or ${minLength - 1} characters\\)`))
    assert.match(readme, new RegExp(`from ${CONTEXT_MIN} characters`))
    assert.match(readme, new RegExp(`lines of ${LINE_MIN} characters or more`))
    assert.match(readme, new RegExp(`each line of ${LINE_MIN} characters or more`))
    assert.match(readme, new RegExp(`min_length = ${minLength}\\b`))
    assert.match(readme, new RegExp(`project_depth = ${DEFAULT_CONFIG.sources.projectDepth}\\b`))
    assert.match(doc['docs/ARCHITECTURE.md']!, new RegExp(`\`min_length\` \\(${minLength}\\)`))
    assert.match(doc['docs/ARCHITECTURE.md']!, new RegExp(`${LINE_MIN} characters or more`))
  })

  it('quote the refresh interval, file cap, base64 limit and proxy budget the code uses', () => {
    const seconds = `every ${REFRESH_MS / 1000} seconds`
    for (const path of ['README.md', 'SECURITY.md', 'docs/ARCHITECTURE.md']) assert.ok(doc[path]!.includes(seconds), path)
    assert.match(doc['docs/ARCHITECTURE.md']!, new RegExp(`over ${MAX_TEXT / 1024 / 1024} MiB`))
    assert.match(doc['docs/ARCHITECTURE.md']!, new RegExp(`over ${KNOWN_ONLY_LENGTH / 1_000_000} MB`))
    assert.match(cli, /new Veil\(\{ budgetMs: 5_000/)
    assert.match(doc['docs/HARNESSES.md']!, /for up to five seconds/)
  })

  it('quote the Claude Code and Node versions veil checks for', () => {
    const minimum = cli.match(/CLAUDE_MINIMUM = \[(\d+), (\d+), (\d+)\]/)?.slice(1, 4).join('.')
    assert.ok(minimum)
    for (const path of ['README.md', 'INSTALL.md', 'CONTRIBUTING.md']) assert.ok(doc[path]!.includes(`Claude Code ${minimum} or later`), path)
    const node = (JSON.parse(read('package.json')) as { engines: { node: string } }).engines.node.replace('>=', '')
    for (const path of ['INSTALL.md', 'CONTRIBUTING.md']) assert.ok(doc[path]!.includes(`Node ${node} or later`), path)
  })
})

describe('the Grok Build setup', () => {
  const harnesses = doc['docs/HARNESSES.md']!

  it('send Grok Build through models_base_url, the custom inference URL its own docs name, with an API key', () => {
    const grok = section(harnesses, 'Grok Build')
    assert.match(grok, /models_base_url = "http:\/\/127\.0\.0\.1:8345\/xai\/v1"/)
    assert.match(grok, /XAI_API_KEY/)
    assert.doesNotMatch(grok, /xai_api_base_url/)
  })
})
