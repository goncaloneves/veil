import { readFile, writeFile } from 'node:fs/promises'

const tag = process.argv[2]
if (!tag || !/^v\d+\.\d+\.\d+/.test(tag)) throw new Error(`expected a release tag such as v1.2.3, got "${tag ?? ''}"`)

const file = new URL('../.claude-plugin/marketplace.json', import.meta.url)
const marketplace = JSON.parse(await readFile(file, 'utf8')) as { plugins: { name: string; source: unknown }[] }
const entry = marketplace.plugins.find(plugin => plugin.name === 'veil')
if (!entry) throw new Error('no veil entry in marketplace.json')
entry.source = { source: 'github', repo: 'goncaloneves/veil', ref: tag }
await writeFile(file, `${JSON.stringify(marketplace, null, 2)}\n`)
console.log(`marketplace pinned to ${tag}`)
