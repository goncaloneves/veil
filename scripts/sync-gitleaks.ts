import { readFile, writeFile } from 'node:fs/promises'
import { convertGitleaks, renderRuleSet } from './lib/gitleaks.ts'

const root = new URL('..', import.meta.url)
const pinFile = new URL('gitleaks-version.txt', new URL('scripts/', root))
const output = new URL('src/rules/gitleaks.ts', root)

async function latestTag(): Promise<string> {
  const response = await fetch('https://api.github.com/repos/gitleaks/gitleaks/releases/latest', {
    headers: { accept: 'application/vnd.github+json', 'user-agent': 'veil-sync' },
  })
  if (!response.ok) throw new Error(`GitHub answered ${response.status}`)
  const body = (await response.json()) as { tag_name?: string }
  if (!body.tag_name) throw new Error('no tag_name in the latest release')
  return body.tag_name
}

const args = process.argv.slice(2)
const pinned = (await readFile(pinFile, 'utf8')).trim()
const tag = args.includes('--latest') ? await latestTag() : (args.find(arg => arg.startsWith('v')) ?? pinned)
const url = `https://raw.githubusercontent.com/gitleaks/gitleaks/${tag}/config/gitleaks.toml`
const response = await fetch(url)
if (!response.ok) throw new Error(`${url} answered ${response.status}`)
const { ruleSet, skipped } = convertGitleaks(await response.text(), tag)

await writeFile(output, renderRuleSet(ruleSet))
await writeFile(pinFile, `${tag}\n`)

console.log(`gitleaks ${tag}: ${ruleSet.rules.length} rules, ${ruleSet.allowlists.length} global allowlists`)
for (const { id, reason } of skipped) console.log(`  skipped ${id}: ${reason}`)
if (tag !== pinned) console.log(`updated from ${pinned}`)
