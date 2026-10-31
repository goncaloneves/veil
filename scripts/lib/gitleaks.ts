import { parseToml, type TomlTable, type TomlValue } from '../../src/config/toml.ts'
import type { Allowlist, AllowTarget, Rule, RuleSet } from '../../src/core/types.ts'
import { re2ToJs } from './re2.ts'

export type Conversion = {
  readonly ruleSet: RuleSet
  readonly skipped: readonly { readonly id: string; readonly reason: string }[]
}

const LONG_RUN = /(?<!\\)[A-Za-z0-9_-]{20,}/g

export function defang(pattern: string): string {
  return pattern.replace(LONG_RUN, run => `${run[0]}\\x${run.charCodeAt(1).toString(16).padStart(2, '0')}${run.slice(2)}`)
}

function tables(value: TomlValue | undefined): TomlTable[] {
  if (Array.isArray(value)) return value.filter((item): item is TomlTable => typeof item === 'object' && !Array.isArray(item))
  if (typeof value === 'object' && value !== null) return [value]
  return []
}

function strings(value: TomlValue | undefined): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function convertAllowlist(raw: TomlTable): Allowlist | undefined {
  const hasPaths = strings(raw.paths).length > 0
  const condition = typeof raw.condition === 'string' ? raw.condition.toUpperCase() : 'OR'
  if (hasPaths && condition === 'AND') return undefined
  const patterns = strings(raw.regexes).map(source => defang(re2ToJs(source)))
  const stopwords = strings(raw.stopwords)
  if (patterns.length === 0 && stopwords.length === 0) return undefined
  const target = (raw.regexTarget === 'match' || raw.regexTarget === 'line' ? raw.regexTarget : 'secret') as AllowTarget
  for (const pattern of patterns) new RegExp(pattern)
  return { patterns, stopwords, target }
}

export function convertGitleaks(toml: string, version: string): Conversion {
  const root = parseToml(toml)
  const rules: Rule[] = []
  const skipped: { id: string; reason: string }[] = []
  for (const raw of tables(root.rules)) {
    const id = typeof raw.id === 'string' ? raw.id : 'unknown'
    if (typeof raw.regex !== 'string') {
      skipped.push({ id, reason: 'matches file paths only' })
      continue
    }
    if (typeof raw.path === 'string') {
      skipped.push({ id, reason: 'limited to certain file paths' })
      continue
    }
    try {
      const pattern = defang(re2ToJs(raw.regex))
      new RegExp(pattern, 'gd')
      rules.push({
        id,
        pattern,
        keywords: strings(raw.keywords).map(word => word.toLowerCase()),
        secretGroup: typeof raw.secretGroup === 'number' ? raw.secretGroup : 0,
        entropy: typeof raw.entropy === 'number' ? raw.entropy : 0,
        allowlists: [...tables(raw.allowlist), ...tables(raw.allowlists)].flatMap(list => convertAllowlist(list) ?? []),
      })
    } catch (error) {
      skipped.push({ id, reason: error instanceof Error ? error.message : String(error) })
    }
  }
  const allowlists = [...tables(root.allowlist), ...tables(root.allowlists)].flatMap(list => convertAllowlist(list) ?? [])
  return { ruleSet: { version, rules, allowlists }, skipped }
}

export function renderRuleSet(ruleSet: RuleSet): string {
  return `import type { RuleSet } from '../core/types.ts'\n\nexport const gitleaks: RuleSet = ${JSON.stringify(ruleSet, null, 2)}\n`
}
