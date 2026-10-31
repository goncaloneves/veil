import type { Masker } from './core/masker.ts'
import { isInside, normalizePath } from './core/paths.ts'
import type { VeilState } from './engine.ts'

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

export function shortPath(path: string, home: string, platform = 'linux'): string {
  const base = normalizePath(home)
  if (!home || /^(?:[A-Za-z]:)?\/$/.test(base) || !isInside(path, home, platform) || normalizePath(path).length === base.length) return path
  return `~${normalizePath(path).slice(base.length)}`
}

export function report(masker: Masker, state: VeilState, options: { readonly version?: string; readonly home?: string } = {}): string {
  const home = state.home || options.home || ''
  const platform = state.platform ?? 'linux'
  const short = (path: string) => shortPath(path, home, platform)
  const info = masker.info
  const lines: string[] = []
  const known = state.loaded.secrets.length
  lines.push(`veil${options.version ? ` ${options.version}` : ''}: masking ${plural(known, 'known value')} and ${plural(info.rules, 'pattern rule')} (gitleaks ${info.ruleSetVersion})`)
  lines.push(`config: ${state.configPath ? short(state.configPath) : 'defaults'}; restore: ${state.config.restore.mode}`)
  if (state.loaded.files.length > 0) {
    lines.push('sources:')
    for (const file of state.loaded.files) lines.push(`  ${short(file.path)} (${file.kind}): ${plural(file.count, 'value')}`)
  } else lines.push('sources: none found')
  const stats = masker.vault.stats().sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
  if (stats.length === 0) lines.push('masked this session: nothing yet')
  else {
    const total = stats.reduce((sum, stat) => sum + stat.count, 0)
    lines.push(`masked this session: ${plural(stats.length, 'value')}, ${plural(total, 'time')}`)
    for (const stat of stats.slice(0, 20)) lines.push(`  [veil:${stat.label}] ×${stat.count}`)
    if (stats.length > 20) lines.push(`  and ${stats.length - 20} more`)
  }
  const unread = state.loaded.errors.filter(error => error.quiet)
  if (unread.length > 0) {
    lines.push('not readable, left to the pattern rules:')
    for (const error of unread.slice(0, 20)) lines.push(`  ${short(error.path)}: ${error.message}`)
    if (unread.length > 20) lines.push(`  and ${unread.length - 20} more`)
  }
  for (const warning of state.warnings) lines.push(`warning: ${warning}`)
  if (info.failedRules.length > 0) lines.push(`warning: ${plural(info.failedRules.length, 'rule')} failed to compile: ${info.failedRules.join(', ')}`)
  return lines.join('\n')
}
