import type { EditTarget, Veil } from './session.ts'

export type Probe = (path: string) => Promise<EditTarget | undefined>

export type Restorer = {
  readonly veil: Veil
  readonly probe: Probe
  readonly tools: ReadonlySet<string>
}

export type Checked = { readonly input: unknown } | { readonly deny: string }

type Walked = { readonly value: unknown; readonly refused?: string }

export const CLAUDE_TOOLS: ReadonlySet<string> = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit'])
export const PI_TOOLS: ReadonlySet<string> = new Set(['edit', 'write'])
export const OPENCODE_TOOLS: ReadonlySet<string> = new Set(['edit', 'write', 'apply_patch'])
export const PROXY_TOOLS: ReadonlySet<string> = new Set([
  ...CLAUDE_TOOLS, ...PI_TOOLS, ...OPENCODE_TOOLS, 'multiedit', 'write_file', 'search_replace', 'hashline_edit', 'str_replace_editor',
  'str_replace_based_edit_tool', 'developer__text_editor', 'write_to_file', 'replace_in_file', 'apply_diff', 'insert_content',
  'search_and_replace', 'create_new_file', 'edit_existing_file', 'edit_file',
])

export const GEMINI_TOOLS: ReadonlySet<string> = new Set(['replace'])

const PATCH_TOOLS = new Set(['apply_patch'])
const PATH_KEYS = ['file_path', 'filePath', 'path', 'filepath', 'filename', 'target_file', 'targetFile', 'notebook_path', 'absolute_path', 'TargetFile']
const CONTENT_KEYS = new Set([
  'content', 'contents', 'file_text', 'new_string', 'old_string', 'newString', 'oldString', 'new_str', 'old_str', 'newText', 'oldText',
  'new_source', 'edits', 'diff', 'patch', 'patchText', 'input', 'new_content', 'old_content', 'search', 'replace', 'replacement',
])
const EDGE_SPACE = /^[\s\u0085]+|[\s\u0085]+$/g
const PATCH_HEADER = /^\*\*\* (?:Add|Delete|Update) File: (.*)$/
const PATCH_KNOWN = /^\*\*\*[\s\u0085]*(?:Begin Patch|End Patch|End of File)[\s\u0085]*$/
const MOVE_HEADER = /^\*\*\*[\s\u0085]*Move to:/

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined
}

function trimmed(text: string): string {
  return text.replace(EDGE_SPACE, '')
}

export function hasPlaceholder(value: unknown): boolean {
  if (typeof value === 'string') return value.includes('[veil:')
  if (Array.isArray(value)) return value.some(hasPlaceholder)
  const top = record(value)
  return top ? Object.values(top).some(hasPlaceholder) : false
}

const FILE_KEY = /path|file|dest|target|output|location|filename/i

export function namesFile(input: unknown): boolean {
  if (Array.isArray(input)) return input.some(namesFile)
  const top = record(input)
  if (!top) return false
  return Object.entries(top).some(([key, value]) => (typeof value === 'string' && (PATH_KEYS.includes(key) || FILE_KEY.test(key))) || namesFile(value))
}

export function targetPathOf(input: unknown): string | undefined {
  const top = record(input)
  if (!top) return undefined
  const target = targetOf(top, 'tool')
  return target !== undefined && 'path' in target ? target.path : undefined
}

type Target = { readonly path: string } | { readonly refused: string } | undefined

function targetOf(input: Record<string, unknown>, tool: string): Target {
  const paths = [...new Set(PATH_KEYS.flatMap(key => (typeof input[key] === 'string' ? [input[key] as string] : [])))]
  if (paths.length === 0) return undefined
  const [path] = paths
  if (paths.length > 1 || path === undefined) return { refused: `veil cannot tell which file this ${tool} call writes, since it names more than one, so it keeps its placeholders out of it.` }
  if (path === '' || trimmed(path) !== path || path.includes('[veil:')) return { refused: `veil keeps placeholders out of this ${tool} call, because its file name is empty, holds a placeholder, or starts or ends with whitespace.` }
  return { path }
}

function first(...reasons: (string | undefined)[]): string | undefined {
  return reasons.find(reason => reason !== undefined)
}

function restoreText(text: string, path: string, target: EditTarget, veil: Veil): Walked {
  if (!text.includes('[veil:')) return { value: text }
  const restored = veil.restorePlaceholders(text, path, target)
  return restored.refused === undefined ? { value: restored.text } : { value: restored.text, refused: restored.refused }
}

function within(value: unknown, path: string, target: EditTarget, veil: Veil): Walked {
  if (typeof value === 'string') return restoreText(value, path, target, veil)
  if (Array.isArray(value)) {
    const items = value.map(item => within(item, path, target, veil))
    const refused = first(...items.map(item => item.refused))
    const same = items.every((item, index) => item.value === value[index])
    return { value: same ? value : items.map(item => item.value), ...(refused === undefined ? {} : { refused }) }
  }
  const top = record(value)
  if (!top) return { value }
  let changed = false
  let refused: string | undefined
  const out: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(top)) {
    const next = CONTENT_KEYS.has(key) ? within(item, path, target, veil) : { value: item }
    refused = first(refused, next.refused)
    if (next.value !== item) changed = true
    out[key] = next.value
  }
  return { value: changed ? out : value, ...(refused === undefined ? {} : { refused }) }
}

type Section = { path: string | undefined; pinned: boolean; text: string }

export function patchSections(text: string): Section[] {
  const sections: Section[] = [{ path: undefined, pinned: false, text: '' }]
  for (const line of text.split(/(?<=\n)/)) {
    const bare = trimmed(line)
    const last = sections[sections.length - 1]
    const header = line.replace(/\r?\n$/, '').match(PATCH_HEADER)
    if (header) {
      const path = header[1] ?? ''
      sections.push({ path, pinned: path !== '' && trimmed(path) === path, text: line })
    } else if (PATCH_KNOWN.test(bare)) sections.push({ path: undefined, pinned: false, text: line })
    else if (last && bare.startsWith('***')) {
      if (!MOVE_HEADER.test(bare)) sections.push({ path: undefined, pinned: false, text: line })
      else {
        last.pinned = false
        last.text += line
      }
    } else if (last) last.text += line
  }
  return sections
}

async function patch(text: string, restorer: Restorer): Promise<Walked> {
  if (!text.includes('[veil:')) return { value: text }
  const out: string[] = []
  let refused: string | undefined
  for (const section of patchSections(text)) {
    if (!section.text.includes('[veil:')) {
      out.push(section.text)
      continue
    }
    if (section.path === undefined || !section.pinned) {
      refused ??= 'veil keeps placeholders out of a patch section that moves a file, names no single file, or has a header it cannot read. Write the change as a plain edit of one file.'
      out.push(section.text)
      continue
    }
    const target = await restorer.probe(section.path)
    if (!target) {
      refused ??= restorer.veil.unreadable(section.path)
      out.push(section.text)
      continue
    }
    const restored = restorer.veil.restorePlaceholders(section.text, section.path, target)
    refused ??= restored.refused
    out.push(restored.text)
  }
  return { value: out.join(''), ...(refused === undefined ? {} : { refused }) }
}

async function walkPatchTool(input: unknown, restorer: Restorer): Promise<Walked> {
  if (typeof input === 'string') return patch(input, restorer)
  const top = record(input)
  if (!top) return { value: input }
  let changed = false
  let refused: string | undefined
  const out: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(top)) {
    const next = CONTENT_KEYS.has(key) && typeof item === 'string' ? await patch(item, restorer) : { value: item }
    refused = first(refused, next.refused)
    if (next.value !== item) changed = true
    out[key] = next.value
  }
  return { value: changed ? out : input, ...(refused === undefined ? {} : { refused }) }
}

async function walk(input: unknown, restorer: Restorer, tool: string | undefined): Promise<Walked> {
  if (tool === undefined || !restorer.tools.has(tool) || !hasPlaceholder(input)) return { value: input }
  if (PATCH_TOOLS.has(tool)) return walkPatchTool(input, restorer)
  const top = record(input)
  if (!top) return { value: input }
  const target = targetOf(top, tool)
  if (target === undefined) return { value: input, refused: `veil cannot tell which file this ${tool} call writes, so it keeps its placeholders out of it.` }
  if ('refused' in target) return { value: input, refused: target.refused }
  const file = await restorer.probe(target.path)
  if (!file) return { value: input, refused: restorer.veil.unreadable(target.path) }
  return within(input, target.path, file, restorer.veil)
}

export async function restoreInput(input: unknown, restorer: Restorer, tool: string | undefined): Promise<unknown> {
  return (await walk(input, restorer, tool)).value
}

export async function checkInput(input: unknown, restorer: Restorer, tool: string | undefined): Promise<Checked> {
  const walked = await walk(input, restorer, tool)
  return walked.refused === undefined ? { input: walked.value } : { deny: walked.refused }
}

export function unrestorable(tool: string): string {
  return `veil cannot write real values through ${tool}, so it refused this call: it names a file and holds a placeholder, which would be written as is. Use the agent's own file tools for files that hold secrets.`
}

export async function restoreArguments(json: string, restorer: Restorer, tool: string | undefined): Promise<string> {
  if (tool === undefined || !restorer.tools.has(tool) || !json.includes('[veil:')) return json
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return PATCH_TOOLS.has(tool) ? String((await patch(json, restorer)).value) : json
  }
  const restored = await restoreInput(parsed, restorer, tool)
  return restored === parsed ? json : JSON.stringify(restored)
}
