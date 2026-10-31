export type Block = { readonly type: string; readonly [field: string]: unknown }

export const WITHHELD = '[veil withheld this content: it could not be checked for secrets]'

function mapText(blocks: readonly Block[], change: (text: string) => string): Block[] {
  return blocks.map(block => (block.type === 'text' && typeof block.text === 'string' ? { ...block, text: change(block.text) } : block))
}

export function rewriteBlocks(blocks: readonly Block[], change: (text: string) => string): Block[] | undefined {
  let changed = false
  const out = blocks.map(block => {
    if (block.type === 'text' && typeof block.text === 'string') {
      const text = change(block.text)
      if (text === block.text) return block
      changed = true
      return { ...block, text }
    }
    if (block.type === 'tool_result') {
      if (typeof block.content === 'string') {
        const content = change(block.content)
        if (content === block.content) return block
        changed = true
        return { ...block, content }
      }
      if (Array.isArray(block.content)) {
        const before = block.content as Block[]
        const after = mapText(before, change)
        if (after.every((item, index) => item === before[index] || item.text === before[index]?.text)) return block
        changed = true
        return { ...block, content: after }
      }
    }
    return block
  })
  return changed ? out : undefined
}

export function withheldBlocks(blocks: readonly Block[]): Block[] {
  return rewriteBlocks(blocks, () => WITHHELD) ?? [...blocks]
}
