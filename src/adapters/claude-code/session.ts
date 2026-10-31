import { Veil, WITHHELD } from '../../session.ts'
import { rewriteBlocks, withheldBlocks, type Block } from './blocks.ts'

export type { Block }
export type { EditTarget, SessionFs as AdapterFs, StartLog } from '../../session.ts'
export { NOTE, WITHHELD } from '../../session.ts'

export const NOTE_ID = 'veil:note'

export const DROP_REASON = 'veil could not check this for secrets, so it was held back.'

const MEDIA_PATH = /\.(?:png|jpe?g|gif|webp|bmp|ico|heic|tiff?|pdf|mp3|m4a|wav|ogg|mp4|mov|webm)$/i

export function isMediaPath(path: string): boolean {
  return MEDIA_PATH.test(path)
}

export class VeilSession extends Veil {
  maskBlocks(blocks: readonly Block[]): Block[] | undefined {
    return rewriteBlocks(blocks, this.maskWithin(this.newDeadline()))
  }

  withheld(blocks: readonly Block[]): Block[] {
    return withheldBlocks(blocks, WITHHELD)
  }
}
