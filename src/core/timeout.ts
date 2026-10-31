export class MaskTimeout extends Error {
  constructor() {
    super('masking ran out of time')
  }
}

export function checkDeadline(deadline: number): void {
  if (Date.now() > deadline) throw new MaskTimeout()
}
