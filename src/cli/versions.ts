export function atLeast(version: string, minimum: readonly number[]): boolean {
  const parts = version.split('.').map(part => Number.parseInt(part, 10))
  for (let i = 0; i < minimum.length; i++) {
    const have = parts[i] ?? 0
    const need = minimum[i] ?? 0
    if (have !== need) return have > need
  }
  return true
}
