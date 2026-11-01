export type Secret = {
  readonly name: string
  readonly value: string
  readonly source: string
  readonly strong?: boolean
  readonly sources?: readonly string[]
  readonly projectName?: boolean
}

export type AllowTarget = 'secret' | 'match' | 'line'

export type Allowlist = {
  readonly patterns: readonly string[]
  readonly stopwords: readonly string[]
  readonly target: AllowTarget
}

export type Rule = {
  readonly id: string
  readonly pattern: string
  readonly keywords: readonly string[]
  readonly secretGroup: number
  readonly entropy: number
  readonly allowlists: readonly Allowlist[]
  readonly multiline?: boolean
  readonly continuation?: string
  readonly own?: boolean
}

export type RuleSet = {
  readonly version: string
  readonly rules: readonly Rule[]
  readonly allowlists: readonly Allowlist[]
}

export type Encoding = 'base64' | 'url' | 'json' | 'lines'

export type HitKind = 'known' | 'rule'

export type Hit = {
  readonly start: number
  readonly end: number
  readonly label: string
  readonly kind: HitKind
}

export type Masked = {
  readonly text: string
  readonly hits: readonly Hit[]
}

