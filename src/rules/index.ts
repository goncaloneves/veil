import type { RuleSet } from '../core/types.ts'
import { gitleaks } from './gitleaks.ts'
import { VEIL_RULES } from './veil.ts'

export const ruleSet: RuleSet = {
  version: gitleaks.version,
  rules: [...gitleaks.rules, ...VEIL_RULES],
  allowlists: gitleaks.allowlists,
}
