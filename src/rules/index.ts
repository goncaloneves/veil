import type { RuleSet } from '../core/types.ts'
import { gitleaks } from './gitleaks.ts'
import { RULE_ALLOWLISTS, VEIL_RULES } from './veil.ts'

export const ruleSet: RuleSet = {
  version: gitleaks.version,
  rules: [
    ...gitleaks.rules.map(rule => {
      const extra = RULE_ALLOWLISTS[rule.id]
      return extra ? { ...rule, allowlists: [...rule.allowlists, ...extra] } : rule
    }),
    ...VEIL_RULES.map(rule => ({ ...rule, own: true })),
  ],
  allowlists: gitleaks.allowlists,
}
