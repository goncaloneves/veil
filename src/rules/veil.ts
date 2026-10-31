import type { Rule } from '../core/types.ts'

export const VEIL_RULES: readonly Rule[] = [
  {
    id: 'url-credentials',
    pattern: "\\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:\\/\\/[^\\s:\\/@'\"`]{1,64}:([^\\s\\/@'\"`]{3,200})@[^\\s\\/'\"`]+",
    keywords: ['://'],
    secretGroup: 1,
    entropy: 0,
    allowlists: [
      {
        patterns: ['^\\$\\{[^}]*\\}$', '^\\$[A-Za-z_][A-Za-z0-9_]*$', '^<[^>]*>$', '^\\{\\{.*\\}\\}$', '^[*x.]+$', '^%[A-Za-z_]+%$'],
        stopwords: ['password', 'passwd', 'changeme', 'example', 'placeholder', 'your_'],
        target: 'secret',
      },
    ],
  },
]
