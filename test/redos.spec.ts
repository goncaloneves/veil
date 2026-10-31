import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ENCODINGS } from '../src/config/config.ts'
import { MaskTimeout, Masker } from '../src/core/masker.ts'
import { compileRules, findRuleSpans } from '../src/core/rules.ts'
import type { Rule } from '../src/core/types.ts'
import { gitleaks } from '../src/rules/gitleaks.ts'
import { ruleSet } from '../src/rules/index.ts'
import { VEIL_RULES } from '../src/rules/veil.ts'
import { keyHeader } from './helpers.ts'

const DEADLINE = 300
const MARGIN = 250
const SIZE = 24_000

function fill(unit: string, size = SIZE): string {
  return unit.repeat(Math.ceil(size / unit.length)).slice(0, size)
}

function adversarial(keyword: string): string[] {
  return [
    fill(keyword),
    fill(`${keyword}a`),
    fill(`${keyword} `),
    fill(`${keyword}-`),
    fill(`${keyword}_`),
    fill(`${keyword}="`),
    fill(`${keyword}:\n>`),
    `${keyword}${'a'.repeat(SIZE)}`,
    `${keyword}\n${' '.repeat(SIZE)}!`,
    `${keyword}=${'a'.repeat(SIZE)}!`,
    `key="${'a'.repeat(SIZE)}${keyword}`,
    `${fill(`${keyword} `, 16_384)}\n${fill(`${keyword} `, 16_384)}`,
  ]
}

function bounded(run: () => void): number {
  const started = performance.now()
  try {
    run()
  } catch (error) {
    assert.ok(error instanceof MaskTimeout, String(error))
  }
  return performance.now() - started
}

function stressRule(rule: Rule, extra: readonly string[] = []): void {
  const compiled = compileRules({ version: 'test', rules: [rule], allowlists: [] })
  const texts = [...rule.keywords.slice(0, 4).flatMap(adversarial), ...extra]
  for (const text of texts) {
    const elapsed = bounded(() => findRuleSpans(text, compiled, Date.now() + DEADLINE))
    assert.ok(elapsed < DEADLINE + MARGIN, `${rule.id} took ${Math.round(elapsed)} ms on ${JSON.stringify(text.slice(0, 40))}`)
  }
}

const REVIEWED: Record<string, string[]> = {
  'rsa-private-parameters-xml': [`InverseQ\n<D>${' '.repeat(4000)}`],
  'private-key-block': [`${keyHeader()}\n${' '.repeat(40_000)}!`, fill(`${keyHeader()} `)],
  'password-xml-attribute': [`key="${'a'.repeat(30_000)}pw`],
  'registry-login-password': ['docker login '.repeat(1000)],
  'redis-auth': [`auth\n>${' '.repeat(30_000)}x`],
}

describe('every veil rule stays inside its deadline on adversarial text', () => {
  for (const rule of VEIL_RULES) {
    it(rule.id, () => stressRule(rule, REVIEWED[rule.id] ?? []))
  }
})

describe('the slowest gitleaks rules stay inside their deadline', () => {
  for (const id of ['okta-access-token', 'sumologic-access-id', 'cisco-meraki-api-key', 'cohere-api-token', 'privateai-api-token', 'curl-auth-user', 'curl-auth-header', 'generic-api-key', 'private-key']) {
    it(id, () => {
      const rule = gitleaks.rules.find(item => item.id === id)
      assert.ok(rule, id)
      const compiled = compileRules({ version: 'test', rules: [rule], allowlists: [] })
      for (const keyword of rule.keywords.slice(0, 2)) {
        for (const text of [fill(keyword, 32_768), fill(`${keyword}-`, 32_768), fill(`${keyword} `, 32_768), `${fill(`${keyword} `, 16_384)}\n${fill(`${keyword} `, 16_384)}`]) {
          const elapsed = bounded(() => findRuleSpans(text, compiled, Date.now() + DEADLINE))
          assert.ok(elapsed < DEADLINE + MARGIN, `${id} took ${Math.round(elapsed)} ms on ${JSON.stringify(text.slice(0, 20))}`)
        }
      }
    })
  }
})

describe('the masker keeps its deadline on the reviewed inputs', () => {
  const m = new Masker({ secrets: [], ruleSet, minLength: 8, encodings: ENCODINGS, salt: 'redos-salt' })
  const inputs = {
    'rsa parameters': `InverseQ\n<D>${' '.repeat(4000)}`,
    'private key padding': `${keyHeader()}\n${' '.repeat(40_000)}!`,
    'xml attribute': `key="${'a'.repeat(30_000)}pw`,
    'registry login': 'docker login '.repeat(1000),
    'three long gitleaks lines': `${fill('oktaa', 32_768)}\n${fill('sumo-', 32_768)}\n${fill('cohere_', 32_768)}`,
    'redis prompt': `auth\n>${' '.repeat(30_000)}x`,
    'two long curl lines': `${fill('curl ', 16_384)}\n${fill('curl ', 16_384)}`,
    'base64 key prefix': fill('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t', 32_768),
  }
  for (const [name, text] of Object.entries(inputs)) {
    it(name, () => {
      const elapsed = bounded(() => m.mask(text, { deadline: Date.now() + 1000 }))
      assert.ok(elapsed < 1000 + MARGIN + 100, `${name} took ${Math.round(elapsed)} ms`)
    })
  }
})
