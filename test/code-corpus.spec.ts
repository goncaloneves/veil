import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { compileRules, findRuleSpans } from '../src/core/rules.ts'
import { ruleSet } from '../src/rules/index.ts'
import { fake, fakeToken, seeded } from './helpers.ts'

const compiled = compileRules(ruleSet)

function hitsIn(text: string): string[] {
  return findRuleSpans(text, compiled).map(span => `${span.label.replace(/#.*$/, '')}: ${text.slice(span.start, span.end)}`)
}

const CODE: Record<string, readonly string[]> = {
  go: [
    'password := os.Getenv("DB_PASSWORD")',
    'secret, err := base64.StdEncoding.DecodeString(raw)',
    'tempPasswd = pbkdf2.Key([]byte(passwd), []byte(salt), 10000, 50, sha256.New)',
    '\tauth := Authentication{\n',
    'if gotPass := r.Header.Get("X-Pass"); gotPass != want {',
    'cfg.Password = viper.GetString("database.password")',
    'mustChangePassword := ctx.FormBool("must_change_password")',
    'func (u *User) SetPassword(passwd string) error {',
  ],
  ruby: [
    'password: ENV.fetch("DB_PASSWORD")',
    'user.password = params[:password]',
    'secret = Rails.application.credentials.secret_key_base',
    'if (user_info = ldap.bind_as(base: base, filter: filter, password: password))',
    'def reset_password(token:, password:)',
  ],
  rust: [
    'let password = env::var("DB_PASSWORD")?;',
    'let secret = config.secret.clone();',
    'fn verify(password: &str, hash: &str) -> bool {',
    'password: Option<String>,',
  ],
  python: [
    'password = models.CharField(_("password"), max_length=128)',
    'session_key=self._get_or_create_session_key(),',
    'with self.subTest(password=password):',
    'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]',
    'secret = settings.SECRET_KEY.encode()',
    'f"pass={len(passed)} fail={len(failed)}"',
  ],
  typescript: [
    'export function auth(username: string, password: string): string {',
    'async login(email?: string, password?: string): Promise<void> {',
    "const elPassword = document.querySelector('#password')!;",
    'where: { id: In(ids), password: Not(IsNull()) },',
    'const pass = (expectation: string): Result => ({',
    'export async function login(page, username = env.E2E_USER, password = env.E2E_PASSWD) {',
    'secretAccessKey: accessKey,',
  ],
  terraform: [
    'password = var.db_password',
    'master_password = random_password.master.result',
    'manage_master_user_password = true',
  ],
  helm: [
    'password: {{ .Values.auth.password | quote }}',
    'secretKeyRef:',
    'existingSecret: {{ include "app.fullname" . }}',
  ],
  shell: [
    'PASSWORD="$(cat /run/secrets/db)"',
    'export PGPASSWORD="${POSTGRES_PASSWORD}"',
    "'--store-password=[password for storefronts]:store-password:' \\",
  ],
  markup: [
    '<tr><th>Password1:</th><td><ul class="errorlist">',
    '"auth.forgot_password": "パスワードをお忘れですか",',
    "'password' => env('DB_PASSWORD', ''),",
  ],
}

describe('real code in many languages', () => {
  for (const [language, lines] of Object.entries(CODE)) {
    it(`leaves ${language} code readable`, () => {
      for (const line of lines) assert.deepEqual(hitsIn(line), [], line)
    })
  }

  it('still masks credentials written in those languages', () => {
    const random = seeded(120)
    const value = `${fakeToken(random, 12)}7q`
    const symbol = fake.symbolPassword(random)
    for (const line of [
      `password := "${value}"`,
      `config.password = '${symbol}'`,
      `let password = "${value}";`,
      `PASSWORD = "${value}"`,
      `const password = '${symbol}';`,
      `password = "${value}"`,
      `password: ${value}`,
      `export DB_PASSWORD='${symbol}'`,
      `'password' => '${symbol}',`,
      `    [password] => ${value}`,
      `Server=db;Password=${value};`,
    ]) assert.ok(hitsIn(line).length > 0, line)
  })
})
