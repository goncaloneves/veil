import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { parseDotenv } from '../src/sources/dotenv.ts'
import { envSecrets } from '../src/sources/env-policy.ts'
import { fishVariables, historySecrets, shellEntries, shellTokens } from '../src/sources/shell.ts'
import { fakeToken, seeded } from './helpers.ts'

const random = seeded(202)
const token = (length = 24) => fakeToken(random, length)
const policy = { secretKeys: [], ignoreKeys: [] }

describe('shell rc files', () => {
  it('reads export, declare -x, fish set -x and PowerShell $env: assignments', () => {
    const [a, b, c, d, e] = [token(), token(), token(), token(), token()]
    const text = [
      'alias ll="ls -l"',
      `export DB_PASS='${a}'`,
      `declare -x API_TOKEN="${b}"`,
      `set -gx SERVICE_SECRET ${c}`,
      `$env:OPENAI_API_KEY = "${d}"`,
      `[Environment]::SetEnvironmentVariable('DEPLOY_TOKEN', '${e}', 'User')`,
      'set -o vi',
      'PS1="%n@%m %~ %# "',
    ].join('\r\n')
    const found = envSecrets(shellEntries(text), '.zshrc', { ...policy, random: false })
    assert.deepEqual(found.map(secret => `${secret.name}=${secret.value}`).sort(), [`DB_PASS=${a}`, `API_TOKEN=${b}`, `SERVICE_SECRET=${c}`, `OPENAI_API_KEY=${d}`, `DEPLOY_TOKEN=${e}`].sort())
  })

  it('never takes command substitutions or variable references as values', () => {
    const literal = token()
    const text = [
      'export DB_PASSWORD="$(op read op://vault/db/password)"',
      'export GITHUB_TOKEN=$(gh auth token)',
      'export API_TOKEN=`cat ~/.token`',
      'export JWT_SECRET="${OTHER_SECRET}"',
      'export SESSION_SECRET=$OTHER',
      'DATABASE_URL=postgres://app:${DB_PASS}@db/app',
      'ONEPASSWORD_TOKEN=op://vault/item/token',
      `export LITERAL_PASSWORD='$(not-a-command)${literal}'`,
      `$env:PS_TOKEN = "$secret"`,
    ].join('\n')
    const found = envSecrets(shellEntries(text), '.bashrc', { ...policy, random: false })
    assert.deepEqual(found.map(secret => secret.name), ['LITERAL_PASSWORD'])
    const envrc = envSecrets(parseDotenv('DB_PASSWORD="$(op read op://vault/db/password)"\nexport DATABASE_URL=postgres://app:$DB_PASS@db/app', { shell: true }), '.envrc', policy)
    assert.deepEqual(envrc, [])
    const dotenv = envSecrets(parseDotenv('CACHE_TOKEN=pa$$word1x\nAPI_SECRET="a$(b"\nDB_PASSWORD=${DB_PASS}\nREDIS_PASSWORD=$REDIS_PASS'), '.env', policy)
    assert.deepEqual(dotenv.map(secret => secret.name), ['CACHE_TOKEN', 'API_SECRET'])
  })

  it('reads exported fish universal variables', () => {
    const value = token()
    const entries = fishVariables(`# This file contains fish universal variable definitions.\nSETUVAR --export NPM_TOKEN:${value}\nSETUVAR fish_greeting:Hello\\x20there\nSETUVAR --export PATHS:/a\\x1e/b\n`)
    assert.deepEqual(entries, [{ key: 'NPM_TOKEN', value, literal: true }, { key: 'fish_greeting', value: 'Hello there', literal: true }])
  })
})

describe('shell history', () => {
  it('reads NAME=value arguments, --from-literal, gh secret bodies and vault logins, and skips value-less or variable flags', () => {
    const t = Array.from({ length: 6 }, () => token())
    const text = [
      `docker run -e POSTGRES_PASSWORD=${t[0]} -e DEBUG=1 postgres`,
      `kubectl create secret generic db --from-literal=password=${t[1]}`,
      `heroku config:set API_TOKEN=${t[2]} -a app`,
      `gh secret set DEPLOY_KEY --body "${t[3]}"`,
      `vault login -method=userpass username=me password=${t[4]}`,
      `cd app && export SERVICE_SECRET=${t[5]}`,
      'gpg --keyserver keys.example --recv-keys 7EA0A9C3F273FCD8',
      'docker login --username me --password-stdin MyRegistry.azurecr.io',
      'gh api --token "$GITHUB_TOKEN" /user',
      'mongosh -u admin -p --authenticationDatabase admin',
      'some-cli --api-key=${API_KEY}',
      `git commit -m "add password 'reset' flow"`,
    ].join('\n')
    assert.deepEqual(historySecrets(text, '.bash_history', policy).map(secret => secret.value).sort(), [...t].sort())
  })

  it('reads URL passwords, header values, aws configure set and cargo login from history', () => {
    const t = Array.from({ length: 7 }, () => token())
    const text = [
      `psql "postgresql://app:${t[0]}@db.example/app"`,
      `git push https://me:${t[1]}@git.example.com/acme/app.git main`,
      `pip install --index-url https://__token__:${t[2]}@pypi.example/simple pkg`,
      `curl -H "Authorization: Bearer ${t[3]}" https://api.example.com`,
      `curl --header 'X-Api-Key: ${t[4]}' https://api.example.com`,
      `aws configure set aws_secret_access_key ${t[5]}`,
      `cargo login ${t[6]}`,
      'curl -H "Authorization: Bearer $TOKEN" https://api.example.com',
      'git push https://me:$GIT_PASS@git.example.com/x.git',
      'aws configure set region eu-west-1',
    ].join('\n')
    const found = historySecrets(text, '.bash_history', policy).map(secret => secret.value)
    for (const value of t) assert.ok(found.includes(value), value)
    assert.ok(!found.some(value => value.includes('$')))
  })

  it('keeps cmd-style %NAME% values in a bash line literal, since bash does not expand them', () => {
    const found = historySecrets('X_PASSWORD=%DB_PASS% ./run.sh', '.bash_history', policy)
    assert.deepEqual(found.map(secret => secret.value), ['%DB_PASS%'])
  })

  it('reads SQL passwords only in SQL statements', () => {
    const [a, b, c] = [token(), token(), token()]
    const text = `CREATE USER app WITH PASSWORD '${a}';\nALTER USER 'root'@'localhost' IDENTIFIED BY '${b}';\nSET PASSWORD FOR 'u'@'h' = '${c}';\necho "the password 'hunter22' is weak"\n`
    assert.deepEqual(historySecrets(text, '.psql_history', policy).map(secret => secret.value).sort(), [a, b, c].sort())
  })

  it('splits commands and keeps quoting', () => {
    assert.deepEqual(
      shellTokens(`A=1 cmd -p'x y' "$HOME" ; next | other`).map(command => command.map(item => [item.text, item.expands])),
      [
        [['A=1', false], ['cmd', false], ['-px y', false], ['$HOME', true]],
        [['next', false]],
        [['other', false]],
      ],
    )
  })

  it('reads assignments, password flags, SQL and redis passwords from bash, zsh, fish and PowerShell history', () => {
    const t = Array.from({ length: 11 }, () => token())
    const text = [
      `: 1700000000:0;export AWS_SECRET_ACCESS_KEY=${t[0]}`,
      `DB_PASSWORD=${t[1]} ./migrate.sh`,
      `mysql -u root -p${t[2]} app`,
      `docker login -u me -p ${t[3]} registry.example.com`,
      `sshpass -p '${t[4]}' ssh host`,
      `curl -u me:${t[5]} https://api.example.com`,
      `some-cli deploy --api-token=${t[6]} --region eu`,
      `psql -c "ALTER USER app WITH PASSWORD '${t[7]}'"`,
      `AUTH ${t[8]}`,
      `- cmd: set -x FISH_TOKEN ${t[9]}`,
      `$cred = ConvertTo-SecureString "${t[10]}" -AsPlainText -Force`,
      'git commit -p',
      'mkdir -p build/out',
      'ssh -p 2222 host',
      'export GITHUB_TOKEN=$(gh auth token)',
    ].join('\n')
    const found = historySecrets(text, '.zsh_history', policy)
    assert.deepEqual(found.map(secret => secret.value).sort(), [...t].sort())
    assert.ok(found.filter(secret => secret.name.startsWith('history/')).every(secret => secret.strong))
    assert.equal(found.find(secret => secret.name === 'DB_PASSWORD')?.strong, true)
  })
})
