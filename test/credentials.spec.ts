import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { base64Encode } from '../src/core/encoding.ts'
import {
  configParser,
  parseAwsCredentials,
  parseBundlerConfig,
  parseClaudeJson,
  parseDockerConfig,
  parseGitCredentials,
  parsePgpass,
  parseGitConfig,
  parseKubeConfig,
  parseNetrc,
  parseNpmrc,
  parseOpenvpnAuth,
  parseSqliteTokens,
  parseSvnAuth,
  parseXmlCredentials,
  parseYarnrc,
  rawSecret,
  treeParser,
} from '../src/sources/credentials.ts'
import { gpgKeyParts, jwkSecrets, keyFileSecrets, privateKeyBlocks, puttyKeys } from '../src/sources/keys.ts'
import { parseDotenv } from '../src/sources/dotenv.ts'
import { envSecrets } from '../src/sources/env-policy.ts'
import { envEntrySecrets, keyedLeaves } from '../src/sources/tree.ts'
import { PRINTABLE, fake, fakeToken, seeded } from './helpers.ts'

const random = seeded(101)
const token = (length = 32) => fakeToken(random, length)
const values = (found: readonly { value: string }[]) => found.map(secret => secret.value)

describe('agent credential files', () => {
  it('reads Claude Code OAuth tokens from .credentials.json', () => {
    const access = ['sk', 'ant', 'oat01', token(80)].join('-')
    const refresh = ['sk', 'ant', 'ort01', token(80)].join('-')
    const text = JSON.stringify({ claudeAiOauth: { accessToken: access, refreshToken: refresh, expiresAt: 1, scopes: ['user:inference'], subscriptionType: 'max' } })
    const found = treeParser('claude')(text, '.credentials.json')
    assert.deepEqual(values(found), [access, refresh])
    assert.ok(found.every(secret => secret.strong))
  })

  it('reads OpenCode, Codex and Gemini CLI auth files', () => {
    const [access, refresh, key] = [token(), token(), token()]
    const opencode = treeParser('opencode', { keys: ['access', 'refresh'] })(JSON.stringify({ anthropic: { type: 'oauth', access, refresh, expires: 1 }, openai: { type: 'api', key } }), 'auth.json')
    assert.deepEqual(values(opencode), [access, refresh, key])
    const [apiKey, idToken, codexAccess] = [token(), fake.jwt(random, 40), token()]
    const codex = treeParser('codex')(JSON.stringify({ OPENAI_API_KEY: apiKey, tokens: { id_token: idToken, access_token: codexAccess, account_id: 'acct-1234' } }), 'auth.json')
    assert.deepEqual(values(codex), [apiKey, idToken, codexAccess])
    const gemini = treeParser('gemini')(JSON.stringify({ access_token: `ya29.${token(60)}`, refresh_token: `1//0${token(50)}`, token_type: 'Bearer', expiry_date: 1 }), 'oauth_creds.json')
    assert.equal(gemini.length, 2)
  })

  it('reads MCP server env, headers, URL query secrets and secret flags, and skips references', () => {
    const [envToken, bearer, query, flag] = [token(), token(), token(), token()]
    const text = JSON.stringify({
      mcpServers: {
        github: { command: 'npx', args: ['server', '--api-key', flag, '--port', '8080'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: envToken, DEBUG: 'true', OTHER_TOKEN: '${OTHER_TOKEN}' } },
        remote: { url: `https://mcp.example.com/sse?token=${query}&mode=fast`, headers: { Authorization: `Bearer ${bearer}`, 'X-Trace': 'abc' } },
      },
    })
    const found = treeParser('mcp')(text, '.mcp.json')
    assert.deepEqual(values(found).sort(), [envToken, `Bearer ${bearer}`, bearer, query, flag].sort())
  })

  it('reads only the API key and MCP servers from ~/.claude.json', () => {
    const [apiKey, envToken, projectToken] = [token(), token(), token()]
    const text = JSON.stringify({
      primaryApiKey: apiKey,
      oauthAccount: { emailAddress: 'me@example.com', accountUuid: token() },
      mcpServers: { a: { env: { SERVICE_TOKEN: envToken } } },
      projects: { '/repo': { mcpServers: { b: { env: { DB_PASSWORD: projectToken } } }, history: [{ display: token() }] } },
    })
    assert.deepEqual(values(parseClaudeJson(text, '.claude.json')), [apiKey, envToken, projectToken])
  })
})

describe('cloud credential files', () => {
  it('reads AWS config profiles and the SSO and CLI caches, never the access key id', () => {
    const [secret, session] = [token(40), token(60)]
    const config = parseAwsCredentials(`[profile dev]\r\nregion = eu-west-1\r\naws_access_key_id = ${fake.awsKeyId(random)}\r\naws_secret_access_key = ${secret}\r\n[sso-session corp]\r\nsso_start_url = https://corp.example/start\r\n`, 'config')
    assert.deepEqual(config.map(s => [s.name, s.value]), [['aws/dev/aws_secret_access_key', secret]])
    const sso = treeParser('aws')(JSON.stringify({ startUrl: 'https://x', accessToken: token(), refreshToken: `aorAAAAA${token(60)}`, clientSecret: token(), clientId: token(), region: 'us-east-1' }), 'sso.json')
    assert.equal(sso.length, 3)
    const cli = treeParser('aws')(JSON.stringify({ Credentials: { AccessKeyId: fake.awsKeyId(random), SecretAccessKey: secret, SessionToken: session, Expiration: '2026-01-01' } }), 'cli.json')
    assert.deepEqual(values(cli), [secret, session])
  })

  it('reads Google ADC, legacy boto, and tokens inside the gcloud SQLite stores', () => {
    const [clientSecret, refresh] = [token(24), `1//0${token(60)}`]
    const adc = treeParser('gcloud')(JSON.stringify({ client_id: '123-abc.apps.googleusercontent.com', client_secret: clientSecret, refresh_token: refresh, type: 'authorized_user' }), 'adc.json')
    assert.deepEqual(values(adc), [clientSecret, refresh])
    const boto = treeParser('boto', {}, 'keyed')(`[Credentials]\ngs_oauth2_refresh_token = ${refresh}\n`, '.boto')
    assert.deepEqual(values(boto), [refresh])
    const access = `ya29.${token(120)}`
    const credentials = `SQLite format 3\u0000\u0000\u0002\u0017me@example.com${JSON.stringify({ client_secret: clientSecret, refresh_token: refresh })}`
    assert.deepEqual(values(parseSqliteTokens(credentials, 'credentials.db')).sort(), [clientSecret, refresh].sort())
    const tokens = `SQLite format 3\u0000\u0000\u0003\u0015\u0081me@example.com${access}2026-10-31 12:00:00${fake.jwt(random, 40)}`
    assert.deepEqual(values(parseSqliteTokens(tokens, 'access_tokens.db')), [access])
  })

  it('reads Azure CLI token caches and service principals', () => {
    const [secret, refresh] = [token(), token(120)]
    const msal = JSON.stringify({ AccessToken: { k: { secret, credential_type: 'AccessToken' } }, RefreshToken: { r: { secret: refresh } }, Account: { a: { username: 'me@example.com' } } })
    assert.deepEqual(values(treeParser('azure')(msal, 'msal_token_cache.json')), [secret, refresh])
  })

  it('reads unprefixed CLI tokens: hcloud, linode, scw, Vercel, Netlify, Wrangler, Railway, Terraform, Kaggle, Pulumi', () => {
    const t = Array.from({ length: 10 }, () => token())
    const hcloud = treeParser('hcloud', {}, 'toml')(`active_context = "a"\n[[contexts]]\nname = "a"\ntoken = "${t[0]}"\n`, 'cli.toml')
    const linode = treeParser('linode', {}, 'keyed')(`[DEFAULT]\ndefault-user = me\n\n[me]\ntoken = ${t[1]}\nregion = us-east\n`, 'linode-cli')
    const scw = treeParser('scw', {}, 'keyed')(`profiles:\n  default:\n    secret_key: ${t[2]}\n    default_region: fr-par\n`, 'config.yaml')
    const vercel = treeParser('vercel')(JSON.stringify({ token: t[3] }), 'auth.json')
    const netlify = treeParser('netlify')(JSON.stringify({ telemetryDisabled: true, users: { u1: { id: 'u1', auth: { token: t[4] } } } }), 'config.json')
    const wrangler = treeParser('wrangler', {}, 'toml')(`oauth_token = "${t[5]}"\nexpiration_time = "2026-01-01T00:00:00Z"\nrefresh_token = "${t[6]}"\n`, 'default.toml')
    const terraform = treeParser('terraform')(JSON.stringify({ credentials: { 'tfe.example.com': { token: t[7] } } }), 'credentials.tfrc.json')
    const kaggle = treeParser('kaggle')(JSON.stringify({ username: 'me', key: t[8] }), 'kaggle.json')
    const pulumi = treeParser('pulumi')(JSON.stringify({ current: 'https://api.pulumi.com', accessTokens: { 'https://api.pulumi.com': t[9] } }), 'credentials.json')
    assert.deepEqual([hcloud, linode, scw, vercel, netlify, wrangler, terraform, kaggle, pulumi].flatMap(values), t)
  })

  it('reads every key in llm keys.json but not its note, and API keys in Continue configs', () => {
    const [openai, mistral, continueKey] = [token(), token(), token()]
    const llm = treeParser('llm', { all: true })(JSON.stringify({ '// Note': 'This file stores secret API credentials. Do not share!', openai, mistral }), 'keys.json')
    assert.deepEqual(values(llm), [openai, mistral])
    const cont = treeParser('continue', {}, 'keyed')(`models:\n  - name: GPT\n    provider: openai\n    apiKey: ${continueKey}\n`, 'config.yaml')
    assert.deepEqual(values(cont), [continueKey])
  })
})

describe('registry credentials', () => {
  it('reads cargo, gem and composer tokens and strips Bearer and Basic schemes', () => {
    const [cargo, alt, gem, ghToken, composer, pass] = [token(), token(), token(), token(), token(), token(16)]
    const cargoFound = treeParser('cargo', {}, 'toml')(`[registry]\ntoken = "${cargo}"\n[registries.alt]\ntoken = "Bearer ${alt}"\n`, 'credentials.toml')
    assert.deepEqual(values(cargoFound), [cargo, `Bearer ${alt}`, alt])
    const gemFound = treeParser('gem', { all: true }, 'keyed')(`---\n:rubygems_api_key: rubygems_${gem}\nhttps://rubygems.pkg.github.com/acme: Bearer ${ghToken}\n`, 'credentials')
    assert.deepEqual(values(gemFound), [`rubygems_${gem}`, `Bearer ${ghToken}`, ghToken])
    const composerFound = treeParser('composer', { all: true, skip: ['username'] })(JSON.stringify({ 'http-basic': { 'repo.example.com': { username: 'me', password: pass } }, 'github-oauth': { 'github.com': composer } }), 'auth.json')
    assert.deepEqual(values(composerFound), [pass, composer])
  })

  it('reads Maven and NuGet passwords, skipping property references', () => {
    const [maven, master, nuget, apiKey] = [token(16), token(20), token(16), token(40)]
    const settings = `<settings><servers><server><id>corp</id><username>me</username><password>${maven}</password></server><server><id>env</id><password>\${env.PASS}</password></server></servers></settings>`
    assert.deepEqual(parseXmlCredentials(settings, 'settings.xml').map(s => [s.name, s.value]), [['xml/corp/password', maven]])
    assert.deepEqual(values(parseXmlCredentials(`<settingsSecurity><master>{${master}}</master></settingsSecurity>`, 's')), [`{${master}}`])
    const config = `<configuration><packageSources><add key="feed" value="https://feed.example/v3/index.json" /></packageSources><packageSourceCredentials><feed><add key="Username" value="me" /><add key="ClearTextPassword" value="${nuget}" /></feed></packageSourceCredentials><apikeys><add key="https://www.nuget.org/api/v2/package" value="${apiKey}" /></apikeys></configuration>`
    assert.deepEqual(parseXmlCredentials(config, 'NuGet.Config').map(s => [s.name, s.value]), [['xml/feed/ClearTextPassword', nuget], ['xml/apikeys/https://www.nuget.org/api/v2/package', apiKey]])
  })

  it('reads gradle, poetry, pypirc and pip URL passwords, yarn and npm auth', () => {
    const [gradle, poetry, pypi, pip, yarnToken, yarnPass, npmPass] = [token(), token(), token(16), token(16), token(), token(12), token(12)]
    assert.deepEqual(values(treeParser('gradle', {}, 'keyed')(`org.gradle.jvmargs=-Xmx2g\nsigning.password=${gradle}\nsigning.keyId=ABCD1234\n`, 'gradle.properties')), [gradle])
    assert.deepEqual(values(treeParser('poetry', {}, 'toml')(`[http-basic.corp]\nusername = "me"\npassword = "${poetry}"\n`, 'auth.toml')), [poetry])
    assert.deepEqual(values(treeParser('pypirc', {}, 'keyed')(`[distutils]\nindex-servers = corp\n[corp]\nrepository = https://pypi.example\nusername = me\npassword = ${pypi}\n`, '.pypirc')), [pypi])
    assert.deepEqual(values(treeParser('pip', {}, 'keyed')(`[global]\nindex-url = https://me:${pip}@pypi.example/simple\n`, 'pip.conf')), [pip])
    const yarn = parseYarnrc(`npmRegistries:\n  "//npm.example.com":\n    npmAuthToken: ${yarnToken}\n    npmAuthIdent: "me:${yarnPass}"\n`, '.yarnrc.yml')
    assert.deepEqual(values(yarn), [yarnToken, `me:${yarnPass}`, yarnPass])
    assert.deepEqual(values(parseNpmrc(`//r.example/:_auth=${base64Encode(`me:${npmPass}`)}\n`, '.npmrc')), [base64Encode(`me:${npmPass}`), npmPass])
  })
})

describe('kube, git, netrc, svn and raw files', () => {
  it('reads extended kubeconfig fields, exec env values and JSON kubeconfigs', () => {
    const [access, secret, envToken, json] = [token(), token(), token(), token()]
    const yaml = `users:\n- name: oidc\n  user:\n    auth-provider:\n      config:\n        access-token: ${access}\n        client-secret: ${secret}\n        client-id: kubernetes\n- name: aws\n  user:\n    exec:\n      env:\n      - name: AWS_PROFILE\n        value: prod\n      - name: VAULT_TOKEN\n        value: ${envToken}\n`
    assert.deepEqual(parseKubeConfig(yaml, 'config').map(s => [s.name, s.value]), [['kube/oidc/access-token', access], ['kube/oidc/client-secret', secret], ['kube/aws/env/VAULT_TOKEN', envToken]])
    const fromJson = parseKubeConfig(JSON.stringify({ users: [{ name: 'u', user: { 'client-key-data': json, 'client-certificate-data': token() } }] }), 'config')
    assert.deepEqual(values(fromJson), [json])
  })

  it('reads git token-only userinfo, remote passwords and extra headers, and skips plain user names', () => {
    const [ghToken, pass, basicPass] = [fake.githubPat(random), token(16), token(16)]
    const basic = base64Encode(`x-access-token:${basicPass}`)
    const text = `[url "https://${ghToken}@github.com/"]\n\tinsteadOf = https://github.com/\n[remote "origin"]\n\turl = https://me:${pass}@git.example.com/repo.git\n[remote "plain"]\n\turl = https://goncalo@git.example.com/repo.git\n[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic ${basic}\n`
    assert.deepEqual(values(parseGitConfig(text, '.git/config')), [ghToken, pass, `basic ${basic}`, basic, basicPass])
  })

  it('treats a netrc account as secret only when it is not a plain name', () => {
    const [pass, account] = [token(16), token(16)]
    const found = parseNetrc(`machine a.example login me password ${pass} account billing-team\nmachine b.example login me password ${pass}x account ${account}`, 'netrc')
    assert.deepEqual(found.map(s => [s.name, s.strong === true]), [['netrc/a.example', true], ['netrc/b.example', true], ['netrc/b.example/account', false]])
  })

  it('reads svn simple auth files and openvpn auth files', () => {
    const pass = token(16)
    assert.deepEqual(values(parseSvnAuth(`K 8\npasstype\nV 6\nsimple\nK 8\npassword\nV ${pass.length}\n${pass}\nK 15\nsvn:realmstring\nV 4\nrepo\nEND\n`, 'svn')), [pass])
    assert.deepEqual(values(parseOpenvpnAuth(`me\n${pass}\n`, 'auth.txt')), [pass])
  })

  it('reads raw secret files whole, private keys inside them, and skips certificates', () => {
    const value = token(40)
    assert.deepEqual(rawSecret('secret/db-password')(`${value}\n`, '/run/secrets/db-password').map(s => [s.name, s.value, s.strong]), [['secret/db-password', value, true]])
    assert.deepEqual(values(rawSecret('secret/short')('pw12\n', '/run/secrets/short')), ['pw12'])
    assert.deepEqual(rawSecret('secret/cert')(['-----BEGIN', 'CERTIFICATE-----\nAAAA\n-----END', 'CERTIFICATE-----'].join(' '), 'ca.crt'), [])
    const key = fake.privateKey(random)
    assert.deepEqual(values(rawSecret('secret/tls.key')(key, 'tls.key')), [key])
    assert.deepEqual(values(rawSecret('secret/dockerconfigjson')(JSON.stringify({ auths: { 'r.example': { auth: base64Encode(`me:${value}`) } } }), '.dockerconfigjson')), [base64Encode(`me:${value}`), value])
  })
})

describe('private key formats', () => {
  it('reads PGP private key blocks', () => {
    const body = Array.from({ length: 4 }, () => token(64)).join('\n')
    const begin = ['-----BEGIN PGP', 'PRIVATE KEY BLOCK-----'].join(' ')
    const end = ['-----END PGP', 'PRIVATE KEY BLOCK-----'].join(' ')
    const block = `${begin}\n\n${body}\n${end}`
    assert.deepEqual(values(privateKeyBlocks(`noise\n${block}\n`, 'gpg', 'f')), [block])
  })

  it('reads PuTTY private lines, GnuPG s-expression members and private JWK members', () => {
    const lines = Array.from({ length: 3 }, () => token(64))
    const ppk = `PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 1\n${token(64)}\nPrivate-Lines: 3\n${lines.join('\n')}\nPrivate-MAC: ${fake.hex(random, 64)}\n`
    assert.deepEqual(values(puttyKeys(ppk, 'ssh/id.ppk', 'f')), [lines.join('\n')])
    assert.deepEqual(values(keyFileSecrets(ppk, 'ssh/id.ppk', 'f')), [lines.join('\n')])
    const d = fake.hex(random, 128).toUpperCase()
    const sexp = `Created: 20240101T000000\nKey: (private-key (rsa (n #00${fake.hex(random, 64)}#)(e #010001#)(d #${d}#)))\n`
    assert.deepEqual(values(gpgKeyParts(sexp, 'gpg/k', 'f')), [d])
    const jwk = JSON.stringify({ kty: 'RSA', n: token(64), e: 'AQAB', d: token(64), p: token(32), q: token(32), dp: token(32), dq: token(32), qi: token(32) })
    assert.equal(jwkSecrets(jwk, 'jwk', 'f').length, 6)
    assert.deepEqual(jwkSecrets(JSON.stringify({ kty: 'RSA', n: token(64), e: 'AQAB' }), 'jwk', 'f'), [])
    const rsaparams = JSON.stringify({ d: token(64), dp: token(32), dq: token(32), exponent: 'AQAB', inverseQ: token(32), modulus: token(64), p: token(32), q: token(32) })
    assert.equal(jwkSecrets(rsaparams, 'runner', 'f').length, 6)
  })
})

describe('references and placeholders', () => {
  it('never takes variable names or references as values', () => {
    const codex = treeParser('codex', {}, 'toml')('[model_providers.azure]\nname = "Azure"\nenv_key = "AZURE_OPENAI_API_KEY"\nquery_params = { api-version = "2025-04-01" }\n', 'config.toml')
    assert.deepEqual(codex, [])
    const opencode = treeParser('opencode')(JSON.stringify({ provider: { anthropic: { options: { apiKey: '{env:ANTHROPIC_API_KEY}' } }, other: { options: { apiKey: '{file:~/.secrets/key}' } } } }), 'opencode.json')
    assert.deepEqual(opencode, [])
    const yaml = configParser('config', 'yaml')(`services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: $DB_PASS\n      REDIS_PASSWORD: \${REDIS_PASS:-x}\n`, 'docker-compose.yml')
    assert.deepEqual(yaml, [])
    assert.deepEqual(treeParser('bunfig', {}, 'toml')('[install.scopes]\nacme = { token = "$npm_token", url = "https://npm.example" }\n', 'bunfig.toml'), [])
    assert.deepEqual(treeParser('mcp')(JSON.stringify({ mcpServers: { a: { env: { API_TOKEN: '%API_TOKEN%', OTHER_TOKEN: '$env:OTHER_TOKEN' }, headers: { Authorization: 'Bearer ${TOKEN}' } } } }), 'mcp.json'), [])
    assert.deepEqual(treeParser('x', {}, 'keyed')('api_key_env_var: OPENAI_API_KEY\ntoken_env: GH_TOKEN\n', 'x.yaml'), [])
  })

  it('never loads placeholder values, even under strong names', () => {
    const entries = ['YOUR_API_KEY_HERE', '<your-anthropic-key>', 'CHANGE_ME', 'changeme', `sk_test_${'X'.repeat(24)}`, 'xxx', '********', 'sk-...', '[secret]', 'your-openai-key'].map(value => ({ key: 'DB_PASSWORD', value }))
    assert.deepEqual(envSecrets(entries, '.env', { secretKeys: [], ignoreKeys: [] }), [])
    assert.deepEqual(treeParser('x')(JSON.stringify({ password: 'CHANGE_ME', token: '<token>', apiKey: 'xxxxxxxxxxxx' }), 'x.json'), [])
  })

  it('takes a git user name only when it looks like a token', () => {
    const pat = fake.githubPat(random)
    const randomUser = token(40)
    const found = parseGitConfig(`[remote "a"]\n\turl = https://goncalo-neves@github.com/x.git\n[remote "b"]\n\turl = https://${pat}@github.com/x.git\n[remote "c"]\n\turl = https://${randomUser}@dev.azure.com/x\n`, '.git/config')
    assert.deepEqual(values(found), [pat, randomUser])
  })
})

describe('values inside variables', () => {
  it('reads JSON keys, connection strings and JDBC URLs inside secret-named variables', () => {
    const [accountKey, password, jdbc, query] = [`${token(64)}==`, token(16), token(16), token(16)]
    const key = fake.privateKey(random)
    const found = envEntrySecrets([
      { key: 'GCP_SA_KEY', value: JSON.stringify({ type: 'service_account', private_key: key, client_email: 'a@b.iam' }) },
      { key: 'BLOB_CONNECTION_STRING', value: `DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=${accountKey};EndpointSuffix=core.windows.net` },
      { key: 'SQL_CONN', value: `Server=db;Database=app;User Id=app;Password=${password};` },
      { key: 'JDBC_URL', value: `jdbc:postgresql://app:${jdbc}@db:5432/app` },
      { key: 'REPORTS_DB', value: `jdbc:mysql://db/app?user=app&password=${query}` },
    ], 'environment', { secretKeys: [], ignoreKeys: [], random: false })
    const got = values(found)
    for (const value of [key, accountKey, password, jdbc, query]) assert.ok(got.includes(value), value.slice(0, 12))
  })

  it('reads header lists in ANTHROPIC_CUSTOM_HEADERS and OTEL variables, also inside settings.json env', () => {
    const [custom, otel] = [token(), token()]
    const found = envEntrySecrets([{ key: 'ANTHROPIC_CUSTOM_HEADERS', value: `X-Api-Key: ${custom}\nX-Team: platform` }], 'environment')
    assert.deepEqual(values(found), [custom])
    const settings = treeParser('claude-settings')(JSON.stringify({ env: { OTEL_EXPORTER_OTLP_HEADERS: `authorization=Bearer%20${otel}`, ANTHROPIC_CUSTOM_HEADERS: `x-api-key: ${custom}` } }), 'settings.json')
    assert.deepEqual(values(settings).sort(), [`Bearer ${otel}`, otel, custom].sort())
  })

  it('reads proxy and package index credentials, including URL lists', () => {
    const [proxy, index, goproxy] = [token(16), token(16), token(16)]
    const found = envEntrySecrets([
      { key: 'HTTPS_PROXY', value: `http://me:${proxy}@proxy.example:3128` },
      { key: 'PIP_EXTRA_INDEX_URL', value: `https://pypi.org/simple https://me:${index}@pypi.example/simple` },
      { key: 'GOPROXY', value: `https://me:${goproxy}@goproxy.example,direct` },
      { key: 'HTTP_PROXY', value: 'http://proxy.example:3128' },
    ], 'environment', { secretKeys: [], ignoreKeys: [], random: false, known: new Set(['HTTPS_PROXY', 'PIP_EXTRA_INDEX_URL', 'GOPROXY', 'HTTP_PROXY']) })
    const got = values(found)
    for (const value of [proxy, index, goproxy]) assert.ok(got.includes(value))
    assert.ok(!got.includes('http://proxy.example:3128'))
  })
})

describe('more credential stores', () => {
  it('reads Pi, s3cmd, MinIO, OpenStack, bundler and wireguard files, and skips access key ids', () => {
    const t = Array.from({ length: 7 }, () => token())
    assert.deepEqual(values(treeParser('pi', { keys: ['access', 'refresh'] })(JSON.stringify({ anthropic: { type: 'oauth', access: t[0], refresh: t[1], expires: 1 } }), 'auth.json')), [t[0], t[1]])
    assert.deepEqual(values(treeParser('s3cfg', { ignore: ['access_key'] }, 'keyed')(`[default]\naccess_key = ${fake.awsKeyId(random)}\nsecret_key = ${t[2]}\nhost_base = s3.amazonaws.com\n`, '.s3cfg')), [t[2]])
    assert.deepEqual(values(treeParser('minio', { ignore: ['accessKey'] })(JSON.stringify({ version: '10', aliases: { local: { url: 'http://localhost:9000', accessKey: 'minioadmin', secretKey: t[3], api: 's3v4' } } }), 'config.json')), [t[3]])
    assert.deepEqual(values(treeParser('openstack', {}, 'keyed')(`clouds:\n  prod:\n    auth:\n      auth_url: https://keystone.example/v3\n      username: me\n      password: ${t[4]}\n      project_name: app\n`, 'clouds.yaml')), [t[4]])
    const bundler = parseBundlerConfig(`---\nBUNDLE_PATH: "vendor/bundle"\nBUNDLE_GEMS__CONTRIBSYS__COM: "me:${t[5]}"\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "https://mirror.example"\n`, 'config')
    assert.deepEqual(values(bundler), [`me:${t[5]}`, t[5]])
    const wg = treeParser('wireguard', {}, 'keyed')(`[Interface]\nPrivateKey = ${t[6]}=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ${token()}=\n`, 'wg0.conf')
    assert.deepEqual(values(wg), [`${t[6]}=`])
  })
})

describe('real passwords with symbols', () => {
  const passwords = (() => {
    const generate = seeded(4242)
    return Array.from({ length: 3000 }, () => fakeToken(generate, 20, PRINTABLE))
  })()
  const missing = (found: readonly { value: string }[]) => {
    const got = new Set(found.map(secret => secret.value))
    return passwords.filter(password => !got.has(password))
  }
  const dotenvLine = (password: string, index: number) =>
    password.includes("'") ? `DB_PASSWORD_${index}="${password.replace(/[\\"]/g, '\\$&')}"` : `DB_PASSWORD_${index}='${password}'`

  it('loads every random symbol password from .env files', () => {
    const text = passwords.map(dotenvLine).join('\n')
    assert.deepEqual(missing(envSecrets(parseDotenv(text), '.env', { secretKeys: [], ignoreKeys: [] })), [])
  })

  it('loads every random symbol password from .pgpass, .netrc, docker auth and git-credentials', () => {
    const pgpass = passwords.map((password, index) => `db${index}:5432:app:me:${password.replace(/[\\:]/g, '\\$&')}`).join('\n')
    assert.deepEqual(missing(parsePgpass(pgpass, '.pgpass')), [])
    const netrc = passwords.map((password, index) => `machine m${index}.example login me password ${password}`).join('\n')
    assert.deepEqual(missing(parseNetrc(netrc, '.netrc')), [])
    const docker = JSON.stringify({ auths: Object.fromEntries(passwords.map((password, index) => [`r${index}.example`, { auth: base64Encode(`me:${password}`) }])) })
    assert.deepEqual(missing(parseDockerConfig(docker, 'config.json')), [])
    const git = passwords.map((password, index) => `https://me:${encodeURIComponent(password)}@h${index}.example`).join('\n')
    assert.deepEqual(missing(parseGitCredentials(git, '.git-credentials')), [])
  })

  it('loads every random symbol password from JSON and YAML configs, expanding or not', () => {
    const json = JSON.stringify({ servers: passwords.map(password => ({ host: 'db', password })) })
    assert.deepEqual(missing(treeParser('app')(json, 'app.json')), [])
    assert.deepEqual(missing(treeParser('app', { literal: true })(json, 'app.json')), [])
    const yaml = `servers:\n${passwords.map(password => `  - host: db\n    password: "${password.replace(/[\\"]/g, '\\$&')}"`).join('\n')}\n`
    assert.deepEqual(missing(treeParser('app', {}, 'keyed')(yaml, 'app.yaml')), [])
  })

  it('keeps the cases the review found', () => {
    assert.deepEqual(values(parsePgpass('db:5432:app:me:ab`cd`ef9!', 'p')), ['ab`cd`ef9!'])
    assert.deepEqual(values(parseNetrc('machine h login me password x%ab%y9Q', 'n')), ['x%ab%y9Q'])
    assert.deepEqual(values(parseDockerConfig(JSON.stringify({ auths: { r: { password: 'p{{w}}0rd!' } } }), 'd')), ['p{{w}}0rd!'])
    assert.deepEqual(envSecrets(parseDotenv("DB_PASSWORD='abc...def!Q9'"), '.env', { secretKeys: [], ignoreKeys: [] }).map(secret => secret.value), ['abc...def!Q9'])
  })
})

describe('references in configs', () => {
  it('skips Spring, CloudFormation and Azure Key Vault references, and compose secret names', () => {
    const yaml = configParser('config', 'yaml')
    assert.deepEqual(yaml("spring:\n  datasource:\n    password: '#{systemProperties.dbPassword}'\n", 'application.yml'), [])
    assert.deepEqual(yaml('Resources:\n  Db:\n    Properties:\n      MasterUserPassword: !Ref DBPassword\n', 'serverless.yml'), [])
    assert.deepEqual(configParser('config', 'json')(JSON.stringify({ Values: { DbPassword: '@Microsoft.KeyVault(SecretUri=https://vault.example/secrets/db/)' } }), 'appsettings.json'), [])
    const compose = `services:\n  db:\n    image: mysql\n    environment:\n      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/db_root_password\n    secrets:\n      - db_root_password\n      - source: db_password\n        target: db_password\nsecrets:\n  db_root_password:\n    file: ./db_root_password.txt\n`
    assert.deepEqual(yaml(compose, 'docker-compose.yml'), [])
  })

  it('treats MinIO secret keys as strong, even in lower case', () => {
    const key = `minio${token(12).toLowerCase()}secret`
    assert.deepEqual(values(treeParser('minio', { ignore: ['accessKey'], strong: ['secretKey'], literal: true })(JSON.stringify({ aliases: { local: { accessKey: 'minioadmin', secretKey: key } } }), 'config.json')), [key])
  })

  it('skips bundler build flags, local paths and relative paths', () => {
    const value = token()
    const config = `BUNDLE_BUILD__PG: "--with-pg-config=/usr/bin/pg_config"\nBUNDLE_LOCAL__RACK: "../rack"\nBUNDLE_GEMS__EXAMPLE__COM: "me:${value}"\nBUNDLE_CACHE__ALL__PLATFORMS: "vendor/cache"\n`
    assert.deepEqual(values(parseBundlerConfig(config, 'config')), [`me:${value}`, value])
  })
})

describe('project config files', () => {
  it('reads strong-named literals in compose, Spring, appsettings, wp-config and settings.py, and skips references', () => {
    const [compose, spring, conn, wp, salt, django] = [token(16), token(16), token(16), token(16), token(64), token(50)]
    const yaml = configParser('config', 'yaml')
    assert.deepEqual(values(yaml(`services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=${compose}\n      - POSTGRES_USER=app\n      - API_TOKEN=\${API_TOKEN}\n`, 'docker-compose.yml')), [compose])
    assert.deepEqual(values(yaml(`spring:\n  datasource:\n    username: app\n    password: ${spring}\n    url: jdbc:postgresql://db/app\n`, 'application.yml')), [spring])
    assert.deepEqual(values(yaml(`production:\n  password: <%= ENV['DB_PASSWORD'] %>\n`, 'database.yml')), [])
    const json = configParser('config', 'json')(JSON.stringify({ ConnectionStrings: { Default: `Server=db;Database=app;User Id=app;Password=${conn};` }, Logging: { LogLevel: 'Info' } }), 'appsettings.json')
    assert.deepEqual(values(json), [conn])
    const code = configParser('config', 'code')
    assert.deepEqual(values(code(`define( 'DB_PASSWORD', '${wp}' );\ndefine('AUTH_KEY', '${salt}');\ndefine('DB_NAME', 'wordpress');`, 'wp-config.php')), [wp, salt])
    assert.deepEqual(values(code(`SECRET_KEY = '${django}'\nDATABASES = {'default': {'PASSWORD': os.environ['DB_PASSWORD'], 'NAME': 'app'}}\n`, 'settings.py')), [django])
  })

  it('reads YAML block scalars and inline JSON values', () => {
    const [block, inner] = [token(40), token(40)]
    const leaves = keyedLeaves(`key: |\n  ${block}\n  more\nrclone_token = {"access_token":"${inner}","expiry":"x"}\n`)
    assert.deepEqual(leaves.map(leaf => leaf.value), [`${block}\nmore`, inner, 'x'])
  })
})
