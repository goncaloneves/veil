import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import { nodeFs, readCapped } from '../src/cli/node-host.ts'
import { DEFAULT_CONFIG, parseConfig, type Config } from '../src/config/config.ts'
import { Masker } from '../src/core/masker.ts'
import { emptyRuleSet } from '../src/core/rules.ts'
import { loadState } from '../src/engine.ts'
import { report, shortPath } from '../src/report.ts'
import { ruleSet } from '../src/rules/index.ts'
import { isEnvFileName, loadSecrets, secretMounts, type SourceFs } from '../src/sources/load.ts'
import { LOWER, fake, fakeToken, pathFs, seeded } from './helpers.ts'

const random = seeded(404)
const token = (length = 32) => fakeToken(random, length)

function only(sources: Partial<Config['sources']>): Config {
  return { ...DEFAULT_CONFIG, sources: { ...DEFAULT_CONFIG.sources, project: false, home: false, system: false, environment: false, ...sources } }
}

function byValue(loaded: { secrets: readonly { value: string; source: string }[] }): Map<string, string> {
  return new Map(loaded.secrets.map(secret => [secret.value, secret.source]))
}

describe('home sources on Linux', () => {
  it('honours the override variables, KUBECONFIG lists and XDG_CONFIG_HOME', async () => {
    const t = Array.from({ length: 13 }, () => token())
    const files = {
      '/srv/aws/creds': `[default]\naws_secret_access_key = ${t[0]}\n`,
      '/srv/aws/config': `[profile ci]\naws_session_token = ${t[1]}\n`,
      '/srv/kube/a.yaml': `users:\n- name: a\n  user:\n    token: ${t[2]}\n`,
      '/srv/kube/b.yaml': `users:\n- name: b\n  user:\n    token: ${t[3]}\n`,
      '/srv/docker/config.json': JSON.stringify({ auths: { 'r.example': { identitytoken: t[4] } } }),
      '/srv/gh/hosts.yml': `github.com:\n    oauth_token: ${t[5]}\n`,
      '/xdg/git/credentials': `https://me:${t[6]}@git.example.com\n`,
      '/srv/netrc': `machine api.example.com login me password ${t[7]}\n`,
      '/srv/pgpass': `db:5432:app:me:${t[8]}\n`,
      '/srv/npmrc': `//registry.example/:_authToken=${t[9]}\n`,
      '/srv/claude/.credentials.json': JSON.stringify({ claudeAiOauth: { accessToken: t[10] } }),
      '/srv/codex/auth.json': JSON.stringify({ OPENAI_API_KEY: t[11] }),
      '/srv/gcp/sa.json': JSON.stringify({ type: 'service_account', private_key_id: token(), private_key: fake.privateKey(random), client_email: 'a@b.iam' }),
      '/srv/gcloud/application_default_credentials.json': JSON.stringify({ client_secret: t[12], type: 'authorized_user' }),
      '/home/me/.aws/credentials': `[default]\naws_secret_access_key = ${token()}\n`,
    }
    const locations = {
      AWS_SHARED_CREDENTIALS_FILE: '/srv/aws/creds',
      AWS_CONFIG_FILE: '/srv/aws/config',
      KUBECONFIG: '/srv/kube/a.yaml:/srv/kube/b.yaml',
      DOCKER_CONFIG: '/srv/docker',
      GH_CONFIG_DIR: '/srv/gh',
      XDG_CONFIG_HOME: '/xdg',
      NETRC: '/srv/netrc',
      PGPASSFILE: '/srv/pgpass',
      NPM_CONFIG_USERCONFIG: '/srv/npmrc',
      CLAUDE_CONFIG_DIR: '/srv/claude',
      CODEX_HOME: '/srv/codex',
      GOOGLE_APPLICATION_CREDENTIALS: '/srv/gcp/sa.json',
      CLOUDSDK_CONFIG: '/srv/gcloud',
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {}, locations }, only({ home: true }))
    const found = byValue(loaded)
    for (const value of t) assert.ok(found.has(value), value)
    assert.ok(loaded.secrets.some(secret => secret.source === '/srv/gcp/sa.json' && secret.value.includes('PRIVATE KEY')))
    assert.ok(!loaded.files.some(file => file.path === '/home/me/.aws/credentials'))
  })

  it('reads keys in ~/.ssh folders, PuTTY keys, GnuPG keys, shell files, history and agent files', async () => {
    const [key, work, d, rc, hist, opencode, sso] = [fake.privateKey(random), fake.privateKey(random), fake.hex(random, 96), token(), token(), token(), token()]
    const ppkLines = [token(64), token(64)]
    const files = {
      '/home/me/.ssh/id_ed25519': key,
      '/home/me/.ssh/work/id_rsa': work,
      '/home/me/.ssh/putty.ppk': `PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 2\n${ppkLines.join('\n')}\nPrivate-MAC: x\n`,
      '/home/me/.ssh/known_hosts': `host ssh-ed25519 ${token(68)}`,
      '/home/me/.gnupg/private-keys-v1.d/ABCD.key': `Key: (private-key (rsa (n #00${fake.hex(random, 64)}#)(d #${d}#)))\n`,
      '/home/me/.zshrc': `export DB_PASS='${rc}'\n`,
      '/home/me/.bash_history': `docker login -u me -p ${hist} r.example\n`,
      '/home/me/.local/share/opencode/auth.json': JSON.stringify({ anthropic: { type: 'oauth', access: opencode, refresh: token() } }),
      '/home/me/.aws/sso/cache/abc.json': JSON.stringify({ accessToken: sso }),
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ home: true }))
    const found = byValue(loaded)
    for (const value of [key, work, ppkLines.join('\n'), d, rc, hist, opencode, sso]) assert.ok(found.has(value), value.slice(0, 20))
    assert.ok(!loaded.files.some(file => file.path.endsWith('known_hosts')))
    assert.ok(loaded.secrets.every(secret => secret.source !== '/home/me/.ssh/work/id_rsa' || secret.name === 'ssh/work/id_rsa'))
  })
})

describe('home sources on macOS and Windows', () => {
  it('reads Application Support and Preferences paths on macOS', async () => {
    const [desktop, vercel, netlify] = [token(), token(), token()]
    const files = {
      '/Users/me/Library/Application Support/Claude/claude_desktop_config.json': JSON.stringify({ mcpServers: { db: { env: { DB_PASSWORD: desktop } } } }),
      '/Users/me/Library/Application Support/com.vercel.cli/auth.json': JSON.stringify({ token: vercel }),
      '/Users/me/Library/Preferences/netlify/config.json': JSON.stringify({ users: { u: { auth: { token: netlify } } } }),
    }
    const loaded = await loadSecrets(pathFs(files, { platform: 'darwin' }), { home: '/Users/me', root: '/repo', platform: 'darwin', vars: {} }, only({ home: true }))
    assert.deepEqual([...byValue(loaded).keys()].sort(), [desktop, vercel, netlify].sort())
  })

  it('reads %USERPROFILE% and %APPDATA% paths on Windows, with backslashes and any letter case', async () => {
    const t = Array.from({ length: 7 }, () => token())
    const files = {
      'C:\\Users\\Me\\_netrc': `machine api.heroku.com login me password ${t[0]}\n`,
      'C:\\Users\\Me\\AppData\\Roaming\\postgresql\\pgpass.conf': `db:5432:app:me:${t[1]}\r\n`,
      'C:\\Users\\Me\\AppData\\Roaming\\GitHub CLI\\hosts.yml': `github.com:\r\n    oauth_token: ${t[2]}\r\n`,
      'C:\\Users\\Me\\AppData\\Roaming\\npm\\etc\\npmrc': `//registry.example/:_authToken=${t[3]}\r\n`,
      'C:\\Users\\Me\\AppData\\Roaming\\gcloud\\application_default_credentials.json': JSON.stringify({ refresh_token: t[4] }),
      'C:\\Users\\Me\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt': `$env:DEPLOY_TOKEN = "${t[5]}"\r\n`,
      'C:\\Users\\Me\\.aws\\credentials': `[default]\r\naws_secret_access_key = ${t[6]}\r\n`,
    }
    const fs = pathFs(files, { platform: 'win32' })
    const loaded = await loadSecrets(fs, { home: 'c:\\users\\me', root: 'C:\\repo', platform: 'win32', vars: {}, locations: { APPDATA: 'C:\\Users\\Me\\AppData\\Roaming' } }, only({ home: true }))
    assert.deepEqual([...byValue(loaded).keys()].sort(), [...t].sort())
  })
})

describe('system sources', () => {
  it('reads raw secrets under /run/secrets and the Kubernetes service account token, but not its namespace or CA', async () => {
    const [db, sa, k3s] = [token(24), fake.jwt(random, 60), token(48)]
    const files = {
      '/run/secrets/db_password': `${db}\n`,
      '/var/run/secrets/kubernetes.io/serviceaccount/token': sa,
      '/var/run/secrets/kubernetes.io/serviceaccount/namespace': 'production',
      '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt': ['-----BEGIN', 'CERTIFICATE-----\nAAAA\n-----END', 'CERTIFICATE-----'].join(' '),
      '/var/lib/rancher/k3s/server/token': `K10${k3s}::server:${token(16)}\n`,
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ system: true }))
    const values = [...byValue(loaded).keys()]
    assert.ok(values.includes(db) && values.includes(sa) && values.some(value => value.includes(k3s)))
    assert.ok(!values.includes('production'))
    assert.ok(loaded.secrets.every(secret => secret.strong))
  })

  it('reads systemd Environment= lines and CIFS passwords in fstab, skipping vendor unit links', async () => {
    const [unit, dropIn, cifs] = [token(), token(), token(16)]
    const files = {
      '/etc/systemd/system/app.service': `[Service]\nEnvironment="API_TOKEN=${unit}" "LOG_LEVEL=debug"\nExecStart=/usr/bin/app\n`,
      '/etc/systemd/system/app.service.d/override.conf': `[Service]\nEnvironment=DB_PASSWORD=${dropIn}\n`,
      '/etc/systemd/system/multi-user.target.wants/vendor.service': `[Service]\nEnvironment=VENDOR_TOKEN=${token()}\n`,
      '/etc/fstab': `# comment password=nope1234\n//nas/share /mnt/share cifs username=me,password=${cifs},uid=1000 0 0\n`,
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ system: true }))
    assert.deepEqual([...byValue(loaded).keys()].sort(), [unit, dropIn, cifs].sort())
  })

  it('reports unreadable system and home files quietly, and project files loudly', async () => {
    const fs = pathFs({ '/repo/.env.production': `DB_PASSWORD=${token()}`, '/home/me/.netrc': 'machine x password y1234567', '/etc/ssl/private/server.key': 'x' }, { denied: ['/repo/.env.production', '/home/me/.netrc', '/etc/ssl/private'] })
    const state = await loadState(fs, { home: '/home/me', root: '/repo', platform: 'linux', vars: {} })
    const loud = state.loaded.errors.filter(error => !error.quiet).map(error => error.path)
    const quiet = state.loaded.errors.filter(error => error.quiet).map(error => error.path).sort()
    assert.deepEqual(loud, ['/repo/.env.production'])
    assert.deepEqual(quiet, ['/home/me/.netrc'])
    assert.deepEqual(state.loaded.skipped?.map(item => item.path), ['/etc/ssl/private'])
    assert.ok(state.warnings.some(warning => warning.startsWith('could not read /repo/.env.production')))
    const text = report(new Masker({ secrets: [], ruleSet, minLength: 8, encodings: [], salt: 's' }), state, { home: '/home/me' })
    assert.doesNotMatch(text, /\/etc\/ssl\/private/)
    assert.match(text, / {2}~\/\.netrc: EACCES/)
  })
})

describe('project discovery', () => {
  it('finds more env file names, any letter case, three levels down and in dev-container folders', async () => {
    const names = ['.ENV', '.dev.vars', '.env-local', 'env.production', '.devcontainer/.env', 'packages/api/src/.env', '.env.example', '.env-sample', 'example.env', 'node_modules/x/.env', '.git/.env']
    const files = Object.fromEntries(names.map(name => [`/repo/${name}`, `APP_SECRET=${token()}`]))
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    assert.deepEqual(loaded.files.map(file => file.path.slice('/repo/'.length)).sort(), names.slice(0, 6).sort())
    for (const name of ['.ENV', '.Env.Local', '.dev.vars.staging', 'env.local']) assert.ok(isEnvFileName(name), name)
    for (const name of ['.env.default', 'env.ts', 'env.d.ts', '.env-template', '.environment']) assert.ok(!isEnvFileName(name), name)
  })

  it('reads mise, Azure Functions, Streamlit, Terraform, Rails, npm, compose and git config files in the project', async () => {
    const t = Array.from({ length: 9 }, () => token())
    const files = {
      '/repo/mise.toml': `[tools]\nnode = "22"\n[env]\nDEPLOY_TOKEN = "${t[0]}"\nNODE_ENV = "production"\n`,
      '/repo/api/local.settings.json': JSON.stringify({ IsEncrypted: false, Values: { AzureWebJobsStorage: 'UseDevelopmentStorage=true', SERVICE_API_KEY: t[1] }, ConnectionStrings: { Sql: `Server=db;Password=${t[2]};` } }),
      '/repo/.streamlit/secrets.toml': `openai_key = "${t[3]}"\n[connections.db]\nhost = "localhost"\nusername = "app"\n`,
      '/repo/infra/terraform.tfvars': `region = "eu-west-1"\ndb_password = "${t[4]}"\n`,
      '/repo/config/master.key': `${fake.hex(random, 32)}\n`,
      '/repo/.npmrc': `//npm.pkg.github.com/:_authToken=${t[5]}\n`,
      '/repo/docker-compose.yml': `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${t[6]}\n      POSTGRES_DB: app\n`,
      '/repo/.git/config': `[remote "origin"]\n\turl = https://${t[7]}@github.com/acme/app.git\n`,
      '/repo/.mcp.json': JSON.stringify({ mcpServers: { s: { env: { SERVICE_TOKEN: t[8] } } } }),
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    const values = [...byValue(loaded).keys()]
    for (const value of t) assert.ok(values.includes(value), value)
    assert.ok(loaded.files.some(file => file.path === '/repo/config/master.key' && file.count === 1))
    assert.ok(!values.includes('localhost') && !values.includes('UseDevelopmentStorage=true'))
  })

  it('reads the shared git config of a worktree', async () => {
    const value = token()
    const files = {
      '/wt/feature/.git': 'gitdir: /repo/.git/worktrees/feature\n',
      '/repo/.git/worktrees/feature/commondir': '../..\n',
      '/repo/.git/config': `[remote "origin"]\n\turl = https://me:${value}@git.example.com/app.git\n`,
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/wt/feature', vars: {} }, only({ project: true }))
    assert.deepEqual(loaded.secrets.map(secret => secret.value), [value])
  })

  it('never walks /proc, /sys or /usr when the session starts at /', async () => {
    const listed: string[] = []
    const base = pathFs({ '/app/.env': `APP_SECRET=${token()}`, '/proc/1/environ': 'X=1', '/usr/lib/x/.env': `LIB_SECRET=${token()}`, '/sys/a/.env': 'Y=1' })
    const fs: SourceFs = { ...base, list: async dir => (listed.push(dir), base.list(dir)) }
    const loaded = await loadSecrets(fs, { home: '/root', root: '/', vars: {} }, only({ project: true }))
    assert.deepEqual(loaded.files.map(file => file.path), ['/app/.env'])
    assert.ok(!listed.some(dir => /^\/(?:proc|sys|usr)/.test(dir)))
  })
})

const MOUNTINFO = [
  '1546 1205 0:412 / / rw,relatime master:451 - overlay overlay rw,lowerdir=/var/lib/containerd/l1,upperdir=/var/lib/containerd/u1,workdir=/var/lib/containerd/w1',
  '1547 1546 0:415 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw',
  '1548 1546 0:416 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755',
  '1556 1546 0:418 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro',
  '1560 1548 0:414 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k',
  '1561 1546 259:1 /var/lib/kubelet/pods/abc/etc-hosts /etc/hosts rw,relatime - ext4 /dev/nvme0n1p1 rw',
  '1563 1546 0:787 / /srv/app-secrets ro,relatime - tmpfs tmpfs rw,size=7868548k',
  '1564 1546 0:788 / /var/run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=7868548k',
  '1565 1546 0:789 / /tmp rw,relatime - tmpfs tmpfs rw',
  '1566 1546 0:790 / /var/lib/kubelet/pods/abc/volumes ro,relatime - tmpfs tmpfs rw',
].join('\n')

describe('review fixes for sources', () => {
  it('finds read-only tmpfs secret mounts in a real mountinfo, and nothing else', () => {
    assert.deepEqual(secretMounts(MOUNTINFO), ['/srv/app-secrets', '/var/run/secrets/kubernetes.io/serviceaccount'])
  })

  it('never reads an empty-sized file, a second procfs mount, or a .git file that points into /proc', async () => {
    const reads: string[] = []
    const base = pathFs({ '/repo/.env': 'x', '/repo/.git': 'gitdir: /proc/self\n', '/repo/.env.local': `APP_SECRET=${token()}` }, { onRead: path => reads.push(path) })
    const sizes: Record<string, number> = { '/repo/.env': 0, '/repo/.git': 0, '/repo/.env.local': 50 }
    const fs: SourceFs = { ...base, stat: async path => ({ kind: await base.kindOf(path), size: sizes[path] ?? 10, mtimeMs: 1, realPath: path === '/repo/.env' ? '/mnt/p/self/environ' : path }) }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    assert.deepEqual(reads, ['/repo/.env.local'])
    assert.equal(loaded.secrets.length, 1)
  })

  it('re-reads a file whose change time or inode changed even when size and mtime were restored', async () => {
    const files: Record<string, string> = { '/repo/.env': `APP_SECRET=${token()}` }
    let ctime = 1
    const fs = (): SourceFs => {
      const base = pathFs(files)
      return { ...base, stat: async path => ({ kind: await base.kindOf(path), size: 43, mtimeMs: 5, ctimeMs: ctime, ino: 7, realPath: path }) }
    }
    const host = { home: '/home/me', root: '/repo', vars: {} }
    const first = await loadSecrets(fs(), host, only({ project: true }))
    const changed = token()
    files['/repo/.env'] = `APP_SECRET=${changed}`
    ctime = 2
    const second = await loadSecrets(fs(), host, only({ project: true }), first)
    assert.deepEqual(second.secrets.map(secret => secret.value), [changed])
  })

  it('reuses the project walk for a few minutes, while still finding new files in folders it knows', async () => {
    const files: Record<string, string> = { '/repo/.env': `APP_SECRET=${token()}`, '/repo/apps/web/.env': `WEB_SECRET=${token()}`, '/repo/apps/api/src/readme.md': 'x' }
    const listed: string[] = []
    const fs = (): SourceFs => {
      const base = pathFs(files)
      return { ...base, list: async dir => (listed.push(dir), base.list(dir)) }
    }
    const host = { home: '/home/me', root: '/repo', vars: {} }
    const first = await loadSecrets(fs(), host, only({ project: true }))
    assert.ok(listed.length > 3)
    listed.length = 0
    files['/repo/apps/web/.env.local'] = `LOCAL_SECRET=${token()}`
    files['/repo/apps/api/src/.env'] = `DEEP_SECRET=${token()}`
    const second = await loadSecrets(fs(), host, only({ project: true }), first)
    assert.deepEqual([...new Set(listed)].sort(), ['/repo', '/repo/apps/web'])
    assert.deepEqual(second.files.map(file => file.path).sort(), ['/repo/.env', '/repo/apps/web/.env', '/repo/apps/web/.env.local'])
    const stale = second.walk ? { ...second, walk: { ...second.walk, at: 0 } } : second
    const third = await loadSecrets(fs(), host, only({ project: true }), stale)
    assert.ok(third.files.some(file => file.path === '/repo/apps/api/src/.env'))
  })

  it('sends denied reads and listings of system files to skipped, not errors', async () => {
    const base = pathFs({ '/etc/fstab': 'x', '/etc/ssl/private/a.key': 'x' })
    const fs: SourceFs = {
      ...base,
      read: async path => {
        if (path === '/etc/fstab') throw Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })
        return base.read(path)
      },
      list: async dir => {
        if (dir === '/etc/ssl/private') throw Object.assign(new Error('EPERM: operation not permitted'), { code: 'EPERM' })
        return base.list(dir)
      },
    }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, only({ system: true }))
    assert.deepEqual(loaded.errors, [])
    assert.deepEqual(loaded.skipped?.map(item => item.path).sort(), ['/etc/fstab', '/etc/ssl/private'])
  })

  it('never reads a source whose real path is under /proc, /sys or /dev', async () => {
    const reads: string[] = []
    const base = pathFs({ '/repo/.env': 'x', '/repo/.env.local': `APP_SECRET=${token()}` }, { onRead: path => reads.push(path) })
    const fs: SourceFs = { ...base, stat: async path => ({ kind: await base.kindOf(path), size: 64, mtimeMs: 1, realPath: path === '/repo/.env' ? '/proc/self/pagemap' : path }) }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    assert.deepEqual(reads, ['/repo/.env.local'])
    assert.deepEqual(loaded.files.map(file => file.path), ['/repo/.env.local'])
    assert.deepEqual(loaded.errors, [])
  })

  it('re-reads only files whose size or modification time changed, and still finds new files', async () => {
    const reads: string[] = []
    const files: Record<string, string> = { '/repo/.env': `APP_SECRET=${token()}`, '/repo/.env.local': `LOCAL_SECRET=${token()}` }
    const times: Record<string, number> = { '/repo/.env': 1, '/repo/.env.local': 1 }
    const fs = (): SourceFs => {
      const base = pathFs(files, { onRead: path => reads.push(path) })
      return { ...base, stat: async path => ({ kind: await base.kindOf(path), size: files[path]?.length ?? 0, mtimeMs: times[path] ?? 0, realPath: path }) }
    }
    const host = { home: '/home/me', root: '/repo', vars: {} }
    const first = await loadSecrets(fs(), host, only({ project: true }))
    reads.length = 0
    const changed = token()
    files['/repo/.env.local'] = `LOCAL_SECRET=${changed}`
    times['/repo/.env.local'] = 2
    files['/repo/.env.test'] = `TEST_SECRET=${token()}`
    const second = await loadSecrets(fs(), host, only({ project: true }), first)
    assert.deepEqual(reads.sort(), ['/repo/.env.local', '/repo/.env.test'])
    assert.equal(second.secrets.length, 3)
    assert.ok(second.secrets.some(secret => secret.value === changed))
  })

  it('reads the last 8 MiB of a larger history file', async () => {
    const value = token()
    const base = pathFs({ '/home/me/.bash_history': 'x' })
    const fs: SourceFs = { ...base, stat: async path => ({ kind: await base.kindOf(path), size: 9 * 1024 * 1024, mtimeMs: 1 }), readTail: async () => `partial line\nexport API_TOKEN=${value}\n` }
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, only({ home: true }))
    assert.deepEqual(loaded.secrets.map(secret => secret.value), [value])
  })

  it('reads every file in a big folder before its subfolders, and warns when it stops', async () => {
    const files: Record<string, string> = { '/home/me/.ssh/a/id_ed25519': fake.privateKey(random) }
    for (let i = 0; i < 300; i++) files[`/home/me/.ssh/note-${i}.txt`] = 'x'
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ home: true }))
    assert.match(loaded.warnings.join('\n'), /veil read only the first 256 files under \/home\/me\/\.ssh/)
    const small: Record<string, string> = { '/home/me/.ssh/a/id_ed25519': fake.privateKey(random) }
    for (let i = 0; i < 100; i++) small[`/home/me/.ssh/note-${i}.txt`] = 'x'
    const ok = await loadSecrets(pathFs(small), { home: '/home/me', root: '/repo', vars: {} }, only({ home: true }))
    assert.equal(ok.secrets.length, 1)
    assert.deepEqual(ok.warnings, [])
  })

  it('skips Documents, Desktop and cloud folders when the session starts in the home folder, and /Users, /home and /mnt at /', async () => {
    const listed: string[] = []
    const base = pathFs({ '/home/me/app/.env': `APP_SECRET=${token()}`, '/home/me/Documents/x/.env': 'A=1', '/home/me/Dropbox/.env': 'A=1', '/home/me/Google Drive/.env': 'A=1' })
    const fs: SourceFs = { ...base, list: async dir => (listed.push(dir), base.list(dir)) }
    await loadSecrets(fs, { home: '/home/me', root: '/home/me', vars: {} }, only({ project: true }))
    assert.ok(!listed.some(dir => /Documents|Dropbox|Google Drive/.test(dir)))
    listed.length = 0
    await loadSecrets(fs, { home: '/root', root: '/', vars: {} }, only({ project: true }))
    assert.ok(!listed.some(dir => /^\/(?:home|Users|mnt|media)(?:\/|$)/.test(dir)))
  })

  it('reads secret mounts, systemd EnvironmentFile, PKI keys, wireguard and rke2 on servers', async () => {
    const [vaultSecret, csi, mounted, envFile, wg, rke2] = [token(), token(), token(), token(), token(), token()]
    const files = {
      '/vault/secrets/db': `DB_PASSWORD=${vaultSecret}\n`,
      '/mnt/secrets-store/api-key': csi,
      '/srv/app-secrets/token': mounted,
      '/proc/self/mountinfo': MOUNTINFO,
      '/etc/systemd/system/app.service': '[Service]\nEnvironmentFile=-/etc/default/app\n',
      '/etc/default/app': `API_TOKEN=${envFile}\n`,
      '/etc/pki/tls/private/server.key': fake.privateKey(random),
      '/etc/wireguard/wg0.conf': `[Interface]\nPrivateKey = ${wg}=\n`,
      '/etc/rancher/rke2/rke2.yaml': `users:\n- name: default\n  user:\n    token: ${rke2}\n`,
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ system: true }))
    const found = [...byValue(loaded).keys()]
    for (const value of [vaultSecret, csi, mounted, envFile, `${wg}=`, rke2]) assert.ok(found.includes(value), value)
    assert.ok(loaded.secrets.some(secret => secret.source === '/etc/pki/tls/private/server.key'))
  })

  it('follows sourced shell files and reads ~/.env, local rc files, rc folders, oh-my-zsh custom files and environment.d', async () => {
    const t = Array.from({ length: 7 }, () => token())
    const files = {
      '/home/me/.zshrc': `[ -f ~/.secrets.sh ] && source ~/.secrets.sh\n. "$HOME/.work.sh"\nsource $UNKNOWN/x.sh\n`,
      '/home/me/.secrets.sh': `export API_TOKEN=${t[0]}\n`,
      '/home/me/.work.sh': `export WORK_SECRET=${t[1]}\n`,
      '/home/me/.env': `OPENAI_API_KEY=${t[2]}\n`,
      '/home/me/.zshrc.local': `export LOCAL_TOKEN=${t[3]}\n`,
      '/home/me/.bashrc.d/50-cloud.sh': `export CLOUD_SECRET=${t[4]}\n`,
      '/home/me/.oh-my-zsh/custom/keys.zsh': `export ZSH_SECRET=${t[5]}\n`,
      '/home/me/.config/environment.d/10-keys.conf': `DEPLOY_TOKEN=${t[6]}\n`,
    }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {} }, only({ home: true }))
    assert.deepEqual([...byValue(loaded).keys()].sort(), [...t].sort())
  })

  it('reads Pi, s3cmd, MinIO, OpenStack and bundler files and Ansible vault password files in the home folder', async () => {
    const t = Array.from({ length: 7 }, () => token())
    const files = {
      '/agents/pi/auth.json': JSON.stringify({ openai: { type: 'api', key: t[0] } }),
      '/home/me/.s3cfg': `[default]\nsecret_key = ${t[1]}\n`,
      '/home/me/.mc/config.json': JSON.stringify({ aliases: { s3: { secretKey: t[2] } } }),
      '/home/me/.config/openstack/clouds.yaml': `clouds:\n  a:\n    auth:\n      password: ${t[3]}\n`,
      '/home/me/.bundle/config': `BUNDLE_GEMS__EXAMPLE__COM: "me:${t[4]}"\n`,
      '/home/me/.vault_pass.txt': `${t[5]}\n`,
      '/srv/ansible/vault-pass': `${t[6]}\n`,
    }
    const locations = { PI_CODING_AGENT_DIR: '/agents/pi', ANSIBLE_VAULT_PASSWORD_FILE: '/srv/ansible/vault-pass' }
    const loaded = await loadSecrets(pathFs(files), { home: '/home/me', root: '/repo', vars: {}, locations }, only({ home: true, environment: true }))
    for (const value of t) assert.ok(byValue(loaded).has(value), value)
  })

  it('reads the PowerShell profile under OneDrive Documents on Windows', async () => {
    const value = token()
    const files = { 'C:\\Users\\me\\OneDrive\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1': `$env:DEPLOY_TOKEN = '${value}'\r\n` }
    const loaded = await loadSecrets(pathFs(files, { platform: 'win32' }), { home: 'C:\\Users\\me', root: 'C:\\repo', platform: 'win32', vars: {} }, only({ home: true }))
    assert.deepEqual([...byValue(loaded).keys()], [value])
  })

  it('does not report root-only system files as unreadable', async () => {
    const fs = pathFs({ '/etc/ssh/ssh_host_ed25519_key': 'x' }, { denied: ['/etc/ssh/ssh_host_ed25519_key'] })
    const loaded = await loadSecrets(fs, { home: '/home/me', root: '/repo', vars: {} }, only({ system: true }))
    assert.deepEqual(loaded.errors, [])
    assert.deepEqual(loaded.skipped?.map(item => item.path), ['/etc/ssh/ssh_host_ed25519_key'])
  })

  it('parses .envrc as a shell script, so references are never values', async () => {
    const loaded = await loadSecrets(pathFs({ '/repo/.envrc': 'export DATABASE_URL=postgres://app:$DB_PASS@db/app\nexport API_TOKEN="$(op read op://v/i/t)"\n' }), { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    assert.deepEqual(loaded.secrets, [])
  })
})

describe('the Node file system', () => {
  it('caps reads, decodes UTF-16 files, and reports size and modification time', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'veil-fs-'))
    try {
      const value = token()
      const big = join(dir, 'big')
      await writeFile(big, 'x'.repeat(64))
      await assert.rejects(readCapped(big, 32), /larger than/)
      assert.equal((await readCapped(big, 64)).length, 64)
      const wide = join(dir, 'wide.env')
      await writeFile(wide, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`API_TOKEN=${value}\r\n`, 'utf16le')]))
      assert.equal(await nodeFs.read(wide), `API_TOKEN=${value}\r\n`)
      const info = await nodeFs.stat?.(wide)
      assert.equal(info?.kind, 'file')
      assert.ok((info?.size ?? 0) > 0 && (info?.mtimeMs ?? 0) > 0)
      assert.equal(await nodeFs.readTail?.(big, 8), 'xxxxxxxx')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe('configured files', () => {
  it('reads Windows patterns with backslashes and ~\\, and raw or JSON files', async () => {
    const [a, b, raw, json] = [token(), token(), token(40), token()]
    const files = {
      'C:\\Users\\dev\\app\\staging.env': `STAGING_TOKEN=${a}`,
      'C:\\Users\\dev\\app\\prod.ENV': `PROD_TOKEN=${b}`,
      'C:\\Users\\dev\\secrets\\db-password': `${raw}\r\n`,
      'C:\\Users\\dev\\secrets\\service.json': JSON.stringify({ api_key: json }),
    }
    const { config } = parseConfig(String.raw`[sources]
project = false
home = false
system = false
environment = false
files = ['C:\Users\dev\app\*.env', '~\secrets\db-password', '~/secrets/service.json']
`)
    const loaded = await loadSecrets(pathFs(files, { platform: 'win32' }), { home: 'C:\\Users\\dev', root: 'C:\\repo', platform: 'win32', vars: {} }, config)
    assert.deepEqual([...byValue(loaded).keys()].sort(), [a, b, raw, json].sort())
    assert.deepEqual(loaded.files.map(file => file.kind).sort(), ['dotenv', 'dotenv', 'json', 'raw'])
    assert.deepEqual(loaded.warnings, [])
  })

  it('warns about a missing file, a pattern with no matches, and a file with no values', async () => {
    const { config } = parseConfig('[sources]\nproject = false\nhome = false\nsystem = false\nenvironment = false\nfiles = ["~/missing.env", "~/conf/*.env", "~/notes.txt"]\n')
    const loaded = await loadSecrets(pathFs({ '/home/me/conf/readme.md': 'x', '/home/me/notes.txt': 'line one\nline two\n' }), { home: '/home/me', root: '/repo', vars: {} }, config)
    assert.deepEqual(loaded.warnings, ['sources.files: ~/missing.env was not found', 'sources.files: /home/me/notes.txt holds no values veil recognises', 'sources.files: "~/conf/*.env" matched no files'])
    const twice = parseConfig('[sources]\nproject = false\nhome = false\nsystem = false\nenvironment = false\nfiles = ["~/conf/app.env", "~/conf/*.env"]\n')
    const again = await loadSecrets(pathFs({ '/home/me/conf/app.env': `A_TOKEN=${fake.hex(seeded(92), 32)}\n` }), { home: '/home/me', root: '/repo', vars: {} }, twice.config)
    assert.deepEqual(again.warnings, [])
  })
})

describe('values', () => {
  it('reads a hostile .git file or origin URL in linear time', async () => {
    const started = Date.now()
    await loadSecrets(pathFs({ '/work/a/.git': `gitdir:x${' '.repeat(100_000)}y`, '/work/a/raw.env': `A=${'='.repeat(100_000)}x`, '/work/a/.env': 'DB_PASSWORD=x9Kq\n' }), { home: '/home/me', root: '/work/a', vars: {} }, { ...only({ project: true }), sources: { ...only({ project: true }).sources, files: ['/work/a/raw.env'] } })
    await loadSecrets(pathFs({ '/work/b/.git/config': `[remote "origin"]\n\turl = https://x${'/'.repeat(100_000)}y\n`, '/work/b/.env': 'DB_PASSWORD=x9Kq\n' }), { home: '/home/me', root: '/work/b', vars: {} }, only({ project: true }))
    assert.ok(Date.now() - started < 2000, `${Date.now() - started} ms`)
  })

  it('masks a password that is the project folder or origin repository name, or a part of it, only where it is assigned', async () => {
    const name = fakeToken(seeded(93), 12, LOWER)
    const other = fakeToken(seeded(94), 12, LOWER)
    const root = `/work/${name}-team`
    const loaded = await loadSecrets(pathFs({ [`${root}/.env`]: `DB_PASSWORD=${name}\nOTHER_PASSWORD=${other}\n` }), { home: '/home/me', root, vars: {} }, only({ project: true }))
    const m = new Masker({ secrets: loaded.secrets, ruleSet: emptyRuleSet(), minLength: 8, encodings: ['base64', 'url', 'json', 'lines'], salt: 's' })
    assert.equal(m.mask(`cd ${root}/src && ls ~/.config/${name}`).text, `cd ${root}/src && ls ~/.config/${name}`)
    assert.equal(m.mask(`DB_PASSWORD=${name}`).text, 'DB_PASSWORD=[veil:DB_PASSWORD]')
    assert.ok(!m.mask(`postgres://app:${name}@db:5432/app`).text.includes(name))
    assert.equal(m.mask(`cd /work/${other}`).text, 'cd /work/[veil:OTHER_PASSWORD]')
    const cased = await loadSecrets(pathFs({ [`/work/${name.toUpperCase()}/.env`]: `DB_PASSWORD=${name}\n` }), { home: '/home/me', root: `/work/${name.toUpperCase()}`, vars: {} }, only({ project: true }))
    assert.equal(cased.secrets[0]?.projectName, true)
    const worktree = {
      '/wt/self-answer/.git': 'gitdir: /repo/.git/worktrees/self-answer\n',
      '/wt/self-answer/.env': `DB_PASSWORD=${name}\n`,
      '/repo/.git/worktrees/self-answer/commondir': '../..\n',
      '/repo/.git/config': `[remote "upstream"]\n\turl = https://git.example.com/other/${other}.git\n[remote "origin"]\n\turl = git@git.example.com:me/${name}-team.git\n`,
    }
    const named = await loadSecrets(pathFs(worktree), { home: '/home/me', root: '/wt/self-answer', vars: {} }, only({ project: true }))
    assert.equal(named.secrets.find(secret => secret.value === name)?.projectName, true)
    const upstream = await loadSecrets(pathFs({ ...worktree, '/wt/self-answer/.env': `DB_PASSWORD=${other}\n` }), { home: '/home/me', root: '/wt/self-answer', vars: {} }, only({ project: true }))
    assert.equal(upstream.secrets.find(secret => secret.value === other)?.projectName, undefined)
    const upper = await loadSecrets(pathFs({ [`${root}/.env`]: `DB_PASSWORD=${name.toUpperCase()}\n` }), { home: '/home/me', root, vars: {} }, only({ project: true }))
    assert.equal(upper.secrets[0]?.projectName, true)
    const slashed = await loadSecrets(pathFs({ ...worktree, '/repo/.git/config': `[remote "origin"]\n\turl = https://git.example.com/me/${name}-team/\n` }), { home: '/home/me', root: '/wt/self-answer', vars: {} }, only({ project: true }))
    assert.equal(slashed.secrets[0]?.projectName, true)
    const nested = { '/work/plain/.env': `DB_PASSWORD=${other}\n`, '/work/plain/sub/.git/config': `[remote "origin"]\n\turl = https://git.example.com/me/${other}.git\n` }
    const fromCwd = await loadSecrets(pathFs(nested), { home: '/home/me', root: '/work/plain', cwd: '/work/plain/sub', vars: {} }, only({ project: true }))
    assert.equal(fromCwd.secrets.find(secret => secret.value === other)?.projectName, undefined)
    const atHome = await loadSecrets(pathFs({ [`/home/${name}/.env`]: `DB_PASSWORD=${name}\n` }), { home: `/home/${name}`, root: `/home/${name}`, vars: {} }, only({ project: true }))
    assert.equal(atHome.secrets.length, 1)
    assert.equal(atHome.secrets[0]?.projectName, undefined)
  })

  it('emits short non-trivial values from four characters, flagged strong only when the source proves it', async () => {
    const loaded = await loadSecrets(pathFs({ '/repo/.env': 'ADMIN_PIN=4821\nDB_PASS=x7k2\nAPI_KEY=k8s9\nSHORT_KEY=abc\nFEATURE_SECRET=false' }), { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    assert.deepEqual(loaded.secrets.map(secret => [secret.name, secret.strong === true]), [['ADMIN_PIN', true], ['DB_PASS', true], ['API_KEY', false]])
  })

  it('keeps one copy of a value and keeps it strong when any source proves it', async () => {
    const value = token()
    const loaded = await loadSecrets(pathFs({ '/repo/.env': `SOME_VALUE=${value}`, '/repo/.env.local': `DB_PASSWORD=${value}` }), { home: '/home/me', root: '/repo', vars: {} }, only({ project: true }))
    assert.equal(loaded.secrets.length, 1)
    assert.equal(loaded.secrets[0]?.strong, true)
  })

  it('shortens home paths on every platform', () => {
    assert.equal(shortPath('C:\\Users\\Me\\.aws\\credentials', 'c:\\users\\me', 'win32'), '~/.aws/credentials')
    assert.equal(shortPath('/home/me/.netrc', '/home/me'), '~/.netrc')
    assert.equal(shortPath('/etc/x', '/'), '/etc/x')
    assert.equal(shortPath('/home/meow/x', '/home/me'), '/home/meow/x')
  })
})
