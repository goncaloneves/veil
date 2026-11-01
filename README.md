<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img alt="veil" src="docs/assets/logo-light.svg" width="280">
  </picture>
</p>

<p align="center"><strong>Masks your secrets before your coding agent's model sees them.</strong></p>

<p align="center">
  <a href="https://github.com/goncaloneves/veil/actions/workflows/ci.yml"><img alt="ci" src="https://github.com/goncaloneves/veil/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/goncaloneves/veil/releases"><img alt="release" src="https://img.shields.io/github/v/release/goncaloneves/veil?color=8B5CF6"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/github/license/goncaloneves/veil?color=6366F1"></a>
  <img alt="works with any model" src="https://img.shields.io/badge/models-any-8B5CF6">
  <img alt="no runtime dependencies" src="https://img.shields.io/badge/runtime%20dependencies-0-22C55E">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#what-veil-masks">What it masks</a> ·
  <a href="docs/HARNESSES.md">Agents</a> ·
  <a href="#what-it-reads">What it reads</a> ·
  <a href="#configure">Configure</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#what-veil-cannot-do">Limits</a>
</p>

Coding agents read your files and run your commands, and everything they see goes to the model and into the session file on disk: the `.env` they open, the `docker inspect` they run, the key you paste into a prompt. veil sits between the agent and the model and swaps each secret for a named placeholder before the model sees it. It works with Claude, GPT, Gemini, Grok, DeepSeek, open models and the agents built on them.

```text
$ cat .env                                    # what runs on your machine
API_TOKEN=4f9c2a…
DATABASE_URL=postgres://app:hunter2…@db:5432/app

API_TOKEN=[veil:API_TOKEN]                    # what the model reads
DATABASE_URL=[veil:DATABASE_URL]
```

## Why veil

- 🔑 **It knows your real values, not just key formats.** veil reads the secrets you already keep and masks those exact values wherever they show up: shell output, logs, `docker inspect`, error messages, even base64-encoded or JSON-escaped. Pattern-only scanners miss a plain password, a custom token or one line of a private key.
- 🧭 **It also catches secrets it has never seen.** The [gitleaks](https://github.com/gitleaks/gitleaks) rule set, kept current every week, plus veil's own rules for what gitleaks misses: agent OAuth tokens, passwords in config files and connection strings, auth headers, passwords on command lines and private keys cut off mid-output.
- 🛡️ **It covers the paths to the model.** Prompts, tool results and errors, the model's own text, the system prompt and `CLAUDE.md` or `AGENTS.md`, attachments, skills, slash-command arguments and messages between sessions. In Claude Code and Pi it also masks the records the screen and the session file keep.
- 🤝 **Almost any agent, any model.** Native plugins for Claude Code, Pi, opencode and Kilo Code, and `veil proxy` for Codex, Copilot CLI, Grok Build, Gemini CLI, Crush, Goose, Aider, Cline, Continue, Zed, grok-cli and anything else that takes a custom API URL.
- ✍️ **Your agent still works with your secrets.** Placeholders keep their names, and when the agent edits the file a secret came from, or one that already holds it, veil writes the real value back into that edit, and nowhere else.
- 🏠 **Nothing leaves your machine.** The plugins make no network calls and call no model; the Pi plugin runs your own `!` commands through Pi's shell runner so it can mask their output. `veil proxy` forwards only your agent's own requests, to the API you point it at. Real values live only in memory; veil never logs them or writes them anywhere but back into an edit.
- 📦 **Zero runtime dependencies.** A tool that sees your secrets should not pull in code you have not read. Nothing from npm is installed when veil runs: the plugin is veil's own small TypeScript, and `claude plugin validate .` lists every call it makes and every variable it reads.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
    <img alt="veil reads your secret files and environment, keeps the files current, masks what your coding agent sends to the model, and restores real values only into their own file or one that already holds them" src="docs/assets/architecture-light.svg" width="100%">
  </picture>
</p>

1. **Read your secrets.** When a session starts, veil reads the secrets you already keep: your project's `.env` files, the credentials in your home folder and secret variables in the environment, and it reads a file again when it changes.
2. **Mask everything that goes out.** Text the agent sends to the model passes through veil first, and in Claude Code and Pi so do the records the session file keeps. Each known value, and anything a pattern rule recognises, becomes a named placeholder such as `[veil:API_TOKEN]`.
3. **Restore only where it belongs.** When the agent edits a file with a placeholder in it, veil writes the real value back only into the file that value came from, or one that already holds it. Anything else keeps its placeholder, so a prompt injection cannot use veil to copy your secret into a file that did not already hold it.

The same core runs as a plugin inside the agent where the agent allows it, and as a local proxy in front of the model API for any agent that takes a custom API URL; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What veil masks

veil makes one promise and one best effort. Everything else is out of scope, and listed here so you can plan around it.

| | What | How |
| --- | --- | --- |
| **Promise** | every value veil loads from your secret files and environment ([What it reads](#what-it-reads)) | masked exactly, wherever it appears in text the model reads: as written, base64 (anywhere inside a blob, or wrapped), URL-encoded, JSON-escaped, shell- or PowerShell-quoted, UTF-16, and line by line (lines of 16 characters or more) for multi-line values such as keys. Values of 8 characters or more are masked everywhere, except a password that is a one-case word of up to 8 letters, such as `postgres`, which is masked where it is assigned (and in base64 at 8 letters); a random-looking 6 or 7 is masked as a whole word; a shorter value from a strong name or a credential file is masked only where it is assigned, and any other shorter value not at all |
| **Best effort** | secrets veil has not loaded but whose format it knows | the [gitleaks](https://github.com/gitleaks/gitleaks) rule set and veil's own rules: agent and cloud tokens, passwords in config files, connection strings and URLs, auth headers, passwords on command lines, private keys. A format no rule knows slips through |

veil does not mask:

- a secret it has not loaded and whose format no rule knows, such as a short password typed into a prompt with nothing around it;
- a loaded value transformed any other way: reversed, hex-encoded, split by other text, encrypted or escaped more than once;
- the visible part of a token shown cut off, such as `sk-abc123…` or a truncated table column;
- images, audio, video and PDFs, and the fields an API needs unchanged, such as ids, model names, signatures, MCP server authorization tokens, thinking blocks and encrypted reasoning;
- a secret only a pattern rule would catch inside a single unbroken base64-like string over 1 MB in a JSON value, or in a whole `veil proxy` text body or upload part: veil checks such a string for loaded values only;
- text an agent sends without veil seeing it: Claude Code's `--append-system-prompt`, opencode's own side requests, instructions typed after Pi's `/compact`;
- what an agent stores outside veil's reach: opencode's database and `tool-output` folder, the session files of agents behind `veil proxy`, Pi's streamed `bash` output and its full-output log;
- anything a model does on purpose to recover a value, such as probing what veil masks or using the secret through a program it runs;
- agents whose model calls go through their own servers (Cursor, Warp).

When a new case comes up, the test is the promise: a loaded value that leaks is a bug; a new format or transformation is a request for a new rule.

## Install

| Agent | Install |
| --- | --- |
| Claude Code | the plugin, below |
| Pi, opencode, Kilo Code | `veil init pi`, `veil init opencode` or `veil init kilo` |
| Codex, Copilot CLI, Grok Build, Gemini CLI, Crush, Goose, Aider, Cline, Continue, Zed, grok-cli | run `veil proxy` and point the agent at it |

[docs/HARNESSES.md](docs/HARNESSES.md) has the exact setup for each agent, and [INSTALL.md](INSTALL.md) installs the `veil` command on macOS, Linux and Windows.

### Claude Code

In a Claude Code session in the terminal:

```text
/plugin install veil --marketplace goncaloneves/veil
```

Answer `y` to add the marketplace, then pick the user scope. Or from a shell:

```sh
claude plugin marketplace add goncaloneves/veil
claude plugin install veil@veil
```

In the desktop app, click **+** next to the prompt box, then **Plugins**, **Add marketplace** with `goncaloneves/veil`, then **Add plugin**.

veil starts in every new session. Run `/veil` in a session to see what it reads and what it masked. [INSTALL.md](INSTALL.md) covers updates, the command-line tool and uninstalling.

## What it reads

veil reads the secrets you already keep, on macOS, Linux, servers, containers and Windows, each from its usual place and from the variable that moves it (`AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`, `DOCKER_CONFIG`, `GH_CONFIG_DIR`, `NETRC`, `PGPASSFILE`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CLOUDSDK_CONFIG`, `XDG_CONFIG_HOME`, `APPDATA` and more):

| Source | What veil takes from it |
| --- | --- |
| the project, three folders deep | `.env` files in the usual spellings (`.env.*`, `*.env`, `.envrc`, `.dev.vars`, `env.production`), dev-container folders, mise `[env]`, `local.settings.json`, `.streamlit/secrets.toml`, Terraform `*.tfvars`, Rails keys, project `.npmrc`, `.yarnrc.yml`, `bunfig.toml`, NuGet, gradle and composer credentials, and passwords in common config files such as `docker-compose.yml`, `database.yml` and `wp-config.php` |
| the environment veil runs in | every variable, through the policy below, in `veil proxy`, the CLI, the Pi and opencode plugins and the Claude Code plugin on Linux; on macOS and Windows the Claude Code plugin reads about 200 well-known secret names such as `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `PGPASSWORD`, `VAULT_TOKEN` and `DATABASE_URL` |
| agent credentials | Claude Code's credentials file and settings `env` (on macOS its OAuth token lives in the Keychain, where a pattern rule catches it instead), MCP server keys and headers (Claude, Cursor, Windsurf, VS Code), Codex, OpenCode, Pi, Gemini CLI, Copilot, aider, Continue, llm and goose |
| cloud and CLI credentials | AWS credentials, config and SSO caches, Google application default and legacy credentials, Azure token caches, s3cmd, MinIO, OpenStack `clouds.yaml`, gh, glab, Hetzner, Linode, Scaleway, Vercel, Netlify, Wrangler, Railway, Terraform, kaggle and more |
| git, registries and databases | git credentials and token URLs, netrc, npm, Docker and podman auth, cargo, gem, bundler, pip, poetry, Maven, pgpass, svn, Ansible vault password files |
| keys | `~/.ssh` (two folders deep), PuTTY, PGP and GnuPG, JWKs, Kubernetes, k3s and minikube credentials, and server key folders such as `/etc/ssl/private` |
| shell files | `export` lines in shell rc files and the files they `source`, `~/.env`, `~/.bashrc.d`, oh-my-zsh custom files, `environment.d`, fish and PowerShell profiles, and passwords in shell, PowerShell and database histories |
| server secrets | `/run/secrets`, Kubernetes service accounts and other read-only secret mounts on Linux, Vault agent and CSI secret folders, the files named by `*_PASSWORD_FILE`, `*_TOKEN_FILE`, `*_SECRET_FILE` and `*_KEY_FILE` variables, systemd `Environment=` lines and `EnvironmentFile=` files, WireGuard configs, server key folders, CIFS passwords in `/etc/fstab` |
| files you list in the config | dotenv, JSON, YAML, INI or single-value files, such as `~/.config/myapp/*.env` |

In an env file or the environment, a strong name, one with a password word in its last part (`PASSWORD`, `PASSWD`, `PASS`, `PWD`, `PW`, `PASSPHRASE`, `PASSCODE`, `SECRET`, `CREDENTIAL`, `CREDS`, `APIKEY`, `PRIVKEY`, `PASSKEY`, `PIN`, `OTP`, `PSK`, `DSN`; a trailing `_PROD`, `_DEV`, `_V2` or similar is ignored), is masked whatever its value, except `true`, `false` and the like. A weak name, one with `KEY` or `TOKEN` in it, or ending in `AUTH`, `SESSION`, `COOKIE`, `SALT` or `JWT`, is masked unless its value is a number, a path, a URL with no credentials, or plain lowercase words such as `us-east-1`; when `KEY` or `TOKEN` is not the last word, the value must also look random. A name that ends in `TYPE`, `PATH`, `HOST`, `PORT`, `URL`, `HEADER` or a similar descriptor, or that names another variable (`TOKEN_ENV`, `env_key`), is not a secret, and a name ending in `ID` or `HASH` counts only when it also holds a password word. Names are read in many shapes (`API_TOKEN_V2`, `TOKEN_GITHUB`, `GITHUB_TOKEN_RO`, `PASS_PHRASE`), and secrets inside a value are found too: JSON keys, connection-string parts such as `Password=` and `AccountKey=`, URL credentials and header lists. Public values are left alone: `NEXT_PUBLIC_*`, publishable and anon keys, site keys, OAuth client ids, a DSN URL with no password and `.env.example`. So are references to other values in files that expand them (`$VAR`, `${VAR}`, `$(…)`, `%VAR%`, `{env:…}`, `op://…`) and placeholders such as `YOUR_API_KEY_HERE`, `<your-key>` or `CHANGE_ME`.

Values of 8 characters or more are masked everywhere, except a password that is a one-case word of up to 8 letters, such as `postgres` or `password`: it is masked where it is assigned, and in base64 when it is 8 letters long, so `image: postgres:16` stays readable. A shorter value is masked everywhere as a whole word when it looks random (6 or 7 characters), and a short password from a strong name or a credential file, from 4 characters, is masked where it is assigned, such as `PGPASSWORD=…`, `--password …` or a URL, but not when the same letters appear in prose. Name a weak variable whose value is plain words, such as `JWT_KEY=mysecretkey`, in `[env] secret_keys` to mask it.

Each value is also matched in its encoded forms: base64 (anywhere inside a larger blob, or wrapped at 76 columns), UTF-16 as Windows tools write it, URL encoding, JSON escapes, shell and PowerShell quoting, and each line of 16 characters or more of a multi-line value such as a private key, whatever its line endings. Symlinked files are followed; named pipes, such as a 1Password-mounted `.env`, and files under `/proc`, `/sys` or `/dev` are never read as secret files. veil warns when a project or configured file cannot be read (not in the opencode and Kilo plugins), and lists home files it cannot read in `/veil`; root-only system files are skipped quietly. When a session starts in your home folder, veil does not walk Documents, Desktop or cloud-drive folders, so macOS never asks for access to them. After a secret file changes, veil re-reads only the files that changed.

## How Claude Code is covered

| Where a secret could reach the model | How veil covers it |
| --- | --- |
| a prompt you type or paste into | masked before the turn starts; if veil cannot check it, a notice is sent in its place |
| a tool's result: a file read, shell output, an MCP or web result | masked in the tool's own record and again in the row the model reads |
| a tool's error, such as a failing command's output | replaced by a masked error before it is stored |
| Claude's own text | masked before it is stored |
| the system prompt, `CLAUDE.md` and memory files | masked in each section and context block |
| a reminder the agent attaches | masked as it is attached |
| a file you @-mention | refused when it holds a secret, since Claude Code stores a mention as read; Claude reads it with its Read tool instead, which veil masks |
| a secret file that changes during the session | read again when Claude reads it with Read or changes it with Edit or Write, and otherwise at most every 15 seconds, so a new value is masked from then on |
| an MCP tool call that names a file and holds a placeholder | refused, since veil writes real values only through Claude Code's own Edit, Write and NotebookEdit tools |
| a skill's body, a slash command's arguments | masked before they run |
| a message to or from another session or subagent | masked in both directions |

veil fails closed and stays inside Claude Code's time limits. A row, prompt or message it cannot check in time is replaced with a notice, and if a check fails outright the prompt is not sent, the message is not delivered and the edit is refused.

## Writing secrets back

When the agent edits a file, veil turns placeholders back into real values only in the file the secret came from, or in a file that already holds that value. The plugins refuse an edit holding a placeholder they may not restore there, with the reason, so a prompt injection cannot use veil to copy a secret into a file that did not already hold it. The plugins write real values only through each agent's own file tools, never a third-party or MCP tool; `veil proxy` goes by tool name, and since it cannot refuse a tool call it leaves such a placeholder as written. A value shorter than `min_length` goes back only into its own file. Placeholders in shell commands and every other argument always stay placeholders. veil does not stop the agent from copying or moving a secret file with its own tools; keep such files out of reach with the agent's permission rules.

veil checks where a file really is, not just its name: if a secret file is swapped for a link to somewhere else during a session, veil no longer treats it as the secret's own file.

The plugins never write a placeholder where it would replace real content. A placeholder it cannot resolve, a value that has since changed in your secret files, or any placeholder while `[restore] mode` is `never` is refused, unless the file already holds that exact placeholder text, as documentation might. A key you paste into a prompt belongs to no file, so Claude cannot write it into a new `.env` for you; add it yourself, or set `[restore] mode = "always"` to restore into any file.

## Configure

Every setting is optional. `veil config init` writes a starter file, or create one yourself at `~/.config/veil/config.toml` (`%USERPROFILE%\.config\veil\config.toml` on Windows, under `XDG_CONFIG_HOME` when it is set; on macOS, `~/Library/Application Support/veil/config.toml` works too). `VEIL_CONFIG` names any other absolute path outside your projects:

```toml
[sources]
project = true          # .env and config files in the project, up to project_depth folders down
project_depth = 3
home = true             # credentials in your home folder: cloud, git, registries, agents, keys, shell files
system = true           # server secrets such as /run/secrets, Kubernetes service accounts and key folders
environment = true      # secret variables in the environment veil runs in
files = ["~/.config/myapp/*.env"]

[env]
secret_keys = ["*_DSN"]               # more variable names to treat as secret
ignore_keys = ["SENTRY_ENVIRONMENT"]  # variable names never treated as secret

[rules]
gitleaks = true         # gitleaks' rules; veil's own rules always run
disable = []            # rule ids to turn off, such as "generic-api-key"

[mask]
min_length = 8
encodings = ["base64", "url", "json", "lines"]

[restore]
mode = "holding"        # holding: the value's own file or a file that holds it; always; never
```

An invalid value falls back to its default with a warning, so a typo never turns masking off. Any setting that weakens protection is named in a warning when veil starts in Claude Code, Pi and `veil proxy`, in `/veil`, and by `veil config show`; the opencode and Kilo plugins do not show it. After editing the file, run `/veil reload` in Claude Code; elsewhere restart the agent or `veil proxy`.

## Commands

In a Claude Code session:

| Command | What it does |
| --- | --- |
| `/veil` | what veil reads, how many values and rules are active, and what it masked this session, by name, never by value |
| `/veil reload` | read the config and your secret files again |

From a shell, after installing the [command-line tool](INSTALL.md#command-line-tool):

| Command | What it does |
| --- | --- |
| `veil scan [file …]` | print files, or stdin, with secrets masked; exits 1 when it masked something |
| `veil sources` | list the secret files veil reads and the names of the values in each, never the values |
| `veil config [path\|show\|init]` | where the config is, the settings in effect, or a starter file |
| `veil doctor` | check the config, the sources, the rules, the Claude Code version and the plugin |
| `veil init [claude\|pi\|opencode\|kilo]` | install veil into an agent; Claude Code when none is named |
| `veil proxy` | mask what an agent that takes a custom API URL sends to its model, through a server on `127.0.0.1:8345`; see [docs/HARNESSES.md](docs/HARNESSES.md) |

`veil scan` works as a filter anywhere: `kubectl logs api | veil scan`.

## What veil cannot do

> [!WARNING]
> veil restores a value into an edit before Claude Code's permission step checks that edit, so in auto mode its permission classifier, and an approval card shown through Remote Control, can see the real value. If you use either, set `[restore] mode = "never"`.

Beyond [What veil masks](#what-veil-masks):

- **Change what your programs see.** Commands Claude runs still read real values, as they need to. veil changes only what reaches the model.
- **Rewrite a few records Claude Code pins:** thinking blocks and the tool calls Claude writes. They only ever hold what Claude was shown, which veil masked.
- **Hide a value from the screen before it is masked.** Claude Code notes that the screen, an SDK stream or Remote Control may show a row just before plugins rewrite it. The model and the session file never read that form.

> [!IMPORTANT]
> veil is a strong second layer, not the first. Keep secrets out of reach in the first place: Claude Code's [deny rules](https://code.claude.com/docs/en/permissions) for `.env` and `~/.ssh` stop the reads veil would otherwise have to mask.

## Works well with

- **[rtk](https://github.com/rtk-ai/rtk)** shrinks command output; veil masks what is left. They run side by side.
- **Deny rules** in `~/.claude/settings.json` block the reads; veil catches what still gets through.

## Agents

| Agent | How | Tested |
| --- | --- | --- |
| Claude Code 2.1.287 or later, 2.1.299 in the VS Code and Cursor extension (terminal, extension, desktop app) | native plugin | 2.1.308 and 2.1.316, in real sessions |
| Pi | native extension | 1.4.0, in real sessions |
| opencode | native plugin | 1.19.5, in real sessions |
| Kilo Code | native plugin, the opencode format | not tested; its CLI loads the opencode plugin |
| Codex | `veil proxy` | 0.166, in real sessions through the proxy |
| Copilot CLI (own key), Grok Build, Gemini CLI (API key), Crush, Goose, Aider, Cline, Continue, Zed, grok-cli | `veil proxy` | settings from each tool's documentation |
| Cursor, Warp | not supported: their model calls go through their own servers | |

[docs/HARNESSES.md](docs/HARNESSES.md) has the setup for each, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) how an adapter plugs in.

## Development

```sh
npm ci
npm test                    # unit tests, Node's own runner
npm run typecheck           # the core is checked with no Node or DOM types
claude plugin validate .    # what the Claude Code adapter hooks and calls
claude plugin test .        # the adapter's tests, inside Claude Code's runtime
claude --plugin-dir .       # try your working copy in a session
npm run build:adapters      # bundle the Pi and opencode adapters into dist/ (needs Bun)
```

veil has no runtime dependencies. [CONTRIBUTING.md](CONTRIBUTING.md) has the conventions, and [SECURITY.md](SECURITY.md) how to report a vulnerability.

## License

[MIT](LICENSE). The pattern rules are converted from [gitleaks](https://github.com/gitleaks/gitleaks), MIT licensed; see [NOTICE](NOTICE).
