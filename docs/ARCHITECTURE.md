# Architecture

veil is a core that knows nothing about agents or model APIs, a session layer that every integration shares, and one thin layer per way of plugging in: a plugin inside the agent where the agent allows it, and a local proxy in front of the model API everywhere else.

```text
       secret files, environment
                  │
   ┌──────────────▼──────────────┐
   │ sources: parse and classify │
   │ dotenv, aws, ssh, gh, npm…  │
   └──────────────┬──────────────┘
                  │ Secret[]
   ┌──────────────▼──────────────┐      ┌─────────────────────────────┐
   │ engine: config + sources    ├─────►│ core: Masker                │
   └─────────────────────────────┘      │ known values + rules → Vault│
                                        └──────────────▲──────────────┘
                                                       │
                                        ┌──────────────┴──────────────┐
                                        │ session: Veil               │
                                        │ mask, refresh, restore rule │
                                        └──┬──────────┬────────────┬──┘
                                           │          │            │
                             ┌─────────────▼─┐ ┌──────▼──────┐ ┌───▼──────────────┐
                             │ Claude Code   │ │ Pi,         │ │ veil proxy       │
                             │ plugin        │ │ opencode,   │ │ + wire formats   │
                             │ (hooks)       │ │ Kilo plugins│ │ (any agent)      │
                             └───────────────┘ └─────────────┘ └──────────────────┘
```

## Core (`src/core`)

- **`Masker`** finds secrets in a text and replaces them with `[veil:LABEL]`. It combines two detectors in one sorted pass: overlapping hits merge into a single span, so no tail of a secret is left visible. Placeholders the vault knows are left alone, so masking is idempotent; a known value wrapped to look like a placeholder is still masked, but a rule hit inside any `[veil:…#hex]` is not. A deadline bounds the work everywhere, known-value search included; past it, `MaskTimeout` lets the caller withhold the text instead of overrunning a time limit. `knownOnly` skips the rules and views, which `Veil` uses for a single unbroken base64-like string over 1 MB inside a JSON value, a `veil proxy` text body or an upload part, such as an image in a field veil does not know: its known values are still found, in about 0.2 seconds for 16 MB.
- **Known values** (`known.ts`) are the exact secrets from your files and every encoded form the output might show: base64 at any byte offset or wrapped at 76 columns, base64 of UTF-16, URL encodings, JSON escapes, shell, PowerShell and cmd quoting, Unicode normalisations, and each line of a multi-line value with any line ending. They are found with a rolling-hash index, and each line of a multi-line value only when it has 16 characters or more. How far a value is masked depends on its length and source (`scopeOf`): `min_length` (8) characters or more everywhere; a random-looking 6 or 7 as a whole token; a shorter value from a strong name or a credential file, or a proven password that is a default word such as `postgres` (one case, letters only, at most 8 characters), only where it is assigned (`context.ts`: `KEY=v`, `key: v`, JSON and YAML `name`/`value` pairs, flags, URLs, netrc, pgpass, PowerShell listings).
- **Views** (`views.ts`) let both detectors see text the way it was meant: NUL-separated environments, carriage-return progress output, terminal colour codes (raw or written as `\u001b[`), UTF-16 shown with a NUL between characters, and one level of JSON escapes. Known values also see lines wrapped by `base64`; rules see values wrapped by `Format-List`. Every hit maps back to the original offsets. Views are not combined, and JSON is unescaped one level deep.
- **Rules** (`rules.ts`) run the gitleaks rule set and veil's own (`src/rules/veil.ts`): a keyword prefilter, the regular expression, the secret group, an entropy floor, the rule's own allowlists and, for gitleaks rules only, gitleaks' global allowlists. One regular expression call is always bounded, so the deadline holds to within about 0.1 seconds on adversarial input (0.2 at most): a rule whose longest possible match is short runs on 1 KB windows (2 KB for matches up to 1 KB) that overlap by that length (`reach.ts`); other rules run on groups of whole lines up to 12 KB, overlapping by the most lines any rule can span, with a long line cut into 12 KB windows overlapping by 8 KB; key-block rules run on windows around their keywords and follow a key past the window to its END line. A rule runs only on windows that hold one of its keywords, and never matches inside or across a placeholder.
- **`Vault`** maps each masked text to a stable label: a known value by its name (`DATABASE_URL`, `DATABASE_URL~base64`) and, when two files share a name, by its file (`API_KEY@.env.test`); a rule hit by its rule and a salted hash (`github-pat#3fa2c1`), so the label never reveals the value. It records which file each known value came from, for the restore rule.
- **`paths.ts`** and **`text.ts`** compare POSIX and Windows paths (case-folded where the file system is) and decode UTF-16 or BOM-marked files.

The core uses no Node, browser or agent API, so it runs in any JavaScript runtime, including Claude Code's sandboxed mod environment.

## Sources and config (`src/sources`, `src/config`)

Parsers turn file contents into `Secret`s, each marked `strong` when its source proves it is a secret; a value found in several files keeps all of them. `loadSecrets` walks the project and the home folder through a `SourceFs` the caller supplies, so it never touches a file system itself. It never reads kernel files or named pipes as secret files, and skips anything over 8 MiB except a shell history, whose last 8 MiB it reads in the CLI and the Node plugins. It skips references (`${VAR}`, `{env:…}`) and placeholders as values, and on a refresh re-reads only files whose size, time or inode changed, re-walking the project every few minutes. The config is TOML, parsed by a small parser in `toml.ts`; an invalid value warns and keeps its default.

## Engine (`src/engine.ts`)

`loadState` reads the config and the sources; `maskerSettings` turns that state into the settings a `Masker` takes.

## Session (`src/session.ts`, `src/restore.ts`)

`Veil` is the runtime every integration shares. It loads the state, masks strings and whole JSON values (`maskValue`, with a `Skip` spec for ids, signatures and media), reloads the secret files at most every 15 seconds, and sooner when a plugin sees one read or edited, and owns the restore rule: a placeholder becomes its real value only in a file that already holds the value, or in the value's own source file when that path still resolves to the same real file it did when veil last read it. `restore.ts` applies the rule to tool calls: only to each integration's exact file-writing tools (`CLAUDE_TOOLS`, `PI_TOOLS`, `OPENCODE_TOOLS`, `PROXY_TOOLS`, plus `GEMINI_TOOLS` on Gemini requests), only in their content fields, only when the call names exactly one file with no padding, and in `apply_patch` text per file section, split on any header Codex or opencode would accept, never in a section that moves its file or names none. A value shorter than `min_length` goes back only into its own file, so a file of guesses cannot prove it. It reports the first refusal so a plugin can deny the call; the plugins also refuse third-party tools that name a file and hold a placeholder.

With `cache: true`, `Veil` remembers what it masked for each text, per route, so the conversation an agent resends on every request comes out byte for byte the same and prompt caches keep working. The cache is cleared when veil learns a new secret, so earlier messages that hold it are masked too.

`maskValue` walks JSON in three modes. Structurally, it leaves the keys a `Skip` names (ids, signatures, roles) and records of the types it names (images, thinking, encrypted reasoning) as they are, and keeps base64 media by its mime type. Below the top level, inside the fields it names as free (tool inputs, arguments, outputs, metadata), it masks every string and every key. Inside schemas (tool definitions, response formats) it masks every value except schema keywords such as `type`, `pattern` and `required`.

## Wire formats (`src/wire`)

`request.ts` knows the request shapes of the OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, Bedrock Converse, Gemini and Ollama APIs and Pi's provider payloads: which fields hold text the model reads, which must never change (ids, signatures, encrypted reasoning, media), and where the system prompt goes, so veil's note can join it. `response.ts` restores placeholders in tool calls, whole or streamed: OpenAI chat argument fragments, Anthropic `input_json_delta`s and Responses argument deltas are held until the call is complete, restored once, then sent on.

## Integrations

### Claude Code (`hooks/register.ts`, `src/adapters/claude-code`)

`hooks/register.ts` holds every `$` call, as Claude Code requires, and delegates to `VeilSession`:

| Event | What veil does |
| --- | --- |
| `session.start` | reads the environment and the secret files, configures the masker, registers `/veil` |
| `prompt.submit` | masks the prompt and its context, sends a notice in place of what it cannot check in time, and drops the prompt if the hook fails |
| `session.append` | masks every row before it is stored and sent; withholds it if it cannot |
| `tool.call` (every tool) | masks the tool's result record and turns an error holding a secret into a masked refusal; refuses an MCP or MultiEdit call that names a file and holds a placeholder; reloads the secret files when one is read |
| `tool.call` (Edit, Write, NotebookEdit) | restores placeholders under the restore rule, refuses edits holding a placeholder it cannot restore, refuses the edit if the hook fails, and reloads after Edit or Write changes a secret file |
| `prompt.mention` | refuses an @-mention of a file that holds a secret, since Claude Code stores the mention as read |
| `prompt.compose`, `prompt.context`, `prompt.attachment` | masks the system prompt, the context blocks and attachments; adds veil's note for the model |
| `skill.prompt`, `command.run` | masks skill bodies and slash-command arguments |
| `session.send`, `session.receive` | masks messages between sessions |

### Pi and opencode (`src/adapters/pi`, `src/adapters/opencode`)

Both run in the agent's own Node or Bun process, bundled with the core into one file (`npm run build:adapters`), and start from the project's git root. Pi's adapter masks the provider payload in `before_provider_request` with the same code as the proxy (withholding rather than failing open when time runs out), the prompt in `input`, tool results in `tool_result`, saved messages in `message_end`, compaction and tree summaries in `session_before_compact` and `session_before_tree`, and the user's own `!` commands in `user_bash`; it restores or blocks edits in `tool_call`. opencode's masks `chat.message`, any shape of tool result in `tool.execute.after`, the history and the system prompt, and restores or refuses edits in `tool.execute.before`. Kilo Code loads the opencode plugin.

### veil proxy (`src/proxy`)

A `node:http` server on `127.0.0.1` with one route per upstream API, rooted at the project's git root. It unpacks compressed request bodies, masks JSON field by field and any other text whole (multipart text parts included), refuses binary that is not media, forwards with the caller's own credentials, and restores tool calls in the responses. It refuses other hosts, browser requests, WebSocket upgrades and upstream redirects, answers 503 rather than forwarding a request it could not check in time, and logs only an error's name and code, never a body, a header or a URL.

## The CLI (`src/cli`)

`veil` runs the same engine with a Node file system, and hosts `veil proxy` and `veil init`. Releases compile it into self-contained binaries with Bun for macOS, Linux (glibc and musl) and Windows.

## Adding an integration

If the agent has in-process plugins, wrap `Veil`: mask every text the agent sends to its model and every record it saves, restore placeholders only in file edits through `checkInput`, and deny when it refuses. If it only takes a custom API URL, it already works through `veil proxy`; add a route if its upstream is new. Either way, add tests in `test/`, and prove with a real session that the model never sees a value.
