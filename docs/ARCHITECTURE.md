# Architecture

veil is a core that knows nothing about agents, plus one thin adapter per agent.

```text
            secret files, environment                      agent events
                       │                                          │
        ┌──────────────▼──────────────┐            ┌──────────────▼──────────────┐
        │ sources: parse and classify │            │ adapter (hooks/register.ts) │
        │ dotenv, aws, ssh, gh, npm…  │            │ prompts, rows, tool results │
        └──────────────┬──────────────┘            │ system prompt, edits        │
                       │ Secret[]                  └──────┬───────────────▲──────┘
        ┌──────────────▼──────────────┐                   │ text          │ masked text,
        │ engine: config + sources    │                   │               │ restored edits
        └──────────────┬──────────────┘            ┌──────▼───────────────┴──────┐
                       └──────────────────────────►│ core: Masker                │
                                                   │ known values + gitleaks     │
                                                   │ rules → Vault of labels     │
                                                   └─────────────────────────────┘
```

## Core (`src/core`)

- **`Masker`** finds secrets in a text and replaces them with `[veil:LABEL]`. It combines two detectors in one sorted pass: overlapping hits merge into a single span, so no tail of a secret is left visible. Only placeholders the vault knows are left alone, so masking is idempotent and a secret wrapped to look like a placeholder is still masked. A deadline bounds the work; past it, `MaskTimeout` lets the adapter withhold the text instead of overrunning the agent's time limit.
- **Known values** (`known.ts`) are the exact secrets from your files, plus their base64, base64url, URL-encoded and JSON-escaped forms, and each line of a multi-line value. Matching is exact substring search, longest first.
- **Rules** (`rules.ts`) run the gitleaks rule set and veil's own (`src/rules/veil.ts`): a keyword prefilter, the regular expression, the secret group, an entropy floor, and the rule's and the global allowlists. Generic rules also need a digit, as in gitleaks. A rule runs on groups of whole lines up to about 8 KB, each group overlapping the next by two lines, and only on groups that hold one of its keywords; a line over 32 KB is split into 32 KB windows overlapping by 8 KB. One regular expression therefore never sees more than one window, while a value written on the line after its key, or a token up to 8 KB long, is still seen whole. Rules that span many lines, such as private keys, run on the whole text.
- **`Vault`** maps each masked text to a stable label. Every known value is registered when the masker is configured, labelled by its name (`DATABASE_URL`, `DATABASE_URL~base64`) and, when two files share a name, by its file (`API_KEY@.env.test`), so the same labels come back in a resumed session. A rule hit gets its rule and a salted hash (`github-pat#3fa2c1`), so the label never reveals the value. The vault also records which file a known value came from, for the restore rule.

The core uses no Node, browser or agent API, so it runs in any JavaScript runtime, including Claude Code's sandboxed mod environment.

## Sources and config (`src/sources`, `src/config`)

Parsers turn file contents into `Secret`s: dotenv (with the secret-name policy in `env-policy.ts`), AWS, netrc, pgpass, git credentials, npm, Docker, gh, kube and private keys. `loadSecrets` walks the project and the home folder through a `SourceFs` the adapter supplies, so it never touches a file system itself. The config is TOML, parsed by a small parser in `toml.ts`; an invalid value warns and keeps its default.

## Engine (`src/engine.ts`)

`loadState` reads the config and the sources; `maskerSettings` turns that state into the settings a `Masker` takes. Every adapter and the CLI use these two calls.

## Rules (`src/rules`, `scripts`)

`src/rules/gitleaks.ts` is generated from gitleaks' `config/gitleaks.toml` by `scripts/sync-gitleaks.ts`. RE2 syntax that JavaScript lacks (scoped `(?i:…)` and `(?-i:…)`, a mid-pattern `(?i)`, `(?s:…)`, `\z`, POSIX classes) is rewritten into plain JavaScript by `scripts/lib/re2.ts`, expanding case-insensitive letters into `[aA]` classes. The output needs no regex flags and behaves the same in every engine. Rules limited to file paths are left out, since a conversation has none.

## The Claude Code adapter

`hooks/register.ts` is the plugin's hooks module. It holds every `$` call, as Claude Code requires, and delegates the work to `VeilSession` in `src/adapters/claude-code/session.ts`:

| Event | What veil does |
| --- | --- |
| `session.start` | reads the environment and the secret files, configures the masker, registers `/veil` |
| `prompt.submit` | masks the prompt and its context; drops it if it cannot |
| `session.append` | masks every row before it is stored and sent; withholds it if it cannot |
| `tool.call` (every tool) | masks the tool's result record, which the screen and the transcript keep, and turns an error holding a secret into a masked refusal |
| `tool.call` (Edit, Write, NotebookEdit) | restores placeholders only into the value's own file or a file that already holds it, refuses other edits that carry a known secret, and reloads after a secret file changes |
| `prompt.mention` | refuses an @-mention of a file that holds a secret, since Claude Code stores the mention as read |
| `prompt.compose`, `prompt.context`, `prompt.attachment` | masks the system prompt, the context blocks and attachments; adds veil's note for the model |
| `skill.prompt`, `command.run` | masks skill bodies and slash-command arguments |
| `session.send`, `session.receive` | masks messages between sessions |

## The CLI (`src/cli`)

`veil` runs the same engine with a Node file system. Releases compile it into self-contained binaries with Bun.

## Adding an adapter

Write a `SourceFs` and a `VeilHost` for the agent, call `loadState`, build a `Masker`, and mask every text the agent sends to its model. Restore placeholders only in file edits, under `config.restore.mode`. Keep the adapter's tests next to it, and prove with a real session that the model and the session file never see a value.
