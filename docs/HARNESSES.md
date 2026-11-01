# Using veil with your coding agent

veil works with any model and almost any coding agent. How it plugs in depends on what the agent allows:

| Agent | How veil runs | What it covers |
|---|---|---|
| **Claude Code** | Native plugin | Every text the model reads, except `--append-system-prompt`, and everything the transcript keeps |
| **Pi** | Native extension | Every text the model reads, compaction and tree summaries included but not `/compact` instructions, and the saved session, including your own `!` commands |
| **opencode** | Native plugin | Every text the model reads except opencode's own side requests; its database and its `tool-output` folder can still hold tool output, diffs and the edits veil restored |
| **Kilo Code** | Native plugin (opencode format) | Same as opencode |
| **Codex**, **Copilot CLI**, **Grok Build**, **Gemini CLI**, **Crush**, **Goose**, **Aider**, **Cline**, **Continue**, **Zed**, **grok-cli**, any tool that takes a custom API URL | `veil proxy` | Every text the agent sends; its own session files may still hold tool output and restored edits |
| **Cursor**, **Warp** | Not supported | Their model traffic goes through their own servers, so nothing local can mask it |

Claude Code, Pi, opencode, and Codex through the proxy are tested end to end in real sessions. opencode loads plugins from both `plugin/` and `plugins/` in its config folder; Kilo Code's CLI loads them from `~/.config/kilo/plugin/`, and its VS Code and JetBrains extensions are not confirmed. The other proxy settings below come from each tool's own documentation; if a release changes them, please open an issue.

## Native plugins

```sh
veil init            # Claude Code
veil init pi         # Pi: ~/.pi/agent/extensions/veil.js
veil init opencode   # opencode: ~/.config/opencode/plugins/veil.js
veil init kilo       # Kilo Code: ~/.config/kilo/plugin/veil.js
```

Each `init` for Pi, opencode or Kilo downloads the adapter built for your veil version from the GitHub release and checks it against the release's `SHA256SUMS`. Without the CLI, download `veil-pi.js` or `veil-opencode.js` from the [latest release](https://github.com/goncaloneves/veil/releases/latest) into the folder shown.

The native plugins restore and refuse edits exactly like the Claude Code plugin: a placeholder goes back only into its value's own file or a file that already holds it, and an edit holding any other placeholder is refused. They write real values only through the agent's own file tools; a third-party or MCP tool call that names a file and holds a placeholder is refused, since it would write the placeholder over real content.

`veil init <agent> --from <file>` installs a bundle you built yourself, without a checksum.

## veil proxy

`veil proxy` is a small server on `127.0.0.1` that sits between your agent and its model API. Start it in the folder you start your agent in: it loads the secret files of the project around it (the git root above it, or the folder you give `--root`), and it always reads relative file paths in tool calls from the folder it was started in, as the agent does. Run one proxy per project on its own `--port`:

```sh
cd ~/code/my-app
veil proxy            # http://127.0.0.1:8345
```

Then point your agent at a route. The route names the upstream API:

| Route | Upstream |
|---|---|
| `/openai` | `https://api.openai.com` |
| `/codex` | `https://chatgpt.com/backend-api/codex` (Codex with a ChatGPT login) |
| `/anthropic` | `https://api.anthropic.com` |
| `/xai` | `https://api.x.ai` |
| `/gemini` | `https://generativelanguage.googleapis.com` |
| `/openrouter` | `https://openrouter.ai/api` |
| `/deepseek`, `/groq`, `/mistral`, `/together`, `/fireworks`, `/cerebras`, `/moonshot`, `/zai` | Each provider's API |
| `/ollama`, `/lmstudio` | Local Ollama (`:11434`) and LM Studio (`:1234`) |

Add your own with `--route name=https://host/base`, change the port with `--port`, and the project folder with `--root`.

What the proxy does:

- Masks every request body: the OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, Gemini and Ollama formats and any other JSON field by field, other text whole, and the text parts of a multipart upload. Fields the API needs unchanged, such as ids, model names, signatures and encrypted reasoning, and images stay untouched; everything inside tool inputs, outputs and descriptions is masked. It adds a short note to the system prompt that explains the placeholders. Compressed bodies (gzip, deflate, Brotli, zstd) are unpacked first. A body it cannot read, binary other than images, audio, video or PDF, or a request it cannot check in time is refused, never forwarded.
- Writes real values back only into the content of a file-writing tool call whose target is the value's own file or a file that already holds it. It knows each agent's built-in file tools by their exact names (`Write`, `Edit`, `write`, `edit`, `apply_patch`, `write_file`, `search_replace`, `str_replace_editor` and so on, and Gemini CLI's `replace` on Gemini requests); a tool under any other name, MCP included, never gets real values. Shell commands, URLs and every other argument keep their placeholders. Those calls are held until complete, then sent once; every other tool call streams through as it arrives.
- Masks the same text the same way on every request, so prompt caches keep working. When it learns a new secret, it masks that secret in earlier messages too, which can cost one cache miss.
- Answers only on `127.0.0.1`, refuses browser requests and WebSockets, forwards only to its routes, and never follows a redirect. Your API key passes through untouched and is never logged.

`P` below is `http://127.0.0.1:8345`.

### Codex

In `~/.codex/config.toml`, with an API key:

```toml
model_provider = "veil"

[model_providers.veil]
name = "veil"
base_url = "http://127.0.0.1:8345/openai/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
```

With a ChatGPT login, use `base_url = "http://127.0.0.1:8345/codex"`, remove `env_key` and add `requires_openai_auth = true`. Leave `supports_websockets` off: the proxy refuses WebSockets and Codex falls back to HTTP.

### GitHub Copilot CLI (bring your own key)

```sh
export COPILOT_PROVIDER_TYPE=anthropic
export COPILOT_PROVIDER_BASE_URL=http://127.0.0.1:8345/anthropic
export COPILOT_PROVIDER_API_KEY=...   # your Anthropic key
export COPILOT_MODEL=...
```

Or `COPILOT_PROVIDER_TYPE=openai`, `COPILOT_PROVIDER_BASE_URL=P/openai/v1` and `COPILOT_PROVIDER_WIRE_API=responses`. Copilot's reference calls these variables legacy: a provider in `~/.copilot/providers.json` takes precedence, so set its `baseUrl` there if you have one. GitHub-hosted models cannot be redirected.

### Grok Build

In `~/.grok/config.toml`, with `XAI_API_KEY` set, as Grok Build needs for a custom inference URL:

```toml
[endpoints]
models_base_url = "http://127.0.0.1:8345/xai/v1"
```

### Gemini CLI

```sh
export GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8345/gemini
```

This works with API-key sign-in. The Google-login route goes to Code Assist, which the proxy does not cover yet. Gemini CLI's edit tool is named `replace`, so veil restores into it only on Gemini-format requests, where that bare name belongs to the built-in tool.

### Crush

```sh
export ANTHROPIC_API_ENDPOINT=http://127.0.0.1:8345/anthropic
```

### Goose

```sh
export GOOSE_PROVIDER=anthropic ANTHROPIC_HOST=http://127.0.0.1:8345/anthropic
```

### Aider

```sh
aider --openai-api-base http://127.0.0.1:8345/openai/v1 --model openai/<model>
# or
ANTHROPIC_BASE_URL=http://127.0.0.1:8345/anthropic aider --model anthropic/<model>
```

Aider edits through search-and-replace blocks in the model's text, not tool calls, so the proxy leaves placeholders there as written. A search block that names a placeholder will not match the real file, so Aider reports it; a placeholder in a replacement or a whole-file edit is written as is.

### Cline

Set the Anthropic provider's custom base URL to `P/anthropic`, or the OpenAI Compatible provider's base URL to `P/openai/v1`. CLI: `cline auth -p anthropic -k <key> -b http://127.0.0.1:8345/anthropic`.

### Continue

In `config.yaml`:

```yaml
models:
  - name: Claude via veil
    provider: anthropic
    model: <model>
    apiBase: http://127.0.0.1:8345/anthropic/v1/
```

### Zed

In `settings.json`:

```json
{ "language_models": { "anthropic": { "api_url": "http://127.0.0.1:8345/anthropic" } } }
```

### grok-cli

```sh
export GROK_BASE_URL=http://127.0.0.1:8345/xai/v1
```

### Local models

Point the tool's OpenAI-compatible URL at `P/ollama/v1` or `P/lmstudio/v1`, or Ollama's native URL at `P/ollama`.

## Limits

- **The proxy sees only what goes over the wire.** History an API keeps on its servers (`previous_response_id`, `store: true`, Gemini cached contents) was masked when it was first sent, as long as the proxy was in place from the start.
- **Session files.** Through the proxy, the agent's own local session files can still hold tool output and restored edits with real values. They never reach the model. The Claude Code and Pi plugins mask those too; opencode's database keeps what its tools return.
- **Media.** Images, audio, video and PDFs pass through unmasked, since veil cannot read them.
- **Thinking.** Signed thinking and encrypted reasoning blocks are sent back as they were, because changing them breaks the API. They only hold what the model was shown.
- **Large requests.** veil masks each request before forwarding it. A very large first request can hold up other requests through the same proxy for up to five seconds; past that it is refused.
- **Tool names.** Through the proxy, veil trusts a tool by its name. An agent that exposes an MCP server's tool under the bare name of a built-in file tool, such as `write_file` or `edit_file`, would let that server receive real values. Claude Code, Codex and Pi prefix MCP tool names. opencode names one `<server>_<tool>`: in its plugin only a server named `apply` with a `patch` tool could pass for `apply_patch`, but through the proxy any pair that joins into a name veil trusts, such as `write` and `file` for `write_file`, could.
- **Pi.** Output the model's own `bash` tool streams while it runs, and the full-output log file Pi keeps for a long run (`pi-bash-*.log` in the system temp folder), are written before veil sees them; the result the model reads is masked. So are your own `!` commands, end to end. Instructions you type after `/compact` go to the summarizer as written.
- **opencode.** Requests opencode makes on its own, such as generating an agent with `opencode agent create`, do not pass through plugins.
- **Cursor and Warp** route model calls through their own servers, so neither a local proxy nor a plugin can mask what they send.
