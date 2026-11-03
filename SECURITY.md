# Security

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, and never include a real secret in a report; describe the shape of the value instead.

You get an answer within a week. Fixes ship as a new release, and the advisory credits you unless you ask otherwise.

Only the latest release is supported.

## What veil protects

veil keeps secret values out of what a coding agent sends to its model and, in Claude Code and Pi, out of what it stores in its session files. It does that inside the agent's own process, or in `veil proxy` between the agent and the model API:

- It reads your secret files when a session starts, re-reads the ones that changed as the agent works (checking at most every 15 seconds, and in the plugins also when the agent reads a secret file), keeps the values in memory, never logs them, and writes them only back into an edit.
- The plugins make no network requests and call no model; the Pi plugin runs your own `!` commands through Pi's shell runner so it can mask their output, and warns when it cannot. In Claude Code, `claude plugin validate .` lists every call the plugin makes and every environment variable it reads by name; on Linux it also reads the whole environment from `/proc/self/environ`.
- `veil proxy` listens only on `127.0.0.1`, answers only requests addressed to localhost, refuses browser requests and WebSocket upgrades, forwards only to its configured routes, and never logs a body, a header or a URL. Your API credentials pass through to the upstream untouched. A request body it cannot decode is refused, never forwarded unmasked, unless it is an image, audio, video or PDF, which it forwards as is.
- It fails closed: text it cannot check, or cannot check within the agent's time limits, is withheld from the model, not passed through. Images, audio, video and PDFs pass unchecked, and a single base64-like string over 1 MB is checked for loaded values only.
- By default (`[restore] mode = "holding"`), it writes a real value back only into an edit of the file that value came from (checked by where the file really resolves, not its name), or of a file that already holds it, and the plugins refuse any other edit holding a placeholder for a known secret. `veil proxy` leaves such a placeholder as written. A prompt injection therefore cannot use veil to copy a secret into a file that did not already hold it. `mode = "always"` gives that up and restores into any file.
- In Claude Code, it refuses an @-mention of a secret file, or of a file that holds a secret or that it cannot check, because Claude Code stores a mentioned file as read. Images, audio, video and PDFs pass unchecked.
- Through the agent's own file tools, the plugins never write a placeholder over real content: an edit holding a placeholder they cannot restore is refused unless the file already holds that exact text. A shell command, or a tool whose arguments do not name a file the way veil recognises, writes the placeholder as is, and `veil proxy` cannot refuse a tool call, so there too the placeholder is written as is.
- It reads only regular files and links to them, never named pipes, sockets or devices.
- A config file can only weaken protection from your own machine: `VEIL_CONFIG` must be an absolute path outside the project, and every weakened setting is named in a warning when a Claude Code or Pi session or `veil proxy` starts, and by `veil config show`; the opencode and Kilo plugins do not show it.

## What it does not protect against

- A program the agent runs reads real values, as it must to work. veil changes what the model sees, not what your code sees.
- A secret veil has never seen and that matches no known format, or that a rule skips: `password-assignment` skips, among others, a value without digits made of letters, alone or joined by `-`, `_`, `.`, `:` or `/`, a value containing a placeholder word such as `example`, a value that reads as code, and one that holds non-ASCII characters.
- A loaded value too short to mask: under 4 characters, or under `min_length` (8) when it comes from neither a strong name nor a credential file and is not a random-looking 6 or 7.
- A secret file veil does not read: one whose name it does not recognise and that is not listed in `[sources] files`; one in a folder the project walk skips, such as `node_modules` or a dot-folder other than `.devcontainer`, `.docker`, `.streamlit` and `.secrets`, or Documents, Desktop and similar folders when a session starts in the home folder; one deeper than `project_depth`, past the first 2,000 folders of the walk, past the first 256 files of a home or system folder veil reads, such as `~/.ssh` or `/run/secrets`, or over 8 MiB (of a history, only the last 8 MiB is read); one inside a linked folder, which neither the project walk nor a home or system folder follows; a shell file sourced past the first 32 that veil follows, or more than 3 levels deep; and one added to a project subfolder that held none, until veil next walks the project.
- The visible part of a token shown cut off, such as `sk-abc123…`.
- A secret only a pattern rule would catch, inside a single base64-like string over 1 MB.
- The agent copying or moving a secret file with its own tools.
- A value transformed in a way veil does not try: split by other text, hex-encoded, reversed, encrypted, encoded twice (base64 of base64, URL-encoded twice, JSON-escaped three times), backslash-escaped character by character, or UTF-16 inside a JSON-escaped string.
- A password veil masks only where it is assigned (short, a default word, or the project's name) shown outside an assignment, such as in a table cell, after its flag in an argument list, or under a generic `value` key.
- The agent's own interface showing a row in the instant before plugins rewrite it.
- Text the agent adds after plugins run, such as Claude Code's `--append-system-prompt`.
- A restored value seen by the agent's permission step: in Claude Code's auto mode its classifier, and an approval card shown through Remote Control, see the edit veil restored. Set `[restore] mode = "never"` if you use either.
- Through `veil proxy`, the agent's own local session files: they can hold tool output with real values, and the edits veil restored. Neither reaches the model.
- Agents whose model calls go through their vendor's servers, such as Cursor and Warp.
- A model that deliberately works to recover a value: printing it transformed, probing what veil masks, or using the secret through a program it runs. veil keeps secrets out of what the model reads by accident, not away from an agent that has turned against you; the agent's permission rules are the defence there.
- Images, audio, video and PDFs: veil cannot read them, so the plugins and `veil proxy` pass them unmasked, including binary request bodies and upload parts. Fields an API needs unchanged, such as ids, model names, signatures and MCP server authorization tokens, are sent as they are.
- Signed thinking and encrypted reasoning blocks, which are sent back as they were because changing them breaks the API.
- Through the opencode plugin, opencode's own database, `tool-output` folder and `run --format json` output: they can hold tool output, diffs and the edits veil restored. opencode's own side requests skip veil's message hooks, so the description you type for `opencode agent create` is sent as written.
- In Pi, the output of the model's `bash` tool while it streams, the full-output log Pi writes for long runs, instructions typed for `/compact` or a custom `/tree` summary, and the output of your `!` commands saved when veil cannot wrap Pi's shell runner.
- An MCP tool that an agent exposes under the bare name of a built-in file tool: `veil proxy` trusts tool names, so such a tool would receive real values. Claude Code, Codex and Pi prefix MCP tool names. opencode names one `<server>_<tool>`: in its plugin only a server named `apply` with a `patch` tool could pass for `apply_patch`, but through the proxy any pair that joins into a name veil trusts, such as `write` and `file` for `write_file`, could.
- An attacker with access to your machine or to the agent's process.

Treat veil as a second layer behind the agent's own permission rules, which should stop reads of secret files in the first place.
