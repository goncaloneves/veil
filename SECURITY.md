# Security

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, and never include a real secret in a report; describe the shape of the value instead.

You get an answer within a week. Fixes ship as a new release, and the advisory credits you unless you ask otherwise.

Only the latest release is supported.

## What veil protects

veil keeps secret values out of what a coding agent sends to its model and stores in its session files. It does that inside the agent's own process, or in `veil proxy` between the agent and the model API:

- It reads your secret files when a session starts, re-reads a file when it changes (checking at most every 15 seconds, and whenever a secret file is read), keeps the values in memory, and never writes them anywhere or logs them.
- The plugins make no network requests and call no model; the Pi plugin runs your own `!` commands through Pi's shell runner so it can mask their output. In Claude Code, `claude plugin validate .` lists every call the plugin makes and every environment variable it reads.
- `veil proxy` listens only on `127.0.0.1`, answers only requests addressed to localhost, refuses browser requests and WebSocket upgrades, forwards only to its configured routes, and never logs a body, a header or a URL. Your API credentials pass through to the upstream untouched. A request body it cannot decode is refused, never forwarded unmasked.
- It fails closed: content it cannot check, or cannot check within the agent's time limits, is withheld from the model, not passed through.
- It writes a real value back only into an edit of the file that value came from (checked by where the file really resolves, not its name), or of a file that already holds it, and the plugins refuse any other edit that would carry a known secret. `veil proxy` leaves such a placeholder as written. A prompt injection therefore cannot use veil to place a secret where it could be sent out.
- It refuses an @-mention of a file that holds a secret, because Claude Code stores a mentioned file as read.
- The plugins never write a placeholder over real content: an edit holding a placeholder they cannot restore is refused unless the file already holds that exact text. `veil proxy` cannot refuse a tool call, so there the placeholder is written as is.
- It reads only regular files and links to them, never named pipes, sockets or devices.
- A config file can only weaken protection from your own machine: `VEIL_CONFIG` must be an absolute path outside the project, and every weakened setting is named in a warning when a Claude Code or Pi session or `veil proxy` starts, and by `veil config show`.

## What it does not protect against

- A program the agent runs reads real values, as it must to work. veil changes what the model sees, not what your code sees.
- A secret veil has never seen and that matches no known format.
- A value transformed in a way veil does not try: split, hex-encoded, reversed, or encrypted.
- The agent's own interface showing a row in the instant before plugins rewrite it.
- Text the agent adds after plugins run, such as Claude Code's `--append-system-prompt`.
- A restored value seen by the agent's permission step: in Claude Code's auto mode its classifier, and an approval card shown through Remote Control, see the edit veil restored. Set `[restore] mode = "never"` if you use either.
- Through `veil proxy`, the agent's own local session files: they can hold tool output with real values, and the edits veil restored. Neither reaches the model.
- Agents whose model calls go through their vendor's servers, such as Cursor and Warp.
- A model that deliberately works to recover a value: printing it transformed, probing what veil masks, or using the secret through a program it runs. veil keeps secrets out of what the model reads by accident, not away from an agent that has turned against you; the agent's permission rules are the defence there.
- Binary request bodies: `veil proxy` forwards images, audio, video and PDFs unmasked, since it cannot read them.
- Signed thinking and encrypted reasoning blocks, which are sent back as they were because changing them breaks the API.
- Through the opencode plugin, opencode's own database and `tool-output` folder: they can hold tool output, diffs and the edits veil restored. opencode's own side requests, such as generating an agent, do not pass through plugins.
- In Pi, the output of the model's `bash` tool while it streams, the full-output log Pi writes for long runs, and instructions typed after `/compact`.
- Through `veil proxy`, an MCP tool that an agent exposes under the bare name of a built-in file tool: the proxy trusts tool names, so such a tool would receive real values. Claude Code, Codex, Pi and opencode prefix MCP tool names.
- An attacker with access to your machine or to the agent's process.

Treat veil as a second layer behind the agent's own permission rules, which should stop reads of secret files in the first place.
