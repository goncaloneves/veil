# Security

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, and never include a real secret in a report; describe the shape of the value instead.

You get an answer within a week. Fixes ship as a new release, and the advisory credits you unless you ask otherwise.

Only the latest release is supported.

## What veil protects

veil keeps secret values out of what a coding agent sends to its model and stores in its session files. It does that inside the agent's own process:

- It reads your secret files once per session, keeps the values in memory, and never writes them anywhere or logs them.
- It makes no network requests, starts no processes and calls no model. In Claude Code, `claude plugin validate .` lists every call the plugin makes and every environment variable it reads.
- It fails closed: content it cannot check, or cannot check within the agent's time limits, is withheld from the model, not passed through.
- It writes a real value back only into an edit of the file that value came from, or of a file that already holds it, and refuses any other edit that would carry a known secret. A prompt injection therefore cannot use veil to place a secret where it could be sent out.
- It refuses an @-mention of a file that holds a secret, because Claude Code stores a mentioned file as read.
- It never writes a placeholder over real content: an edit holding a placeholder it cannot restore is refused unless the file already holds that exact text.
- It reads only regular files and links to them, never named pipes, sockets or devices.
- A config file can only weaken protection from your own machine: `VEIL_CONFIG` must be an absolute path outside the project, and every weakened setting is named in a warning at the start of each session.

## What it does not protect against

- A program the agent runs reads real values, as it must to work. veil changes what the model sees, not what your code sees.
- A secret veil has never seen and that matches no known format.
- A value transformed in a way veil does not try: split, hex-encoded, reversed, or encrypted.
- The agent's own interface showing a row in the instant before plugins rewrite it.
- Text the agent adds after plugins run, such as Claude Code's `--append-system-prompt`.
- A restored value seen by the agent's permission step: in Claude Code's auto mode its classifier, and an approval card shown through Remote Control, see the edit veil restored. Set `[restore] mode = "never"` if you use either.
- An attacker with access to your machine or to the agent's process.

Treat veil as a second layer behind the agent's own permission rules, which should stop reads of secret files in the first place.
