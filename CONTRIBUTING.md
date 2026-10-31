# Contributing to veil

Thanks for helping. Issues and pull requests are welcome; for a larger change, open an issue first so we can agree on the approach.

## Setup

Node 22.18 or later and Claude Code 2.1.287 or later.

```sh
npm ci
npm test
npm run typecheck
claude plugin validate .
claude plugin test .
```

Try your working copy in a real session with `claude --plugin-dir .`. To try the Pi or opencode adapter, run `npm run build:adapters` (it needs [Bun](https://bun.sh)) and `veil init pi --from dist/veil-pi.js` or `veil init opencode --from dist/veil-opencode.js`. To try the proxy, run `node src/cli/main.ts proxy` from a project folder and point an agent at it.

## Conventions

- **Conventional commits.** Releases, versions and the changelog come from commit messages through release-please: `feat:` for something users get, `fix:` for a bug, `perf:`, `docs:`, `refactor:`, `test:`, `ci:`, `build:`, `chore:`. A breaking change says `!` after the type.
- **No runtime dependencies.** veil runs inside agents and is a security tool; every dependency is code with access to secrets. Dev dependencies are fine.
- **The core stays agent-neutral and runtime-neutral.** `src/core`, `src/sources`, `src/config`, `src/rules`, `src/engine.ts` and `src/report.ts` use no Node, browser or agent API. `npm run typecheck` checks them with no ambient types. Anything that touches files, the environment or an agent goes through `SourceFs`, `SourceHost` or an adapter.
- **In the Claude Code adapter, `$` stays in `hooks/register.ts`.** Claude Code requires every `$` call to be written at its call site, so `claude plugin validate` can list what the plugin does. Helpers in `src/adapters/claude-code` take plain values and functions, never `$`.
- **No real-looking secrets in the repository.** Tests build fake tokens at run time from a seeded generator (`test/helpers.ts`), so nothing in the tree looks like a live key.
- **No code comments.** Names and tests carry the meaning; documentation lives in the Markdown files.
- **Every change has a test.** Unit tests go in `test/*.spec.ts` (Node's runner). Tests of the Claude Code adapter go in `tests/claude-code/*.test.ts` and run in Claude Code's own runtime through `claude plugin test .`.

## The gitleaks rules

`src/rules/gitleaks.ts` is generated. Do not edit it by hand:

```sh
node scripts/sync-gitleaks.ts            # the version in scripts/gitleaks-version.txt
node scripts/sync-gitleaks.ts --latest   # the newest gitleaks release
```

A weekly workflow opens a pull request when gitleaks releases new rules. If a rule fails to convert, fix the converter in `scripts/lib/re2.ts` and add a case to `test/rules.spec.ts`.

## Repository settings

release-please and the weekly rules sync open pull requests with the workflow's own token, so **Settings → Actions → General → Allow GitHub Actions to create and approve pull requests** must be on. Pull requests opened that way do not start other workflows on their own, so both workflows start `ci.yml` on the pull request's branch themselves.

`src/rules/veil.ts` holds veil's own rules, for formats gitleaks does not cover; they run beside the generated gitleaks rules.

## Adding an agent

If the agent takes a custom API URL, it already works through `veil proxy`: add its setup to [docs/HARNESSES.md](docs/HARNESSES.md), and a route in `src/proxy/server.ts` if its upstream is new. If it has in-process plugins, wrap `Veil` from `src/session.ts`: mask every text it sends to its model and every record it saves, restore placeholders in file edits with `checkInput` from `src/restore.ts`, and deny when that refuses. `src/adapters/pi` and `src/adapters/opencode` are short references. Test the adapter in `test/`, then prove it in a real session against a fake model that records every request. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
