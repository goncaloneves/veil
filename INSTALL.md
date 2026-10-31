# Installing veil

veil runs as a native plugin in Claude Code, Pi, opencode and Kilo Code, and as `veil proxy` for every other agent. [docs/HARNESSES.md](docs/HARNESSES.md) has the setup for each agent.

## Claude Code

veil is a Claude Code plugin. Its repository is also its marketplace, so one line installs it.

**In a terminal session:**

```text
/plugin install veil --marketplace goncaloneves/veil
```

You see `Add marketplace?` naming `github:goncaloneves/veil`; answer `y`, then pick the **user** scope so veil runs in every project.

**From a shell:**

```sh
claude plugin marketplace add goncaloneves/veil
claude plugin install veil@veil
claude plugin list          # veil@veil ... enabled
```

**In the desktop app:** click **+** next to the prompt box, then **Plugins**, **Add marketplace** with `goncaloneves/veil`, then **Add plugin**. A plugin installed from a terminal at the user scope also loads in the desktop app and in the VS Code and Cursor extension.

veil needs Claude Code 2.1.287 or later, the first release with plugin mods, and 2.1.299 or later in the VS Code and Cursor extension. It is tested on 2.1.308 and 2.1.316. `veil doctor` checks the version on your PATH. Start a new session after installing, or run `/reload-plugins` in an open one, then run `/veil` to check it loaded.

If you have no GitHub SSH key, set `CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1` before adding the marketplace.

### Updates

The marketplace always points at the latest release, never at unreleased work. To update, refresh the marketplace and update the plugin, then restart Claude Code:

```sh
claude plugin marketplace update veil
claude plugin update veil@veil
```

To update without thinking about it, open `/plugin`, go to **Marketplaces**, select `veil` and choose **Enable auto-update**.

### Uninstall

```sh
claude plugin uninstall veil@veil
claude plugin marketplace remove veil
```

## Pi, opencode and Kilo Code

With the command-line tool below:

```sh
veil init pi         # ~/.pi/agent/extensions/veil.js
veil init opencode   # ~/.config/opencode/plugins/veil.js
veil init kilo       # ~/.config/kilo/plugin/veil.js
```

Each downloads the adapter built for your veil version and checks it against the release's `SHA256SUMS`. `--from <file>` installs a bundle you built yourself instead, without a checksum. `PI_CODING_AGENT_DIR` and `XDG_CONFIG_HOME` move the folders, as they do for the agents. Start a new session to load it.

These agents have no `/veil` command. To check that veil works, run `veil sources` to see what it reads, then ask the agent to read a file that holds a secret: you should see `[veil:…]` placeholders. To update, install the newer command-line tool, then run `veil init <agent>` again so the plugin matches it. To uninstall, delete the file.

## Every other agent: veil proxy

Codex, Copilot CLI, Grok Build, Gemini CLI, Crush, Goose, Aider, Cline, Continue, Zed, grok-cli and any agent that takes a custom API URL use `veil proxy`, a local server between the agent and its model API. Install the command-line tool below, start `veil proxy` in the folder you run your agent from, and point the agent at it; [docs/HARNESSES.md](docs/HARNESSES.md) has the exact setting for each agent.

## Command-line tool

The `veil` command masks files and streams, lists what veil reads, checks your setup, installs the agent plugins and runs `veil proxy`. The Claude Code plugin does not need it.

On macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/goncaloneves/veil/main/install.sh | sh
```

On Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/goncaloneves/veil/main/install.ps1 | iex
```

The scripts download the build for your system from the latest release, check it against the release's `SHA256SUMS` and install it to `~/.local/bin/veil`, or `%LOCALAPPDATA%\Programs\veil\veil.exe` on Windows. To pick a release or folder, set `VEIL_VERSION` or `VEIL_INSTALL_DIR` for the shell that runs the script: `curl -fsSL https://raw.githubusercontent.com/goncaloneves/veil/main/install.sh | VEIL_VERSION=v0.2.0 sh`, or in PowerShell `$env:VEIL_VERSION = 'v0.2.0'` before `irm … | iex`. To update, run the script again; to uninstall, delete the binary. Builds exist for macOS, Linux and Windows, on arm64 and x64, with musl builds for Alpine and similar systems. The x64 builds run on any x64 processor, including older servers without AVX2.

Every release build carries a GitHub build attestation. To confirm a binary was built from this repository by its release workflow:

```sh
gh attestation verify ~/.local/bin/veil --repo goncaloneves/veil
```

You can also download a build from the [releases page](https://github.com/goncaloneves/veil/releases) yourself (then `chmod +x` it, and on macOS `xattr -d com.apple.quarantine` it, since the build is only ad-hoc signed), or run veil from a clone with Node 22.18 or later:

```sh
git clone https://github.com/goncaloneves/veil.git
node veil/src/cli/main.ts doctor
```

`veil init` installs the Claude Code plugin for you, running the two `claude plugin` commands above; `veil init pi`, `opencode` or `kilo` installs the other plugins.

## Configuration

veil runs with sensible defaults and no config file. To change them, run `veil config init` or see [Configure](README.md#configure).
