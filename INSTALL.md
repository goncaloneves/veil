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

The marketplace always points at the latest release, never at unreleased work. To update:

```text
/plugin marketplace update veil
```

or from a shell, `claude plugin update veil@veil`. To update without thinking about it, open `/plugin`, go to **Marketplaces**, select `veil` and choose **Enable auto-update**.

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

Each downloads the adapter built for your veil version and checks it against the release's `SHA256SUMS`. `--from <file>` installs a bundle you built yourself instead, without a checksum. `PI_CODING_AGENT_DIR` and `XDG_CONFIG_HOME` move the folders, as they do for the agents. Start a new session to load it. To uninstall, delete the file.

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

The scripts download the build for your system from the latest release, check it against the release's `SHA256SUMS` and install it to `~/.local/bin/veil`, or `%LOCALAPPDATA%\Programs\veil\veil.exe` on Windows. Set `VEIL_VERSION=v0.2.0` to pick a release and `VEIL_INSTALL_DIR` to install elsewhere. Builds exist for macOS, Linux and Windows, on arm64 and x64, with musl builds for Alpine and similar systems. The x64 builds run on any x64 processor, including older servers without AVX2.

Every release build carries a GitHub build attestation. To confirm a binary was built from this repository by its release workflow:

```sh
gh attestation verify ~/.local/bin/veil --repo goncaloneves/veil
```

You can also download a build from the [releases page](https://github.com/goncaloneves/veil/releases) yourself, or run veil from a clone with Node 22.18 or later:

```sh
git clone https://github.com/goncaloneves/veil.git
node veil/src/cli/main.ts doctor
```

`veil init` installs the Claude Code plugin for you, running the two `claude plugin` commands above; `veil init pi`, `opencode` or `kilo` installs the other plugins.

## Configuration

veil runs with sensible defaults and no config file. To change them, run `veil config init` or see [Configure](README.md#configure).
