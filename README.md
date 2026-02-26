# agentvm

A small Python CLI to **create and manage a local libvirt/KVM Ubuntu 24.04 VM** designed for
running coding agents with a stronger boundary than containers.

Features:
- Explicit libvirt NAT network creation (named, dedicated subnet)
- Optional host firewall isolation via nftables (bridge-scoped)
- Ubuntu 24.04 cloud-image provisioning via cloud-init
- SSH helpers + VS Code Remote-SSH snippet
- Optional virtiofs host directory share (explicit break in default isolation model)
- Optional provisioning inside VM (docker + dev tools)
- Optional host settings sync into VM user profile (git/vscode shell config, etc.)
- Global VM/folder registry and per-directory metadata for attachment tracking

## Install

```bash
uv pip install .
```

## Quickstart

In your repo directory (recommended):

```bash
agentvm init --config .agentvm.toml
agentvm plan --config .agentvm.toml
agentvm status --config .agentvm.toml
agentvm status --config .agentvm.toml --detail
agentvm apply --config .agentvm.toml --interactive
```

If there is no local `.agentvm.toml`, `agentvm status` can resolve the VM from directory metadata / global registry (or use `--vm`).

Then connect with VS Code Remote-SSH using:

```bash
agentvm vm ssh_config --config .agentvm.toml
```

Or do it in one step (share current project directory and launch VS Code in the VM):

```bash
# top-level shortcut (works in a new repo with no local init)
agentvm code . --sync_settings
# equivalent vm-group form
agentvm vm code --config .agentvm.toml --host_src . --sync_settings
# shorthand positional host folder
agentvm vm code . --sync_settings
```

List managed resources:

```bash
agentvm list
agentvm list --section vms
agentvm list --section networks
agentvm list --section folders
```

Attach a folder to a managed VM (shared mode):

```bash
agentvm attach .
# explicit vm-group form
agentvm vm attach --vm agentvm-2404 --host_src .
```

By default, attached folders mount to the same absolute path inside the VM as on the host.
Use `--guest_dst` to override.
When possible, `agentvm code .` now live-attaches new shares to an existing VM instead of requiring recreation.

## Make VM Feel Like Your Host

Sync selected user settings/files into the VM:

```bash
agentvm vm sync_settings --config .agentvm.toml
```

Override what to sync ad hoc:

```bash
agentvm vm sync-settings --config .agentvm.toml \
  --paths "~/.gitconfig,~/.config/Code/User/settings.json,~/.tmux.conf"
```

You can set defaults in config:

```toml
[sync]
enabled = true
overwrite = true
paths = [
  "~/.gitconfig",
  "~/.gitignore",
  "~/.config/Code/User/settings.json",
  "~/.config/Code/User/keybindings.json",
  "~/.tmux.conf",
  "~/.bashrc",
]
```

When `[sync].enabled=true`, `agentvm vm code ...` will sync those paths before launching VS Code.

### Command groups

```bash
agentvm net --help
agentvm fw --help
agentvm vm --help
```

## Notes

- This tool assumes **Linux + libvirt**. It focuses on Debian/Ubuntu hosts for dependency installation.
- NAT alone does not prevent VM -> LAN. Enable firewall isolation if you want “internet-only” access.
- virtiofs sharing is optional; it’s powerful, but it intentionally exposes that host directory to the VM.
- `agentvm vm code` requires VS Code's `code` CLI and the Remote - SSH extension.
