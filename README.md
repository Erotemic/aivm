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

## Install

```bash
uv pip install .
```

## Quickstart

In your repo directory (recommended):

```bash
agentvm init --config .agentvm.toml
agentvm plan --config .agentvm.toml
agentvm apply --config .agentvm.toml --interactive
```

Then connect with VS Code Remote-SSH using:

```bash
agentvm vm ssh-config --config .agentvm.toml
```

## Notes

- This tool assumes **Linux + libvirt**. It focuses on Debian/Ubuntu hosts for dependency installation.
- NAT alone does not prevent VM -> LAN. Enable firewall isolation if you want “internet-only” access.
- virtiofs sharing is optional; it’s powerful, but it intentionally exposes that host directory to the VM.
