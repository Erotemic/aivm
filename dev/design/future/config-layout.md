# Concatenation-friendly config layout

Written: 2026-05-15 11:20:43 America/New_York
Updated: 2026-05-15 15:40:00 America/New_York
Baseline commit: 5c7effe87377ca29b832eeeda76e2da0f0e37b20

## Goal

AIVM's editable configuration should remain easy to inspect and hand-edit while
keeping any one file from becoming huge.  VM-specific desired state such as RAM,
CPU count, disk size, provisioning options, and attachments should live near the
VM they affect.  Drift detection should continue to compare that user-authored
desired state against real libvirt XML and disk state.

The target design is a small config directory whose fragments concatenate into
one canonical TOML document.  This makes the layout low risk: the existing
logical schema remains the contract, and physical files become an implementation
detail.

## Target disk layout

```text
~/.config/aivm/
  config.toml
  defaults.toml
  networks.toml
  vms/
    aivm-2404.toml
    scratch.toml
```

The deterministic load order is:

```text
1. config.toml
2. defaults.toml, if present
3. networks.toml, if present
4. vms/*.toml sorted by filename
```

The literal concatenation of those files should be valid TOML and should parse
as the canonical AIVM desired-state document.

## File roles

### `config.toml`

Owns singleton/global tables only:

```toml
schema_version = 6
active_vm = "aivm-2404"

[behavior]
yes_sudo = false
auto_approve_readonly_sudo = true
verbose = 1
```

### `defaults.toml`

Owns reusable defaults.  Defaults are split out because they are less important
to day-to-day editing once one or more VM files exist.

```toml
[defaults.vm]
user = "agent"
cpus = 4
ram_mb = 8192
disk_gb = 40

[defaults.paths]
base_dir = "/var/lib/libvirt/aivm"
```

### `networks.toml`

Owns shared network desired state:

```toml
[[networks]]
name = "aivm-net"

[networks.network]
bridge = "virbr-aivm"
subnet_cidr = "10.77.0.0/24"

[networks.firewall]
enabled = true
block_cidrs = []
```

Networks are separate from VM files because one or two VMs will often share a
single managed network.  Keeping the shared network in one file avoids silent
copy/paste drift between VM configs.

### `vms/{vm_name}.toml`

Each VM file owns exactly one `[[vms]]` entry and the attachments for that VM:

```toml
[[vms]]
name = "aivm-2404"
network_name = "aivm-net"

[vms.vm]
cpus = 8
ram_mb = 32768
disk_gb = 80
timezone = "America/New_York"

[vms.provision]
enabled = true
install_docker = true

[[vms.attachments]]
host_path = "/home/joncrall/code/aivm"
mode = "shared-root"
access = "rw"
guest_dst = "/home/agent/code/aivm"
```

The `[[vms]]` prefix is slightly noisier when editing a single VM file, but it
preserves the more important invariant: the file is a literal fragment of the
canonical document.

## Commands

The user-facing command for canonicalizing the layout is:

```bash
aivm config format
```

There is intentionally no `aivm config split` alias.  The command is a formatter:
it reads any supported layout, validates it, and writes the canonical layout.

Useful edit commands:

```bash
aivm config edit              # edit global config.toml
aivm config edit defaults     # edit defaults.toml when formatted
aivm config edit networks     # edit networks.toml when formatted
aivm config edit vm [NAME]    # edit a VM fragment, defaulting to active_vm
aivm vm edit [NAME]           # shorthand for editing a VM fragment
```

Useful path inspection commands:

```bash
aivm config paths             # show config, data, and libvirt-related paths
aivm config paths config      # show editable config fragments
aivm config paths vm [NAME]   # show one VM config plus VM host paths
aivm config paths libvirt     # show /var/lib/libvirt/aivm-style paths
```

There is intentionally no separate `config files`, `config path`, or `vm
config-path` command.  `config paths` is the single inspection surface because
it reports both editable config fragments and the host directories/files AIVM
expects libvirt to use.

## Desired-state boundaries

This design concerns editable desired state only.  Runtime observations and
cache files are intentionally out of scope for this refactor.

Examples of desired state that belongs in editable config fragments:

- VM RAM, CPU count, disk size, timezone, image, and provisioning options.
- Shared network and firewall policy.
- Persistent or registered attachments.
- Runtime backend choices, when rootless/system backend work resumes.

Examples that should not be placed in the editable desired-state document:

- last known VM IP address;
- last successful SSH probe;
- transient libvirt domain state;
- cloud-init boot tokens;
- generated host helper paths;
- cached diagnostics.

## Drift detection invariant

Drift detection must consume the logical desired-state document, not a physical
file path.  The intended flow is:

```text
load config fragments
concatenate deterministically
parse canonical desired-state document
materialize VM config and network references
read actual libvirt/domain/disk state
compare desired vs actual
apply requested drift updates
```

A user changing `vms/aivm-2404.toml` should be enough to request a VM update:

```bash
$EDITOR ~/.config/aivm/vms/aivm-2404.toml
aivm vm update
```

## Implementation checkpoints

Completed chunks:

1. `aivm/store.py` was split internally into focused `aivm/config_store/*`
   modules while keeping the old `aivm.store` import facade.
2. The parser accepts nested `[[vms.attachments]]` while keeping legacy global
   `[[attachments]]` readable.
3. The loader reads split fragments by deterministic concatenation and tracks
   source metadata.
4. The writer formats the logical document into canonical split fragments.
5. The canonical layout now includes `defaults.toml` and the public command is
   `aivm config format`, with no `config split` alias.

Legacy top-level `[[attachments]]` remains readable for compatibility, but the
formatter should not produce it for normal VM-owned attachment records.
