# Concatenation-friendly config layout

Written: 2026-05-15 11:20:43 America/New_York
Baseline commit: 5c7effe87377ca29b832eeeda76e2da0f0e37b20

## Goal

AIVM's editable configuration should remain easy to inspect and hand-edit while
keeping the main config file from becoming huge.  VM-specific desired state such
as RAM, CPU count, disk size, provisioning options, and attachments should live
near the VM they affect, and drift detection should continue to compare that
user-authored desired state against real libvirt XML and disk state.

The target design is a small config directory whose fragments concatenate into
one canonical TOML document.  This makes the split layout low risk: the existing
logical schema remains the contract, and physical files become an implementation
detail.

## Target disk layout

```text
~/.config/aivm/
  config.toml
  networks.toml
  vms/
    aivm-2404.toml
    scratch.toml
```

The deterministic load order is:

```text
1. config.toml
2. networks.toml, if present
3. vms/*.toml sorted by filename
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

[defaults.vm]
user = "agent"
cpus = 4
ram_mb = 8192
disk_gb = 40
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

## Migration principles

The current monolithic config must keep working until a user explicitly migrates.
The transition should proceed in chunks:

1. Split the current store implementation internally without changing behavior.
2. Teach the parser/renderers about nested `[[vms.attachments]]` while keeping
   legacy global `[[attachments]]` compatible.
3. Add read-only support for split layouts by deterministic concatenation.
4. Add a split writer and `aivm config split` migration command.
5. Prefer the split layout for new writes after the compatibility path is tested.

During the transition, duplicate VM or network definitions across fragments
should be loud errors, not silently merged.
