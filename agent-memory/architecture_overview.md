# AIVM Architecture Overview

## Project Summary

**aivm** is a Python CLI for managing local libvirt/KVM Ubuntu 24.04 VMs designed for running coding agents with stronger isolation than containers.

**Package:** `aivm`  
**Version:** 0.4.1  
**Primary Entry Point:** [`aivm.cli.main()`](aivm/cli/main.py:192)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            CLI Layer                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ aivm vm  │  │ aivm host│  │ aivm config│ │ aivm code│               │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
│       │             │              │              │                      │
│       └─────────────┴──────────────┴──────────────┘                      │
│                              │                                           │
└──────────────────────────────┼───────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────────┐
│                      Command Manager                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Intent Stack (breadcrumb context)                               │   │
│  │  Plan Stack (grouped commands)                                   │   │
│  │  Approval Handling (sudo, file updates)                          │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┼───────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────────┐
│                         Domain Layer                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   VM        │  │ Attachments │  │  Network    │  │  Firewall   │    │
│  │  Lifecycle  │  │   (shared)  │  │   (libvirt) │  │  (nftables) │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└──────────────────────────────┼───────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────────┐
│                        Config & State                                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Config Store (~/.config/aivm/config.toml)                       │   │
│  │  - [[defaults]]  - [[networks]]  - [[vms]]  - [[attachments]]   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### Core Modules

| Module | Purpose | Key Types/Functions |
|--------|---------|---------------------|
| [`config.py`](aivm/config.py) | Configuration schema, TOML serialization | `AgentVMConfig`, `dump_toml()`, `load()`, `save()` |
| [`store.py`](aivm/store.py) | Single-file registry for VMs, networks, attachments | `Store`, `load_store()`, `save_store()`, `upsert_vm()` |
| [`commands.py`](aivm/commands.py) | Command orchestration, approval handling | `CommandManager`, `CommandPlan`, `IntentScope` |
| [`host.py`](aivm/host.py) | Host prerequisite checks, dependency installation | `check_commands()`, `install_deps_debian()` |
| [`net.py`](aivm/net.py) | Libvirt network lifecycle | `ensure_network()`, `network_status()`, `destroy_network()` |
| [`firewall.py`](aivm/firewall.py) | Nftables policy generation | `apply_firewall()`, `firewall_status()`, `_nft_script()` |

### VM Submodules

| Module | Purpose | Key Types/Functions |
|--------|---------|---------------------|
| [`vm/lifecycle.py`](aivm/vm/lifecycle.py) | VM creation, start, stop, provisioning | `create_or_start_vm()`, `fetch_image()`, `wait_for_ip()`, `provision()` |
| [`vm/update_ops.py`](aivm/vm/update_ops.py) | VM update drift detection and application | `VMUpdateDrift`, `_vm_update_drift()`, `_apply_vm_update()` |
| [`vm/share.py`](aivm/vm/share.py) | Virtiofs share management | `attach_vm_share()`, `vm_share_mappings()`, `ensure_share_mounted()` |
| [`vm/drift.py`](aivm/vm/drift.py) | Configuration drift detection | `DriftReport`, `hardware_drift_report()`, `saved_vm_drift_report()` |
| [`vm/sync.py`](aivm/vm/sync.py) | Host-to-guest settings sync | `sync_settings()` |

### Attachments Submodules

| Module | Purpose | Key Types/Functions |
|--------|---------|---------------------|
| [`attachments/session.py`](aivm/attachments/session.py) | Session preparation, attachment reconciliation | `_prepare_attached_session()`, `_reconcile_attached_vm()` |
| [`attachments/shared_root.py`](aivm/attachments/shared_root.py) | Shared-root bind mount management | `_ensure_shared_root_host_bind()`, `_ensure_shared_root_guest_bind()` |
| [`attachments/guest.py`](aivm/attachments/guest.py) | Guest-side operations | `_ensure_guest_symlink()`, `_ensure_git_clone_attachment()` |
| [`attachments/resolve.py`](aivm/attachments/resolve.py) | Attachment resolution | `_resolve_attachment()`, `_normalize_attachment_mode()` |

### Utility Modules

| Module | Purpose | Key Types/Functions |
|--------|---------|---------------------|
| [`runtime.py`](aivm/runtime.py) | Runtime command helpers | `virsh_system_cmd()`, `ssh_base_args()` |
| [`status.py`](aivm/status.py) | Status probes and rendering | `probe_network()`, `render_status()`, `ProbeOutcome` |
| [`detect.py`](aivm/detect.py) | Host default detection | `detect_ssh_identity()`, `auto_defaults()` |
| [`resource_checks.py`](aivm/resource_checks.py) | Resource sanity checks | `vm_resource_warning_lines()`, `vm_resource_impossible_lines()` |
| [`util.py`](aivm/util.py) | Utility re-exports | `which()`, `ensure_dir()`, `expand()` |
| [`errors.py`](aivm/errors.py) | Exception types | `AIVMError`, `MissingSSHIdentityError` |
| [`results.py`](aivm/results.py) | Result dataclasses | `SyncSettingsResult` |

---

## Key Architectural Patterns

### 1. Command Manager Pattern

The [`CommandManager`](aivm/commands.py:371) centralizes all subprocess execution with:

- **Intent Stack**: Breadcrumb context for nested operations
- **Plan Stack**: Grouped commands with approval boundaries
- **Approval Handling**: Interactive prompts with `y`/`a`/`s`/`N` options
- **Lazy Execution**: `CommandHandle` for deferred execution

**Example Flow:**
```python
with mgr.intent('Create VM', why='Provision new VM', role='modify'):
    with mgr.step('Ensure network', why='Network must exist first'):
        mgr.submit(['virsh', 'net-start', 'aivm-net'], sudo=True)
    with mgr.step('Create VM', why='Define and start VM'):
        mgr.submit(['virt-install', ...], sudo=True)
```

### 2. Config Store Pattern

Single TOML file at `~/.config/aivm/config.toml` with sections:

```toml
schema_version = 5
active_vm = "aivm-2404"

[behavior]
yes_sudo = false
auto_approve_readonly_sudo = true

[defaults]
[defaults.vm]
name = "aivm-2404"
cpus = 4
ram_mb = 8192

[[networks]]
name = "aivm-net"
[networks.network]
subnet_cidr = "10.77.0.0/24"
[networks.firewall]
enabled = true

[[vms]]
name = "aivm-2404"
network_name = "aivm-net"
[vms.vm]
...

[[attachments]]
host_path = "/home/user/project"
vm_name = "aivm-2404"
mode = "shared-root"
```

### 3. Attachment Resolution Pattern

Three attachment modes with different sharing strategies:

| Mode | Host Side | VM Side | Guest Side |
|------|-----------|---------|------------|
| **shared** | Direct virtiofs mapping | virtiofs device | Mount virtiofs |
| **shared-root** | Bind mount under shared-root export | One virtiofs export | Mount + bind subdirectory |
| **git** | Git remote registration | Git repo over SSH | Clone + push |

**Resolution Flow:**
1. Check saved attachment in config store
2. Validate mode/access against saved (if override)
3. Generate/align tag for virtiofs modes
4. Return `ResolvedAttachment` with all fields computed

### 4. Drift Detection Pattern

Separation of detection vs handling:

1. **Detection**: [`DriftReport`](aivm/vm/drift.py:60) with structured items
2. **Handling**: Caller decides (warn, auto-heal, report)

**Drift Types:**
- Hardware: CPU, RAM vs libvirt
- Share mappings: Expected vs actual virtiofs devices
- Network: Config vs live XML (warn only, no auto-fix)

### 5. Status Probe Pattern

Tri-state outcomes for privilege-aware checks:

```python
@dataclass
class ProbeOutcome:
    ok: bool | None  # True/False/None (inconclusive)
    detail: str
    diag: str = ''
```

**Usage:**
- `ok=True`: Check succeeded
- `ok=False`: Check failed
- `ok=None`: Inconclusive (e.g., needs sudo)

---

## Data Flow Examples

### VM Creation Flow

```
CLI: aivm vm create
  ↓
Resolve defaults from config store
  ↓
Check host resources (warnings/errors)
  ↓
Ensure network (libvirt XML define/start)
  ↓
Apply firewall (nftables rules)
  ↓
Fetch image (download + SHA256 verify)
  ↓
Generate cloud-init (user-data, meta-data, seed ISO)
  ↓
Create disk (qcow2 with backing file)
  ↓
Define VM (virt-install with virtiofs if shared)
  ↓
Record VM in config store
```

### Code Session Flow

```
CLI: aivm code .
  ↓
Resolve VM context (from cwd attachment or active VM)
  ↓
Resolve attachment (mode, access, tag, guest_dst)
  ↓
Reconcile VM state:
  - Check network, firewall
  - Start VM if needed
  - Attach virtiofs if missing
  ↓
Wait for IP (DHCP lease or domifaddr)
  ↓
Wait for SSH (probe with identity)
  ↓
Ensure attachment in guest:
  - Mount virtiofs
  - Bind to guest_dst
  - Create symlinks (companion, mirror-home)
  ↓
Restore saved attachments (best-effort)
  ↓
Sync settings (if --sync_settings)
  ↓
Update SSH config
  ↓
Launch VS Code (code --remote ssh-remote+<vm> <guest_dst>)
```

### Shared-Root Attachment Flow

```
Host Side:
  1. Create /var/lib/libvirt/aivm/<vm>/shared-root/
  2. Create target: <shared-root>/<tag>
  3. Bind mount: <host_src> -> <target>

VM Side:
  4. Ensure virtiofs device: source=<shared-root>, target=aivm-shared-root

Guest Side:
  5. Mount virtiofs: mount -t virtiofs aivm-shared-root /mnt/aivm-shared
  6. Bind mount: /mnt/aivm-shared/<tag> -> <guest_dst>
  7. Verify source and access mode
```

---

## Design Principles

1. **Simple Defaults**: `aivm code .` works with minimal configuration
2. **Explicit Privilege**: Ask before sudo unless `--yes` provided
3. **Safe Status**: `aivm status` avoids privileged checks by default
4. **Idempotent Operations**: Reconcile flows handle already-correct state
5. **Structured Errors**: Specific error messages with suggested fixes
6. **Separation of Concerns**: Detection vs handling, probe vs render
7. **Audit Trail**: Config store tracks VMs, networks, attachments with reasons

---

## Key Design Decisions

### Shared-Root vs Shared Mode

**Shared mode** creates one virtiofs device per folder. Problem: hits PCI slot limits with many folders.

**Shared-root mode** uses one virtiofs export with per-folder bind mounts. Benefit: scales to many folders without device limits.

### Tag Generation

Tags include SHA1 hash of resolved path to avoid basename collisions:
```
hostcode-<basename>-<sha1_hash[:8]>
```

### Image Verification

SHA256 against built-in registry prevents corrupted/modified images:
```python
SUPPORTED_IMAGE_SHA256 = {
    'https://cloud-images.ubuntu.com/noble/.../noble-server-cloudimg-amd64.img':
    '7aa6d9f5e8a3a55c7445b138d31a73d1187871211b2b7da9da2e1a6cbf169b21',
}
```

### Sudo Escalation

Prefers non-sudo probes, escalates when needed:
1. Try without sudo first
2. If permission denied, retry with sudo
3. Report `ok=None` if still inconclusive

---

## Future Considerations

From code comments and TODOs:

1. **Image Registry**: Move from hardcoded URL/hash to network asset registry with mirrors, torrents, IPFS
2. **Action Model**: Refine command roles beyond read/modify (user-file write vs system write)
3. **Network Rebinding**: Auto-fix network drift (currently warns only)
4. **Lazy Unmount**: Add explicit force/lazy detach mode for orphaned mount cleanup

---

## References

- [`README.rst`](README.rst) - User-facing documentation
- [`AGENTS.md`](AGENTS.md) - Development rules and conventions
- [`docs/source/design.rst`](docs/source/design.rst) - Design documentation
- [`dev/journals/`](dev/journals/) - Developer journal entries
