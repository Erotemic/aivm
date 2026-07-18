# Core Module Discovery Log

## Timestamp: 2026-04-04 02:38:00 UTC

## Overview
The `aivm` project is a Python CLI for managing local libvirt/KVM Ubuntu 24.04 VMs designed for running coding agents. The architecture is organized around several key concerns:

1. **Configuration & State Management** - TOML-based config store
2. **VM Lifecycle** - Create, start, stop, destroy VMs
3. **Networking** - Libvirt NAT networks with optional firewall isolation
4. **Folder Attachments** - Multiple modes for sharing host folders with guests
5. **Command Execution** - Centralized command manager with approval workflows

---

## Core Modules

### [`aivm/config.py`](aivm/config.py)
**Purpose:** Configuration schema and TOML serialization helpers

**Key Dataclasses:**
- `NetworkConfig` - Network name, bridge, subnet CIDR, DHCP range
- `FirewallConfig` - Nftables policy, blocked CIDRs, allowed ports
- `ImageConfig` - Ubuntu image URL, cache name, SHA256 verification
- `VMConfig` - VM name, user, CPU, RAM, disk, SSH settings
- `ProvisionConfig` - Packages to install, Docker option
- `SyncConfig` - Settings sync paths (gitconfig, VS Code settings, etc.)
- `PathsConfig` - Base dir, state dir, SSH identity paths
- `BehaviorConfig` - CLI behavior flags (yes_sudo, auto_approve_readonly_sudo)
- `AgentVMConfig` - Composite config combining all above

**Key Functions:**
- `dump_toml(cfg)` - Serialize config to TOML string
- `load(path)` - Load config from TOML file
- `save(path, cfg)` - Write config to file

**Design Notes:**
- Config schema is narrow and focused on user-facing knobs
- SHA256 verification for image integrity
- Path expansion for ~ and environment variables

---

### [`aivm/store.py`](aivm/store.py)
**Purpose:** Single-file registry model for defaults, networks, VMs, and attachments

**Key Dataclasses:**
- `Store` - Top-level registry with schema_version, active_vm, behavior, defaults, networks, vms, attachments
- `VMEntry` - VM name, network_name reference, full AgentVMConfig
- `NetworkEntry` - Network name, NetworkConfig, FirewallConfig
- `AttachmentEntry` - host_path, vm_name, mode, access, guest_dst, tag, host_lexical_path

**Key Functions:**
- `load_store(path)` - Load registry from TOML
- `save_store(reg, path, reason)` - Save registry with audit reason
- `upsert_vm(reg, cfg)` - Add/update VM entry
- `find_vm(reg, vm_name)` - Lookup VM by name
- `upsert_network(reg, network, firewall, name)` - Add/update network
- `find_attachments(reg, host_path)` - Find attachments by host path
- `materialize_vm_cfg(reg, vm_name)` - Join VM entry + network for effective config

**Design Notes:**
- Single TOML file at `~/.config/aivm/config.toml`
- Network/firewall details live in `[[networks]]` section, VMs reference by name
- Attachments track lexical (unresolved) paths for symlink preservation
- Schema versioning for migration support

---

### [`aivm/commands.py`](aivm/commands.py)
**Purpose:** Centralized command orchestration, logging, and approval handling

**Key Classes:**
- `CommandManager` - Main entry point for command submission, execution, approval
- `CommandSpec` - Normalized spec for queued commands (cmd, sudo, role, check, capture, etc.)
- `CommandHandle` - Lazy handle for submitted commands (can defer execution)
- `CommandPlan` - Ordered group of commands previewed and executed as one step
- `IntentFrame` - Intent stack entry describing why traversing command tree
- `IntentScope` - Context manager that pushes intent frame
- `PlanScope` - Context manager that groups commands into one plan

**Key Functions:**
- `shell_join(cmd)` - Render command as shell-escaped string for logging
- `CommandManager.current()` - Get thread-local current manager
- `mgr.submit(cmd, ...)` - Submit command, return handle
- `mgr.run(cmd, ...)` - Submit and wait for result immediately
- `mgr.confirm_sudo_scope(...)` - Pre-flight sudo approval/authentication
- `mgr.render_breadcrumb()` - Render intent stack as breadcrumb string

**Design Notes:**
- Commands grouped into plans with human-readable titles and "why" explanations
- Approval prompts show semantic summaries plus exact commands
- Intent stack provides breadcrumb context for nested operations
- Role-based approval: 'read' vs 'modify' with sudo escalation
- Lazy execution via handles, eager execution via `eager=True` flag
- Auto-approve read-only sudo by default (configurable)

---

### [`aivm/host.py`](aivm/host.py)
**Purpose:** Host prerequisite checks and installation helpers

**Key Constants:**
- `REQUIRED_CMDS` - virsh, virt-install, qemu-img, cloud-localds, curl, ip, ssh
- `OPTIONAL_CMDS` - nft, ssh-keyscan

**Key Functions:**
- `check_commands()` - Check for required/optional binaries
- `check_commands_with_sudo()` - Check commands with sudo probe
- `host_is_debian_like()` - Detect Debian/Ubuntu host
- `install_deps_debian(assume_yes)` - Install libvirt/QEMU dependencies

**Design Notes:**
- Narrow scope: detect binaries and install Debian/Ubuntu deps
- Non-interactive apt mode for bootstrap flows
- Virtiofsd installed as optional dependency

---

### [`aivm/net.py`](aivm/net.py)
**Purpose:** Libvirt network lifecycle helpers for managed NAT network

**Key Functions:**
- `ensure_network(cfg, recreate, dry_run)` - Ensure network exists with given config
- `network_status(cfg)` - Read network info and XML dump
- `destroy_network(cfg, dry_run)` - Destroy and undefine network
- `_route_overlap(target_cidr)` - Check if subnet overlaps existing routes

**Design Notes:**
- Idempotent-oriented (ensure/destroy/status)
- Generates libvirt XML for NAT network definition
- Bridge name limited to 15 chars (Linux constraint)
- Route overlap detection to prevent IP conflicts

---

### [`aivm/firewall.py`](aivm/firewall.py)
**Purpose:** Nftables policy generation/apply helpers for guest network isolation

**Key Functions:**
- `apply_firewall(cfg, dry_run)` - Apply nftables rules from config
- `firewall_status(cfg)` - Read current nftables table
- `remove_firewall(cfg, dry_run)` - Delete nftables table
- `_effective_bridge_and_gateway(cfg)` - Prefer live libvirt metadata over stale config
- `_nft_script(cfg)` - Generate nftables script string

**Design Notes:**
- Bridge-scoped rules for "WAN allowed, private ranges restricted"
- Prefers live libvirt XML for bridge/gateway (avoids stale config)
- Default blocks: private CIDRs (0.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
- Configurable allow_tcp_ports / allow_udp_ports for exceptions

---

## Cross-Cutting Concerns

### Command Execution Flow
1. CLI command invokes manager.submit() or manager.run()
2. Commands grouped into plans via `with mgr.step(...)`
3. Plans previewed with semantic summaries before execution
4. Approval prompted for sudo/modify operations (unless --yes)
5. Commands executed in order, results cached in handles
6. Intent stack provides breadcrumb context throughout

### Config Resolution Flow
1. CLI receives --config, --vm, or host_src path
2. `_resolve_cfg_for_code()` finds VM via:
   - Explicit --vm flag
   - Config store lookup by host_path attachment
   - Active VM default
3. `materialize_vm_cfg()` joins VM entry + network entry
4. Effective config passed to lifecycle operations

---

## Next Steps
- Explore CLI modules (vm.py, host.py, config.py)
- Explore VM submodules (lifecycle, update_ops, drift, sync, share)
- Explore attachments submodules (session, shared_root, guest, resolve)
