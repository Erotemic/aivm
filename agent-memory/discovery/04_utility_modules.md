# Utility Modules Discovery Log

## Timestamp: 2026-04-04 02:41:30 UTC

## Overview
The `aivm/` directory contains several utility modules that support the core functionality: runtime helpers, status probes, resource checks, detection, and error types.

---

## [`aivm/runtime.py`](aivm/runtime.py)
**Purpose:** Runtime command-shaping helpers for virsh/ssh invocations

**Key Constants:**
- `LIBVIRT_URI` = `'qemu:///system'`

**Key Functions:**
- `virsh_system_cmd(*args)` - Build virsh command with system URI
- `require_ssh_identity(identity)` - Validate SSH identity path is configured
- `ssh_base_args(ident, ...)` - Build common SSH options list

**SSH Options:**
- `BatchMode=yes` (optional)
- `ConnectTimeout=N` (optional)
- `StrictHostKeyChecking=accept-new` (default)
- `UserKnownHostsFile=...` (optional)
- `-i <identity>` (required)

**Design Notes:**
- Centralized connection defaults reduce drift across modules
- `virsh_system_cmd` ensures consistent libvirt URI usage

---

## [`aivm/status.py`](aivm/status.py)
**Purpose:** Status probe and rendering utilities for host + VM operational visibility

**Key Dataclasses:**
- `ProbeOutcome` - ok (bool|None), detail, diag (tri-state: True/False/None)

**Key Functions:**
- `status_line(ok, label, detail)` - Render status line with icons (✅/❌/➖)
- `probe_cwd_shared_with_vm(cfg, store_cfg_path)` - Check if cwd is covered by saved share
- `probe_runtime_environment()` - Detect bare metal vs VM
- `probe_network(cfg, use_sudo)` - Check libvirt network state
- `probe_firewall(cfg, use_sudo)` - Check nftables table exists
- `probe_vm_state(cfg, use_sudo)` - Check VM running state
- `probe_ssh_ready(cfg, ip)` - SSH readiness probe
- `probe_provisioned(cfg, ip)` - Check if provisioned packages installed
- `render_status(cfg, path, detail, use_sudo)` - Render full VM status report
- `render_global_status()` - Render global status (no VM context)
- `anticipated_status_sudo_commands(cfg, detail)` - Preview sudo commands for status

**Probe Semantics:**
- `ok=True`: Check succeeded / condition present
- `ok=False`: Check failed / condition absent
- `ok=None`: Inconclusive / skipped (often privilege-dependent)

**Status Report Sections:**
1. Host dependencies (required/optional commands)
2. Runtime environment (bare metal vs VM)
3. Libvirt network (active/autostart)
4. Firewall (table present/missing)
5. Base image cache (file exists)
6. VM state (running/shutdown/not defined)
7. VM shared folders (mappings count)
8. Current directory shared (cwd coverage)
9. Config drift (hardware/mappings vs libvirt)
10. Cached VM IP (from cache file)
11. SSH readiness (probe result)
12. Provisioning (packages installed)

**Design Notes:**
- Separation of concerns: Probe functions return structured data, rendering is separate
- Tri-state outcomes: Handle privilege-dependent inconclusive states
- Detail mode: Shows raw command output for debugging
- Next steps: Suggests commands based on failed checks

---

## [`aivm/util.py`](aivm/util.py)
**Purpose:** Shared utility re-exports and small filesystem/path helpers

**Key Functions:**
- `which(cmd)` - Wrapper around `shutil.which`
- `ensure_dir(path)` - Create directory with parents, exist_ok
- `expand(path)` - Expand `~` and environment variables

**Re-exports:**
- `CmdError`, `CmdResult`, `shell_join` from commands module
- `os`, `sys`, `subprocess` standard library modules

**Design Notes:**
- Re-exports for convenience and testability
- Small helpers to avoid inline imports

---

## [`aivm/errors.py`](aivm/errors.py)
**Purpose:** Project-specific exception types

**Key Classes:**
- `AIVMError` - Base error for domain-level failures
- `MissingSSHIdentityError(AIVMError)` - SSH identity config missing

**Design Notes:**
- Narrow exception hierarchy
- Specific errors for common failure modes

---

## [`aivm/results.py`](aivm/results.py)
**Purpose:** Result dataclasses used by sync/provision operations

**Key Classes:**
- `SyncSettingsResult` - copied, skipped_missing, skipped_exists, failed lists

**Design Notes:**
- Structured results for convenience operations
- `as_dict()` method for serialization

---

## [`aivm/detect.py`](aivm/detect.py)
**Purpose:** Host default detection for first-run/bootstrap ergonomics

**Key Functions:**
- `detect_ssh_identity()` - Detect SSH identity from ssh_config or ~/.ssh/
- `existing_ipv4_routes()` - Introspect host IPv4 routes
- `pick_free_subnet(preferred)` - Pick non-overlapping subnet from candidates
- `auto_defaults(cfg, project_dir)` - Auto-detect SSH identity, network, VM resources

**SSH Identity Detection:**
1. Parse `~/.ssh/config` for matching Host block
2. Fallback to `ssh -G` probe for IdentityFile
3. Fallback to `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`
4. Fallback to any `~/.ssh/id_*` file

**Network Detection:**
- Preferred subnets: 10.77.0.0/24, 10.78.0.0/24, 10.79.0.0/24, 10.88.0.0/24, 10.99.0.0/24, 192.168.77.0/24, 192.168.88.0/24
- Check against existing routes, pick first non-overlapping

**VM Resource Detection:**
- CPU: Based on host CPU count (1-8 cores depending on host)
- RAM: Based on host memory (2GB-12GB depending on host)
- Disk: Based on free disk space (16GB-64GB depending on space)

**Design Notes:**
- Advisory detection: Callers can override via config/CLI
- Conservative defaults: Avoid resource exhaustion on constrained hosts
- Bridge name: Truncate to 15 chars if needed (Linux constraint)

---

## [`aivm/resource_checks.py`](aivm/resource_checks.py)
**Purpose:** Host/VM resource sanity checks for init/create paths

**Key Functions:**
- `host_mem_available_mb()` - Read MemAvailable from /proc/meminfo
- `host_mem_total_mb()` - Read MemTotal from /proc/meminfo
- `host_cpu_count()` - Get host CPU count
- `host_free_disk_gb(path)` - Get free disk space at path
- `vm_resource_warning_lines(cfg)` - Advisory warnings for high resource requests
- `vm_resource_impossible_lines(cfg)` - Hard errors for impossible requests

**Warning Thresholds:**
- RAM > 80% of host total or available
- CPUs > host count
- Disk > 90% of free space

**Impossible Thresholds:**
- RAM > host total
- CPUs > host count

**Design Notes:**
- Advisory vs hard errors: Warnings vs impossible
- /proc/meminfo parsing for Linux
- os.statvfs for disk space

---

## Cross-Module Patterns

### Status Probe Pattern
1. Run command with/without sudo
2. Parse output for success/failure
3. Return `ProbeOutcome(ok, detail, diag)`
4. `ok=None` for privilege-dependent inconclusive states

### Detection Pattern
1. Try primary detection method
2. Fallback to secondary methods
3. Return empty/default if all fail
4. Callers can override detected values

### Resource Check Pattern
1. Read host resources from /proc or os module
2. Compare against requested VM resources
3. Return warnings (advisory) or errors (impossible)
4. Use warnings during create, errors as hard fail-fast

---

## Next Steps
- Explore CLI modules (vm.py, host.py, config.py, _common.py)
- Create architecture overview document
