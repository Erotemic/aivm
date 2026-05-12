# VM Submodules Discovery Log

## Timestamp: 2026-04-04 02:39:30 UTC

## Overview
The `aivm/vm/` directory contains submodules for VM lifecycle operations, share management, drift detection, and settings synchronization.

---

## [`aivm/vm/lifecycle.py`](aivm/vm/lifecycle.py)
**Purpose:** VM lifecycle primitives - image acquisition, cloud-init, VM definition/start, readiness waits, provisioning

**Key Functions:**
- `fetch_image(cfg, dry_run)` - Download/verify Ubuntu cloud image with SHA256 checksum
- `_write_cloud_init(cfg, dry_run)` - Generate cloud-init user-data, meta-data, network-config, seed ISO
- `_ensure_disk(cfg, base_img, dry_run, recreate)` - Create qcow2 disk image with backing file
- `create_or_start_vm(cfg, dry_run, recreate, share_source_dir, share_tag)` - Ensure VM exists and is running
- `_destroy_and_undefine_vm(name)` - Destroy domain and undefine definition (with retry logic)
- `wait_for_ip(cfg, timeout_s, dry_run)` - Poll DHCP leases until VM IP available
- `wait_for_ssh(cfg, ip, timeout_s, dry_run)` - Probe SSH readiness on guest
- `provision(cfg, dry_run)` - SSH into VM and install packages (Docker, dev tools)
- `destroy_vm(cfg, dry_run)` - Destroy and undefine VM
- `vm_status(cfg)` - Read VM state and cached IP
- `ssh_config(cfg)` - Generate SSH config stanza for VM access

**Key Design Patterns:**
- Image verification: SHA256 against built-in registry, atomic temp file downloads
- Cloud-init: NoCloud seed ISO via `cloud-localds`, SSH key injection, sudo NOPASSWD
- VM creation: `virt-install` with UEFI (fallback to BIOS), shared memory backing for virtiofs
- IP discovery: DHCP lease lookup via MAC, fallback to `domifaddr`, SSH probe verification
- Error handling: Specific error messages for missing UEFI, virtiofsd, memory allocation

**Error Handling:**
- `_is_missing_uefi_firmware_error()` - Retry without UEFI if firmware missing
- `_is_missing_virtiofsd_error()` - Clear error message for virtiofsd not installed
- `_is_guest_memory_allocation_error()` - Suggest lowering RAM on low-memory hosts
- `_is_missing_command_error()` - Detect missing host binaries

---

## [`aivm/vm/update_ops.py`](aivm/vm/update_ops.py)
**Purpose:** VM update helpers - drift detection, planning, and application

**Key Dataclasses:**
- `VMUpdateDrift` - cpus, ram_mb, disk_bytes, disk_path, notes (tuple of diagnostics)

**Key Functions:**
- `_vm_update_drift(cfg, yes)` - Compute drift between config and live libvirt state
- `_print_vm_update_plan(cfg, drift)` - Print human-readable update plan
- `_apply_vm_update(cfg, drift, dry_run)` - Apply CPU/RAM/disk changes via virsh
- `_maybe_restart_vm_after_update(cfg, restart_policy, dry_run, yes)` - Reboot if needed

**Drift Detection:**
- CPU: Parse `virsh dominfo` for vCPU count
- RAM: Parse `virsh dominfo` for max memory (handle KiB/MiB/GiB units)
- Disk: `qemu-img info` or `virsh domblkinfo` for virtual size
- Network: Parse domain XML for network name, warn if mismatch (no auto-fix)

**Update Operations:**
- CPU: `virsh setvcpus --config`
- RAM: `virsh setmaxmem --config` + `virsh setmem --config`
- Disk: `qemu-img resize` (grow only, shrink not supported)
- Restart: Interactive prompt or `--restart=always/never/auto`

**Design Notes:**
- Non-destructive: `--config` flag preserves changes across reboots
- Disk expansion only: Safety check prevents shrink operations
- Sudo escalation: Prefers non-sudo probes, escalates when needed
- Diagnostic notes: Collects warnings instead of failing on inconclusive probes

---

## [`aivm/vm/share.py`](aivm/vm/share.py)
**Purpose:** Virtiofs share inspection, attach, and guest-side mount reconciliation

**Key Enums:**
- `AttachmentMode` - SHARED, SHARED_ROOT, GIT
- `AttachmentAccess` - RW, RO

**Key Dataclasses:**
- `ResolvedAttachment` - vm_name, mode, access, source_dir, guest_dst, tag

**Key Functions:**
- `vm_share_mappings(cfg, use_sudo)` - Parse domain XML for (source, tag) tuples
- `vm_has_virtiofs_shared_memory(cfg, use_sudo)` - Check for memfd/shared memory backing
- `vm_has_share(cfg, source_dir, tag, use_sudo)` - Check if specific mapping exists
- `attach_vm_share(cfg, source_dir, tag, dry_run, vm_running)` - Attach virtiofs device
- `detach_vm_share(cfg, source_dir, tag, dry_run)` - Detach virtiofs device
- `ensure_share_mounted(cfg, ip, guest_dst, tag, read_only, dry_run)` - Mount share in guest
- `align_attachment_tag_with_mappings(att, host_src, mappings)` - Align tag to avoid conflicts
- `_auto_share_tag_for_path(host_src, existing_tags)` - Generate unique tag with path hash

**Tag Management:**
- Tags limited to 36 chars (libvirt constraint)
- Tags include SHA1 hash of resolved path to avoid basename collisions
- Tag alignment: Reuse existing tag if source_dir matches, otherwise generate new unique tag

**Guest Mount Logic:**
- Retry loop: Up to 12 attempts with 2s delays for mount readiness
- Read-only support: Mount with `-o ro` or remount after bind
- Verification: Check mount source and options after mount

---

## [`aivm/vm/drift.py`](aivm/vm/drift.py)
**Purpose:** Shared VM configuration drift detection - separation of detection vs handling

**Key Dataclasses:**
- `DriftItem` - key, expected, actual, reason
- `DriftReport` - available, summary, items, diag, ok property

**Key Functions:**
- `hardware_drift_report(cfg, use_sudo)` - CPU/RAM drift from config vs libvirt
- `attachment_drift_report(cfg, attachment, host_src, use_sudo)` - Share mapping drift
- `vm_config_drift_report(cfg, use_sudo, expected_mappings)` - Combined hardware + share drift
- `saved_vm_drift_report(cfg, reg, use_sudo)` - Drift vs saved config store attachments
- `parse_dominfo_hardware(dominfo_text)` - Parse CPU/memory from virsh output
- `desired_saved_vm_mappings(cfg, reg)` - Derive expected mappings from saved attachments

**Drift Report Semantics:**
- `available=False`: Libvirt query failed (permission denied, VM not found)
- `available=True, items=[]`: No drift detected
- `available=True, items=[...]`: Drift detected with structured items

**Design Notes:**
- Separation of concerns: Drift detection returns structured data, callers decide actions
- Two-way set diff: Detects both missing expected mappings and unexpected extra mappings
- Tag alignment: Uses `align_attachment_tag_with_mappings` for compatibility with existing VMs
- Sudo escalation: Prefers non-sudo, escalates when needed for libvirt queries

---

## [`aivm/vm/sync.py`](aivm/vm/sync.py)
**Purpose:** Host-to-guest settings synchronization helpers

**Key Functions:**
- `sync_settings(cfg, ip, paths, overwrite, dry_run)` - Copy host settings files to VM via SCP

**Sync Behavior:**
- Paths: From `[sync].paths` config or explicit `--paths` override
- Expansion: `~` expanded to host home, relative paths made absolute
- Remote path: Relative to `$HOME` or `.aivm-sync/` for non-home paths
- Existence check: Skip if file exists and `overwrite=False`
- Result: `SyncSettingsResult` with copied/skipped_missing/skipped_exists/failed lists

**Design Notes:**
- Convenience feature: Separate from core VM lifecycle
- SSH/SCP: Uses dedicated SSH identity, StrictHostKeyChecking=accept-new
- Directory creation: Creates parent dirs on guest before SCP

---

## Cross-Module Patterns

### Virtiofs Share Flow
1. **Host preparation**: Create shared-root directory, set permissions
2. **VM definition**: Attach virtiofs device via `virt-install` or `virsh attach-device`
3. **Guest mount**: SSH to guest, mount virtiofs, bind to destination
4. **Verification**: Check mount source and options via `findmnt`

### Tag Generation
1. Start with user-provided tag or empty
2. If empty, generate from basename + SHA1 hash of resolved path
3. Check against existing mappings, add suffix if collision
4. Align with existing mapping if source_dir matches

### Drift Detection Flow
1. Query libvirt for actual state (dominfo, dumpxml, domblkinfo)
2. Parse XML/text output for hardware/mappings
3. Compare against config values
4. Return structured DriftReport with items and diagnostics

---

## Next Steps
- Explore CLI modules (vm.py, host.py, config.py)
- Explore attachments submodules (session, shared_root, guest, resolve)
- Explore remaining modules (runtime, status, util, errors, results, detect)
