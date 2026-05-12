# Attachments Submodules Discovery Log

## Timestamp: 2026-04-04 02:40:30 UTC

## Overview
The `aivm/attachments/` directory contains submodules for managing host folder attachments to VMs, including session preparation, shared-root bind mounts, guest-side operations, and attachment resolution.

---

## [`aivm/attachments/session.py`](aivm/attachments/session.py)
**Purpose:** Session/reconcile helpers - attachment saving, VM reconciliation, session preparation

**Key Dataclasses:**
- `ReconcilePolicy` - ensure_firewall_opt, recreate_if_needed, dry_run, yes
- `ReconcileResult` - attachment, cached_ip, cached_ssh_ok, shared_root_host_side_ready

**Key Functions:**
- `_prepare_attached_session(...)` - Main entry point for `aivm code`/`aivm ssh` workflows
- `_reconcile_attached_vm(cfg, host_src, attachment, policy)` - Reconcile VM/network/firewall/share state
- `_saved_vm_attachments(cfg, cfg_path, primary_attachment)` - Get saved attachments for VM restore
- `_restore_saved_vm_attachments(cfg, cfg_path, ip, primary_attachment, yes, mirror_home)` - Best-effort restore saved attachments
- `_record_attachment(cfg, cfg_path, host_src, mode, access, guest_dst, tag, force)` - Persist attachment to config store
- `_resolve_ip_for_ssh_ops(cfg, yes, purpose)` - Get VM IP, wait if needed
- `_maybe_warn_hardware_drift(cfg)` - Warn if VM hardware differs from config

**Session Preparation Flow:**
1. Resolve VM context from config store or create new VM
2. Resolve attachment (mode, access, guest_dst, tag)
3. Reconcile attached VM state:
   - Check network, firewall, VM running state
   - Create/start VM if needed
   - Attach virtiofs share if missing
4. Generate SSH identity if needed
5. Record attachment in config store
6. Wait for IP and SSH readiness
7. Ensure attachment available in guest
8. Restore saved attachments for VM
9. Return `PreparedSession` with IP, paths, etc.

**Restore Behavior:**
- Primary attachment: Reconciled first with full host-side repair allowed
- Secondary attachments: Best-effort restore, avoid disruptive rebinds
- Shared-root: Skip if host bind already mounted (avoid disrupting active mounts)
- Shared mode: Re-attach virtiofs mapping if missing, remount in guest

**Design Notes:**
- Idempotent: Reconcile logic handles already-correct state
- Non-disruptive restore: `allow_disruptive_shared_root_rebind=False` for automatic restore
- Lexical path preservation: Store lexical path for symlink companion creation
- Mirror-home: Create symlinks under guest home mirroring host-home-relative paths

---

## [`aivm/attachments/shared_root.py`](aivm/attachments/shared_root.py)
**Purpose:** Shared-root attachment helpers - host bind, VM mapping, guest bind management

**Key Constants:**
- `SHARED_ROOT_GUEST_MOUNT_ROOT` = `/mnt/aivm-shared`
- `SHARED_ROOT_VIRTIOFS_TAG` = `aivm-shared-root` (from share.py)

**Key Functions:**
- `_shared_root_host_dir(cfg)` - VM-specific shared-root host directory
- `_shared_root_host_target(cfg, token)` - Project-specific bind target path
- `_ensure_shared_root_parent_dir(cfg, dry_run)` - Create shared-root parent directory
- `_ensure_shared_root_host_bind(cfg, attachment, yes, dry_run, allow_disruptive_rebind)` - Bind host folder to shared-root target
- `_ensure_shared_root_vm_mapping(cfg, yes, dry_run, vm_running)` - Ensure VM has shared-root virtiofs mapping
- `_ensure_shared_root_guest_bind(cfg, ip, attachment, dry_run)` - Mount and bind inside guest
- `_detach_shared_root_host_bind(cfg, attachment, yes, dry_run)` - Unmount and remove host bind
- `_detach_shared_root_guest_bind(cfg, ip, attachment, dry_run)` - Unmount inside guest

**Shared-Root Architecture:**
- One virtiofs export per VM: `/var/lib/libvirt/aivm/<vm>/shared-root`
- Per-project bind targets: `<shared_root>/ <token>` where token is attachment tag
- Guest mount: `/mnt/aivm-shared` (virtiofs) -> bind to `<guest_dst>`

**Host Bind Logic:**
1. Verify source directory exists
2. Probe current mount state via `findmnt`
3. If already correct (SOURCE/ROOT match or stat inode match), return early
4. If mismatch and `allow_disruptive_rebind=False`, raise error (restore mode)
5. If mismatch and `allow_disruptive_rebind=True`, unmount and rebind
6. Shell-level idempotence: Check inode before issuing bind mount

**Mount Source Comparison:**
- `findmnt SOURCE` is unstable across bind-mount backends
- Compare candidates: raw value, prefix before `[`, content inside `[]`
- Also compare inode via `stat -Lc %d:%i` for definitive match

**Guest Bind Logic:**
1. Mount shared-root virtiofs at `/mnt/aivm-shared`
2. Verify source subdirectory exists
3. If destination already mounted, check source match
4. Unmount if stale, create parent dirs
5. Bind mount source to destination
6. Verify source and access mode (ro/rw)

**Design Notes:**
- Robust mount detection: Multiple comparison strategies for findmnt output
- Lazy unmount handling: Refuse during normal detach, suggest manual cleanup
- Verification: Final check of source and options after mount operations

---

## [`aivm/attachments/guest.py`](aivm/attachments/guest.py)
**Purpose:** Guest-side attachment helpers - symlinks, git clone, SSH config management

**Key Functions:**
- `_ensure_guest_symlink(cfg, ip, symlink_path, target_path)` - Safely ensure symlink exists
- `_apply_guest_derived_symlinks(cfg, ip, host_src, attachment, mirror_home)` - Create companion and mirror-home symlinks
- `_upsert_ssh_config_entry(cfg, dry_run, yes)` - Update SSH config with VM entry
- `_ensure_attachment_available_in_guest(cfg, host_src, attachment, ip, yes, dry_run, ...)` - Dispatcher for mode-specific reconciliation
- `_ensure_git_clone_attachment(cfg, host_src, attachment, ip, yes, dry_run)` - Git-mode attachment sync

**Symlink Safety Rules:**
- Path doesn't exist: Create symlink
- Already correct symlink: No-op
- Empty directory: Remove and replace with symlink
- Non-empty directory: Warn and skip (exit 4)
- Regular file: Warn and skip (exit 5)
- Symlink to wrong target: Warn and skip (exit 3)

**Companion Symlink Logic:**
- If host_src is a symlink, create guest symlink at lexical path -> resolved guest_dst
- Enables accessing same content via both symlink and resolved paths

**Mirror-Home Logic:**
- If `behavior.mirror_shared_home_folders=True` and host path under `$HOME`:
  - Create symlink at `$HOME/<relative_path>` -> guest_dst
  - Also apply to resolved path if host_src is a symlink
- Allows accessing guest content at same relative path under guest home

**Git-Mode Attachment:**
1. Verify host_src is Git worktree, get repo root and relative path
2. Get current branch name
3. Compute guest repo root (parent dirs of guest_dst)
4. Generate remote name: `aivm-<vm-stem>-<sha1_hash>`
5. Register host remote pointing to `vm_name:guest_repo_root`
6. Prepare guest repo (init, set receive.denyCurrentBranch)
7. Push host branch to guest
8. Verify guest path exists after push

**SSH Config Management:**
- Block format: `# >>> aivm:<vm_name> >>>` ... `# <<< aivm:<vm_name> <<<`
- Idempotent: Replace existing block or append new one
- Returns (path, changed) for audit

---

## [`aivm/attachments/resolve.py`](aivm/attachments/resolve.py)
**Purpose:** Attachment resolution helpers - path computation, mode/access normalization

**Key Constants:**
- `ATTACHMENT_MODE_SHARED` = `'shared'`
- `ATTACHMENT_MODE_SHARED_ROOT` = `'shared-root'`
- `ATTACHMENT_MODE_GIT` = `'git'`
- `ATTACHMENT_ACCESS_RW` = `'rw'`
- `ATTACHMENT_ACCESS_RO` = `'ro'`

**Key Functions:**
- `_resolve_attachment(cfg, cfg_path, host_src, guest_dst_opt, mode_opt, access_opt)` - Resolve full attachment
- `_normalize_attachment_mode(mode)` - Normalize mode with aliases
- `_normalize_attachment_access(access)` - Normalize access with aliases
- `_default_primary_guest_dst(host_src)` - Compute default guest destination
- `_host_symlink_lexical_path(host_src)` - Get lexical path if host_src is symlink
- `_compute_mirror_home_symlink(cfg, host_src, guest_dst, is_default_dst)` - Compute mirror-home path

**Mode Aliases:**
- Git: `clone`, `cloned`, `repo`, `git`
- Shared-root: `sharedroot`, `shared_root`, `root`
- Shared: `shared`

**Access Aliases:**
- RO: `readonly`, `read-only`, `read_only`
- RW: `readwrite`, `read-write`, `read_write`

**Resolution Logic:**
1. Resolve source_dir (absolute, resolved)
2. Resolve guest_dst (override or default)
3. Generate/lookup tag
4. Normalize mode/access (with aliases)
5. Check saved attachment for mode/access mismatch
6. Reuse saved values if no override provided
7. Return `ResolvedAttachment`

**Mode Mismatch Error:**
- If explicit `--mode` differs from saved mode, error with detach+reattach instructions
- Same for access mode

**Design Notes:**
- Git mode: Tag is empty (no virtiofs mapping)
- Read-only: Only supported for shared/shared-root modes
- Default guest_dst: Resolved path if symlink, else lexical absolute path

---

## Cross-Module Patterns

### Attachment Resolution Flow
1. CLI receives `aivm code .` or `aivm attach .`
2. `_resolve_attachment()` computes mode, access, tag, guest_dst
3. Check config store for saved attachment
4. Validate mode/access against saved (if override provided)
5. Return `ResolvedAttachment` for reconciliation

### Shared-Root Reconciliation Flow
1. **Host side**: Create bind target, bind source to target
2. **VM side**: Ensure virtiofs mapping exists
3. **Guest side**: Mount virtiofs, bind subdirectory to guest_dst
4. **Verification**: Check mount source and options

### Git-Mode Sync Flow
1. Verify Git repo, get branch
2. Register host remote pointing to guest
3. Prepare guest repo (init, configure)
4. Push host -> guest
5. Verify guest path exists

### Symlink Companion Flow
1. Detect if host_src is symlink
2. Compute lexical guest path
3. Create symlink at lexical -> resolved guest_dst
4. Also create mirror-home symlinks if enabled

---

## Next Steps
- Explore remaining modules (runtime, status, util, errors, results, detect, cli/_common)
- Create architecture overview document
