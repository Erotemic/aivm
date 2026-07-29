# Shared-machine operational lifecycle

This document records the final trusted-host operational rules for the 0.6.0
shared-machine architecture. The serialized model still uses `principal` and
`principal_id`; user-facing commands call the same object an **access identity**.
That wording can change later without changing the machine/profile boundary.

## Trust mode

The 0.6.0 shared-machine release uses `trusted-host-users` mode. Its
security boundary excludes unrestricted root and unrestricted system-libvirt
administrators: either capability can bypass AIVM policy. Access identities and
ownership records protect ordinary operation from accidental cross-user
mutation and preserve audit/recovery metadata; they are not a sandbox against a
host account that already has either excluded capability.

Caller selection is derived from the process UID/GID and the passwd database,
not `USER`, `LOGNAME`, or `SUDO_USER`. Stored UID and username must both match.
An account rename is repaired explicitly with `aivm vm access
repair_host_identity`; same-name/different-UID records fail closed as account
recreation or UID reuse. Whole-command root execution of `aivm host permissions
setup` requires an explicit `--user` target.

## Access identity lifecycle

The supported commands are:

```bash
aivm vm access list --vm <vm>
aivm vm access reconcile --vm <vm>
aivm vm access reconcile --vm <vm> --enable
aivm vm access repair_host_identity --vm <vm>
aivm vm access disable [identity] --vm <vm>
aivm vm access remove [identity] --vm <vm>
```

An identity selector is its stable id or host login and defaults to the caller.
Targeting another host user requires `--admin_override`. Disabling or removing
the final active identity requires `--allow_last_access` because ordinary SSH
and editor workflows will stop until the restricted bootstrap path restores an
identity.

### Disable

Disable is the reversible operation. The forced guest helper removes only the
recorded personal public key and the AIVM-managed sudoers fragment. It retains:

- the guest account and home;
- unrelated authorized keys;
- attachment and credential ownership records;
- provider ids, fingerprints, and revocation evidence.

The machine record moves to `disabled`, and the owning caller's profile stops
selecting that VM. Disable/remove run under the authoritative store and VM locks
and always reconcile and verify guest revocation, even when metadata already
says `disabled`; retries therefore converge after interruption or guest-state
drift. Re-enablement is explicit through `access reconcile --enable`, which
reinstalls and verifies the caller's current personal key.

Reconcile does not rotate an existing identity's SSH key material or guest
username. Comment-only SSH-key changes are treated as the same key, while real
key/account changes are rejected pending a dedicated resumable rotation
operation. Active identities use distinct guest usernames.

### Remove

Remove deletes only the machine-store identity record. It first ensures guest
access is disabled and never deletes the guest account, home, or files. Removal
is refused while the identity owns attachments or credential records. Those
records must be detached, transferred through an explicit administrative
attachment operation, or revoked/abandoned through the owning user's credential
context before identity removal.

## Persistent attachment teardown

Persistent approvals bind the recorded source path to its device/inode. The
privileged helper opens source, export root, and target without following
symlinks, holds those descriptors through `mount --bind`, mounts through
`/proc/self/fd`, and verifies the resulting mount. Immediate attach and boot
replay use the same primitive.

Detach is a recoverable transition. The record first becomes `detaching`; AIVM
installs the reduced approved manifest, immediately prunes the host bind, and
removes any live guest mount. The record is deleted only after cleanup succeeds.
A stopped VM needs no live guest cleanup because the next boot consumes the
reduced manifest. Detach matches stored lexical paths and aliases even when the
original source has disappeared.

## VM deletion

VM deletion is a durable, idempotent journal. It records storage and all
AIVM-owned cleanup coordinates, then completes attachment exposure, credential
material, domain/storage, bootstrap/state trees, profile selection, and store
finalization in that order. Retries skip completed phases. The VM record is
removed last, and an explicit delete can close the narrow crash window where
the atomic store write landed before `store-finalized` was journaled.

Before the first destructive phase, every recorded disk path must remain
inside the VM's AIVM-managed tree both lexically and after resolving existing
symlink components. Externally located storage is rejected before attachment,
credential, libvirt, or storage changes begin. Every libvirt undefine attempt
retains `--remove-all-storage`; unverifiable non-file disks and retained storage
fail closed with a recoverable journal instead of being silently forgotten.

## Machine-wide operations

VM start, shutdown, restart, delete, hardware update, and network
create/recreate/destroy affect shared state. Before execution, AIVM labels the
action as machine-wide and reports the number of affected VM, access identity,
attachment, and credential records. Machine list/status output also shows the
trust mode and active/total identity counts.

These messages make scope visible; they do not add a second authorization
system. State-changing code remains behind service functions so a future
privileged broker can replace direct trusted-host mutation without replacing
the stored ownership model.

## Deferred enforcement

The following are still intentionally outside 0.6.0:

- removing ordinary users from the `libvirt` group;
- a privileged host daemon;
- isolation between mutually untrusted host users;
- deletion of guest homes as part of access lifecycle;
- automatic ownership transfer on identity removal.
