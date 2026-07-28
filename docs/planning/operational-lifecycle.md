# Shared-machine operational lifecycle

This document records the final trusted-host operational rules for the 0.6.0
shared-machine architecture. The serialized model still uses `principal` and
`principal_id`; user-facing commands call the same object an **access identity**.
That wording can change later without changing the machine/profile boundary.

## Trust mode

The 0.6.0 shared-machine release uses `trusted-host-users` mode. Enrolled host
users share one VM and may already have root-equivalent control through the
system libvirt daemon. Access identities and ownership records prevent
accidental cross-user mutation and preserve audit/recovery metadata; they are
not an isolation boundary between mutually hostile host users.

## Access identity lifecycle

The supported commands are:

```bash
aivm vm access list --vm <vm>
aivm vm access reconcile --vm <vm>
aivm vm access reconcile --vm <vm> --enable
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
selecting that VM. Re-enablement is explicit through `access reconcile
--enable`, which reinstalls and verifies the caller's current personal key.

### Remove

Remove deletes only the machine-store identity record. It first ensures guest
access is disabled and never deletes the guest account, home, or files. Removal
is refused while the identity owns attachments or credential records. Those
records must be detached, transferred through an explicit administrative
attachment operation, or revoked/abandoned through the owning user's credential
context before identity removal.

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
