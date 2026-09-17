# Machine and user-profile store contract

Status: implemented for fresh implicit installations in the 0.6.0 development
branch. Released per-user stores remain readable and are not migrated
implicitly.

This document records the logical persistence split built on top of the
filesystem contract in
[`machine-store-filesystem-contract.md`](machine-store-filesystem-contract.md).

## Store selection

AIVM selects one persistence mode at the beginning of each invocation:

1. An explicit `--config /var/lib/aivm/config.toml` selects the machine store.
2. Any other explicit `--config` path selects legacy single-document behavior.
3. Without `--config`, an existing machine store is preferred.
4. If no machine store exists, an existing released user store remains active.
5. A brand-new implicit installation starts with the machine/profile split.

These rules prevent an upgrade from silently moving or rewriting an existing
released store. They also give a newly configured shared host one canonical
machine authority. If both persistence modes exist, implicit commands select
the machine store; the legacy document remains available through its explicit
path until the migration command is implemented.

## Machine document

The machine document uses config-store schema version 9 and declares:

```toml
schema_version = 9
store_kind = "machine"
```

It reuses the existing split layout:

```text
/var/lib/aivm/
├── config.toml
├── defaults.toml
├── networks.toml
└── vms/
    └── <vm-name>.toml
```

The machine store owns:

- global defaults that affect VM resources or provisioning;
- network and firewall definitions;
- VM hardware, image, provision, tool, and virtiofs declarations;
- machine storage roots such as `paths.base_dir`;
- persisted VM principals;
- attachments and credentials during the current transition.

Machine TOML deliberately omits:

- `active_vm`;
- behavior and approval preferences;
- `vm.user`;
- SSH private/public key paths;
- the caller's local state/cache directory.

`AgentVMConfig` remains the compatibility aggregate used by some internal
machine operations. Materialization fills its omitted caller fields from the
selected principal and profile; those reconstructed fields are not written
back to the machine document.

## User profile

Each host user has a private schema-version-1 profile at:

```text
~/.config/aivm/profile.toml
```

It owns:

- `active_vm`;
- command behavior and verbosity;
- personal SSH private/public key paths;
- the caller's local state directory;
- `default_guest_user`, used only while creating a new VM from global defaults.

The profile is written atomically with directory mode `0700` and file mode
`0600`. A profile update cannot serialize a VM, network, attachment, or
principal and therefore cannot redefine machine state by construction.

`aivm config paths` reports both physical stores, and
`aivm config edit profile` opens the private profile directly.

## Persisted principals

Each machine VM may contain one principal per host login:

```toml
[[vms.principals]]
id = "principal-..."
host_user = "alice"
host_uid = 1001
host_gid = 1001
guest_user = "alice-agent"
ssh_public_key = "ssh-ed25519 ..."
state = "active"
```

Principal IDs are deterministic from the VM name and host login. The persisted
principal owns the authoritative guest username after VM creation; changing a
profile's `default_guest_user` does not rename or retarget an existing guest
account.

The first successful `aivm vm create` against a machine store atomically writes
the VM/network/principal portion of the machine document, then updates the
creator's private profile. Repeating creator persistence is idempotent and
preserves the existing guest username.

Runtime resolution requires exactly one principal matching the invoking host
login. Missing, duplicate, or non-active principals fail with an actionable
error. This tranche does not create a later user's guest account: the bootstrap
and enrollment control plane is the next stage.

## Host setup

The production store is prepared through:

```bash
aivm host permissions setup
```

In addition to the pre-existing libvirt and VM-storage work, setup now:

- creates the trusted system group `aivm` when absent;
- adds the invoking host user to that group;
- creates `/var/lib/aivm` as `root:aivm` mode `02775`.

A login refresh is required after new group membership. `config init` refuses
to improvise weaker permissions and reports this setup command when the shared
root cannot be initialized.

Tests and advanced sandboxes may set `AIVM_MACHINE_STORE_ROOT`; those roots are
caller-owned and use the current process GID rather than requiring a real
system group.

## Compatibility and current limitations

- Existing released stores are never migrated merely because 0.6.0 code reads
  them.
- Explicit non-machine `--config` paths retain the legacy aggregate semantics.
- There is not yet a cross-file transaction spanning the machine document and
  private profile. Operations write machine state first and make profile
  updates idempotent, so interruption is recoverable without losing the
  authoritative VM record.
- Attachments are now physically global for fresh machine-store installs, but
  principal ownership and global replay reconciliation land in a later stage.
- Credential records remain VM-scoped during this tranche; principal scoping is
  also deferred.
- A second host user receives a clear "not enrolled" error until the restricted
  bootstrap helper and `config init` join flow are implemented.
