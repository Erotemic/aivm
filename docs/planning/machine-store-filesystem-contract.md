# Machine-store filesystem contract

Status: implemented and used by fresh machine/profile installations in the
0.6.0 development branch. Released stores are still not migrated implicitly.

This document records the executable filesystem decisions used by the
machine-global store. They were settled in isolation before activation and now
serve fresh machine/profile installations.

## Layout

The default root is `/var/lib/aivm`. Tests and advanced development setups may
replace it with `AIVM_MACHINE_STORE_ROOT`.

```text
/var/lib/aivm/
├── config.toml
├── defaults.toml
├── networks.toml
├── vms/
├── state/
├── bootstrap/
└── locks/
    ├── store.lock
    ├── networks/
    └── vms/
```

The split config fragments retain their existing literal-concatenation
contract. Machine schema version 11 changes which logical fields are stored but
reuses this physical layout and transaction machinery.

## Ownership and modes

The production installation is expected to be owned by `root:aivm`.

| Object | Mode | Rationale |
|---|---:|---|
| Machine root, `vms`, `state`, and lock directories | `02775` | Trusted group members can create and replace state; setgid preserves the group on new entries. |
| Config fragments, transaction metadata, and lock files | `0664` | Every trusted group member can complete a read-modify-write cycle and recover an interrupted transaction. |
| `bootstrap` directory | `02750` | Enrollment material is not general config state and should not be world-readable. |
| Bootstrap private key | `0600` | Root owns and uses it through the restricted enrollment channel; group members never read the private key directly. |

The implementation sets the target group before applying the final mode because
`chown` may clear setgid bits. Tests inject the current process GID, so no test
needs root or the real `aivm` group.

## Atomic replacement

Machine-store writes use the same-directory replacement sequence:

1. create the parent hierarchy under the managed root;
2. create a temporary file in the target directory;
3. write and flush the content;
4. apply the intended group and file mode to the open descriptor;
5. `fsync` the file;
6. replace the target with `os.replace`;
7. reassert metadata and `fsync` the parent directory.

Split-layout transactions remain recoverable by a different trusted user. The
staging tree and metadata therefore receive the same group-safe policy rather
than tempfile's default private permissions.

Managed machine-store paths reject symlinked directories and symlinked target
files. The trusted-user model does not claim hostile-local-user isolation, but
there is no reason to make accidental path redirection part of the supported
contract.

## Mutation boundary

Separate `load_store` and `save_store` calls retain optimistic-concurrency
protection: a stale writer is rejected. Machine-wide operations that should
merge concurrent changes use:

```python
update_store(mutate, path, io_policy=policy, force_split=True)
```

`update_store` holds the store lock across load, mutation, validation, and
replacement. The concurrency test starts two processes that add different
attachments to the same VM and verifies that both records survive.

## Resource locks and ordering

The global lock order is:

1. store;
2. networks, sorted by logical name;
3. VMs, sorted by logical name.

A caller must never acquire a store lock while already holding a network or VM
lock. Operations that need multiple resource locks must construct them through
`ordered_machine_locks` / `machine_resource_locks`, which deduplicate names and
apply this order. File locks are process/thread-safe and reentrant, so an
operation may acquire the ordered store/resource set and then call
`update_store`, which re-enters the same store lock rather than deadlocking.

Lock filenames contain a readable normalized prefix plus a digest of the full
logical name. This avoids collisions between names that normalize to the same
filesystem spelling.

## Recovery coverage

The unit tests verify that:

- atomic replacement restores the intended file group and mode;
- split fragments and transaction files remain group writable;
- two process-level mutations serialize and retain both changes;
- an interrupted split transaction updates its intended VM fragment without
  deleting an unrelated VM fragment;
- lock ordering is deterministic;
- machine paths remain inside the isolated test root;
- symlinked roots are refused.

These tests are deliberately unit/integration-scale. The expensive real-host
E2E suite remains deferred until the shared-machine workflow is complete.

## Activation status

Fresh implicit installations now use this layout with the schema and routing
rules in
[`machine-profile-store-contract.md`](machine-profile-store-contract.md).
`aivm host permissions setup` prepares the production group and root. Existing
released stores are still selected unchanged when no machine store exists.

The remaining work on top of this physical contract is:

- install the restricted enrollment bootstrap identity and guest helper;
- migrate released stores explicitly and recoverably;
- add principal ownership to attachments and credentials;
- move persistent replay state into the complete machine-global inventory.
