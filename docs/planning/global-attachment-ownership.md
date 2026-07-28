# Global attachment ownership and replay

A managed shared VM has one machine-wide attachment inventory. Individual host
users still own the declarations that expose their local paths. This document
records the version 0.6 ownership and replay contract.

## Record identity

Machine-store attachment records include `owner_principal_id`. The effective
record identity is:

```text
(vm_name, owner_principal_id, canonical host_path)
```

`system` is reserved for machine-managed exports. An empty owner is accepted
only as legacy or migration input; newly created machine-store records are
attributed to the selected principal.

Machine-store writes reject an owner that is neither `system` nor a principal
of the same VM. Guest destinations are machine-global and therefore must be
unique across owners. Two principals may use similar lexical paths, but they
cannot claim the same guest mount destination.

## Caller-local resolution

Folder-oriented commands resolve the current host login to its VM principal
before using a host path. A lexical or canonical path only selects records
owned by that principal. This prevents Alice's `~/code/project` from selecting
Bob's declaration or making VM selection ambiguous.

Session restoration is also principal-scoped. `aivm ssh` and `aivm code`
restore the caller's saved shared and shared-root mappings; they do not inspect
or replay another principal's private host path as a side effect.

## Global visibility and mutation

The complete inventory remains visible from either account through status and
list output. Each line includes the owner, host source, guest destination,
mode, and access.

Ordinary update and detach operations require ownership. A trusted host
administrator can explicitly target another principal's record with:

```bash
aivm detach /path --owner_principal PRINCIPAL_ID --admin_override
```

The override is deliberately explicit. Merely belonging to the trusted host
group does not make a path-based command silently select somebody else's
record.

## Persistent replay

Persistent attachment intent is global VM state. For machine stores the
canonical manifest lives under:

```text
/var/lib/aivm/state/vms/<vm>/persistent/persistent-attachments.json
```

Manifest generation reads the complete machine inventory while holding the
store and VM locks. Attachment IDs include the owner so equivalent tags or
paths from different principals remain distinct. Any enrolled principal may
trigger reconciliation, but the generated desired state is identical.

Legacy stores retain their released per-user XDG replay location until the
migration stage.

## Private-home exposure

AIVM warns when a path under the caller's home is attached to a VM with
multiple principals. The current release assumes mutually trusted host and
guest users; ownership prevents accidental configuration mutation, not data
isolation inside the shared guest.

## Migration boundary

Existing unattributed records are not guessed at during normal loading. The
migration command will assign them to the creator principal or report a
conflict. Until then, legacy stores continue to use their existing single-user
semantics.
