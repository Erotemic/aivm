# AIVM architecture

This directory is the entry point for understanding AIVM's current 0.6
architecture. It combines reconstructed import data with curated runtime and
state models. The import graph tells us which code depends on which code; the
curated specifications describe sequencing, lock scope, state authority, and
recoverable failures that imports cannot express.

Human-facing text uses **access identity** for the persisted relationship
between one host user and one guest account. The implementation names are
currently `PrincipalEntry`, `principal_id`, and `VMPrincipal`.

## System map

AIVM is organized into these reviewed subsystems:

| Subsystem | Responsibility |
|---|---|
| CLI and command adapters | Parse commands, select requested operations, and present results. |
| Runtime resolution and services | Resolve a store scope, VM, caller profile, and access identity into an operation context. |
| Configuration models | Define `AgentVMConfig`, canonical machine/profile projections, and the runtime context model. |
| Machine store, profile, and locking | Persist global desired state and private caller state; provide optimistic concurrency and resource locks. |
| Access identities and enrollment | Bind host UID/GID identity to a guest account and personal SSH key through the restricted bootstrap channel. |
| Attachments and persistent replay | Own attachment declarations, path safety, host/guest realization, and replay manifests. |
| Repository credentials | Own deploy-key metadata, host key material, guest installation, and provider operations. |
| VM/network/host lifecycle | Realize desired state through libvirt, nftables, images, storage, mounts, and host setup. |
| Commands and privilege | Execute subprocesses and make privileged operations explicit and reviewable. |
| Pre-0.6 compatibility | Read released stores and perform explicit, reviewed, resumable migration. |
| Shared support | Errors, XML, and small compatibility utilities. |

The readable component diagram is
[`generated/component-dependencies.mmd`](generated/component-dependencies.mmd).
It intentionally shows the major edges rather than every foundation import.
The complete, deterministic edge inventory records every importing-module /
imported-module relationship and its occurrence count in each source file:
[`generated/component-edges.json`](generated/component-edges.json).

Dependency arrows point from the importer to the subsystem it uses. Dashed
arrows are transitional compatibility or known-debt edges. The pre-0.6 node is
not a general utility layer: canonical imports into it require an explicit
module-level allowlist.

## Runtime flows

The generated flow diagrams are small enough to read independently:

- [Ordinary VM command resolution](generated/flow-ordinary-command.mmd)
- [First-user initialization and VM creation](generated/flow-create-machine.mmd)
- [Later-user join and access enrollment](generated/flow-join-machine.mmd)
- [Attachment creation, replay, and detach](generated/flow-attachments.mmd)
- [Credential creation and revocation](generated/flow-credentials.mmd)
- [Access identity disable and remove](generated/flow-access-lifecycle.mmd)
- [Resumable VM deletion](generated/flow-vm-deletion.mmd)
- [Explicit released-store migration](generated/flow-migration.mmd)

The curated source is [`flows.yaml`](flows.yaml). Every `symbol` reference is
resolved against the Python AST during `check`; deleted or renamed functions,
classes, methods, and model fields make the documentation check fail. Nodes
that describe an external or control-flow concept without a unique Python
symbol must state `unverified_reason` explicitly.

## State authority

[`generated/state-ownership.mmd`](generated/state-ownership.mmd) distinguishes:

- **Machine store:** VM and network definitions, firewall policy, access
  identity records, attachment declarations, and credential metadata.
- **User profile:** active VM selection, CLI behavior, and references to the
  caller's personal SSH identity.
- **Access identity:** host UID/GID, guest username, public key, and lifecycle
  state (`pending`, `active`, or `disabled`).
- **Attachment:** owner, source identity, guest destination, mode, and
  realization state such as `active` or `detaching`.
- **Credential:** owner, repository/provider identity, access level, and
  lifecycle metadata. Private key bytes remain in host-private storage.
- **Transient/recovery state:** deletion journals and protected migration
  transactions record resumable phases and failure information.

The source is [`state-ownership.yaml`](state-ownership.yaml); model fields and
symbols are validated mechanically.

## The aggregate configuration transition

AIVM still has an important compatibility seam around `AgentVMConfig`:

- `VMEntry.cfg` persists the historical aggregate VM shape.
- `materialize_vm_cfg` joins that VM record with the separately owned network.
- `materialize_machine_cfg` overlays the selected access identity and caller
  profile.
- `ResolvedVMContext` carries canonical `MachineConfig`, `UserProfile`, and
  access-identity projections.
- `ResolvedVMContext.effective_cfg` remains the aggregate compatibility view
  consumed by runtime code that has not yet been narrowed.
- Released stores use the versioned context constructor under
  `aivm.legacy.pre_0_6_0`.

The reproducible inventory is
[`generated/compatibility-inventory.md`](generated/compatibility-inventory.md).
It reports canonical imports of the compatibility package, canonical
`AgentVMConfig` references, and path-based `StoreScope` reconstructions. The
legacy allowlist is enforced now; the other two inventories are observational
and are expected to shrink without being silently reset.

## Curated versus generated files

Curated and reviewed:

- `README.md`
- `architecture.yaml` — subsystem classification, allowed edges, debt labels,
  diagram selection, and legacy import allowlist
- `flows.yaml` — runtime sequencing and recoverable state transitions
- `state-ownership.yaml` — authoritative state locations and transitional views

Generated; do not edit directly:

- `generated/component-dependencies.mmd`
- `generated/component-edges.json`
- `generated/flow-*.mmd`
- `generated/state-ownership.mmd`
- `generated/compatibility-inventory.md`

Generated files contain a schema version but no timestamp or whole-package
source digest. `check` regenerates expected content and compares bytes, so
stale architecture still fails without making unrelated implementation edits
dirty every generated file. Source locations in inventories are file-level so
line movement alone does not create documentation churn.

## Contributor commands

Regenerate after intentionally changing code or a curated specification:

```bash
python dev/devcheck/architecture_docs.py generate
```

Check classifications, dependency rules, symbol references, and generated
file drift without modifying the checkout:

```bash
python dev/devcheck/architecture_docs.py check
```

Print subsystem edges and transitional inventory counts without writing files:

```bash
python dev/devcheck/architecture_docs.py report
```

The check runs from `run_linter.sh` and from the normal pytest matrix via
`tests/test_architecture_docs.py`. CI never regenerates documentation.

## Adding a module or dependency

When adding a production module under `aivm/`:

1. Add it to an existing prefix rule in `architecture.yaml`, or add an exact
   override when the package location does not describe its architectural
   role. Exact rules take precedence over prefixes.
2. Run `report` and inspect every new subsystem edge.
3. If the edge is intended, add it to `allowed_edges`. Add an
   `edge_annotations` entry when it is transitional or known debt. Do not use
   “accepted” to hide a boundary violation.
4. Add a reviewed `diagram_edges` entry only when the edge is important enough
   for the contributor-facing graph. The JSON inventory remains complete.
5. Regenerate and run `check`.

A new canonical import of `aivm.legacy.pre_0_6_0` additionally requires an
exact importer/prefix allowlist entry with a reason. Tests outside
`tests/legacy/pre_0_6_0` may not import compatibility implementation modules.

## Current intentional debt

The policy records, rather than conceals, several current seams:

- `ToolsConfig` obtains optional tool declarations from the guest-tool registry,
  creating a configuration-model to lifecycle edge.
- privilege helpers currently consult host identity and runtime/libvirt state;
- credential guest installation uses the prepared attachment-session path;
- a few shared utilities still re-export command helpers;
- canonical persistence, runtime, attachment, credential, firewall, and update
  modules retain narrowly allowlisted pre-0.6 adapters.

These edges are allowed so the check reflects the repository rather than an
imagined target architecture. Their explicit labels make regression and
future removal reviewable.
