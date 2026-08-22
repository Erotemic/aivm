# Released-store migration planning

AIVM 0.6 keeps released per-user stores readable until an operator explicitly
migrates them. The first migration phase is deliberately read-only:

```bash
aivm config migrate plan
```

The planner loads the current user's released store, compares it with the
machine-store target, and optionally inventories libvirt domains and networks.
It does not create backups, write `/var/lib/aivm`, alter the user profile,
contact a guest, rename credential material, or change provider deploy keys.

## Multiple released stores

An administrator can inspect several old stores in one report:

```bash
aivm config migrate plan \
    alice=/home/alice/.config/aivm/config.toml \
    bob=/home/bob/.config/aivm/config.toml
```

Each positional source uses `[HOST_USER=]PATH`. A bare path belongs to the
invoking host user. The explicit owner spelling is required when inspecting
another user's store or when several inputs are supplied by an administrative
workflow.

AIVM never silently chooses between two released stores that claim the same VM.
The report names every claimant and lists machine-field differences. The later
apply command must require an explicit merge or source-selection decision.

## Report contents

The text report summarizes:

- source layout, schema version, constituent files, and SHA-256 fingerprints;
- proposed machine defaults, networks, VMs, access identities, attachments,
  and credential records;
- proposed per-user profile fields;
- attribution of legacy attachments and credentials to the creator identity;
- legacy-to-principal credential ID changes;
- user-owned credential-directory renames required by those ID changes;
- persistent replay state movement into per-VM machine state;
- existing target-machine records;
- managed, missing, and unmanaged libvirt domains and networks;
- blocking conflicts and non-blocking warnings.

Machine-readable output is available for review tooling:

```bash
aivm config migrate plan --output json
```

The JSON document has its own `plan_schema_version`. It intentionally contains
paths and non-secret credential metadata, but not private key contents.

## Blocking conditions

The planner currently blocks apply readiness when it finds conditions such as:

- a missing or invalid source store;
- a non-legacy source document;
- multiple stores claiming one VM;
- divergent network or machine defaults;
- one user store requiring incompatible profile SSH/state paths;
- an unresolved host UID/GID;
- a missing or malformed personal SSH public key;
- conflicting guest attachment destinations;
- an existing non-empty machine store requiring an explicit merge;
- a legacy VM record with no corresponding libvirt domain.

Unmanaged runtime resources are reported but are not imported or deleted.
Runtime inspection can be skipped with `--no_runtime`. Whether the two
read-only libvirt probes run through sudo is not a migration choice: they take
the same `virsh_needs_sudo()` decision as every other libvirt client command,
so `behavior.privilege_mode` alone governs it. When the probes cannot reach
libvirt, the plan reports a `runtime-inventory-unavailable` warning.

## Next phase

The apply phase will consume a fresh plan rather than trusting an old report. It
must back up every source, verify source fingerprints, write a resumable phase
journal, install the bootstrap helper through the creator's working SSH path,
move persistent state and credential directories, verify the migrated machine,
and retain an explicit rollback path. None of those mutations are implemented
by `migrate plan`.
