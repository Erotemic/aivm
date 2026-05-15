# Config refactor plan and handoff notes

Written: 2026-05-15 13:45:02 America/New_York
Baseline source snapshot: 5c7effe87377ca29b832eeeda76e2da0f0e37b20

## Purpose

This note captures the current AIVM config refactor plan so work can resume
safely after an interruption.  The goal is to make the editable configuration
more manageable without changing the core desired-state model that drift
detection already uses.

The intended endpoint is a concatenation-friendly split config layout:

```text
~/.config/aivm/
  config.toml
  networks.toml
  vms/
    aivm-2404.toml
    scratch.toml
```

The important invariant is:

```text
cat config.toml networks.toml vms/*.toml
```

should be valid TOML that parses as the canonical AIVM desired-state document.
The split files are a physical decomposition of the same logical config schema,
not a new per-file schema.

## Design principles

1. Keep current monolithic configs working until the user explicitly migrates.
2. Optimize for literal concatenation first; it is easier to relax this later
   than to retrofit it after a standalone per-VM schema exists.
3. Keep VM RAM, CPU count, disk size, image, provisioning, and attachments in
   editable desired-state TOML.
4. Drift detection must consume the logical desired-state document, not the
   physical file layout.
5. Runtime observations and cache state are out of scope for this refactor.
6. Do not reintroduce generated host-side virtiofsd wrappers as part of this
   work.  Host-generated wrappers violated the trust model and caused VM start
   failures on toothbrush.

## Target file shapes

### `config.toml`

Owns singleton/global tables only:

```toml
schema_version = 6
active_vm = "aivm-2404"

[behavior]
yes_sudo = false
auto_approve_readonly_sudo = true
verbose = 1
mirror_shared_home_folders = false

[defaults.vm]
user = "agent"
cpus = 4
ram_mb = 8192
disk_gb = 40
timezone = ""

[defaults.paths]
base_dir = "/var/lib/libvirt/aivm"
state_dir = "~/.cache/aivm"

[defaults.virtiofs]
inode_file_handles = ""
```

### `networks.toml`

Owns shared network desired state:

```toml
[[networks]]
name = "aivm-net"

[networks.network]
bridge = "virbr-aivm"
subnet_cidr = "10.77.0.0/24"
gateway_ip = "10.77.0.1"

[networks.firewall]
enabled = true
block_cidrs = []
extra_block_cidrs = []
```

Networks are separate from VM files because one or two VMs will often share a
single managed network.  Keeping the shared network in one file avoids silent
copy/paste drift between VM configs.

### `vms/{vm_name}.toml`

Each VM file owns exactly one `[[vms]]` entry and that VM's attachments:

```toml
[[vms]]
name = "aivm-2404"
network_name = "aivm-net"

[vms.vm]
cpus = 8
ram_mb = 32768
disk_gb = 80
timezone = "America/New_York"

[vms.provision]
enabled = true
install_docker = true
packages = [
  "git",
  "jq",
  "ripgrep",
]

[vms.virtiofs]
inode_file_handles = ""

[[vms.attachments]]
host_path = "/home/joncrall/code/aivm"
mode = "shared-root"
access = "rw"
guest_dst = "/home/agent/code/aivm"
```

The `[[vms]]` prefix is noisier when editing one VM file, but it preserves the
more important invariant that each file is a literal fragment of the canonical
document.

## Chunk plan

### Chunk 1: document the target and isolate the current store

Status: implemented as overlay `aivm-config-store-chunk1-overlay-5c7effe8.zip`.

Goal: make the current monolithic config easier to work on without changing
behavior.

Scope:

- Add config-layout design documentation.
- Fix stale refactor docs around virtiofsd wrappers.
- Split `aivm/store.py` internally into focused modules:
  - `aivm/config_store/models.py`
  - `aivm/config_store/parse.py`
  - `aivm/config_store/render.py`
  - `aivm/config_store/io.py`
  - `aivm/config_store/paths.py`
  - `aivm/config_store/mutate.py`
  - `aivm/config_store/resolve.py`
- Keep `aivm/store.py` as a compatibility facade.
- Do not change physical config layout.
- Do not change schema semantics.

Expected validation:

```bash
pytest tests/test_config.py \
       tests/test_store.py \
       tests/test_cli_config_init.py \
       tests/test_cli_config_lint.py \
       tests/test_attachment_persistent.py::test_persistent_host_manifest_path_uses_app_data_dir
```

Suggested commit message:

```text
Refactor config store internals without changing layout
```

### Chunk 2: support the future schema inside the existing logical document

Status: implemented as overlay `aivm-config-store-chunk2-overlay-5c7effe8.zip`.

Goal: teach AIVM that attachments can live under `[[vms]]` while preserving the
current global attachment form.

Scope:

- Add parser support for `[[vms.attachments]]`.
- Keep legacy top-level `[[attachments]]` parsing unchanged.
- Keep the in-memory `Store.attachments` model flat for existing callers.
- Add renderer support for nested VM attachments behind an explicit option.
- Keep default rendering behavior legacy-compatible.
- Add equivalence tests showing legacy global attachments and nested VM
  attachments materialize to the same effective attachment records.
- Ensure drift/update code sees the same desired state regardless of attachment
  layout.

Current intended behavior:

- Nested attachments inherit `vm_name` from the owning `[[vms]]` entry.
- If a nested attachment redundantly specifies `vm_name`, it must match the
  owning VM; a mismatch is an error.
- `render_store_toml(..., attachment_style="legacy")` remains the default.
- `render_store_toml(..., attachment_style="nested")` emits
  `[[vms.attachments]]`.

Expected validation:

```bash
pytest tests/test_store.py \
       tests/test_attachment_resolve.py \
       tests/test_vm_drift.py \
       tests/test_cli_vm_update.py
```

Suggested commit message:

```text
Support nested VM attachment config
```

### Chunk 3: add split-layout read support and user-facing inspection

Status: not implemented.

Goal: make the split layout readable without migrating or rewriting users'
configs automatically.

Scope:

- Add a loaded-document/source metadata abstraction, for example:
  - `LoadedStore`
  - `ConfigSource`
  - layout value such as `"monolith"` or `"split"`
- Teach the loader to read either:
  - current monolith: `~/.config/aivm/config.toml`
  - split layout: `config.toml`, optional `networks.toml`, sorted `vms/*.toml`
- Implement deterministic concatenation in the loader:
  1. `config.toml`
  2. `networks.toml`, if present
  3. `vms/*.toml`, sorted by filename
- Parse the concatenated TOML as the same canonical desired-state document.
- Detect duplicate VM or network definitions loudly.
- Preserve old monolithic config behavior when split files do not exist.
- Add or adjust inspection commands:
  - `aivm config show`
  - `aivm config show --resolved`
  - `aivm config files`
  - `aivm vm config-path <name>`

Suggested behavior:

```text
aivm config show
  Print the canonical source document, equivalent to deterministic
  concatenation.  It may parse/validate first, but the mental model is `cat`.

aivm config show --resolved
  Print effective desired state after defaults and references are materialized.

aivm config files
  Print physical source files in load order.

aivm vm config-path aivm-2404
  In split layout, print ~/.config/aivm/vms/aivm-2404.toml.
  In monolith layout, print ~/.config/aivm/config.toml with a note that the VM
  still lives in the monolith.
```

Expected validation:

```bash
pytest tests/test_config.py \
       tests/test_store.py \
       tests/test_cli_config_init.py \
       tests/test_cli_config_lint.py \
       tests/test_cli_helpers.py
```

Suggested commit message:

```text
Read concatenation-friendly split config layouts
```

### Chunk 4: write and migrate to the split layout

Status: not implemented.

Goal: make the new config layout real and preferred while keeping monolith
compatibility.

Scope:

- Add a split writer:
  - `config.toml` gets schema, active VM, behavior, and defaults.
  - `networks.toml` gets all `[[networks]]` entries.
  - `vms/{name}.toml` gets exactly one `[[vms]]` entry with nested
    `[[vms.attachments]]` records.
- Add migration commands:
  - `aivm config split --dry-run`
  - `aivm config split`
- Migration behavior:
  - read the current logical store;
  - write a timestamped backup of the monolith;
  - write split fragments;
  - reload deterministic concatenation;
  - compare logical desired state before and after;
  - fail loudly if equivalence does not hold.
- Update write paths after split support is proven:
  - `aivm vm create` writes/updates `vms/{name}.toml`.
  - `aivm vm attach` writes nested `[[vms.attachments]]` into the owning VM
    file.
  - `aivm vm detach` removes records from the owning VM file.
  - network commands write `networks.toml`.
  - `aivm config init` eventually prefers split layout for new installs.

Expected validation:

```bash
pytest tests/test_config.py \
       tests/test_store.py \
       tests/test_cli_config_init.py \
       tests/test_cli_config_lint.py \
       tests/test_cli_vm_create.py \
       tests/test_cli_vm_detach.py \
       tests/test_attachment_resolve.py \
       tests/test_vm_drift.py \
       tests/test_cli_vm_update.py
```

Suggested commit message:

```text
Write and migrate split AIVM config layouts
```

## Current open issue: e2e SSH connection refused

After applying chunk 2, `tests/test_e2e_full.py::test_e2e_full_cycle` failed with:

```text
ssh: connect to host 10.250.183.119 port 22: Connection refused
```

This failure is not obviously caused by the chunk 2 config parser/rendering
change, because chunk 2 should only affect how config TOML accepts and emits
attachment records.  However, it should be treated as an open investigation
item before claiming the branch is clean.

Initial triage suggestions:

1. Re-run the e2e test once to check for timing/flakiness.
2. Inspect whether the guest reached an IP before sshd was ready.
3. Compare logs from `wait_for_ssh` / SSH readiness paths.
4. Verify that the test config did not unexpectedly render nested attachments
   into a path consumed by e2e setup.
5. If reproducible, add more readiness logging before changing config code.

Do not assume the config refactor caused the SSH refusal without evidence, but
do not ignore it either.

## Do-not-regress list

- Current monolithic `config.toml` must keep reading.
- Existing imports from `aivm.store` must keep working during the transition.
- Default config writes must remain legacy-compatible until chunk 4 intentionally
  changes write behavior.
- Drift detection must continue to use materialized desired VM state, including
  user-edited RAM, CPUs, and disk size.
- Attachments must remain associated with the intended VM after migration from
  global `[[attachments]]` to nested `[[vms.attachments]]`.
- Split config fragments must concatenate into valid TOML.
- Duplicate VM/network definitions across fragments must be errors.
- Generated host-side virtiofsd wrappers must not be reintroduced as a normal
  feature.

## Resume checklist for a new session

1. Confirm which overlays are already applied:

```bash
git diff --stat
```

2. Confirm chunk 1 and chunk 2 tests:

```bash
pytest tests/test_store.py tests/test_attachment_resolve.py tests/test_vm_drift.py
```

3. Investigate or re-run the e2e SSH failure before declaring the branch clean:

```bash
pytest tests/test_e2e_full.py::test_e2e_full_cycle -s
```

4. If continuing implementation, start chunk 3.  Do not start chunk 4 until
   read-only split layout support and source-file inspection commands are solid.

## Chunk 3 checkpoint: read-only split layout support

Status: implemented as overlay after chunk 2.

This chunk adds read-only support for the target physical layout:

```text
~/.config/aivm/config.toml
~/.config/aivm/networks.toml
~/.config/aivm/vms/{vm_name}.toml
```

The split files are read by deterministic literal concatenation and parsed as the
same canonical desired-state document that the monolithic config already uses.
Each `vms/{name}.toml` fragment should contain exactly one `[[vms]]` entry with
nested `[[vms.attachments]]` records.

Implemented pieces:

- `ConfigSource` and `LoadedStore` source metadata.
- `load_config_document()` for monolith or split layouts.
- Transparent `load_store()` support for split fragments.
- Duplicate VM/network definition detection across fragments.
- `aivm config show` for the canonical source document.
- `aivm config show --resolved` for the effective selected VM config.
- `aivm config files` for physical source files in load order.
- `aivm vm config-path <vm>` for the source file that defines a VM.
- A guard that refuses monolith writes when split fragments are present.

Chunk 4 remains responsible for writing split fragments and implementing
`aivm config split`.

## Chunk 4 checkpoint: split writes and migration

Status: implemented as an overlay after chunk 3.

Chunk 4 makes the split layout writable while keeping monolithic configs
compatible:

- `save_store()` is now layout-aware. If `networks.toml` or `vms/*.toml`
  fragments exist beside `config.toml`, writes are routed back to split files
  instead of refusing or collapsing the layout.
- `save_store_split()` writes:
  - `config.toml` for singleton/global tables,
  - `networks.toml` for all `[[networks]]`, and
  - `vms/{vm_name}.toml` for exactly one `[[vms]]` record plus nested
    `[[vms.attachments]]`.
- `aivm config split` migrates the currently loaded logical store to split
  fragments and backs up the old monolithic `config.toml` first.
- `aivm config split --dry-run` reports the target files without writing.
- `aivm config split --force` rewrites existing split fragments from the loaded
  logical document.

The important invariant remains: concatenating `config.toml`, `networks.toml`,
and sorted `vms/*.toml` produces a canonical desired-state TOML document that
parses through the same logical `Store` model used by drift detection.

Recommended validation after applying chunk 4:

```bash
pytest tests/test_store.py \
       tests/test_config.py \
       tests/test_cli_config_init.py \
       tests/test_cli_config_lint.py \
       tests/test_cli_helpers.py
```

The e2e SSH readiness failure seen after chunk 2 remains an open investigation
item unless it reproduces consistently after the config-only changes.
