# Shared-machine implementation roadmap

This roadmap implements the architecture in
[`shared-machine-architecture.md`](shared-machine-architecture.md). It favors a
sequence of mergeable changes that keep the released single-user workflow
working while eliminating the current scope ambiguity.

The project should not add a documented shadow-store or shared-single-user mode
as an intermediate product feature. Compatibility adapters are acceptable
inside the migration, but new APIs should point toward global machine state plus
per-user principals.

## Current-state seam map

The migration crosses five central assumptions in the present code:

1. `Store` mixes `active_vm`, behavior, defaults, networks, VMs, attachments,
   and credentials in one per-user XDG location.
2. `AgentVMConfig` mixes machine configuration with `vm.user`, SSH paths, and
   user cache paths.
3. SSH-facing code reads `cfg.vm.user` directly throughout lifecycle,
   provisioning, attachments, status, VS Code, and credentials.
4. Persistent host replay state is rooted in the invoking user's application
   data directory even though the manifest controls one global VM.
5. Config-store locking is per file, while libvirt, nftables, disks, and
   attachment mappings are machine-global.

The existing split-fragment store, parser migrations, optimistic concurrency,
and attachment ownership concepts provide useful foundations. Reuse them rather
than introducing a parallel configuration engine.

## Work package 0: Freeze the design and build test scaffolding

### Goals

- Make the scope boundary executable in tests before moving files.
- Ensure tests cannot touch a developer's real user or machine store.
- Establish shared-host fixtures with two synthetic host principals.

### Tasks

- Add autouse isolation for `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and the
  proposed machine-store root.
- Add fixtures for Alice and Bob with distinct usernames, UIDs, GIDs, SSH keys,
  and profiles but one libvirt domain.
- Add a fake or command-captured guest enrollment transport.
- Add concurrency tests capable of running two store writers against one VM.
- Inventory all direct `cfg.vm.user`, `cfg.paths.ssh_*`, and
  `persistent_host_state_dir` uses and classify each as machine, profile,
  principal, or runtime-derived.
- Record the released schema version and migration fixtures before changing it.

### Exit criteria

- No test reads or writes the real AIVM state directories.
- A failing test demonstrates that two current per-user stores can disagree
  about one domain and attachment inventory.
- The codebase has an agreed call-site inventory for the principal refactor.

## Current implementation status

### Version 0.6.0 first organizational slice

The first 0.6.0 change establishes the runtime boundary without changing the
on-disk store. `aivm.config_scopes` now defines machine, principal, profile,
and resolved-context types and translates the current `AgentVMConfig` into a
synthetic legacy principal. This deliberately makes the first change
serialization-neutral and keeps existing installations working.

All post-creation guest operations now resolve that compatibility context:
SSH connections and config rendering, provisioning, status probes, guest
credential installation, attachment guest operations, persistent replay
transport, shared-root reconciliation, cache flushing, and fdguard management.
These paths no longer read `cfg.vm.user` or caller SSH paths directly.

The remaining direct legacy reads are intentionally limited to boundaries that
still create or edit the old schema:

- `config init`, config review, and runtime default hydration;
- host detection of SSH key paths;
- cloud-init and VM creation of the original guest account.

This completes the safe reorganizational half of work package 1. No code
should move persistent files to `/var/lib/aivm` until group-safe atomic writes
and migration rollback are implemented and tested.

### Stage 0/1 execution checklist

The second 0.6.0 tranche completes the test and runtime prerequisites before
physical store movement:

#### Stage 0: isolated shared-host scaffolding

- [x] Route implicit `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
  `XDG_CACHE_HOME`, and `XDG_STATE_HOME` paths into each pytest sandbox.
- [x] Reserve an isolated `AIVM_MACHINE_STORE_ROOT` in every test process so
  the later machine-store implementation cannot accidentally touch
  `/var/lib/aivm`.
- [x] Add reusable Alice and Bob fixtures with different homes, UIDs, GIDs,
  SSH keys, guest users, and legacy stores selecting one VM identity.
- [x] Freeze representative released schema-version-8 monolithic and split
  stores as migration fixtures.
- [x] Characterize the current split-brain failure: Alice and Bob can describe
  the same VM while seeing disjoint attachment inventories.
- [x] Add a synthetic end-to-end path that crosses real store parsing, VM
  selection, context resolution, attachment resolution, and prepared-session
  construction while capturing libvirt/SSH/sudo boundaries.
- [x] Run the complete non-e2e suite as a non-root user; privilege-sensitive
  tests must not be evaluated under root semantics.

#### Stage 1: central resolved-context service boundary

- [x] Add canonical `load_vm_context_with_path`, `load_vm_context`, and
  `resolve_context_for_code` service entry points.
- [x] Make `PreparedSession` carry the selected `ResolvedVMContext`; retain a
  read-only `cfg` compatibility property while machine operations still use
  the legacy aggregate model.
- [x] Make code/SSH session entry points use the context already selected by
  session preparation instead of reconstructing principal identity.
- [x] Move direct cache-flush and fdguard CLI loading onto the context service.
- [x] Refresh a prepared context after on-demand SSH-key creation so the
  session cannot carry stale profile paths.
- [x] Add static regression checks preventing session code from returning to
  `resolve_cfg_for_code` or `session.cfg` as its identity source.
- [x] Preserve the legacy serialized bytes and current single-user behavior.

### Stage 2 execution checklist: machine-store filesystem contract

The third 0.6.0 tranche implements the physical machine-store foundation while
leaving normal config resolution on the legacy per-user store:

- [x] Define the injectable machine layout under `/var/lib/aivm`, including
  config fragments, state, bootstrap material, and centralized lock paths.
- [x] Define the trusted `root:aivm` mode contract: `02775` for ordinary
  machine directories, `0664` for config/transaction/lock files, and `02750`
  for the bootstrap directory.
- [x] Make atomic replacement set group and mode on the temporary descriptor
  before replacement and reassert metadata afterward.
- [x] Make split-layout staging and interrupted-transaction recovery use the
  same group-safe policy.
- [x] Reject symlinked managed roots and target files.
- [x] Route the config-store lock to `locks/store.lock` when a machine policy is
  selected.
- [x] Add deterministic store -> sorted network -> sorted VM resource locking.
- [x] Add `update_store` as the lock-spanning read-modify-write primitive for
  mutations that must merge rather than reject concurrent changes.
- [x] Prove with two child processes that concurrent attachment additions both
  survive.
- [x] Prove that recovery of one interrupted VM-fragment replacement preserves
  unrelated VM fragments.
- [x] Keep this machinery inactive in the normal loader until the machine and
  profile schemas are ready.

The exact layout, permissions, replacement sequence, and lock-order rule are
recorded in
[`machine-store-filesystem-contract.md`](machine-store-filesystem-contract.md).

### Stage 3/4 execution checklist: activate scopes and adopt the creator

The fourth 0.6.0 tranche activates the logical store split for fresh implicit
installations and persists the first real principal. It deliberately stops
before automatic enrollment of a second user.

#### Stage 3: machine and profile documents

- [x] Add config-store schema version 9 with an explicit `store_kind =
  "machine"` marker.
- [x] Keep machine defaults, networks, VMs, principals, attachments, and
  transitional credential records in the global split store.
- [x] Omit `active_vm`, behavior, `vm.user`, caller SSH paths, and caller state
  paths from machine serialization.
- [x] Add a private schema-version-1 `~/.config/aivm/profile.toml` with mode
  `0600` for active selection, behavior, SSH paths, local state, and the
  guest-user default used during creation.
- [x] Select an existing released user store without migrating it; select the
  machine/profile split for a brand-new implicit installation.
- [x] Make explicit non-machine `--config` paths retain legacy semantics.
- [x] Make service loading compose the machine document, current profile, and
  persisted principal into `ResolvedVMContext`.
- [x] Expose the profile through `aivm config paths` and `aivm config edit
  profile`.
- [x] Extend `aivm host permissions setup` to create/diagnose the trusted
  `aivm` group and `/var/lib/aivm` root.

#### Stage 4: creator principal persistence

- [x] Add persisted principal records containing stable id, host login,
  UID/GID, guest username, public key, and state.
- [x] Adopt the invoking host user as the active creator principal after a
  successful machine-store VM creation.
- [x] Preserve the creator's selected guest username rather than deriving it
  again at runtime.
- [x] Resolve runtime identity by current host login and reject missing,
  duplicate, disabled, pending, or error principals.
- [x] Keep creator persistence idempotent and keep user-profile writes unable
  to alter machine bytes.
- [x] Add unit coverage for fresh initialization, creator adoption, legacy
  fallback, profile isolation, config-path UX, and missing-principal errors.
- [x] Run the complete non-e2e suite as a non-root user.

The exact logical split and compatibility rules are recorded in
[`machine-profile-store-contract.md`](machine-profile-store-contract.md).
The next tranche is work package 3: the restricted guest bootstrap helper and
idempotent principal enrollment. Until that lands, a later host user sees an
actionable not-enrolled error rather than a shadow machine definition.

### Stage 5 execution checklist: restricted guest enrollment

The fifth 0.6.0 tranche implements work package 3 while leaving automatic
`config init` join behavior for the next stage.

- [x] Generate one stable machine-scoped bootstrap SSH keypair before creating
  a machine-store VM.
- [x] Add a dedicated `aivm-bootstrap` guest system account whose key is forced
  to one non-interactive command with PTY, forwarding, X11, agent forwarding,
  and user rc processing disabled.
- [x] Install a stdlib-only `/usr/local/sbin/aivm-guestctl` executable and an
  exact-command sudoers rule through cloud-init.
- [x] Validate one JSON enrollment request and idempotently create or repair
  the guest group, user, home, authorized personal key, sudoers fragment, and
  existing common development-group memberships.
- [x] Reject invalid usernames, malformed SSH keys, and conflicting UID/GID
  assignments with actionable diagnostics.
- [x] Persist the caller as `pending` before transport, retain `pending` when
  the VM is unreachable, record helper failures as `error`, and mark `active`
  only after a fresh personal-key SSH verification succeeds.
- [x] Add `aivm vm access list` and `aivm vm access reconcile`, including a
  non-mutating dry-run path.
- [x] Keep bootstrap material outside user profiles and prevent it from
  becoming an ordinary interactive SSH identity.
- [x] Cover forced-command rendering, guest reconciliation idempotence,
  collisions, host state transitions, CLI exposure, and machine-create
  integration in unit tests.
- [x] Run the complete non-e2e suite as a non-root user.

The exact protocol and compatibility boundary are recorded in
[`guest-enrollment-control.md`](guest-enrollment-control.md).

### Stage 6 execution checklist: natural create-or-join initialization

The sixth 0.6.0 tranche completes work package 4 by connecting exact managed
machine discovery to the restricted enrollment service:

- [x] Load the machine store before detecting or reviewing creator defaults.
- [x] Derive the hostname-qualified onboarding key exactly once through
  `default_vm_name()`.
- [x] Branch `config init` into new creator initialization, exact managed join,
  and unmanaged-domain collision refusal.
- [x] Keep legacy explicit/per-user stores on their released initialization
  behavior.
- [x] Build a joining user's profile from the managed record without writing
  CPU, RAM, disk, image, network, firewall, provisioning, tools, virtiofs, or
  attachment state.
- [x] Detect or create a personal AIVM SSH identity before enrollment.
- [x] Reuse an active principal when its public key still matches, and reconcile
  missing, pending, errored, or key-rotated principals through the bootstrap
  channel.
- [x] Set `active_vm` only after successful activation or an explicitly saved
  pending enrollment.
- [x] Make `--yes` and `--defaults` auto-join exact managed records while
  refusing unmanaged-domain adoption even with `--yes` or `--force`.
- [x] Keep failed personal-key verification from selecting the machine or
  reporting a successful join.
- [x] Cover active repeat, stopped-VM pending state, verification failure,
  collision refusal, non-interactive confirmation, and no-machine-rewrite
  behavior in synthetic tests.
- [x] Run the complete non-e2e suite as a non-root user.

The decision table and recovery behavior are recorded in
[`config-init-create-or-join.md`](config-init-create-or-join.md).

### Stage 7 execution checklist: global attachment ownership and replay

The seventh 0.6.0 tranche completes work package 5 for fresh machine stores
while preserving legacy single-user attachment semantics:

- [x] Add `owner_principal_id` to attachment records and reserve `system` for
  machine-managed exports.
- [x] Make machine-store writes reject dangling or cross-VM owner references.
- [x] Attribute every new machine-store attachment to the selected principal.
- [x] Resolve folder paths and automatic VM selection against the current
  principal's records before considering the global inventory.
- [x] Keep session restoration principal-scoped so Alice's ordinary SSH/code
  workflow never tries to restore Bob's private host path.
- [x] Require owner permission for update/detach and add an explicit
  `--admin_override` plus `--owner_principal` targeting path.
- [x] Reject machine-wide guest-destination collisions across owners.
- [x] Show the complete inventory, owner, host source, guest destination, mode,
  and access in list and status output.
- [x] Move the canonical persistent manifest into per-VM machine state and
  generate it from every owner's persistent records while holding store and VM
  locks.
- [x] Include the owner in persistent attachment IDs so records remain distinct
  across principals.
- [x] Keep legacy replay state in its released XDG location until migration.
- [x] Warn when a caller exposes a path beneath their private home to a VM with
  multiple principals.
- [x] Prove concurrent Alice/Bob attachment writes retain both owner-attributed
  records and that both accounts see the same global inventory.
- [x] Run the complete non-e2e suite as a non-root user.

The exact ownership, visibility, override, and replay rules are recorded in
[`global-attachment-ownership.md`](global-attachment-ownership.md).

### Stage 8 execution checklist: principal-scoped credentials

The eighth 0.6.0 tranche completes work package 6 for fresh machine stores
without moving legacy credential key material:

- [x] Add `principal_id` to credential records and include it in stable
  credential IDs.
- [x] Advance principal-owned credential stores to schema version 11 while
  preserving the released legacy credential ID calculation.
- [x] Reject machine-store credentials with missing, dangling, or cross-VM
  principal references.
- [x] Keep host private/public key paths in the owning user's application-data
  tree rather than the machine store.
- [x] Install guest keys and regenerate SSH/Git routing from only the selected
  principal's usable credentials.
- [x] Make add, list, status, revoke, and abandon default to the current
  principal.
- [x] Add `--all_principals` list/status views for machine-wide non-secret
  metadata.
- [x] Refuse secret-bearing inspection, repair, revoke, or abandon through
  another principal's host login or provider authentication context.
- [x] Preserve provider key IDs, fingerprints, and lifecycle state when a
  principal is disabled.
- [x] Reject principal removal while owned provider credential records remain,
  so revocation metadata cannot disappear silently.
- [x] Prove Alice and Bob can independently credential the same repository and
  ordinary selection never crosses owners.
- [x] Keep legacy credentials unattributed and byte-compatible until the
  explicit migration stage assigns them to the creator principal.
- [x] Run the complete non-e2e suite as a non-root user.

The ownership and operational contract is recorded in
[`principal-scoped-credentials.md`](principal-scoped-credentials.md).

### Stage 9 execution checklist: released-store migration planning

The ninth 0.6.0 tranche begins work package 7 with a strictly read-only planner.
It intentionally stops before backups, machine-store writes, guest changes, or
rollback state:

- [x] Add `aivm config migrate plan` with deterministic text and JSON output.
- [x] Accept one or more released monolithic or split stores using
  `[HOST_USER=]PATH` source descriptors.
- [x] Fingerprint every contributing source file so the later apply phase can
  detect changes between review and execution.
- [x] Propose machine defaults, networks, VMs, creator access identities,
  per-user profiles, attachment ownership, and credential attribution entirely
  in memory.
- [x] Preserve provider IDs, fingerprints, access, and lifecycle state while
  showing the principal-scoped credential ID that apply will write.
- [x] Report user-owned credential-directory renames and persistent replay state
  movement without performing either operation.
- [x] Detect multiple released stores claiming one VM and report differing
  machine fields instead of merging silently.
- [x] Detect divergent defaults, networks, profile paths, host identity gaps,
  SSH public-key problems, guest destination collisions, and an existing
  non-empty machine store.
- [x] Inventory managed, missing, and unmanaged libvirt domains and networks
  through read-only commands, with explicit skip and sudo modes.
- [x] Prove the planner leaves source bytes, target paths, libvirt state, guest
  state, and provider state unchanged.
- [x] Cover both frozen released monolithic and split fixtures.
- [x] Run the complete non-e2e suite as a non-root user.

The report contract and apply boundary are recorded in
[`released-store-migration-plan.md`](released-store-migration-plan.md).

### Stage 10 execution checklist: released-store migration apply

The tenth 0.6.0 tranche completes the state-changing half of work package 7
without deleting or rewriting the released inputs:

- [x] Rebuild the reviewed plan at apply time and reject changed source hashes,
  planner output, or a mismatched target layout.
- [x] Create and verify backups for every source and replacement target before
  application-state writes.
- [x] Add a deterministic migration id and durable atomic phase journal under
  machine state.
- [x] Write the schema-11 machine store and private user profiles with their
  existing UID/GID ownership.
- [x] Copy principal-scoped credential material and machine persistent state
  while retaining the released source directories for rollback.
- [x] Install the restricted bootstrap helper through each creator's existing
  working SSH account without recreating or redefining a VM.
- [x] Make every phase idempotent and resume at the first incomplete journaled
  phase after interruption.
- [x] Verify source immutability, logical machine/profile state, copied trees,
  libvirt domain identity, and creator SSH before marking complete.
- [x] Add status, verify, resume, and reverse-order host rollback commands; keep
  the journal as durable recovery evidence.
- [x] Keep provider APIs, VM disks, domain definitions, and legacy SSH access
  unchanged.
- [x] Cover completed reruns, injected interruption, resume, source mutation,
  guest-helper rendering/transport, and rollback in synthetic tests.
- [x] Run the complete non-e2e suite as a non-root user.

The transaction, recovery, and retained-input rules are recorded in
[`released-store-migration-apply.md`](released-store-migration-apply.md).

### Stage 11 execution checklist: operational lifecycle and release seam

The eleventh 0.6.0 tranche completes work package 8 without introducing a new
host authorization system:

- [x] Add `aivm vm access disable` and `remove`, with id/host-login targeting,
  caller defaults, dry-run support, and explicit cross-user administration.
- [x] Remove only the selected personal key and AIVM sudoers fragment in the
  guest; retain the account, home, unrelated keys, and ownership metadata.
- [x] Require `--allow_last_access` before disabling or removing the final
  active identity.
- [x] Make `access reconcile --enable` the explicit path for restoring a
  disabled identity and verify the personal key before activation.
- [x] Refuse identity removal while attachment or credential records still
  refer to it; do not invent automatic ownership transfer or discard provider
  revocation evidence.
- [x] Clear the owning caller's active profile selection after disable/remove.
- [x] Label VM and network lifecycle changes as machine-wide and summarize the
  affected identity, attachment, and credential inventory.
- [x] Show trust mode and active/total access identity counts in list and status
  output.
- [x] Keep lifecycle mutations behind reusable services so a future privileged
  broker can enforce the existing model.
- [x] Use “access identity” in new operator-facing text while retaining the
  internal `principal` schema vocabulary until a separate naming decision.
- [x] Run the complete non-e2e suite as a non-root user.

The lifecycle, trust, and removal rules are recorded in
[`operational-lifecycle.md`](operational-lifecycle.md). The implementation
roadmap is complete; the remaining work is real-system migration/shared-user
validation and release review.

## Work package 1: Separate models without moving storage

### Goals

- Remove the conceptual dependency on one `vm.user` per machine.
- Keep the current physical store working through compatibility materialization.
- Make later store movement mostly routing rather than another application-wide
  refactor.

### Tasks

- Introduce explicit `MachineConfig`, `VMPrincipal`, `UserProfile`, and
  `ResolvedVMContext` types, or equivalent names with the same boundaries.
- Add a resolver that determines the invoking host user and selects one
  principal for the target VM.
- Translate legacy `cfg.vm.user` and SSH paths into a synthetic creator
  principal during compatibility loading.
- Split machine paths from user paths in the model. In particular:
  - `base_dir` and replay roots are machine state;
  - SSH identity/public-key paths and caches are profile state.
- Convert SSH, SCP, rsync, VS Code, provisioning, attachment guest operations,
  status probes, and credential installation to use `ResolvedVMContext`.
- Stop passing a bare `AgentVMConfig` into code that needs both machine and
  caller identity.
- Keep serialization unchanged in this work package unless a new field is
  needed solely for compatibility.

### Tests

- Alice and Bob resolve different guest users and SSH identities against the
  same in-memory machine record.
- Machine equality does not depend on current host user or SSH private-key path.
- Legacy `vm.user = "agent"` materializes exactly one creator principal.
- No new production call site reads `cfg.vm.user` directly.

### Exit criteria

- The application can run all current single-user tests through the new context
  boundary.
- `vm.user` is compatibility input, not the runtime source of truth.

## Work package 2: Add the machine store and user profile

### Goals

- Give global resources one host-wide authority.
- Preserve the familiar per-user interaction settings.
- Make multi-user writes safe on the trusted shared host.

### Tasks

- Add machine-store path resolution under `/var/lib/aivm` with injectable paths
  for tests and explicit advanced overrides.
- Add a small user-profile store under the caller's XDG config directory.
- Reuse the current split-fragment representation for global defaults,
  networks, and per-VM fragments where possible.
- Move `active_vm` and `behavior` into the profile schema.
- Move VM definitions, network definitions, principals, and attachments into
  the machine schema.
- Define how credential records reference principals while private material
  remains in user-owned storage.
- Add a host `aivm` group setup/check path and diagnostics.
- Make machine directories setgid and define exact owner/group/modes.
- Update atomic writes so replacement preserves intended group ownership and
  modes.
- Add one global store lock and per-VM locks under the machine state root.
- Define deterministic ordering when an operation needs both network and VM
  locks.
- Reject a per-user `--config` document that attempts to redefine a VM already
  managed by the machine store.

### Tests

- Alice and Bob read identical machine fragments and distinct profiles.
- A profile update cannot alter machine bytes.
- Atomic replacement preserves `root:aivm` ownership and configured modes.
- Concurrent attachment writes serialize and retain both records.
- Interrupted split-layout writes recover without losing unrelated VM
  fragments.
- An unmanaged same-name domain remains explicit discovery/import work.

### Exit criteria

- New machine writes no longer depend on the invoking user's home directory.
- Status from two profiles uses the same complete global desired state.

## Work package 3: Introduce machine enrollment control

### Goals

- Allow a later host user to join without copying a creator's private key or
  asking the creator to run guest commands.
- Establish a narrow control plane that can later move behind `aivmd`.

### Tasks

- Implement a guest-side `aivm-guestctl` command with an idempotent
  `enroll-principal` operation.
- Create a dedicated bootstrap guest account at VM creation.
- Generate a machine-scoped bootstrap SSH identity under protected global
  machine state.
- Restrict the bootstrap key with a forced command and disable interactive
  shell, PTY, forwarding, and unrelated SSH features.
- Have enrollment create/repair:
  - guest username;
  - matching UID/GID where valid;
  - home directory and ownership;
  - authorized personal public key;
  - trusted-user sudo policy;
  - any common guest groups required for Docker or development tools.
- Add principal states such as `pending`, `active`, `disabled`, and `error`.
- Verify enrollment by opening a fresh SSH connection with the user's personal
  key; do not mark active based only on helper exit status.
- Add explicit reconciliation for a pending principal when the VM was down or
  unreachable during initialization.
- Keep the bootstrap transport internal. It is not a general shared SSH account
  and must not become the normal interactive user.

### Tests

- Enrollment is idempotent.
- Re-enrollment rotates or adds the personal public key without duplicating the
  account.
- Invalid usernames, UID/GID collisions, malformed keys, and conflicting guest
  accounts fail with actionable diagnostics.
- A bootstrap connection cannot run arbitrary shell commands.
- A principal is active only after personal-key verification succeeds.

### Exit criteria

- A synthetic Bob can enroll against Alice's existing VM without Alice's
  private key or a manual guest command.

## Work package 4: Make `config init` create or join naturally

### Goals

- Preserve the hostname-derived convention as the primary discovery key.
- Make the same command initialize the first user and later users correctly.

### Tasks

- Load the machine store before generating machine defaults.
- Derive the hostname-qualified VM name exactly once through the existing
  naming helper.
- Branch initialization into three explicit cases:
  1. no machine record and no same-name domain: initialize creator defaults;
  2. exact managed machine record: initialize profile and enroll/join;
  3. same-name unmanaged or conflicting state: stop for explicit import/review.
- Ensure joining never writes CPU, RAM, disk, image, network, firewall,
  provision, tools, virtiofs, or attachment settings.
- Generate a personal AIVM SSH key when needed.
- Select the current host principal if already enrolled; otherwise request
  enrollment through the machine bootstrap channel.
- Set the machine as the user's active VM only after successful or clearly
  recorded pending enrollment.
- Make interactive output state whether it is creating defaults or joining an
  existing machine.
- Define safe `--yes` behavior: auto-join exact managed records, but never
  auto-import unmanaged domains.
- Add an explicit `aivm vm access reconcile` command for pending or damaged
  enrollments even if `config init` normally handles the path.

### Tests

- Alice init -> create -> active principal.
- Bob init -> exact global match -> enrolled principal, no machine diff.
- Bob init is repeatable and does not add duplicate principals.
- A hostname collision with an unmanaged domain refuses silent adoption.
- A down VM produces a pending principal and a clear next action.
- A failed personal-key verification does not report a successful join.

### Exit criteria

- The desired end-user onboarding works with no file copying between Alice and
  Bob and no duplicate machine configuration.

## Work package 5: Globalize attachment ownership and replay

### Goals

- Make every attachment declaration visible to every caller.
- Allow Bob to own Bob's attachments while Alice uses the machine normally.
- Eliminate partial-manifest overwrite hazards.

### Tasks

- Add `owner_principal_id` to every attachment record.
- Add an explicit system owner for machine-managed exports where no human owner
  is appropriate.
- Attribute new records to the current principal.
- Limit local-path resolution and lexical aliases to the current principal's
  records unless a machine-global identifier or guest path is supplied.
- Show the complete inventory in status, including owner and guest destination.
- Require owner or administrative override for update/detach operations.
- Move `persistent_host_state_dir` and all replay manifests into machine state.
- Generate persistent/shared-root replay from the complete global inventory
  while holding the VM lock.
- Update drift so another user's declared mappings are expected, not warnings.
- Preserve existing tag and guest-destination stability during migration.
- Make exposure review mention the shared VM and trusted-user mode when a path
  comes from a private home directory.

### Tests

- Alice and Bob add attachments concurrently and both survive.
- Bob can resolve `~/code/project` to Bob's attachment only.
- Alice's bare `aivm ssh` is unaffected by Bob's attachment ownership.
- Alice cannot accidentally detach Bob's attachment without an explicit
  administrative override.
- Status from either account reports the same attachment inventory.
- Persistent replay contains every global persistent attachment exactly once.

### Exit criteria

- Attachment desired state is truly machine-wide and no command depends on a
  caller's partial registry.

## Work package 6: Principal-scope credentials

### Goals

- Prevent accidental credential sharing while preserving the current trusted
  guest model.
- Make credential ownership compatible with later restricted-user mode.

### Tasks

- Add `principal_id` to credential records or move records into a
  principal-scoped registry with stable machine references.
- Keep private host key material in user-owned application data.
- Install guest keys and SSH/Git routing only in the selected principal's home.
- Make list/status default to the current principal, with an explicit
  machine-wide administrative view.
- Ensure provider revoke/abandon acts through the owning host principal's
  material and authentication context.
- Define behavior when a principal is disabled or removed while provider keys
  remain registered.
- Preserve legacy credentials by attributing them to the migrated creator
  principal.

### Tests

- Alice and Bob can use different repository credentials in the same VM.
- Bob's ordinary credential commands never select Alice's records.
- Migration preserves fingerprints and provider-management state.
- Disabling a principal does not silently lose provider revocation metadata.

### Exit criteria

- Credential metadata no longer implies that a VM has one common guest home.

## Work package 7: Migrate existing installations

### Goals

- Move released per-user stores into the new scopes without recreating VMs.
- Be safe in the presence of partial runs and conflicting old stores.

### Tasks

- Implement a dry-run migration report showing:
  - proposed machine records;
  - proposed creator principals;
  - attachment ownership;
  - persistent-state movement;
  - user-profile fields;
  - credentials attributed to each principal;
  - conflicts and unmanaged runtime resources.
- Back up every input file before mutation.
- Write machine and profile state transactionally enough that restart can
  determine which phase completed.
- Install the bootstrap guest helper through the creator's existing working SSH
  path.
- Preserve the legacy guest username rather than forcing a rename.
- Verify SSH, libvirt identity, attachment drift, and persistent replay before
  marking migration complete.
- Detect multiple old stores claiming one VM and stop with a merge report.
- Add an explicit rollback path while the old store is still retained.
- After a release-defined grace period, make the old store read-only except for
  migration/recovery commands.

### Tests

- Migrate monolithic and split released stores.
- Resume after failure at each write/install/verification phase.
- Re-running a completed migration is a no-op.
- Conflicting per-user stores are never merged silently.
- Existing `agent` access and credentials continue to work.
- No VM disk or domain recreation occurs.

### Exit criteria

- A real existing single-user installation can upgrade in place, then enroll a
  second host user through `config init`.

## Work package 8: Operational polish and future security seam

### Goals

- Make machine-wide effects obvious.
- Prepare for access enforcement without requiring it in the first release.

### Tasks

- Label commands and plans as machine-scoped or principal-scoped.
- Show principal, owner, and trust mode in status and review output.
- Add `aivm vm access list`, `reconcile`, `disable`, and `remove` lifecycle
  commands.
- Define safe semantics for removing a principal that owns attachments or
  credentials.
- Audit lifecycle commands (`down`, restart, delete, resize, network update) for
  global impact messaging.
- Document that direct `libvirt` group membership remains root-equivalent.
- Keep machine mutations behind a service interface so a later `aivmd` broker
  can replace direct calls.
- Add policy schema placeholders only when there is an implemented consumer;
  avoid speculative configuration with no enforcement.

### Exit criteria

- The trusted shared-machine release is understandable and recoverable.
- A future daemon/restricted mode can enforce existing principal and owner
  fields rather than inventing a second model.

## Recommended pull-request sequence

The work packages are deliberately larger conceptual units. A practical PR
sequence is:

1. **Test isolation and seam inventory.**
2. **Resolved principal/context model with legacy compatibility.**
3. **Machine store, profile store, and global locks.**
4. **Guest bootstrap helper and first-principal creation.**
5. **`config init` managed-machine join.**
6. **Global attachment ownership and replay migration.**
7. **Principal-scoped credentials.**
8. **Existing-store migration command and fixtures.**
9. **Operational UX, docs, and deprecation cleanup.**

Do not combine the model split, physical store move, automatic enrollment, and
legacy migration into one patch. Those concerns need independent tests and
failure boundaries even if they land in one release train.

## Early implementation decisions that need prototypes

These are not reasons to delay the architecture, but they should be resolved by
small executable prototypes before the corresponding production work:

- exact `root:aivm` directory and file modes across atomic replacement;
- whether the bootstrap account uses a forced SSH command directly or a tiny
  protocol wrapper around `aivm-guestctl`;
- username normalization when host logins contain characters unsuitable for a
  guest account;
- UID/GID conflict handling inside an existing guest;
- lock ordering for operations touching a network and multiple VMs;
- how pending enrollment is reconciled when the VM is stopped;
- whether `--config` names the user profile, machine store, or a composite
  inspection source after the split;
- migration conflict presentation when two old stores describe one domain.

Prototype results should update this roadmap rather than creating hidden policy
inside implementation code.

## Explicitly deferred

The following remain out of scope until the trusted shared-machine workflow is
complete:

- removing ordinary users from the `libvirt` group;
- a privileged host daemon;
- strict guest-user isolation;
- ACLs for teams that do not mutually trust one another;
- per-user private VM clones from shared templates;
- remote shared machines;
- centralized identity providers;
- automatic account renaming from `agent` to `<host-user>-agent`.
