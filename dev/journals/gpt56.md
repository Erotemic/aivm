## 2026-07-27 11:30:00 -0400

Built an intentionally unintegrated GitLab deploy-key backend so provider work can proceed without touching the active GitHub credential, VM lifecycle, CLI, schema, or configuration changes. The module uses the standard-library HTTP client, keeps the API token in memory and in the `PRIVATE-TOKEN` header, supports nested GitLab namespaces, performs deploy-key CRUD, and follows pagination without forwarding credentials across origins.

I am confident in the provider API surface and its unit tests, but it is deliberately dormant: no existing module imports it, and no schema kind or provider selector refers to it. Later integration will need to decide how GitLab tokens are configured, how repository resolution admits subgroup paths, and how the service layer chooses a backend. The main risk at that stage is not this HTTP client but accidentally coupling provider selection to the currently GitHub-shaped credential schema.

## 2026-07-27 16:30:00 -0400

Rebased the independent GitLab deploy-key client onto commit 9d76f42 and integrated it behind a provider dispatch seam without replacing the completed GitHub setup/version-gating work. The credential schema now admits GitLab records, repository identities preserve nested GitLab namespaces, guest SSH/Git routing remains shared, and add/status/revoke use the recorded provider kind. GitLab.com is inferred automatically from canonical remotes; self-managed GitLab is explicit. Host authentication is a `GITLAB_TOKEN` sent only in the recommended `PRIVATE-TOKEN` header, with optional `GITLAB_API_URL` for nonstandard self-managed endpoints.

I kept the first integration deliberately local and dependency-free: there is no `glab` requirement and no token persistence in AIVM state. The practical consequence is that GitLab status, add, and revoke commands require the token in the host environment. A future credential-store feature can improve that UX without changing the guest key or provider lifecycle model.

## 2026-07-27 17:45:00 -0400

Rebased the GitLab integration onto commit ab2edad, after the credential lifecycle adopted administrator handoff as settled policy. Provider publication is now uniformly best effort: missing GitHub tooling or login, a missing GitLab token, permission and organization-policy failures, definitive provider refusals, and uncertain transport outcomes all preserve the generated keypair, install the private half in the VM, and record an unregistered credential for manual publication. Only failures in the local credential work itself remain fatal.

The GitLab backend remains a direct v4 REST client with no glab dependency. Provider selection and recorded kinds dispatch add, status, and revoke without changing the shared SSH guest model. Direct GitLab API mutations use CommandManager approval, while setup remains a diagnostic for automation readiness rather than a prerequisite for creating a credential.

## 2026-07-28 11:30:02 -0400

Planned the move from AIVM's mixed per-user/global state into one shared-machine authority with per-host-user guest principals. The key decision is not to productize the tempting shadow-store or shared-single-account workaround. Instead, the hostname-qualified VM remains the natural rendezvous point: the first user creates it, and later users join through `aivm config init` without redefining the machine.

The hardest usability seam is initial guest enrollment. A later user cannot use a personal key before it is authorized, so the plan introduces a narrow machine-scoped bootstrap identity and an idempotent guest helper rather than copying the creator's private key. This is intentionally designed so a future privileged host daemon can take over the transport without changing principals, attachments, or the user-facing join workflow.

I am confident about the scope split and phased ordering. The main implementation risks are group-safe atomic machine-store writes, UID/GID collisions in existing guests, migration conflicts when multiple old stores claim one domain, and ensuring persistent attachment replay is generated only from the complete global inventory. The roadmap keeps each of those behind a separately testable work package and preserves legacy `agent` accounts during migration rather than forcing a risky rename.

## 2026-07-28 12:10:00 -0400

Started the 0.6.0 implementation with the least risky architectural seam: a
serialization-neutral runtime scope layer. `AgentVMConfig` still loads and
saves exactly as before, but it is translated into explicit machine,
principal, profile, and resolved-context objects before any post-creation
operation reaches SSH or the guest. I moved the guest-runtime call sites as a
coherent group so the later machine-store migration can change one resolver
instead of reopening every attachment, provisioning, status, credential, and
maintenance module.

I deliberately left config editing, SSH-key discovery/hydration, cloud-init,
and creator-account construction on the legacy fields. Those are persistence
and enrollment boundaries, not ordinary runtime consumers, and pretending the
new store exists before group-safe writes and migration semantics are ready
would make the refactor less honest. The main remaining risk is that
`ResolvedVMContext` is still constructed locally from a legacy config at each
module boundary; the next slice should make the service layer return it
centrally and then persist real principals. I am confident the current slice is
behavior-preserving because it changes how identity is named in code, not which
identity or key the current schema selects.

## 2026-07-28 13:00:58 -0400

Completed the stage 0/1 shared-machine prerequisites without moving persistence.
The most important change is that folder-oriented runtime preparation now asks
the service layer for a `ResolvedVMContext` and carries that exact selection in
`PreparedSession`; the SSH and VS Code entry points no longer reconstruct a
principal from the legacy aggregate config after the session has already been
prepared. I kept a read-only `session.cfg` compatibility property because many
machine operations still need the old aggregate model, but identity-bearing
callers now use `session.context` explicitly.

I also made the test environment match the risk profile of the coming store
migration. Every ordinary test gets an isolated HOME and XDG tree plus a future
machine-store root, and the suite has reusable Alice/Bob fixtures, frozen
schema-version-8 monolithic and split documents, a characterization of the
current partial attachment inventories, and a synthetic end-to-end session
path that stops at captured libvirt/SSH/sudo boundaries. Running the complete
non-e2e suite as a non-root user was important: several privilege tests are
meaningless under root's access semantics. The result was 838 passing tests and
8 expected skips; the opt-in real-host e2e collection also remained healthy and
skipped all seven cases without its enable flags.

The branch used only two ubelt features, so I removed the runtime dependency
rather than preserving it solely for XDG paths and presentation. The new helper
modules explicitly record the historical ubelt APIs they replace and state that
the code is a fresh stdlib/Pygments implementation, not copied vendored source.
The main remaining architectural risk is now concentrated where it belongs:
group-safe atomic machine-store writes, lock ordering, and rollback. None of
those should be hidden inside the compatibility context layer.

## 2026-07-28 13:20:09 -0400

Implemented the machine-store filesystem contract without activating it in the
normal config path. The main decision was to make shared-write semantics an
explicit policy passed into the existing store engine rather than fork a second
I/O implementation. That keeps monolithic and split parsing, optimistic
concurrency, transaction recovery, and rendering in one place while allowing a
machine store to select a centralized lock, setgid directories, group-writable
files, and symlink refusal.

The key concurrency addition is `update_store`, which holds the physical store
lock across load, mutation, and replacement. Separate load/save remains useful
because it rejects stale writers, but it cannot merge Alice's and Bob's changes.
A process-level test now contends two attachment additions and proves both
survive; another constructs an interrupted split transaction and verifies that
recovering one VM fragment leaves an unrelated VM fragment intact. I am
confident this gives the later schema split a sound physical substrate without
prematurely touching `/var/lib/aivm` on real systems.

The principal remaining uncertainty is operational setup: a later tranche must
create or diagnose the `aivm` group and root-owned layout through the normal
approval/privilege machinery. I deliberately did not add that CLI yet, because
there is still no production machine document to initialize. The next step is
to define persisted machine and user-profile documents and composite loading on
top of this contract; released stores and migration should remain untouched
until that new path works for fresh synthetic state.

## 2026-07-28 13:42:46 -0400

Activated the machine/profile split for fresh installations and persisted the
first real VM principal. This is the first tranche where the shared-machine
architecture changes ordinary persistence rather than only introducing a seam
or an inactive filesystem primitive. The selection rule is intentionally
conservative: an existing released per-user store continues to win when no
machine store exists, while a genuinely new implicit installation starts under
`/var/lib/aivm` with a private user profile. Explicit non-machine config paths
remain legacy boundaries, which gives migration and recovery tools a stable way
to inspect old documents later.

The creator-adoption step clarified an important invariant: the profile may
suggest a guest username only before creation, but the persisted principal owns
the guest username afterward. Runtime loading now fails if the current host
login has no active principal rather than falling back to a machine default or
reconstructing identity from `vm.user`. That failure is deliberate; the next
stage must solve enrollment through the restricted bootstrap channel, not by
reviving shadow stores or a shared guest account.

I also connected the physical contract to operator tooling. Config path/edit
commands expose the private profile, and host-permissions setup can create the
trusted `aivm` group and root-owned setgid machine directory. The main remaining
risk is interruption between the authoritative machine write and the private
profile update; both operations are idempotent and machine state is written
first, but the later enrollment/migration commands still need explicit
reconciliation phases. The complete non-e2e suite passed as a non-root user
(859 passed, 8 skipped). I did not run the expensive real-host E2E suite, in
accordance with the release-train testing plan.

## 2026-07-28 14:06:58 -0400

Implemented the restricted principal-enrollment channel on top of the new
machine/profile store. The most important design constraint was keeping the
bootstrap identity useful without turning it into a second shared login. The
machine-owned key is therefore accepted only by a dedicated system account,
and its authorized-key entry replaces every requested remote command with a
stdlib-only guest helper. Forwarding, PTY allocation, X11, agent forwarding,
and user rc processing are disabled, and sudo permits only the exact forced
helper invocation.

I made principal state transactional enough to be recoverable rather than
optimistic: the host writes `pending` before transport, distinguishes an
unreachable VM from a rejected enrollment request, and does not mark a
principal active until a new SSH connection succeeds with the user's personal
key. The helper itself is deliberately idempotent and additive for authorized
keys, while UID/GID collisions fail rather than silently changing another
account. A late review caught a practical executable issue—the installed helper
needed a shebang—which is now asserted in cloud-init tests.

The complete non-e2e suite passed as a non-root user (874 passed, 8 skipped).
I did not run the expensive real-system E2E suite. The main remaining risk is
integration behavior on an actual cloud-init/libvirt guest, especially distro
account-management details and forced-command quoting; that belongs in the
final real-system run. The next code stage should connect exact managed-machine
discovery in `config init` to this reconciliation service without allowing a
joining user to rewrite machine configuration.
