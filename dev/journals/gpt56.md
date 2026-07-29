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

## 2026-07-28 14:16:25 -0400

Followed up on the stage-5 enrollment tranche after the branch's `ty` and
`mypy` checks exposed type-only defects that the runtime tests did not catch.
The parser now narrows raw principal UID/GID values before integer conversion,
and the new tests use concrete pytest fixture, store-scope, guest-system, and
chown callback types rather than broad `object` or heterogeneous dictionary
inference. These are intentionally small corrections with no runtime or schema
behavior change.

The focused enrollment/store tests passed, and the complete non-E2E suite
passed as a non-root user (874 passed, 8 skipped). I could not execute `ty` or
`mypy` in the artifact environment because neither checker is installed and
the package mirror returned HTTP 503, so the final checker confirmation remains
for the development machine. I am confident the patch addresses each reported
diagnostic directly, but future feature tranches should include both type
checkers in the regular local validation loop rather than relying on unit tests
alone.

## 2026-07-28 14:53:14 -0400

Connected `aivm config init` to the persisted-principal enrollment path. The
main design choice was to make the hostname-qualified VM name a strict
onboarding key rather than a heuristic ownership claim. The command now loads
the machine store before doing resource or network detection: an exact managed
record enters a profile-only join flow, an absent record/domain initializes
creator defaults, and an unmanaged same-name domain stops for explicit review.
Even `--yes` and `--force` cannot cross that boundary.

The join sequence deliberately saves the caller's SSH/profile data before
transport but does not select the VM until enrollment is active or explicitly
pending. A stopped VM therefore leaves a recoverable principal and a concrete
`vm access reconcile` next action, while a helper or personal-key verification
failure leaves `active_vm` unchanged. Repeated init by an active principal
compares the recorded public key and skips the bootstrap channel entirely.
Synthetic tests assert that machine defaults, network entries, and VM records
remain unchanged during Bob's join; only Bob's profile and principal are added.

The complete non-e2e suite passed as a non-root user (880 passed, 8 skipped). I
again deferred the expensive real-system E2E suite. The most important remaining
risk is real guest behavior when `config init` performs enrollment against a
stopped, slow, or partially cloud-initialized VM; the state machine is designed
to make those failures recoverable, but the final system run must confirm the
operator experience. The next architectural task is global attachment ownership
and complete replay, where the same principal boundary must prevent one user's
local path aliases from mutating another user's declarations accidentally.

## 2026-07-28 15:24:05 -0400

Completed the machine-wide attachment ownership and replay tranche. The main
tradeoff was separating global visibility from local path authority: the store
and status surfaces must show every declaration, but path-based selection and
ordinary session restoration must not cause Alice to inspect or replay Bob's
private host path. New records are therefore keyed by VM, principal, and
canonical path; owner-less records remain legacy input for the later migration.
An explicit administrative override exists for trusted-host repair, but normal
commands never infer that authority merely from group membership.

Persistent replay is the one intentionally global behavior. Its canonical
manifest now lives under per-VM machine state, is generated from the complete
inventory while the store and VM locks are held, and includes owner identity in
record IDs. I added a machine-wide guest-destination uniqueness check after
noticing that separate ownership alone cannot make two bind mounts to the same
guest path coherent. Shared/shared-root session restoration remains scoped to
the caller, which keeps another user's missing or inaccessible host folder from
breaking a routine SSH/code session.

The complete non-e2e suite passed as a non-root user (890 passed, 8 skipped). I again deferred
the expensive real-system E2E suite. The largest remaining uncertainty is
operational replay across two real host users with different filesystem access:
the desired-state and locking model is now deterministic, but final system
validation must confirm the root host replay service and guest mount cleanup.
The next architectural tranche is principal-scoped credential metadata and
operations.

## 2026-07-28 15:37:29 -0400

Followed up on the attachment-ownership tranche after local static checking
found three variable-inference collisions that runtime tests could not expose.
The attachment resolver and CLI attach path now declare their optional selected
record explicitly before the administrative/current-owner branches, and the
status renderer uses distinct names for attachment inventory entries and drift
items. These changes are deliberately type-only and do not alter ownership,
selection, replay, or status behavior.

The focused attachment/status tests and complete non-E2E suite remain the
behavioral validation target. The artifact environment still lacks `ty` and
`mypy`, so final checker confirmation must happen in the development checkout;
however, each reported error arose from branch or loop-variable inference and is
addressed directly without casts or ignores. I am confident this is a narrow
correction, with the main residual risk being another checker-specific inference
collision elsewhere in the new stage-7 code.


## 2026-07-28 15:58:36 -0400

Completed the principal-scoped credential tranche. The important distinction
was between machine-wide metadata authority and user-owned secret authority:
the shared store needs a complete inventory for lifecycle guards and auditing,
but that does not make one host user's deploy-key private material or provider
login available to another. Credential IDs now include the persisted principal,
ordinary selection is caller-scoped, and the explicit all-principals view stops
at non-secret metadata rather than trying to emulate the owner.

Guest reconciliation exposed the same boundary from the other side. Rebuilding
one principal's SSH and Git configuration from the VM-global credential list
would accidentally install another user's key routing into the wrong guest
home, so the service now filters the inventory before every install or revoke
reconciliation. I also chose to reject principal deletion while provider
records remain. A disabled principal may be inconvenient, but retaining its
provider key ID and fingerprint is safer than silently discarding the only
revocation evidence.

The focused credential suite passed with independent Alice/Bob records for the
same repository, owner-only guest reconciliation, metadata-only foreign status,
and disabled-principal preservation. The complete non-E2E suite is the final
validation target; the expensive real-system provider/guest run remains
intentionally deferred. The next architectural risk is migration: old
unattributed credential IDs and existing key directories must be assigned to
the creator without regenerating provider keys or losing provider-management
state.

## 2026-07-28 16:34:10 -0400

Implemented the read-only half of released-installation migration. The main
constraint was resisting the temptation to make the planner "helpful" by
writing scaffolding or choosing between old stores. A migration report is most
valuable as a trustworthy boundary: every source fragment is fingerprinted,
all proposed machine/profile/ownership translations happen in memory, and any
second store claiming the same VM is a blocker even when much of the machine
configuration appears identical. That conservative choice leaves an explicit
human merge decision for the apply phase rather than turning historical
per-user disagreement into global state accidentally.

The planner also exposed an easy-to-miss credential detail. Principal-scoped
credential IDs differ from released VM/repository IDs, so migration cannot only
rewrite metadata; it must later rename the user-owned credential directory while
preserving provider key IDs, fingerprints, and private key bytes. The plan now
reports those renames separately from persistent replay movement. Public SSH
keys, host UID/GID, profile path consistency, target-store contents, guest mount
destinations, and libvirt identity are all checked before a plan can be marked
ready.

Focused tests cover deterministic JSON/text output, strict non-mutation,
monolithic/split fixture equivalence, duplicate VM claims, profile divergence,
runtime absence, and an existing machine target. The complete non-E2E suite
passed as an unprivileged user (906 passed, 8 skipped). I am confident in the
planning boundary, but the next apply/resume/rollback phase is much higher risk:
it must revalidate fingerprints, journal every phase durably, preserve a
working legacy SSH path until verification completes, and make rollback
meaningful after partial filesystem and guest changes.

## 2026-07-28 17:28:00 -0400

Completed the state-changing half of released-store migration. The central
choice was to treat migration as a durable transaction without pretending the
host filesystem, guest, and libvirt form one atomic database. A reviewed plan
gets a deterministic identity, every replaceable host path is backed up and
verified, and each idempotent phase is journaled before moving to the next.
Resume therefore has evidence rather than heuristics: it rebuilds the plan from
the recorded sources, rechecks their hashes, accepts only the exact machine
state produced by that plan, and continues at the first incomplete phase.

I kept released stores and user-owned credential/persistent directories in
place. Copying costs temporary disk space, but it avoids making rollback depend
on reconstructing old paths and preserves provider key bytes and IDs without
contacting provider APIs. The guest bootstrap installation is similarly
additive: it uses the already-working legacy account, leaves that account
untouched, and installs only the restricted forced-command recovery channel.
Host rollback restores every backed-up path and intentionally retains that
narrow helper so a failed migration cannot delete its own guest recovery path.

Synthetic tests cover successful application, verification-only reruns,
injected interruption after the machine write, journal-based resume, source
mutation detection, restricted guest installation transport, and reverse-order
rollback. The complete non-E2E suite remains the final local validation target.
The largest remaining risks are real multi-user ownership under sudo, guest
package/user variations during helper installation, and runtime attachment
replay after a migrated persistent manifest. Those belong in the deferred
real-system migration rehearsal. The architecture is otherwise ready for the
last operational-lifecycle and release-hardening tranche.

## 2026-07-28 18:07:42 -0400

Completed the final implementation tranche for the trusted shared-machine
architecture. I kept the serialized principal vocabulary stable but moved new
operator-facing text toward “access identity”; this avoids a broad schema/API
rename while the user is still evaluating terminology. The more important
boundary is behavioral: disable is reversible and removes only the exact guest
public key plus AIVM sudoers fragment, whereas remove is metadata deletion and
is blocked until every owned attachment and credential has been resolved.
Neither path deletes a guest home or invents an ownership transfer.

The last-active guard is intentionally explicit. The restricted bootstrap
channel can recover a disabled machine, but making that fact an implicit excuse
to cut off all ordinary access would be surprising and operationally risky.
Cross-user changes likewise require a named trusted-host override. These are
accident-prevention and audit controls, not claims of hostile-user isolation;
libvirt control on the host remains effectively root-equivalent.

I also added machine-impact summaries around VM and network lifecycle changes
and surfaced trust mode plus active identity counts in list/status output. The
service modules now provide a plausible seam for a future privileged broker,
but no daemon or speculative policy schema was introduced. Synthetic tests
cover reversible disable, ownership-blocked removal, cross-user and last-access
guards, explicit re-enable, forced guest cleanup, CLI dry runs, and global
impact counts. The remaining uncertainty is now environmental rather than
architectural: real sudo ownership, distro guest behavior, migrated persistent
replay, and two-host-user operation need the deferred real-system rehearsal.

## 2026-07-28 18:34:00 -0400

Corrected the final operational-lifecycle CLI boundary so the internal action
parameter retains the `AccessAction` literal type all the way into the service
call. Runtime behavior is unchanged; the adjustment prevents `ty` from widening
the class helper's `disable`/`remove` choices to an arbitrary string. The
remaining reported mypy failure is in the installed NumPy stub while the project
is configured to target Python 3.11, not in AIVM source.

## 2026-07-28 18:52:00 -0400

Reworked every generator-decorated context manager in production and E2E
scaffolding into an explicit scope class with `__enter__` and `__exit__`. The
public call patterns remain unchanged through small factory functions, but the
resource lifecycle is now visible in ordinary class methods: nested advisory
file locks, ordered machine locks, store locking, persistent-manifest locking,
handled command attempts, compound-action approval, and E2E teardown.

The lock conversion was the highest-risk part because generator finalization had
implicitly provided exception cleanup. The new classes preserve the same
reentrant process/thread accounting, close descriptors on partial entry failure,
and unwind ordered lock sets through `ExitStack`. I am confident in the resource
lifetimes after focused nesting/exception tests, but type checkers may expose
small annotation differences around `__exit__` return values; those should be
fixed directly rather than reintroducing decorator-based scopes. The repository
style guidance now records the class-based preference so future work does not
recreate a mixed idiom.

## 2026-07-28 19:10:42 -0400

Corrected the explicit machine-resource lock scope's `__exit__` annotation to
match `contextlib.ExitStack`: cleanup may return either `False` or `None` when
it does not suppress an exception. This is an annotation-only fix; ordered lock
release and exception propagation are unchanged. The broader class-based
context-manager conversion remains intact.

## 2026-07-28 19:24:00 -0400

Corrected the persistent-manifest lock scope to expose the same `bool | None`
`__exit__` contract as its machine-resource lock delegate. I also moved the
replay-state decision's final return outside the `with` block so mypy can prove
that the function returns on every normal path. Neither change alters locking,
exception propagation, or replay-state selection.
## 2026-07-28 19:37:16 -0400

Quarantined released pre-0.6 compatibility behind the explicit
`aivm.legacy.pre_0_6_0` package. The migration planner/executor and CLI,
released paths and scope selection, synthetic runtime adapter, old schema
normalization, firewall cleanup, and historical virtiofsd-wrapper recognition
now live there. Canonical store/parser/render/ownership surfaces that still
must accept both generations carry a searchable no-op marker rather than
hiding their compatibility obligation.

The main risk was creating circular imports while moving schema and scope
helpers beneath the canonical config model. Keeping the marker module
dependency-free and making the selection helper return only paths avoided that.
I also renamed `ResolvedVMContext.legacy_cfg` to `effective_cfg`; it was used by
both machine and released stores, so the old name falsely made canonical code
look like compatibility code. I am confident the new boundary is materially
easier to delete, but full-suite and checker validation remain important
because many imports moved even where behavior did not.

## 2026-07-28 19:55:00 -0400

Moved every test and frozen fixture whose purpose is support for released
pre-0.6 installations into `tests/legacy/pre_0_6_0`. This includes migration,
old schema parsing, old per-user paths, firewall-table cleanup, historical
virtiofsd wrappers, and old shared-root ownership repair. Ordinary runtime
tests now construct canonical persisted contexts through `tests.helpers` rather
than importing the legacy adapter as convenient scaffolding.

The boundary test now rejects versioned compatibility imports outside the
legacy test subtree and confirms that the released fixtures move with it. This
makes retirement mechanically clear: delete the production compatibility
subtree, delete the matching test subtree, then remove the explicitly marked
mixed surfaces.

## 2026-07-28 20:18:00 -0400

Narrowed the dynamic pre-0.6 schema header values at the compatibility
boundary. Schema versions now validate as integer-compatible scalar values
before conversion, and behavior keys validate as strings before dynamic
attribute lookup. This preserves the released TOML behavior while making the
versioned adapter acceptable to both ty and mypy without casts or ignores.

## 2026-07-28 21:10:27 -0400

Addressed the external source review as one release-hardening pass rather than
as isolated patches. Caller authorization now comes from kernel UID/GID and the
passwd database, with explicit host-account repair and an explicit target for
whole-command sudo setup. Access disable/remove is serialized under the
machine-store and VM locks and always verifies guest revocation; enrollment
rejects implicit key or guest-account rotation and treats SSH comments as
non-authoritative.

Persistent attachment approval is bound to the source directory device/inode,
and both immediate attachment and reboot replay use one descriptor-pinned
privileged bind primitive that walks source and target path components without
following symlinks. Persistent detach retains a durable `detaching` record,
prunes host exposure immediately, reconciles a live guest, and can select the
stored record even after its original source disappears.

VM deletion now uses a durable, idempotent phase journal. It removes the VM
record only after attachment, credential, libvirt/storage, replay/bootstrap,
machine-state, and profile cleanup succeeds; retries skip completed phases and
repair the crash window after the final atomic store write. All storage paths
are preflighted against the AIVM-managed tree before the first destructive
phase, every libvirt undefine attempt retains `--remove-all-storage`, and
unverifiable or retained storage fails closed with a recoverable journal.
Canonical 0.6 runtime code now consumes real or narrow transport contexts
instead of synthesizing pre-0.6 identities; a static boundary test enforces the
remaining compatibility bridge.

Focused adversarial tests cover source/target replacement, missing-source
detach, comment-only keys, forbidden rotation, concurrent last-access changes,
interruption/retry boundaries, external storage, retained storage, and final
store-write recovery. The complete non-E2E suite passes with 970 tests and 8
skips. Real-system E2E and local ty/mypy execution remain for the consumer
environment because the required host/libvirt setup and checker executables are
not available in this artifact environment.

## 2026-07-28 21:31:15 -0400

Reviewed the post-hardening source as a new implementation pass and kept the
changes narrow to defects still present in that revision. The reported ty and
mypy failures were annotation/narrowing issues: deletion journal string arrays
now narrow item-by-item, the dry-run domain deletion path returns its declared
optional result explicitly, and failure-injection wrappers carry the exact
production call signatures.

Two recovery gaps remained after the larger lifecycle patch. A persistent
detach could successfully remove its root replay unit and approved manifest,
then fail while deleting the durable `detaching` record; retry previously saw
only disabled records and declined to recreate replay state, making host-prune
verification impossible. Replay-state selection now treats any retained
persistent record as unfinished work. Deletion journals were also keyed only by
VM name, so a completed journal could short-circuit deletion of a later VM with
the same name. Create/start now refuses an unfinished journal at the common VM
entry point, and deletion replaces completed or demonstrably superseded
journals before acting on a recreated domain.

Enrollment previously locked each store write but not the guest transaction
between them, allowing access disable/remove to interleave with a pending
enrollment. The complete non-dry-run reconcile operation now shares the ordered
store/VM lock with access lifecycle mutations. Focused regression coverage for
these paths passes (72 tests); the full locked environment could not be
recreated here because the configured package source lacks `kwconf`, `ty`,
`mypy`, and `ruff`, so the consumer environment should rerun the repository's
normal checker and non-E2E commands.

## 2026-07-28 22:05:00 -0400

The real-system E2E run caught a Linux descriptor-semantics mistake that the
unit tests had not exercised. The persistent replay helper deliberately opens
the export root with `O_PATH` so the validated directory object remains pinned,
but `os.listdir(fd)` requires a readable directory descriptor and fails with
`EBADF` for `O_PATH`. I retained the stronger pinning model and enumerate the
same object through `/proc/self/fd/<fd>` rather than reopening the mutable
original pathname.

Added a regression test that loads the generated helper and calls stale pruning
with the actual path-only descriptor returned by `open_absolute_directory`. The
remaining uncertainty is environmental rather than conceptual: the full host
E2E must be rerun to exercise the installed helper under sudo, mount, libvirt,
and systemd. The focused generated-helper test is expected to reproduce the
exact failed syscall boundary without requiring privileged mounts.

## 2026-07-28 22:10:11 -0400

The second real-system E2E attempt got past O_PATH directory enumeration and
then exposed the next Linux mount-lifetime detail: the helper kept an O_PATH
handle open on the token mountpoint while invoking `umount` through that same
handle, and util-linux correctly reported the target busy. I changed cleanup to
close the child handle and address the token through the still-pinned,
root-owned export-root descriptor. This retains protection against replacing
the mutable original export-root pathname without making the mount hold itself
busy.

I also added a lazy-detach fallback for genuine active references. That is a
tradeoff: already-open handles can outlive a lazy detach, but the mount is
removed from namespace lookup immediately, which is the strongest revocation
available without killing the process holding those handles. For an ordinary
running-guest detach, the code now asks the guest replay helper to unmount first
and only then prunes the host bind, reducing the need for the fallback and
making the intended dependency order explicit.

The generated helper compiles and focused direct tests cover parent-descriptor
unmount addressing plus the busy-to-lazy fallback. Full pytest, ty, mypy, and
privileged E2E remain for the consumer environment because this sandbox lacks
`kwconf` and the configured checker executables. The highest-risk remaining
uncertainty is how a live virtiofs server behaves during lazy detach; the E2E
full-cycle detach is the authoritative validation.

## 2026-07-29 10:34:00 -0400

Addressed a review centered on the places where recovery code can be more
hazardous than the original failure. The mount-tree cleanup was treating any
nonzero `findmnt` result as an empty inventory, so it now distinguishes an
already-absent deletion root and otherwise fails closed before `rm -rf`. I was
initially tempted to rely only on the deletion caller for disk revalidation,
but that would leave the lower-level explicit-storage API unsafe for future
callers. Both the journal service and the domain helper now compare the live
file-backed disk set immediately before storage-removing undefine work.

Migration rollback required the largest conceptual change. A backup is not
necessarily permission to restore: released stores and persistent-state
sources are evidence retained for diagnosis, while only migration-owned
outputs are rollback targets. Each successful apply phase now records the
exact digest and existence state it produced. Rollback performs a global
preflight before changing anything, skips evidence-only inputs entirely, and
refuses targets that no longer match either their original state or the known
migration-produced state. If an apply phase crashes after a partial write but
before its output can be fingerprinted, rollback intentionally stops for
manual recovery rather than guessing.

Focused deletion, domain, and legacy migration suites pass (39 tests). Running
the complete non-E2E suite as an ordinary host user with the supplied kwconf
source passes 989 tests with 8 skips. The remaining validation risk is static
checking (`ty`/mypy), whose executables are not available here, so the overlay
consumer should run the normal checker commands before committing.

## 2026-07-29 11:28:14 -0400

Refactored optional guest-tool support around one ordered registry without
adding Claude yet. The motivating problem was extension fan-out: tool names,
defaults, apt prerequisites, installer selection, CLI validation, and status
checks were each duplicated in separate modules. `aivm.vm.guest_tools` now
owns definitions for the existing uv, Rust, and VS Code tools, while CLI,
provisioning, status, config lint/editor validation, and TOML serialization
consume fixed registry APIs. `ToolsConfig` stores dynamic overrides but keeps
the released flat `[tools]` syntax and compatibility attribute access such as
`cfg.tools.rust`.

The most important unexpected finding was that the canonical machine-store
parser and renderer omitted tools even though resolved configuration treats
them as machine-owned state. The refactor now round-trips `[defaults.tools]`
and `[vms.tools]`; legacy files without those sections retain the same effective
defaults, including equality after save/reload. This widened the legitimate
refactor surface into config-store lint and editor validation, but those sites
now query the registry rather than becoming new lists to update for every tool.

I deliberately retained the individual installer helper functions inside the
registry module as narrow test/compatibility surfaces, but no runtime consumer
branches on uv/rust/code anymore. A future tool should need an installer builder
and one registry definition, plus focused tests; it should not require edits to
CLI, provisioning, status, config schema fields, lifecycle exports, or store
allow-lists. The remaining architectural tradeoff is that `ToolsConfig` uses
late imports to query the VM-owned registry, avoiding an import-time cycle but
leaving a lower-level config object aware of the registry's module location. A
future plugin system may justify splitting pure metadata into a lower-level
module, but doing so now would add indirection without reducing the extension
surface.

Focused config, status, migration, CLI, and registry coverage passes 116 tests;
generated uv/Rust/code scripts pass `bash -n`. The complete non-E2E run passes
985 tests with 14 skips and has the same five sandbox-sensitive failures seen
on the clean base: two shared command-approval log tests and three root
writability/sudo-decision tests. Ruff, ty, and mypy are unavailable in this
offline environment, so the consumer should run the repository's normal lint
and type-check commands before committing.

## 2026-07-29 12:05:00 -0400

I addressed the GPT-5.6 review of commit `07a9c14`. First, I restored the
historical guest-tool imports in `aivm.vm.lifecycle` so every name retained in
`__all__` is actually bound again. I added a regression that checks the whole
compatibility export list rather than only the twelve names implicated by the
current failure.

The migration integrity issue required a stronger model than checking whether
a source still happens to exist at copy time. Each credential-material and
persistent-state move now carries a reviewed fingerprint consisting of
existence, path type, and a deterministic content-tree SHA-256. The plan schema
is bumped because these fields are part of the operator-reviewed JSON/text
contract and the migration-id payload. Apply validates all such fingerprints
before creating the machine-store layout, validates each source again at the
copy boundary, and verifies outputs against the reviewed fingerprint rather
than the source's mutable current state. Missing planned inputs are no longer
silently skipped, and inputs absent during planning cannot appear later without
invalidating the plan.

The main tradeoff is that content fingerprints intentionally exclude ownership
and modes so persistent-state targets may receive machine-store policy without
changing their reviewed content identity. Credential copies retain the existing
stronger metadata-preserving `_tree_sha256` check in addition to the reviewed
content fingerprint. Symlinks and unsupported node types fail planning rather
than becoming unverifiable inputs.

Focused lifecycle and migration tests pass 47 tests. The full non-E2E suite
passes 994 tests with 14 skips and the same five environment-sensitive failures
seen previously: two shared command-approval-state tests and three tests whose
root-writability assumptions do not hold in this sandbox. Ruff, flake8, ty, and
mypy are unavailable offline here, but `git diff --check`, compileall, direct
`import *` validation, and the focused regression suite all pass. The highest
remaining risk is static-checker interpretation of the new typed fingerprint
parser, so the normal repository lint and type-check scripts should remain part
of the consumer-side verification.
