# Multi-user onboarding failure-prevention review (2026-10-26)

## Scope and evidence

The 0.6 trusted shared-machine architecture is already working for three
principals on `aivm-2404-aiq-gpu`: a creator, a previously enrolled user, and
an additional non-sudo host user. The third user successfully reached an SSH
session only after an administrator prepared the guest key and declared the
user's private-home persistent attachment.

This review is about host-side CLI orchestration, permissions, operational
status, and regression coverage. **Do not modify or replace the separate
virtiofs attachment server.** Do not introduce a privileged daemon as part of
this work. Preserve the existing trusted-host model and the separate
machine-store/profile/attachment-owner boundaries.

The observed failure sequence was:

1. A shared store existed, but the new user lacked an active `libvirt` group
   credential. An administrator added membership, and the user refreshed the
   login session.
2. `aivm config init` persisted an enrollment request, but the new user could
   not run host sudo for the root-owned guest bootstrap SSH key.
3. The administrator could not inspect the source under the new user's private
   home by ordinary filesystem traversal, even with `--admin_override`.
4. The administrator-installed key plus owner-side personal SSH verification
   completed enrollment; a privileged descriptor-based source probe allowed
   the administrative persistent attachment without modifying home ACLs.
5. The user confirmed that `aivm ssh .` worked.

The direct enrollment/attachment repairs from commit `8f600605` are not to be
reimplemented here: `vm access prepare`, `vm access verify`, and the foreign
private-source descriptor probe already address them.

## Distinguish resource authority from user readiness

There is no single useful `is_ready` Boolean. Reconciliation must separate:

- **Host membership:** not configured / configured but not active in the
  current kernel credentials / currently usable. A successful `usermod` is
  never sufficient proof of current-session access.
- **Guest access identity:** absent / pending / active / error / disabled. The
  machine store records the last proven grant; a failed retry does not revoke
  a previously active grant. The owner controls the private key; the admin
  installs only its registered public half.
- **Host attachment intent:** absent / recorded / being detached; ownership is
  a principal ID, separate from the host path and guest destination.
- **Attachment realization:** source availability and device/inode identity,
  root bind readiness, guest visibility. This is a diagnostic view rather than
  a new authoritative grant field.
- **Actor capability for an operation:** an action might need host sudo even
  if the actor can use the shared store and system libvirt. Do not reduce it
  to one unverified `has_sudo` flag: sudoers may authorize specific commands.

These are orthogonal parts of the workflow. Joining must not require an
attachment, and a folder already registered for another user's guest identity
must not be adopted automatically.

## Improvements, in priority order

### P0: make the two-person join path a normal outcome

At `8f600605`, `_join_existing_machine` calls `reconcile_current_principal`
and catches a failed sudo enrollment attempt as a pending join. Its follow-up
text suggests running `reconcile` when the VM is reachable even when the
actual issue is **lack of sudo**. This review's first patch distinguishes
that failure and prints admin `prepare` / owner `verify` instructions, but
does *not* yet avoid the failed sudo attempt in the first place. It returns
success for initializing a pending profile, which can be correct, but the
result must never look like active guest access.

Target behavior:

- `config init` makes the durable request without requiring a successful
  privileged operation by its requester.
- An unprivileged requester is told, with **actual VM name, login, and
  identity ID**, exactly which `vm access prepare` command the administrator
  should run and which `vm access verify` command the owner should run.
- Owner verification can be retried without privileged bootstrap. If it
  succeeds, advance to active; if it fails, retain the last proven grant.
- A VM-unreachable outcome instead gives the correct availability/retry
  advice; a missing-bootstrap-identity outcome gives migration guidance.
- Do not prompt the non-sudo user repeatedly for a privilege they do not
  have. Preserve an explicit immediate-reconciliation option for host admins.

Prefer typed *operational outcomes* over parsing `str(exception)` to select
remediation. A pending request is not an exception to the durable host-profile
creation, but it is not a successful guest enrollment either.

### P0: make administrator host grants work from their own environment

The documented `sudo aivm host permissions setup --user alice` fails if AIVM
is only installed in the administrator's Python environment. Meanwhile the
unprivileged CLI call with `--user alice` rejects another host identity
before the existing step-level sudo mechanism can run. `setup` is also not an
appropriate way to prepare a different person's VM storage paths: that part
is caller-specific.

This patch adds the narrow `aivm host permissions grant alice --admin_override`
operation. It adds the target account to the shared-store/libvirt groups
and ensures the machine-store root is prepared, without inspecting their home
or rewriting a profile, credential, attachment or disk-storage path. It
preserves the already-implemented group-relogin guidance.

### P0: correct cross-user attachment privilege guidance

At `8f600605`, `_attach_privilege_guidance` recommends `sudo aivm vm attach
...`, which loses the enrolled administrator's host identity and can fail on
`sudo`'s executable `PATH`. This patch instead instructs the administrator to
run their own `aivm vm attach --owner_principal ... --admin_override`, with
normal step-level sudo when the host bind requires it. Future diagnostic
work should print the exact VM, mode, source, destination and principal so
the command can be copied. Do not grant temporary home ACLs as a normal
procedure.

### P1: support shell-only entry independently of an attachment

`aivm ssh` currently defaults to attaching the current host directory. An
otherwise active user in an arbitrary working directory may therefore hit a
persistent bind/sudo failure when all they wanted was a guest shell.

Add an explicit no-attachment SSH mode or a dedicated guest shell entry point
that uses the same VM/principal/SSH checks but does not plan, stage, record,
reconcile or delete host attachments. Preserve `aivm ssh .` as the productive
folder-oriented default. Distinguish the new SSH option from `aivm code
--no_attach`, which currently means *do not attach to the VS Code tunnel*.

### P1: an actionable `aivm vm access status` / join preflight

The inventory lists `pending`/`active`, owners and counts, but does not name
which actor must do what next. A read-only status view should report:

- invoking kernel identity and current-session group membership, including
  the durable-vs-active distinction;
- selected VM, personal profile/key presence and stored access grant;
- next action: refresh login, ask admin to prepare public key, run owner-side
  verification, or attach a project (optional);
- whether a registered persistent attachment's expected root bind is
  actually realized, with a separate operator handoff when host replay needs
  privileged repair; and
- any limitation of checks that require sudo (unknown is not absent).

Never expose personal private keys or assume another user's home can be
traversed. Read-only status must not invoke `sudo` by default.

### P1: bound and serialized cross-user attachment reconciliation

`run_vm_attach` currently resolves/preflights the destination, changes VM
exposure, records an attachment and reconciles host/guest state in separate
phases, without a single outer `machine_resource_locks` boundary around the
whole workflow. `run_vm_detach` does take a VM/store lock. Audit the inner
locks before adding an outer one (nested locks must not deadlock), and test
racing attaches by different principals to the same guest destination.

The successful source-probe patch must remain authoritative through the
actual bind operation, including source device/inode checks. A failed attach
must never leave a successful-looking record unless that record is an
explicitly named recoverable intent; never discard recovery coordinates after
partial external effects.

### P2: resumption and durable host-side replay diagnostics

An administrator can establish a persistent bind for a non-sudo user, but
only the host replay service or a privileged operation can restore a lost
bind after reboot/drift. Detect when that reconciliation is missing and print
which actor or installed replay service must recover it. Do not change the
separate virtiofs server; this is about operator observability and recovery.

### P2: explicit key rotation and account recovery

The current reconcile path deliberately rejects changed personal SSH key
material and renamed guest users. That is safer than silent rotation but can
block users after workstation/key replacement. Add a resumable two-person
key-rotation flow later: stage new public key, admin installs it, owner proves
the new key, then revoke the old one only after proof and retained recovery
metadata. Do not impersonate the owner or copy private credentials.

## Model transitions; use context managers for effects

`CommandManager.intent`/`step`, privilege approval scopes and
`machine_resource_locks` already give a good *execution* vocabulary. Context
managers should delimit effect/lock lifetimes, not carry hidden lifecycle
state that is only observable by executing side effects.

Introduce a small explicit pure planner over inspected facts and operation
requests. It returns named actions/next-user instructions, rather than
running SSH, sudo or store writes in the decision function. Execute actions
under appropriate locks; before any irreversible effect revalidate the
facts that authorized it. Persist only the durable grant/attachment/journal
states already needed for recovery.

Suggested seams:

- `inspect_join_facts(scope, identity, vm) -> JoinFacts`
- `plan_join(facts, requested_operation) -> JoinPlan`
- `execute_join_plan(plan, effects) -> JoinResult`
- `render_next_actions(result) -> user/admin instructions`

Use typed outcomes such as `PendingAdmin`, `PendingVerification`,
`NeedsGroupRefresh`, `Ready` and `NeedsHostRepair` for *presentation*.
Do not persist these as a competing authorization state machine.

## Table-driven regression matrix

Keep the matrix narrowly focused on meaningful branches. All tests must
isolate HOME/XDG/machine stores and prohibit real sudo and libvirt effects.

| Scenario | Required invariant |
| --- | --- |
| Account not in libvirt group | No private fallback store; exact admin action |
| Group configured but not in process credentials | No store writes; relog guidance |
| Active membership, no host sudo, new principal | Durable pending request; no confusing sudo loop |
| Admin grants host access through user-installed AIVM | Only host group/store work escalates; target home untouched |
| Admin prepares pending guest identity | Only stored public key used; owner state pending |
| Owner verifies prepared identity without sudo | Active only after personal SSH proof |
| VM unreachable during prepare | Pending retained; retry is safe |
| Guest key already active, reconcile fails | Grant never downgraded on transport error |
| Owner's SSH key changed unexpectedly | No silent replacement/rotation |
| Admin attaches private-home persistent directory | No temporary ACL; root descriptor identity pinned |
| User connects with registered attachment | Does not replay another owner's private paths |
| User connects with no attachment | Shell succeeds without a host mount operation |
| Two owners race to the same guest destination | One consistent global mapping; no leaked external mutation |
| Host reboot leaves bind absent | Explicitly unready with privileged recovery route |
| Admin declines privileged approval | No guest/store success message |
| Principal disabled/removed | No implicit reactivation or owner transfer |

The high-value integration fixture is exactly a two-user host: an
administrator with host sudo, a coworker without sudo, separate host homes
and guest SSH keys, and one fake VM/domain. Drive `config init` -> pending ->
admin prepare -> owner verify -> admin attach -> owner `ssh .` without invoking
real system services. Use one or two concurrent/race variants, not an
unrestricted Cartesian product of all state flags.

## Deferred system design

The `libvirt` group is effectively a host-administrator-level trust grant.
It is an acceptable explicit assumption for trusted coworkers, not a least-
privilege user capability. A future AIVM-owned privileged broker could replace
that assumption and implement operator-approved, narrowly scoped operations.
Such a broker would need a real identity/policy boundary (e.g. Unix peer
credentials, action-specific authorization, descriptor-bound paths, audit,
quotas, revocation and recovery). It should not be built simply to eliminate
some prompts and is **not** a change to the separate virtiofs attachment
server.

## Acceptance gate

The next user should be able to join an administrator-created VM and be told
exactly what they can do without sudo, what action an administrator must take,
and how to verify readiness, without a traceback, speculative manual ACL
changes, or `sudo aivm` from a different user's Python installation.
