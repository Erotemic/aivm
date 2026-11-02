# Proposal: delegated host operations for multi-user AIVM (2026-10)

> **Status: exploratory proposal; NOT APPROVED.** This document records a
> candidate design for discussion, not a maintainer decision or an
> implementation instruction. In particular, it does **not** authorize a
> privileged daemon, a new service dependency, removing users from `libvirt`,
> changing the machine-store trust boundary, or altering the guest/host
> attachment protocol. Review the decision gates below before implementing.
>
> **Scope exclusion:** The separate virtiofs attachment server is out of
> scope. A proposed AIVM control-plane broker is a different component.

## Motivation and observed case

On 2026-10-26, a new non-sudo host user joined an existing shared AIVM VM.
The administrator had to (1) add their account to `libvirt`, (2) wait for
fresh process group credentials, (3) prepare their guest SSH public key via
AIVM's machine-scoped bootstrap identity, and (4) attach a repository beneath
that user's private home. The user's own SSH verification then succeeded.

The direct repairs already exist: `aivm vm access prepare` / `verify`, a
privileged descriptor-based probe for an administrator attaching another
user's private directory, and the normal-user `aivm host permissions grant`
command. The [onboarding review](multi-user-onboarding-preflight-2026-10.md)
identifies remaining preflight and orchestration improvements. The question
here is whether **future ordinary users can request an authorized host
operation without being host sudoers or general system-libvirt administrators**.

AIVM's current `libvirt`-group shared-machine mode deliberately assumes
trusted coworkers. Its ownership metadata is not a security boundary against
someone who already controls system libvirt or has host root. This proposal
must not imply otherwise. See
[shared-machine architecture](shared-machine-architecture.md).

## Do not conflate two proposals

| Candidate | Purpose | Status and dependency |
| --- | --- | --- |
| Request-first onboarding planner | Inspect user/VM facts, derive next actions, show pending/admin/owner states before attempting sudo; no service required | **Not approved as a new abstraction.** Can be evaluated separately in the existing CLI and test harness. |
| Privileged host-operations broker (`aivmd`, tentative name) | Enforce administrator-selected per-user permissions for a narrow set of host/guest lifecycle actions over a local authenticated IPC interface | **Not approved.** Requires an explicit threat-model, operations API, deployment, migration, and security review. |

Context managers should delimit execution effects, privileges and locks;
explicit plans and typed outcomes should describe lifecycle transitions.
Neither approach requires another persisted state machine for identities or
attachments. A broker is *not* a prerequisite for a useful request-first CLI.

## Candidate user experience (illustrative; not implemented)

- The admin installs AIVM's **root-owned system service and policy** once,
  lists permitted Linux principals/groups, allowed VMs, operation types,
  attachment source scopes, and optional quotas. All grants are explicit.
- A new user runs normal `aivm config init` and sees a durable pending request.
  A user cannot impersonate another enrolled host identity to request access.
- A permitted user runs an ordinary AIVM attachment/entry command. AIVM asks
  the broker to attach *their own* approved host directory; neither `sudo`
  nor membership in the broad `libvirt` host-administration group is required
  for that narrowly approved operation.
- An administrator can prepare an enrollment or attach another principal's
  private directory through an **explicit privileged/delegated operation**;
  assigning another owner is never inferred from the source path.
- Repeated requests are idempotent, partial effects are recoverable, and
  status distinguishes requested, authorized, realized, and blocked actions.
  Declines are actionable and do not leave a misleading success record.

These are target interactions only, not currently supported commands or a
promise of a specific policy syntax. Ordinary AIVM installations continue to
work without a daemon unless a separate approval changes that guarantee.

## Candidate architecture and authority flow

```text
unprivileged AIVM client (kernel UID, personal profile/key)
    |
    | local AF_UNIX request (typed verb, VM id, principal, paths, intent id)
    v
root-owned systemd socket + AIVM host-operations service [PROPOSED]
    | 1. authenticate peer using kernel-supplied credentials
    | 2. authorize specific verb/resource against root-owned policy
    | 3. pin host source using checked directory descriptors
    | 4. lock global VM/store resource; revalidate; execute; verify
    | 5. persist canonical machine records and audit result
    v
existing libvirt / machine store / guest bootstrap / host bind APIs
    |
    +--> personal SSH verification remains with the enrolled user
```

Do not accept a request's `USER`, `SUDO_USER`, `LOGNAME`, owner string, or
client-supplied source inode as an authentication fact. Use the Unix socket's
kernel peer credentials and the NSS/passwd identity mapping as a starting
point. The service should be installed under root-controlled paths, started
with a minimal environment, and never import code from a user's checkout,
virtualenv, or guest-mounted directory. Its socket must not expose a general
shell, arbitrary `virsh`, generic mount, or arbitrary SSH execution interface.

### Authorization is per operation and per resource

Evaluate **all** of: actor identity; proposed owner principal; VM identity;
operation; source/destination path and mount mode; current machine state;
explicit delegation; and policy version. Example operation families to
consider (not a finalized API):

1. Query status and plan (read-only; no implicit sudo or mutation).
2. Prepare an owner's registered **public** guest key, without taking or
   using their private key.
3. Create/reconcile an authorized persistent attachment of the caller's own
   host directory, including private homes, after policy and filesystem
   checks; optional administrator-only cross-owner mode.
4. Repair an authorized recorded host-side attachment after restart or drift.
5. Global VM lifecycle, policy changes, system user/group changes, device
   assignment, and ownership transfers: **not delegated by default**.

Source approval is not a string-prefix check. Resolve under held directory
file descriptors without following unapproved symlinks; check filesystem
identity at the actual privileged operation, consider bind mounts and inode
replacement, and reject races between approval and effect. Policies granting
access to a directory do not automatically grant access to its siblings.
The service must not read or copy a user's personal private SSH keys or
credential files merely because it has root privileges.

### Persistent state, locks, and failure handling

- Keep machine-wide desired state in the existing machine store, personal
  identities in user profiles, and attachment ownership on records.
- Use the existing global resource-lock order; identify and fix nested-lock
  deadlocks before adding an outer transaction. Revalidate authorized facts
  inside the effect boundary.
- Journal an intent and retain recovery coordinates for partially applied
  external effects. Duplicate requests and daemon restarts must be safe.
- An ACL or policy update should affect **future** requests immediately.
  Decide explicitly what it means for already realized mounts, sessions and
  cached grants; revocation must not be claimed without teardown tests.
- Log actual equivalent host/guest commands and the actor, approved policy
  and target, with sensitive material redacted. A named inspectable helper is
  preferable to an anonymous root shell script.

## The central trust-model complication

**Giving someone `libvirt` membership remains a broad host-administration
capability, even if a broker also checks their AIVM attachment requests.**
To obtain a meaningful restricted-host-user mode, the design must remove
that broader path *and* stop relying on those users writing the machine store
or mutating libvirt directly. Introducing a daemon while leaving the bypass
intact can improve UX but does not establish least privilege.

A phased rollout could support existing trusted coworkers unchanged, then
add a separate opt-in `restricted-host-users` policy only after every write
and bypass path is accounted for. Do not silently downgrade the current
machine's assumptions or attempt to enforce a boundary only in the CLI.

The **AIVM host-operations broker is distinct from `aivm-secrets`**, which is
an experimental, opt-in, separately installed credential/identity project.
Do not make basic AIVM installation or host permissions depend on it. See
[aivm-secrets repository boundary](aivm-secrets-repository-boundary.md).

## Alternatives to compare before approval

| Alternative | Benefit | Main limitation / evaluation |
| --- | --- | --- |
| Existing admin-assisted CLI + request-first planner | Small change, no daemon deployment; solves observed support problem | Non-sudo user still needs admin for persistent host operations |
| Narrow `sudoers` or polkit-authorized root-owned helper | Delegates predefined commands without a resident service | Argument/path validation, policy scope, and safe execution are still necessary; beware arbitrary command escapes |
| Root-owned systemd socket service + typed operations | Natural peer-credential and centralized policy boundary; enables self-service delegation | Larger permanent privileged attack surface, deployment/migration/restart/revocation burden |
| Continue trusting `libvirt` group | Least implementation complexity | Broad system-libvirt capability; does not meet restricted-user security goal |
| Adopt/compose with an external runtime | Potentially avoids maintaining authorization/policy infrastructure | Must reproduce AIVM's shared persistent-VM and per-principal host-filesystem workflow, or explicitly give it up |

See the [related-work survey](related-work-sbx-openshell-2026-10.md) before
proposing a new policy engine or standalone sandbox runtime. In particular,
OpenShell already offers an extensible gateway/driver model and rich policy
controls; whether these map to AIVM's **shared guest** model remains untested.

## Explicit review and approval gates

The following decisions are **open**; this document approves none of them:

1. **Product need:** How many non-sudo users/sites need self-service host
   attachments? Does a request-first CLI plus admin help cover them?
2. **Security goal:** Is the objective convenience for trusted `libvirt`
   members, or meaningful per-user isolation from host libvirt/root authority?
3. **Policy contract:** Who can approve and revoke which source directories,
   destinations, VM resources, guest identities, mounts, and lifecycle verbs?
4. **Implementation choice:** Existing CLI + narrowly authorized helper,
   sudoers/polkit, systemd broker, or integration with OpenShell?
5. **Deployment and migration:** Root-controlled packaging/versioning, service
   failures, immutable host identity, machine-store writes, pre-existing grants
   and shared-machine compatibility.
6. **Evidence:** Synthetic two-user tests plus live-user integration on a
   disposable test VM; failed/aborted/duplicated concurrent requests; private
   source traversal; symlink/race tests; no unauthorized user-to-user access;
   crash/reboot/revocation cleanup.

**Approval record (intentionally blank):**

- Maintainer decision: *not recorded*.
- Accepted scope: *none*.
- Implementation authorized: **no**.
- Required follow-up: product/threat-model review, related-work experiments,
  then a separate explicit approval before coding a privileged service.
