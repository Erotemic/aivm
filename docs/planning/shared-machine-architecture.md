# Shared-machine architecture

## Status

Accepted planning direction. This document defines the target architecture for
multiple trusted host users operating one AIVM-managed libvirt VM on the same
physical host.

This replaces the proposed short-term shadow-config and shared-single-guest-user
workarounds. Those may be useful for manual recovery, but they are not a product
surface to implement or document as the normal workflow.

The first implementation targets trusted coworkers on one machine. It does not
claim isolation between host users or guest users. The data model and control
boundaries must nevertheless leave room for later access-control enforcement.

## Product goal

A host should normally have one machine-qualified AIVM VM, for example:

```text
aivm-2404-workstation
```

Every authorized host user should be able to run the ordinary initialization
flow and join that same machine:

```text
alice$ aivm config init
alice$ aivm vm create

bob$ aivm config init
```

The second `config init` derives the same hostname-qualified VM name, sees the
existing managed machine record, initializes Bob's user profile, and enrolls a
separate guest principal such as `bob-agent`. Bob can then run:

```text
bob$ aivm attach ~/code/project
bob$ aivm ssh ~/code/project
```

The attachment becomes part of the one machine-wide attachment inventory. Bob
owns its lifecycle. Alice does not need a duplicate attachment record and can
continue to use plain `aivm ssh` as `alice-agent`.

## Settled decisions

### One machine resource has one machine authority

Libvirt domains, networks, VM disks, firewall rules, virtiofs devices, host bind
mounts, persistent replay manifests, and attachment declarations are global to
the host. Their desired state must therefore live in one machine-wide store.

No per-user store may independently redefine a managed domain with the same
name. A user profile may select and access a machine; it may not provide a
second authoritative description of that machine.

### Each host user has a separate guest principal

The normal guest account name is derived from the host login name:

```text
<host-user>-agent
```

The guest account should use the host user's numeric UID and GID when possible,
so direct virtiofs ownership behaves naturally. Each principal has its own SSH
public key, guest home, shell state, Git identity, and personal credentials.

The original creator of an existing VM may remain mapped to the legacy `agent`
account during migration. Renaming that account is optional and must not block
the architecture migration.

### Attachments are global records with an owner

An attachment mutates the global libvirt domain or one of its global root
exports. The attachment record, replay state, and drift expectation are
therefore machine-wide.

Each record also carries principal attribution:

- who introduced it;
- who owns routine update and detach operations;
- which host lexical aliases belong to that user;
- which guest destination it exposes;
- whether it is shared, shared-root, persistent, or a later backend.

Ownership is useful even before it is a security boundary. It prevents one
user's path aliases from affecting another user's path resolution, makes status
output intelligible, and gives later authorization rules a stable field to
enforce.

### User interaction state remains per-user

The following are user-profile state, not machine state:

- active or preferred VM;
- command behavior and verbosity;
- personal SSH private-key path;
- personal public-key path;
- user-local known-host state;
- provider login tokens;
- personal deploy-key private material;
- local caches and UI preferences.

### Credentials are principal-scoped

Repository credentials belong to a guest principal, even though the VM is
shared. A credential is installed in that principal's guest home and its host
private material remains owned by the corresponding host user.

During the initial trusted-user phase, passwordless sudo means another guest
user can deliberately inspect those credentials. Separate principal ownership
still prevents accidental use and is the correct schema for later hardening.

### Trusted-user mode is explicit

The initial access mode is effectively:

```text
trusted-users
```

Enrolled users may have passwordless sudo and direct system-libvirt access. This
provides identity, ownership, predictable paths, and auditability, but not a
security boundary. Documentation and status output must say so plainly.

A later restricted mode may remove passwordless sudo and route host mutations
through a privileged broker. That later mode must not require another storage
or identity-model rewrite.

## Target state boundaries

| State | Scope | Notes |
|---|---|---|
| VM hardware and image declaration | Machine | One authoritative definition per libvirt domain |
| Networks and firewall policy | Machine | The runtime resources are host-global |
| Enrolled VM principals | Machine | Maps host identity to guest identity and SSH public key |
| Attachments and lexical aliases | Machine | Complete inventory; each record has an owner |
| Persistent attachment manifests | Machine | Must never be generated from one user's partial view |
| VM mutation locks | Machine | Serialize operations from all host users |
| Active/default VM | User | Alice's selection must not change Bob's |
| CLI behavior and verbosity | User | Interaction preference only |
| SSH private key | User | Public key is enrolled in the machine record |
| Repository credentials | User/principal | Referenced from the principal, not the VM as a whole |
| Administrative policy | Machine/root | Future access modes, resource limits, allowed groups |

## Proposed filesystem layout

The exact filenames may change during implementation, but the ownership split
is settled:

```text
/etc/aivm/
    policy.toml                    # root-owned policy; optional initially

/var/lib/aivm/
    config.toml                    # global registry/root fragment
    networks.toml                  # global network definitions
    vms/
        aivm-2404-workstation.toml # VM, principals, attachments
    state/
        aivm-2404-workstation/     # replay/manifests/machine operational state
    keys/
        aivm-2404-workstation/     # restricted machine bootstrap identity
    locks/
        aivm-2404-workstation.lock

~/.config/aivm/
    profile.toml                   # active VM, behavior, user SSH paths

~/.local/share/aivm/
    credentials/                   # user-owned private credential material
```

The existing split-store implementation should be reused where practical. The
important change is not TOML formatting; it is that machine fragments are no
longer rooted in a caller's XDG config directory.

The machine store should be owned by `root:aivm`, with group-controlled writes,
setgid directories, predictable modes after atomic replacement, and one lock
namespace shared by all callers. Tests must cover ownership and mode retention,
not just data serialization.

## Data model

The current `AgentVMConfig` combines machine properties, guest-user identity,
host-user paths, and interaction preferences. The target model separates them.
Names below are illustrative but the boundaries are required.

```python
@dataclass
class MachineConfig:
    vm: MachineVMConfig
    network_name: str
    firewall: FirewallConfig
    image: ImageConfig
    provision: ProvisionConfig
    tools: ToolsConfig
    virtiofs: VirtiofsConfig


@dataclass
class VMPrincipal:
    id: str
    host_user: str
    host_uid: int
    host_gid: int
    guest_user: str
    ssh_public_key: str
    state: str  # pending | active | disabled | error


@dataclass
class UserProfile:
    active_vm: str
    behavior: BehaviorConfig
    ssh_identity_file: str
    ssh_pubkey_path: str


@dataclass
class AttachmentEntry:
    vm_name: str
    owner_principal_id: str
    host_path: str
    guest_dst: str
    mode: str
    access: str
    tag: str
    host_lexical_paths: list[str]


@dataclass
class ResolvedVMContext:
    machine: MachineConfig
    principal: VMPrincipal
    profile: UserProfile
```

The current `vm.user` field must stop being a machine property. Compatibility
loading may translate it into the creator's principal during migration, but new
runtime code should resolve a `VMPrincipal` once and pass a
`ResolvedVMContext` to SSH, provisioning, attachment, status, and credential
operations.

Likewise, `paths.base_dir` and machine replay roots belong to machine state;
SSH identity and user cache paths belong to the profile.

## Enrollment control plane

A second host user cannot create a guest account using their personal SSH key,
because that key is not authorized yet. The architecture therefore needs a
machine-level enrollment channel rather than a manual creator handoff.

### Initial implementation

At VM creation or migration, install:

1. A machine-scoped bootstrap SSH identity stored under the protected global
   machine-state directory.
2. A guest-side `aivm-guestctl` helper.
3. A dedicated bootstrap account whose authorized key is restricted to that
   helper, with no interactive shell, port forwarding, agent forwarding, or
   arbitrary command execution.

The helper accepts a narrow declarative enrollment request and performs an
idempotent reconciliation:

- validate the requested guest username, UID, and GID;
- create or repair the guest account and home directory;
- install the caller's public SSH key;
- configure the current trusted-user sudo policy;
- report the resulting principal identity;
- refuse unrelated guest mutation.

The bootstrap private key is machine state, readable only through the trusted
host `aivm` administration boundary. In the current trust model, membership in
that boundary is already effectively administrative access.

### Why this is not throwaway work

A future `aivmd` privileged broker can hold the same bootstrap credential or
replace its transport while preserving:

- the global principal schema;
- the `config init` join workflow;
- the guest reconciliation helper;
- pending/active enrollment states;
- the attachment and credential ownership model.

Do not implement the temporary workflow by copying a creator's personal private
key or by making all users share one normal guest account. Those approaches
would create compatibility obligations with no value to the target design.

## `aivm config init` target behavior

`config init` becomes both profile initialization and managed-machine join
discovery.

### First user on a host

1. Derive the hostname-qualified default VM name.
2. Initialize the user's profile and personal SSH key if needed.
3. Find no matching global machine record.
4. Save defaults suitable for `aivm vm create`.
5. On creation, write the global machine record, install the bootstrap channel,
   create the first principal, and mark it active.

### Later user on the same host

1. Derive the same hostname-qualified VM name.
2. Load the global machine store before proposing new machine defaults.
3. Find the exact managed machine record.
4. Initialize only the caller's profile and personal SSH key.
5. Create or reconcile a principal named from the host login.
6. Verify personal SSH access.
7. Set the joined machine as the user's active VM.
8. Leave all machine, network, and attachment definitions unchanged.

Interactive mode should show that the user is joining an existing machine.
`--yes` may auto-join only an exact, healthy, AIVM-managed global record. An
unmanaged libvirt domain with the same name still requires explicit import and
review, preserving the repository's current discovery safety principle.

If the VM is unavailable, the principal may be recorded as `pending`; the next
start or explicit reconcile completes enrollment. A failed enrollment must not
leave a profile that falsely claims working access.

## Attachment semantics

### Inventory and drift

Status and reconciliation always use the complete global attachment inventory.
One user's invocation must never classify another user's declared attachment as
unexpected merely because it is absent from a private profile.

Persistent and shared-root manifests are generated from the complete machine
inventory under one machine lock. This removes the current risk that two
partial stores overwrite one another's VM-wide replay declaration.

### Ownership and path resolution

By default:

- the creating principal owns the attachment record;
- only the owner or a machine administrator updates or detaches it;
- all enrolled users can list it;
- the attachment is available in the shared guest according to ordinary guest
  permissions and the VM's trust mode;
- local-path lookup such as `aivm ssh ~/code/project` considers the current
  principal's host paths and lexical aliases, not another user's similarly
  named path;
- a bare `aivm ssh` does not require attachment ownership.

The owner field is enforced as a footgun guard, audit coordinate, and stable
future authorization seam. It is not an isolation boundary against unrestricted
root or system-libvirt administrators.

### Host-path exposure

Attaching a path from a private home directory exposes it to the shared VM and,
in trusted-user mode, effectively to every enrolled guest sudoer. The attach
review should name the VM, owner, source path, guest destination, and trust mode.
It should not silently broaden exposure because another user already joined the
VM.

## Lifecycle and concurrency

Machine lifecycle operations affect every user. Output should distinguish
machine-scoped operations from principal-scoped operations.

At minimum, the global implementation needs:

- a global store lock;
- a per-VM mutation lock;
- optimistic concurrency across all machine fragments;
- deterministic lock ordering for network plus VM mutations;
- ownership/mode-safe atomic replacement;
- recovery for interrupted split-store writes;
- status that reports the actor and scope of pending changes.

The current per-user config lock is not sufficient because independent users
would lock different files while mutating the same libvirt domain.

## Migration requirements

The migration must preserve existing VMs and avoid mandatory recreation.

For each current managed VM:

1. Back up the user's existing store before writing either new scope.
2. Copy machine, network, firewall, image, provisioning, tool, virtiofs, and
   attachment declarations into the global store.
3. Attribute existing attachments to the migrating host user.
4. Create a principal mapping from the host user to the existing `vm.user`.
5. Preserve the existing guest username, home, UID, and credentials.
6. Move VM-wide persistent replay state into the machine state directory.
7. Move interaction behavior, active VM, SSH paths, and personal credential
   references into the user profile.
8. Install the guest bootstrap helper and machine enrollment identity through
   the creator's already-working SSH principal.
9. Verify that the migrated user can still SSH and that drift is unchanged.
10. Mark the old store migrated only after both global and profile writes are
    durable and verified.

The migration must be restartable. Re-running it after a partial failure should
converge or stop with a precise conflict report; it must not duplicate
principals, attachments, or credentials.

When multiple old per-user stores claim the same domain, automatic migration
must stop and present a merge report rather than selecting one silently.

## Compatibility and explicit non-goals

### Compatibility requirements

- Existing monolithic and split per-user stores remain readable long enough to
  migrate.
- Existing VMs using the legacy `agent` account continue working.
- Existing attachment tags and guest destinations remain stable.
- The released config format is treated as the compatibility surface, following
  `AGENTS.md`.
- Explicit `--config` paths remain available for tests, migration inspection,
  and advanced recovery, but cannot create a second machine authority for an
  already-managed global VM.

### Non-goals for the first shared-machine release

- hostile-user isolation;
- removing `libvirt` group root-equivalence;
- a mandatory long-running daemon;
- renaming the legacy creator account;
- per-user VM clones or template instances;
- remote/multi-host orchestration;
- making every guest file private from other sudo-capable guest users.

## Required invariants

Implementation and tests should encode these as hard invariants:

1. A managed libvirt domain has at most one authoritative machine record on a
   host.
2. Every SSH/provisioning/credential operation resolves an explicit principal;
   no machine-level `vm.user` fallback remains in new code.
3. Every attachment used for drift or replay comes from the global inventory.
4. Every attachment has an owning principal or an explicit system owner.
5. Machine writes use global locks and preserve group ownership/modes.
6. User-profile writes cannot modify machine definitions.
7. Joining an existing machine cannot overwrite its CPU, memory, disk, network,
   firewall, image, provision, or attachment configuration.
8. Enrollment is idempotent and independently verifiable by personal SSH.
9. A failed migration or join leaves enough state to retry safely and never
   reports false success.
10. Unmanaged same-name libvirt domains are never silently adopted.

## Definition of done

The architecture is complete when the following end-to-end scenario passes on
a clean shared host:

1. Alice runs `aivm config init` and creates the default hostname-qualified VM.
2. Alice receives `alice-agent` access and attaches a directory.
3. Bob runs `aivm config init` without receiving files or secrets from Alice.
4. AIVM recognizes the existing global machine and enrolls `bob-agent`.
5. Bob attaches his own directory; the record is globally visible and owned by
   Bob.
6. Alice and Bob both SSH with their own keys and guest accounts.
7. Status from either account reports the same machine and complete attachment
   inventory without false drift.
8. Bob cannot accidentally detach Alice's attachment through the normal CLI.
9. Persistent replay is generated once from the complete machine inventory.
10. Concurrent machine mutation is serialized rather than racing two stores.
11. An existing legacy single-user VM migrates without disk recreation or loss
    of SSH access.
