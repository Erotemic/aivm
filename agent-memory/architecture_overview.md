# AIVM architecture overview

This file used to duplicate a pre-0.6 architecture snapshot. That copy became
stale as the repository moved to machine-scoped state, per-user profiles,
access identities, persistent attachment replay, and principal-owned
credentials. It is intentionally kept short now so `agent-memory/` does not
compete with the maintained architecture documentation.

For the current 0.6 architecture, start with:

- `docs/architecture/README.md` for subsystem boundaries, state authority, and
  the aggregate-configuration transition;
- `docs/architecture/flows.yaml` and `docs/architecture/generated/flow-*.mmd`
  for validated runtime flows;
- `docs/architecture/state-ownership.yaml` and
  `docs/architecture/generated/state-ownership.mmd` for persistence authority;
- `docs/source/design.rst` for the long-lived engineering contract;
- `docs/source/quickstart.rst` and `docs/source/workflows.rst` for current CLI
  behavior.

## Current high-level model

AIVM is a local, long-lived libvirt/KVM VM manager for agent workflows. The
security boundary is the VM; AIVM is the management and workflow layer around
system libvirt/QEMU/KVM, nftables, SSH, and optional host-folder exposure.

The 0.6 persistence model separates machine-owned and caller-owned state:

- the **machine store** owns defaults, VM/network definitions, firewall policy,
  access identities, attachment declarations, and credential metadata;
- the **private XDG user profile** owns active-VM selection, SSH identity paths,
  and caller behavior preferences;
- a shared host normally places the machine store at `/var/lib/aivm/machine`;
  an unshared host uses the same machine-store model under the caller's XDG data
  directory;
- released pre-0.6 per-user stores remain readable and migrate only through the
  explicit `aivm config migrate ...` workflow.

Attachments currently use `persistent` by default. `shared-root` remains a
legacy single-export backend, `direct-virtiofs` maps one virtiofs device per
folder, and `git` creates a guest-local repository handoff rather than a live
filesystem share.

Human-facing documentation calls the persisted host-user to guest-account
binding an **access identity**. The implementation intentionally retains names
such as `PrincipalEntry` and `principal_id` for the 0.6 schema.

Do not add detailed module inventories here. The checked architecture files
under `docs/architecture/` validate module classifications and referenced
symbols against the current source tree, which is the mechanism intended to
prevent this overview from becoming stale again.
