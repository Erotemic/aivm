# `config init` create-or-join contract

AIVM 0.6 uses the hostname-qualified default VM name as the discovery key for
both the first host user and later host users. The same command therefore has
two safe meanings:

- initialize creator defaults when no managed machine exists; or
- initialize the caller's private profile and enroll that caller when the exact
  managed machine already exists.

The command never adopts an unmanaged libvirt domain implicitly.

## Decision table

For the canonical name returned by `aivm.config.default_vm_name()`:

| Machine-store record | Libvirt domain | Result |
| --- | --- | --- |
| absent | absent | detect and review creator defaults |
| present | any state | join the managed machine |
| absent | present | stop and require explicit discovery/import |

An exact machine-store record is authoritative even when the domain is stopped
or temporarily unreachable. In that case enrollment can be persisted as
`pending` and retried later.

`--yes` and `--defaults` may accept an exact managed-machine join without an
interactive prompt. They never permit silent import of an unmanaged domain.
`--force` applies only to creator defaults; during a join it cannot rewrite VM,
network, image, firewall, provisioning, tool, virtiofs, or attachment state.

## Join sequence

A managed-machine join performs these steps:

1. Load the global machine record before detecting any machine defaults.
2. Load the caller's private profile.
3. Select an existing principal for the current host login, or derive a guest
   username such as `edward-wang-agent`.
4. Detect or create the caller's personal AIVM SSH identity.
5. Persist only profile-owned fields: SSH paths, local state path, behavior,
   and the prospective guest username.
6. Reuse an already-active principal when its recorded public key still
   matches the profile.
7. Otherwise invoke the restricted bootstrap enrollment channel.
8. Set `active_vm` only after the principal is active or enrollment is
   explicitly recorded as pending.

A personal-key verification failure leaves the principal in `error`, does not
select the machine in the profile, and does not print a successful join.

## Idempotence and recovery

Repeated `aivm config init` calls by an active principal do not add duplicate
principal records or contact the bootstrap account again. A pending principal
can be retried with:

```bash
aivm vm access reconcile --vm <vm-name>
```

The join path may change the caller's private profile and the caller's principal
record. It does not regenerate machine defaults or rewrite the VM definition.

## Compatibility boundary

Existing released per-user stores retain their previous `config init` behavior.
The create-or-join decision applies only to the shared machine-store scope.
Custom or unmanaged domains remain explicit `aivm config discover` work; the
hostname convention is the automatic onboarding key, not an ownership claim.
