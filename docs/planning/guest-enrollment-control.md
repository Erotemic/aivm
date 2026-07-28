# Guest enrollment control channel

## Status

Implemented for the AIVM 0.6 trusted shared-machine architecture.

This control channel enrolls a later host user into an already managed VM
without copying the creator's private SSH key and without requiring the creator
to run an interactive command in the guest. It is intentionally narrower than
a general remote administration account.

Automatic invocation from `aivm config init` is a separate follow-on stage.
The explicit repair and enrollment command is:

```bash
aivm vm access reconcile --vm <vm-name>
```

## Trust model

The current release targets mutually trusted host users. Enrolled guest users
receive passwordless sudo, so separate guest accounts provide ownership,
attribution, independent homes, and independent SSH identities rather than a
security boundary between users.

The bootstrap channel is not the interactive account and must never be used by
normal SSH, code, attachment, provisioning, or credential commands.

## Machine bootstrap identity

Each newly created machine-store VM receives one stable bootstrap keypair under
the protected machine bootstrap directory:

```text
/var/lib/aivm/bootstrap/<vm-storage-id>/
    id_ed25519
    id_ed25519.pub
    known_hosts
```

The private key is mode `0600`. Normal production use invokes the bootstrap SSH
client through sudo because the key is machine-owned. Test roots selected with
`AIVM_MACHINE_STORE_ROOT` remain unprivileged and isolated.

The keypair is generated before cloud-init is rendered. A partial keypair is an
error; AIVM does not silently replace one half or rotate a machine enrollment
identity.

## Guest bootstrap account

Cloud-init creates the system account `aivm-bootstrap` and installs the public
key with an `authorized_keys` forced command. The entry disables:

- agent forwarding;
- port forwarding;
- X11 forwarding;
- PTY allocation;
- user rc processing.

The only permitted command is:

```text
/usr/bin/sudo -n /usr/local/sbin/aivm-guestctl --forced
```

A matching sudoers rule permits only that exact helper invocation. Supplying a
remote shell command does not broaden the capability because OpenSSH replaces
it with the forced command.

## Enrollment request

The host sends one JSON object on standard input. It contains:

- guest username;
- requested UID and GID;
- the caller's personal SSH public key;
- whether trusted-user sudo should be installed;
- optional common development groups such as `docker`.

`aivm-guestctl` is installed as a standalone, stdlib-only Python executable so
it does not depend on the AIVM package or a guest virtual environment.

The helper validates the request, then idempotently creates or repairs:

1. the requested primary group;
2. the guest user with the requested UID/GID and home;
3. the user's `authorized_keys` entry;
4. the trusted-user sudoers fragment;
5. membership in common groups that already exist in the guest.

It rejects malformed keys, invalid POSIX usernames, and UID/GID collisions with
other accounts. Reconciliation adds the requested key without deleting other
explicitly authorized keys.

## Principal state transitions

The machine store is authoritative for enrollment state:

```text
missing/error -> pending -> active
                    |          ^
                    +----------+
```

Before contacting the guest, AIVM writes a `pending` principal. A bootstrap
transport failure leaves it `pending` when the VM is unreachable and records
`error` for a helper or request failure. After the helper succeeds, AIVM opens
a fresh SSH connection using the user's personal private key. Only successful
personal-key verification changes the principal to `active`.

A disabled principal is not automatically re-enabled by reconciliation.

## User and operator commands

```bash
# Show the complete principal inventory for one managed VM
aivm vm access list --vm <vm-name>

# Create, retry, or repair the current host user's guest account
aivm vm access reconcile --vm <vm-name>

# Preview the derived host/guest identity without changing state
aivm vm access reconcile --vm <vm-name> --dry-run
```

The current user's private and public SSH paths come only from that user's
profile. The machine bootstrap private key never enters the profile.

## Compatibility boundary

VMs created through the machine-store path after this stage contain the guest
helper and bootstrap account. Existing VMs do not. Their bootstrap installation
belongs to the explicit existing-installation migration stage; reconciliation
fails with an actionable diagnostic instead of attempting an unsafe implicit
repair.

## Next stage

`aivm config init` will detect an exact hostname-derived managed machine,
initialize the caller's profile and personal key, invoke this reconciliation
path, and select the VM without modifying machine hardware or network state.
