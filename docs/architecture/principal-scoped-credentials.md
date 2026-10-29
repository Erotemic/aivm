# Principal-scoped repository credentials

## Purpose

A shared VM does not imply one shared guest home, one shared host key directory,
or one shared provider login. Repository credentials are therefore owned by a
persisted VM principal. The machine store contains the non-secret desired-state
record; the owning host profile and application-data tree retain all private
material and authentication context.

## Persistence contract

Fresh machine stores use schema version 11. Each credential record contains:

```toml
[[vms.credentials]]
id = "git-..."
principal_id = "principal-..."
kind = "github-deploy-key"
provider_host = "github.com"
owner = "Kitware"
repository = "kwimage"
access = "read"
provider_key_id = "12345"
provider_key_title = "aivm:..."
key_fingerprint = "SHA256:..."
state = "active"
```

The stable ID hashes VM name, principal ID, and canonical repository. Alice and
Bob may consequently hold independent records for the same VM/repository pair.
Machine-store writes reject a missing principal, a principal from another VM,
or a dangling principal reference.

Legacy stores retain their released VM/repository-only ID and an empty
`principal_id`. They are assigned to the creator only by the explicit migration
stage; ordinary loading does not guess ownership.

## Secret boundary

The machine record may contain provider object IDs, titles, fingerprints,
access, and lifecycle state. It never contains:

- the deploy-key private half;
- a GitHub or GitLab token;
- a user's provider CLI login;
- a user profile's application-data path.

Host keypairs remain beneath the owning user's application-data directory.
Provider calls execute with that user's environment. Guest installation uses
the selected principal's guest account and regenerates SSH/Git routing from
only that principal's usable records.

A trusted administrator may inspect global metadata, but administration is not
secret delegation. AIVM does not provide an override that lets Alice revoke,
abandon, repair, or inspect Bob's credential using Alice's host key or provider
session.

## Command behavior

Ordinary commands are principal-scoped:

```bash
aivm vm creds add Kitware/kwimage
aivm vm creds list
aivm vm creds status Kitware/kwimage
aivm vm creds revoke Kitware/kwimage
aivm vm creds abandon Kitware/kwimage --provider_unverified
```

Machine-wide metadata is explicit:

```bash
aivm vm creds list --all_principals
aivm vm creds status <credential-id> --all_principals
```

A foreign status record reports only persisted metadata. It does not probe the
owner's host key, provider API, or guest home. Repository selectors in the
global view fail when more than one principal matches; use the exact credential
ID.

## Principal lifecycle

Disabling a principal leaves credential records intact. This preserves the
provider key ID and fingerprint required for a later owner-driven revocation.
Removing a principal while credential records still reference it is rejected.
The safe sequence is:

1. run revoke as the owning host user, or explicitly abandon with the existing
   provider-unverified warning;
2. verify no credential records remain for the principal;
3. disable or remove the principal according to the access lifecycle.

This is fail-closed: losing guest access does not imply the provider deploy key
has disappeared.

## Concurrency and global operations

Credential writes use the selected machine-store filesystem policy and the
existing store transaction/locking machinery. VM deletion remains a global
operation and checks every principal's live credentials, because deleting the
machine while any deploy key remains registered would orphan provider access.

## Deferred migration

The next stage migrates released per-user stores. It must copy fingerprints,
provider-management state, provider object IDs, and key material without
regenerating deploy keys or assigning a record to the wrong principal. This
stage deliberately defines the destination model but does not perform that
migration.
