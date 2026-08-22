# Personal machine store

## The problem

0.6 moved desired state out of `~/.config/aivm` into a root-owned,
`libvirt`-group-writable `/var/lib/aivm/machine`. That made trusted-group
membership a prerequisite for using AIVM at all, including for a single user
with nobody to share with. A user upgrading a workstation hit it as:

```
$ aivm config migrate apply --yes
PermissionError: [Errno 13] Permission denied: '/var/lib/aivm/machine'
```

`/var/lib/aivm` already existed as `root:root 0755` -- it is the parent of the
persistent-replay state directory from 0.5.x -- so the store root could not be
created without root, and could not be *used* without membership in `libvirt`.

Membership in `libvirt` is root-equivalent. `shared-machine-architecture.md`
lists removing that root-equivalence as an explicit non-goal, so a user
declining it is making a sound security judgment, not a misconfiguration.

## Why sudo is not the answer

The obvious fix -- escalate for the store the way AIVM escalates for `virsh`,
`mount`, and `nft` -- does not work. One-time provisioning is fine; *operating*
the store through sudo is not:

1. **Locking.** `ExclusiveFileLock` takes `fcntl.flock` on a descriptor held
   open for the life of the scope. A lock acquired by a `sudo` child dies when
   that child exits, so `store.lock`, the per-VM and per-network locks, and
   `migration.lock` cannot be satisfied by shelling out.
2. **Read-back.** The store is `2770` and deliberately not world-readable: VM
   documents can carry guest passwords. A store root written by root for a
   non-member stays unreadable to them, so escalating one write commits every
   later read -- `status`, `list`, `ssh` -- to escalating too.
3. **Atomic replacement.** `save_store_split` writes a temporary file, applies
   modes through file descriptors, and renames. Same delegation problem.

So "works without `aivm host permissions setup`" cannot mean "sudo the shared
store". It has to mean not using the shared store.

## Resolution

`resolve_machine_store_root` picks one of four rows:

| Condition | Root |
| --- | --- |
| `AIVM_MACHINE_STORE_ROOT` set | that path, caller-owned |
| Shared root exists and is usable | `/var/lib/aivm/machine` |
| Shared root exists, caller cannot write it | **refuse** (`MachineStoreAccessError`) |
| No shared root | `~/.local/share/aivm/machine`, caller-owned `0700` |

The third row is the one that matters. Falling back there would hand the caller
a second authority over domains the shared store already claims, which is what
invariant 1 of the shared-machine architecture forbids. Refusing is
recoverable -- join the group -- and forking is not.

A fresh install never writes host-global state unprompted: it goes personal,
and `aivm host permissions setup` remains how a host becomes shared. Setup
therefore targets `DEFAULT_MACHINE_STORE_ROOT` explicitly rather than the
active layout, or it would no-op on exactly the hosts it exists to promote.

## Cost

Small, because `MachineStoreLayout` was already a parameter throughout: of the
21 `machine_store_layout()` call sites, nearly all were the
`layout or machine_store_layout()` idiom. Group- and mode-awareness outside
`machine_store.py` was two modules. `StoreScope.mode` stays `'machine'` -- this
adds no third persistence mode beside the `legacy`/`machine` split that already
exists and is scheduled to die.

What the two layouts *do* cost is the loss of an emergent guarantee, addressed
below.

## Domain ownership

"One managed domain has at most one authoritative record on a host" was
previously emergent: a host held one store, so a domain that appeared in it was
owned by it and everything else was `unmanaged` (a set difference on names).
Two possible layouts removes that.

`aivm/domain_authority.py` records ownership where the contested resource
actually lives -- the domain's libvirt `<metadata>` -- so the invariant is
checked rather than assumed. `_load_context_with_path`, the one place every
post-creation command resolves a VM, refuses a domain another store stamped and
names the owner.

Two properties keep this from being a tax:

- an unstamped domain is accepted, because that is the state of every VM from
  an earlier release and is not evidence of a rival owner;
- a host with only one store root on disk skips the libvirt probe, because a
  store that is not on disk owns nothing. The ordinary single-user host pays
  nothing.

This also gives the pre-existing "unmanaged same-name domain" rule (invariant
10) something to check, and would catch a legacy store and a machine store both
claiming a domain during migration.
