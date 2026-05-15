# Refactor before rootless VMs

Written: 2026-05-12 14:31:27 America/New_York
Baseline commit: 525a96e8bafbfa539e3db27ed4c9a128a4665ea6

## Goal

Prepare AIVM for a rootless VM backend by first reducing the sprawl in the
system-libvirt implementation.  The rootless work should not start while VM
creation, disk preparation, cloud-init rendering, domain power control,
connectivity checks, provisioning, and command/log policy are all concentrated
in giant files.

The first refactor pass is intentionally behavior-preserving.  It keeps the
current `qemu:///system`, sudo, `/var/lib/libvirt/aivm`, managed-network, and
attachment semantics intact while moving lifecycle implementation details into
smaller modules.

## Milestone 1: compatibility discipline

Keep the historical `aivm.vm.lifecycle` import path alive while implementation
moves behind it.  `aivm/vm/lifecycle.py` is now a compatibility facade that
re-exports the lifecycle symbols used by callers and tests.  This gives the
codebase a safe migration path: future internal modules can be adjusted without
forcing every external caller to update at once.

The facade should remain until the rest of the package has migrated to focused
imports and the public API boundary is deliberately documented.

## Milestone 2: split lifecycle implementation

The old `aivm/vm/lifecycle.py` mixed nearly every VM runtime concern in one
file.  Its implementation has been split into focused modules:

- `aivm/vm/paths.py`: filesystem path derivation.
- `aivm/vm/host_access.py`: current system-libvirt host access preparation and
  sudo-backed file existence helpers.
- `aivm/vm/images.py`: base image URL validation, cache handling, downloads,
  local image copies, and SHA256 verification.
- `aivm/vm/cloudinit.py`: NoCloud instance metadata, user-data/network-config
  rendering, seed ISO generation, and refresh-on-next-boot handling.
- `aivm/vm/disk.py`: qcow2 disk creation, recreation, and resize logic.
- `aivm/vm/domain.py`: libvirt domain existence, power state, start, shutdown,
  restart, destroy, and status helpers.
- `aivm/vm/connectivity.py`: MAC lookup, DHCP lease/IP cache handling, SSH
  config generation, SSH readiness, and host-key mismatch diagnostics.
- `aivm/vm/guest_tools.py`: guest uv/Rust tool-spec normalization and shell
  script rendering.
- `aivm/vm/provision.py`: post-boot package/tool provisioning orchestration.
- `aivm/vm/create.py`: create-or-start orchestration and create-time error
  classification.

## Current state

This split is mechanical and should not change runtime behavior.  It creates
module boundaries that will make later rootless work easier to localize:

- rootless storage policy will primarily intersect `paths.py`, `host_access.py`,
  `images.py`, `cloudinit.py`, and `disk.py`;
- rootless networking will primarily intersect `connectivity.py` and later a
  runtime/network backend layer;
- rootless libvirt connection handling will primarily intersect `domain.py`,
  `create.py`, and a future command-construction abstraction;
- unsupported/alternative attachment modes can be reasoned about outside the
  lifecycle monolith.


## Follow-up fixes: 2026-05-12 14:51:35 America/New_York

A local full-suite run after applying the milestone 1/2 overlay surfaced two
regressions/edge cases that were fixed before continuing the refactor:

- Dry-run VM update of virtiofsd binary drift no longer tries to inspect or
  install the sudo-owned wrapper.  Dry-run now reports that the wrapper would
  be ensured and returns before sudo-backed filesystem reads.
- The `aivm.vm.lifecycle.detect_host_timezone` compatibility export now
  delegates dynamically to `aivm.vm.cloudinit.detect_host_timezone`, preserving
  the historical monkeypatch-friendly test path while keeping cloud-init as the
  implementation owner.

## Validation notes

Syntax validation was run with:

```bash
python -m py_compile $(find aivm -name '*.py' | sort)
```

The local container did not have the package test dependencies installed
(`scriptconfig` and the configured xdoctest pytest plugin were unavailable), so
the full pytest suite was not executed in this environment.

## Next checkpoint

Before designing rootless VMs, continue with structural cleanup:

1. Split `aivm/cli/vm.py` so the CLI mostly parses arguments and delegates to
   domain operations.
2. Split the command/logging internals or introduce a `commanding/` package to
   avoid the `aivm/commands.py` file/package name conflict.
3. Introduce a small runtime context object that carries the current libvirt URI,
   privilege policy, storage policy, command manager, and dry-run state.
4. Improve command/log rendering once the major boundaries are easier to follow.

## Follow-up correction: virtiofsd inode-file-handles wrappers

A real `aivm vm update` run on the `toothbrush` host showed that the previous
virtiofsd inode-file-handles strategy crossed an unsafe host trust boundary.
The implementation had pointed libvirt at an AIVM-generated host-side wrapper
script under `/var/lib/libvirt/aivm/`.  The host virtiofsd binary did advertise
`--inode-file-handles`, but the generated wrapper still caused libvirt startup
to fail with `virtiofsd died unexpectedly` and a vhost-user handshake error.

A compiled helper was considered and rejected.  Generated host-side executable
wrappers should not be part of normal AIVM operation.  AIVM may generate
guest-side helper scripts, but the host-side libvirt/QEMU execution path should
use known system binaries, admin-owned services, or first-class libvirt XML
features.

The current direction is:

- generated host-side virtiofsd wrappers are disabled in normal update paths;
- old AIVM wrapper paths are treated as legacy drift that should be removed
  from VM XML;
- `virtiofs.inode_file_handles` remains a desired future capability, not
  something forced through generated host executables;
- clean options are first-class libvirt support, admin-owned external
  virtiofsd services, or non-virtiofs fallbacks for pathological FD workloads.

See `dev/design/future/virtiofsd-inode-file-handles.md` for the detailed
strategy and rationale.

## VM CLI split checkpoint


The VM CLI has been split into focused modules while keeping
`aivm.cli.vm` as the compatibility facade and ModalCLI registration point.
See `dev/design/future/cli-refactor.md` for details and the follow-up plan.
