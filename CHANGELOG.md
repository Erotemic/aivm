# Changelog
We [keep a changelog](https://keepachangelog.com/en/1.0.0/).
We aim to adhere to [semantic versioning](https://semver.org/spec/v2.0.0.html).

## Version 0.5.0 - Unreleased

### Added
* Guest-side virtiofs fd guard (`aivm vm fdguard`, on by default via the new
  `virtiofs.fd_guard`, `virtiofs.fd_guard_threshold`, and
  `virtiofs.fd_guard_interval_sec` config knobs). Root cause work on the
  long-lived virtiofs EMFILE failure identified that (a) host `virtiofsd`
  holds one `O_PATH` fd per guest-cached inode and only releases it on guest
  inode eviction, and (b) the guest's stock nightly `plocate` updatedb sweep
  walked every attached inode because Ubuntu's default `PRUNEFS` lacks
  `virtiofs`, deterministically saturating the ~1M host fd ceiling. The guard
  is a guest systemd timer that idempotently prunes virtiofs from
  `/etc/updatedb.conf` and flushes guest dentry/inode caches when the
  `fuse_inode` slab count crosses a watermark (default 500k), releasing the
  host-side descriptors before EMFILE. New VMs install it via cloud-init;
  `aivm vm fdguard --action install` retrofits existing VMs and replaces
  host-side periodic `aivm vm flush_caches` jobs. See
  `docs/source/virtiofs.rst`.
* `aivm vm update` now reconciles the virtiofs fd guard against config like
  any other drift: while the VM is running and reachable it probes the guest
  (install state, timer enablement, sha256 of each managed guard file),
  plans an install/refresh when `virtiofs.fd_guard = true` and the guest is
  missing/stale (e.g. threshold changed or aivm's embedded guard script was
  updated), and plans an uninstall when the knob is disabled. Probe failures
  (VM down, SSH unreachable) become diagnostics notes rather than errors, and
  guard reconciliation never requires a restart.
* Sudoless operation. A new `behavior.privilege_mode` config knob controls
  when aivm invokes sudo: `never` | `as-needed` | `always`, default
  `as-needed`. `as-needed` probes what already works without sudo (libvirt
  group membership for `qemu:///system`, user-writable image trees) and
  escalates only where required; `always` escalates every
  privileged-capable operation; `never` is a hard guarantee enforced inside
  `CommandManager`, where operations with no unprivileged implementation
  (nftables firewall, `apt-get`, establishing a *new* host bind mount) fail
  with actionable guidance. An unrecognized value is an error rather than a
  silent fallback to the permissive mode. A per-invocation `--never_sudo`
  flag forces `never`.

  Enforcement keys on the command actually being run, never on the feature
  requesting it: a `persistent` attachment needs `mount --bind` only when
  the bind is missing, so reconciling an established attachment issues no
  privileged command and is refused in no mode. State-changing hypervisor
  commands (`virsh`/`virt-install` with role=modify) keep their interactive
  approval prompt even when they run without sudo, so libvirt-group access
  does not silently drop the confirmation contract for destructive
  operations.
* `aivm host sudoless check` reports sudoless readiness (libvirt group, live
  unprivileged libvirt access, user-writable VM storage, libvirt-qemu
  traversal ACLs, firewall compatibility) and `aivm host sudoless setup`
  establishes the host-side prerequisites, using sudo at most once (libvirt
  group membership). Setup changes no configuration: establishing a
  capability and choosing a policy are separate acts, so `privilege_mode`
  and `firewall.enabled` remain the operator's to set. `--persist` opts in
  to writing the single value the host work depends on,
  `defaults.paths.base_dir`.

### Changed
* Attaching directories now has mirrors that resolve to exact path matches on the guest and paths relative to root.
* Added a `persistent` attachment mode that uses its own `persistent-root` virtiofs export, persists desired guest-visible bind mounts as declarations, and replays them from a guest systemd helper instead of reconstructing every attachment on each `aivm code .` / `aivm ssh .` run. New folder attachments now default to this mode when `--mode` is omitted.
* Refreshed README and Sphinx docs to describe the current attachment-first workflow, known long-lived virtiofs file-descriptor growth, and related alternatives (`matchlock`, `jai`).
* Ported command-line configuration declarations to `kwconf` and annotated CLI schema fields so parsing/documentation can use bool/int/list types and closed-value hints.
* New implicit VM names are host-qualified by default (for example `aivm-2404-workstation`) and that same canonical name is used for the VM, guest hostname, and generated SSH alias. Existing explicit config values are not migrated.

### Removed
* Removed the flaky settings-sync feature for now: `aivm vm sync_settings`, `aivm code --sync_settings`, `--sync_paths`, and the `[sync]` config section are no longer supported.

### Fixed
* `aivm vm flush_caches` now quotes the guest script into a single remote
  `sh -c` argument. Previously the remote login shell executed each line
  independently, so `set -eu` never applied and a failed drop_caches write
  (e.g. missing guest passwordless sudo) still exited 0 and was reported as
  success.
* Attaching directories now uses consistent guest locations between different attach modes 
* Read-only access is now documented and wired through the new persistent attachment replay path.
* Tightened local annotations in firewall, VM update rendering, and persistent attachment transport helpers so the package is clean for the reported mypy diagnostics.
* Tightened dynamic test helper annotations so `ty check tests` can type-check replay namespaces, fake subprocess hooks, and legacy boolean tool-spec cases.


## [Version 0.4.0] - Released 2026-03-27

### Added
- New `CommandManager` module (`aivm/commands.py`) centralizing all subprocess execution with intent-based approval workflows, command plans, and role annotations (read vs modify).
- VM configuration drift detection (`aivm/vm/drift.py`) with `DriftReport` and `DriftItem` dataclasses covering hardware (CPU/RAM) and share-mapping mismatches.
- Status command now reports whether the current working directory is shared with a VM and flags any detected VM configuration drift.
- Formal attachment model with `AttachmentMode` (shared, shared-root, git), `AttachmentAccess` (rw, ro), and `ResolvedAttachment` dataclasses in `aivm/vm/share.py`.
- Read-only share access mode for folder attachments.
- Directory share status display in `aivm status` output.
- Grouped command approval: related commands are batched into plans with unified previews before execution.
- SSH bootstrap prompting improvements.

### Changed
- All subprocess calls across lifecycle, firewall, host, and network modules now route through `CommandManager` instead of the previous ad-hoc `run_cmd` utility.
- Operations declare explicit intent contexts describing *why* they are happening, improving logs and approval prompts.
- Status and drift probes return tri-state outcomes (True/False/None) to gracefully handle permission or query errors.
- Firewall and network setup operations now show clear intent in command previews.
- Better error classification for apt lock conflicts, missing UEFI firmware, and memory allocation failures.
- Python target version updated from 3.8 to 3.11 in ruff configuration.
- Added mypy configuration section in `pyproject.toml`.
- Bumped project version metadata to `0.4.0`.

### Removed
- Removed legacy `run_cmd`, `CmdResult`, and sudo intent arming from `aivm/util.py`; all command execution now lives in `CommandManager`.

### Fixed
- Fixed mounting issues and improved virtiofs tag alignment across lifecycle operations.
- Fixed auto-approval logic for read-only sudo commands.
- Various type annotation improvements and test fixes.

## [Version 0.3.0] - Released 2026-03-27

### Added
- Added a Git-backed attachment mode that keeps a guest-local repo instead of creating a writable virtiofs share.
- Host repos can now register a Git remote that targets the guest working repo over the managed VM SSH alias.

### Changed
- Folder-oriented `attach` / `code` / `ssh` flows now persist and honor per-attachment mode (`shared` or `git`).
- Bumped project version metadata to `0.3.0`.

### Notes
- Git-backed attachments currently seed committed repository state only; uncommitted host worktree changes are not copied into the guest clone.
- Git-backed attachments currently sync committed branch state; uncommitted host worktree changes are not pushed into the guest repo.

## [Version 0.2.0] - Released 2026-03-27

### Added
- New CLI package and commands: `aivm.cli` with subcommands for `config`, `firewall`, `help`, `host`, `main`, `net`, and `vm`.
- New runtime and state modules: `aivm/runtime.py`, `aivm/status.py`, `aivm/results.py`, and `aivm/store.py`.
- New `aivm/errors.py` and `aivm/resource_checks.py` helpers.
- New `aivm/vm` package with `lifecycle`, `share` and `sync` modules.
- Added many tests covering CLI, config, detect, firewall, host, net, resource checks, status/runtime, store, util and VM helpers.
- Added `AGENTS.md` developer guidance and several developer journal entries.

### Changed
- Major refactor of CLI into a package; removed single-file `aivm/cli.py` in favor of modular commands.
- Refactored submodules and internal structure to improve testability and separation of concerns.
- Consolidated configuration: moved from per-VM config files to a single user-level configuration (reducing per-VM files written under `configs`).
- Improved global configuration handling and color/logging configuration (`loguru` defaults and color config).
- Documentation updates: updated `README.rst` and docs configuration.
- Bumped project version and updated `pyproject.toml` for the 0.2.0 release candidate.

### Fixed
- Fixes to VM creation/management flows and related tests.
- SSH permission and prompt fixes.
- Fixed issues with outdated MAC address handling.
- Various test and lint fixes (formatting, import fixes) to stabilize the test suite.

### Removed
- Removed legacy `aivm/registry.py` and the old `aivm/vm.py` single-file VM implementation.
- Removed `README.md` in favor of the reworked `README.rst`.

### Notes
- Added ability to open firewall ports via CLI.
- UX and provisioning improvements (avoid sudo where possible, better prompts).


## [Version 0.1.0] - 2026-02-25

### Added
- Project scaffold and initial CLI: single-file `aivm/cli.py` providing basic VM lifecycle and host utilities.
- Core modules included: `aivm/config.py`, `aivm/detect.py`, `aivm/firewall.py`, `aivm/host.py`, `aivm/net.py`, `aivm/vm.py`, `aivm/util.py`, and `aivm/registry.py`.
- Packaging and docs: `pyproject.toml`, `requirements.txt`, `README.md` and `README.rst`.
- Initial tests and CI helpers: minimal tests (dry-run/import) under `tests/` and basic CI/workflow files.
- Minimal, experimental release focused on local libvirt/KVM Ubuntu 24.04 VM management; intended as a starting scaffold for subsequent refactors.
