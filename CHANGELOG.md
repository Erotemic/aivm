# Changelog
We [keep a changelog](https://keepachangelog.com/en/1.0.0/).
We aim to adhere to [semantic versioning](https://semver.org/spec/v2.0.0.html).

## Version 0.6.0 - Unreleased

### Added
* Added principal-scoped machine-store repository credentials. Credential
  records now carry `principal_id`, stable IDs include the principal scope,
  and machine writes reject unattributed or dangling owners. Ordinary
  add/list/status/revoke/abandon operations select only the current principal;
  `--all_principals` exposes non-secret machine-wide metadata without probing
  another user's host key, provider login, or guest home. Guest reconciliation
  regenerates Git/SSH routing from only the selected principal's credentials,
  while disabled principals retain provider IDs and fingerprints needed for
  later revocation. Legacy stores retain their released unattributed IDs until
  explicit migration.
* Added principal-owned machine-wide attachments. New machine-store records
  carry `owner_principal_id`; path resolution and session restoration default
  to the current principal, while list/status expose the complete inventory.
  Updates and detaches cannot select another principal's record without an
  explicit `--admin_override`. Persistent replay manifests now live in per-VM
  machine state, contain every owner's declarations exactly once, and are
  generated under the global store/VM lock. Legacy stores retain their
  released unattributed and XDG replay behavior until migration.
* `aivm config init` now creates or joins naturally in shared-machine mode. It
  uses the hostname-qualified VM name as the onboarding key, initializes
  creator defaults only when no managed machine exists, and enrolls a later
  host user through the restricted bootstrap channel when an exact managed
  record exists. Active joins are idempotent, stopped VMs retain a recoverable
  pending principal, failed personal-key verification is not reported as
  success, and unmanaged same-name libvirt domains are never adopted silently.
* Added the restricted shared-machine enrollment channel. New machine-store
  VMs receive a machine-owned bootstrap SSH key and a forced, non-interactive
  `aivm-guestctl` account that can only create or repair one guest principal
  from a validated JSON request. `aivm vm access reconcile` persists pending
  and error states, verifies the caller's personal SSH key before activation,
  and `aivm vm access list` shows the machine-wide principal inventory.
* Added ``aivm vm creds`` for VM-scoped repository credentials. The initial
  backend creates one GitHub deploy key per VM/repository pair, keeps a
  protected host copy, installs the private key in the guest, and supports
  ``add``, ``list``, ``status``, and provider-first ``revoke`` workflows.
  Revocation now identifies provider keys by the recorded key id and
  cryptographic fingerprint, malformed credential records fail closed, and
  guest Git authentication is configured for non-interactive first use.
  Persisted credential ids are recomputed from their VM/repository scope before
  any host or guest path is used, configuration fields reject control-character
  injection, status reports malformed host keys without crashing, and explicit
  transport URLs with unsupported ports or a missing ``.git`` suffix are
  rejected rather than silently misconfigured.
  Explicit repository URLs are now limited to canonical HTTPS or ``git``-user
  SSH forms, and guest verification proves that Git rewrote the selected URL
  through the credential-specific SSH alias before contacting the repository.
  Host status validates the private/public keypair, ownership, file type, and
  permissions rather than trusting only the public half. Added an explicit
  provider-unverified ``creds abandon`` recovery path with audit tombstones,
  and VM deletion now aborts instead of forgetting credentials when private-key
  cleanup fails.
* Added ``aivm vm creds setup`` and ``setup --check`` to install missing
  GitHub CLI/OpenSSH prerequisites, authenticate ``gh`` without uploading a
  user SSH key, and optionally verify deploy-key administration for a
  repository. Installs use the host's package backend (apt, dnf5, dnf,
  zypper, pacman, or apk), selected in the new `credentials/gh_install.py`.
* The GitHub CLI is now version-checked. `gh repo deploy-key` requires gh
  2.5.0, and distributions ship much older builds (Ubuntu 22.04 packages
  2.4.0), so `creds setup` reports the installed version, refuses a host whose
  gh cannot manage deploy keys, and installs or replaces gh from GitHub's own
  repository per the official instructions. `--skip-ssh-key` is passed only to
  gh 2.48.0+, which is where that flag was added; older builds get a warning
  instead of a failed login.
* Added GitLab project deploy keys as a second repository-credential provider.
  GitLab.com is inferred from canonical repository URLs, self-managed GitLab
  can be selected with ``--provider gitlab``, nested group namespaces are
  preserved, and direct v4 REST calls manage read-only or read-write deploy
  keys using a host-only ``GITLAB_TOKEN``. The guest still receives only its
  repository-scoped SSH private key; ``glab`` is not required.

* Provider publication is now best effort for both GitHub and GitLab. Missing
  clients, logins, or tokens; insufficient repository permission;
  organization approval requirements; provider refusals; and uncertain
  transport outcomes no longer block ``creds add``. AIVM keeps the generated
  keypair, installs the private half in the VM, records the credential as
  provider-unmanaged, and prints the public half for an administrator to add.
  Local key-generation, ownership, and guest-installation failures remain
  errors.
* A 404 from the deploy-key endpoints is disambiguated instead of surfacing
  raw. GitHub answers 404 rather than 403 on private repositories so a
  response cannot confirm what exists, which makes the status ambiguous
  between "not an admin" and "no such repository". AIVM now probes whether the
  repository is visible to the signed-in account and reports whichever it is:
  the admin-assisted path for a permission failure, or a message naming the
  repository, account, and SAML authorization to check.
* Provider administration failures become a handoff rather than a failure. Deploy-key endpoints need admin
  permission on the repository, which write access does not confer, so AIVM
  generates the keypair, installs the private half in the VM, configures Git,
  and prints the public half for an administrator to add. Nothing else needs
  to run: access begins working as soon as GitHub accepts the key. The denial
  is recognized whether it lands on creating a deploy key or on reading the
  repository's existing ones. Such credentials record
  `provider_managed = false`, are shown as `unregistered` by `creds list`,
  reprint the key to send from `creds status`, and refuse `creds revoke` --
  AIVM never registered the key and will not claim a deletion it cannot
  perform. Installing an unregistered key is safe and deliberate: it
  authenticates against nothing until the provider holds its public half. See
  the policy note in `aivm/credentials/__init__.py`.

### Changed
* Added the inactive machine-store filesystem foundation for the shared-host
  architecture. AIVM now has an injectable `/var/lib/aivm` layout, explicit
  `root:aivm`-style directory and file modes, metadata-preserving atomic
  replacement, group-readable split-transaction recovery, a centralized store
  lock, deterministic network/VM lock ordering, and a lock-spanning
  `update_store` mutation primitive. Unit tests exercise real process-level
  contention and interrupted recovery without changing the default per-user
  persistence path.
* Completed the stage 0/1 prerequisites for the shared-machine migration.
  Tests now isolate all implicit HOME/XDG paths, provide Alice/Bob fixtures and
  frozen released-store migration documents, and exercise a captured
  two-principal session path from store loading through attachment resolution.
  The service layer now exposes canonical `ResolvedVMContext` loaders and
  `PreparedSession` retains that selected context through SSH and VS Code
  entry points instead of reconstructing caller identity later.
* Removed the runtime `ubelt` dependency. AIVM now owns the small XDG path
  resolver it needs and calls Pygments directly when optional terminal syntax
  highlighting is available. The replacement modules record the historical
  ubelt symbols they replace and explicitly note that their implementations
  are new rather than copied source.
* Began the shared-machine architecture refactor by introducing explicit
  runtime scopes for machine state, VM principals, and per-user access
  profiles. The existing on-disk schema remains compatible, but post-creation
  guest operations now resolve a `ResolvedVMContext` instead of treating
  `vm.user` and SSH identity paths as intrinsic VM properties. SSH, guest
  provisioning, status probes, credentials, attachment reconciliation,
  persistent replay transport, shared-root operations, cache maintenance, and
  fdguard management all pass through this boundary. Config editing,
  detection, and cloud-init intentionally remain on the legacy schema until
  the machine-global store and principal enrollment work lands.
* A command that changes state now requires confirmation because it is a
  write, not because it needs sudo or happens to be a `virsh` command. The
  previous rule guarded `virsh undefine --remove-all-storage` only by the
  coincidence that it shares a binary with `setvcpus`, while an unprivileged
  command doing the same damage by another route was never guarded, and
  `role='modify'` gated nothing anywhere. `CommandSpec` gains an `ownership`
  field defaulting to `user`; `ownership='tool'` is a per-call-site exemption
  for aivm's own regenerable bookkeeping, so forgetting to mark a bookkeeping
  write costs a prompt rather than costing the user their consent. 53 call
  sites were classified against `docs/planning/command-approval-audit.md`.
* An unknown VM or network name now suggests the likely intended name and
  lists what the store actually defines, instead of only reporting the miss.
  `aivm config edit aivm-2404` on a host whose store has no such VM said only
  `VM not found in config: aivm-2404`, which cannot distinguish a typo from a
  VM that lives on a different machine. Suggestions use containment before
  edit distance, so a name that is a prefix of a longer one is caught while a
  uniformly-named store does not manufacture a confident wrong guess. The
  lookups are centralized in `require_vm` / `require_network`, so all seven
  raise sites report identically.
* Command previews no longer guess which arguments to hide. A call site that
  passes a large payload marks it `Elided(value, label)` and the log prints
  that label; everything else prints verbatim, so the line stays the command
  the user could have typed. The previous rules inferred from an argument's
  shape and position -- `bash -c` tails became `<shell script omitted>`, ssh
  tails `<remote command omitted>` -- which stated as fact something the
  renderer could not know, and silently truncated any other long argument at
  57 characters. An unmarked argument past `PREVIEW_ARG_MAX_LEN` now says only
  that it is too long and asks to be marked, naming the work rather than
  hiding it. Marked so far: the fdguard guest scripts, the shared-root bind
  repair script, the libvirt group adoption program, and cloud-init user-data.
* `RUN:` lines render through the same preview, with the literal command kept
  at `DEBUG` in the same run. `aivm vm update` previously emitted several
  kilobytes of base64 on one line when installing the virtiofs fd guard.
  Anything left out of a line is now announced beneath it rather than only
  marked inline, at `WARNING` when the payload is unmarked, since a quietly
  shortened command is indistinguishable from a faithful one.
* Command log visibility now announces every command that changed state or
  actually escalated, and holds only unprivileged reads for `--verbose 2`.
  Previously a state-changing command was visible only when it happened to
  pass `check=True`, while seven read-only libvirt probes were hidden purely
  because they needed no sudo -- including the `virsh dominfo` that reports
  what a VM actually has. Escalation is always called out even for a read,
  because merely invoking `sudo` on the command line has the potential to
  perform an unbounded privileged operation whatever the program is; see the
  policy note in `CLAUDE.md` and :doc:`privilege-modes`. Quiet is declared
  rather than inferred: a command is demoted only where a call site says
  `role='read'` or runs inside a read intent *and* no `sudo` prefix was
  applied, and an unclassified command defaults to `modify` and stays loud.
* `aivm vm update` groups its planning probes under one read intent. The
  `dominfo`, `domstate`, `dumpxml`, `domblkinfo`, and `qemu-img` probes were
  ungrouped, so each was classified as a state change and prompted separately
  under a header that called a read-only probe a hypervisor mutation.

### Fixed
* Reading a failed command handle no longer executes an unrelated queued
  command. A raise skipped the bookkeeping that resolves the handle, so it
  stayed pending; asking for its result again flushed the queue and ran
  whatever was waiting there -- including state-changing commands -- before
  dying on an assertion that discarded the original failure. Handles now own
  a terminal outcome (`succeeded` / `failed` / `not-executed`) and answer from
  it: a success replays, a failure re-raises the original exception, and a
  command abandoned with its plan raises `CommandNotExecutedError`. Reading a
  resolved handle executes nothing, and `flush_through` refuses to substitute
  some other pending command for the one it was asked about.
* An explicit approval refusal is no longer swallowed as provider bureaucracy.
  Declining "publish this deploy key" raised a bare `AIVMError`, which the
  credential flow's `attempt(catch=AIVMError)` treated as the provider being
  uncooperative -- so saying no still generated the keypair, installed the
  private half in the VM, and printed a handoff telling the user to give the
  public half to an administrator. Refusals now raise typed
  `CommandControlError` subclasses (`UserDeclinedError`,
  `ApprovalUnavailableError`, `CommandNotExecutedError`, and `SudoRequiredError`),
  which `attempt()` re-raises whatever `catch` says, and which broad handlers
  around command-manager calls re-raise explicitly. Provider bureaucracy still
  produces the handoff; a non-interactive run with no `--yes` now stops rather
  than inferring approval from silence.
* A run that could not reach the provider no longer erases the evidence needed
  to revoke a live deploy key. Re-running `creds add` after a token expired
  cleared `provider_key_id` and set `provider_managed = false`, after which
  `creds revoke` permanently refused to delete a key that still existed. A
  recorded key id now survives transient authentication, permission, policy,
  or transport failures; only a verified deletion clears it.
* Self-managed GitLab hosts are recognized without `--provider`. A host named
  `gitlab.<domain>` was resolved to GitHub, which stored a
  `github-deploy-key` for a GitLab project, gated it on `gh`, and named the
  wrong forge in the administrator handoff. The provider decides which API is
  called and is recorded permanently in the credential's `kind`, so guessing
  it is not cosmetic. `--provider` still overrides the inference.
* A nested namespace is rejected on `github.com` rather than silently
  reinterpreted. GitHub has no subgroups, so `github.com/a/b/c` parsed as
  owner `a/b` and recorded a credential naming a repository that cannot exist.
* The GitLab API token is no longer sent over an unencrypted transport. It
  rides in a `PRIVATE-TOKEN` request header on every call, and an explicit
  `GITLAB_API_URL` could downgrade the endpoint to plaintext HTTP. Non-loopback
  endpoints must now be `https`.
* A GitLab token is only valid on the server that issued it, so a host-scoped
  `GITLAB_TOKEN_<HOST>` now takes precedence over the generic `GITLAB_TOKEN`.
  Without one, naming a host was enough to send it a token minted elsewhere.
  The generic variable still serves any host with no scoped token, and setup
  names whichever variables actually apply to the host being checked.
* `ProviderRejectedError` and `ProviderPermissionError` moved to
  `credentials/errors.py`. The GitLab dispatcher had defined a second class of
  the same name, so `except ProviderRejectedError` caught different things
  depending on which module the caller imported.
* A command that raised was never removed from its queue, so the next flush --
  triggered by an unrelated later command -- re-ran it and re-raised its
  failure there. Any caller that caught a `CommandError` was exposed; it
  surfaced as `aivm vm creds add` dying inside an SSH probe that reported a
  `gh` error it never issued. Both queues now mark a command attempted before
  executing it.

### Added
* `CommandManager.attempt(...)` for steps whose failure is an expected
  outcome. The block reports its result on an `Attempt` (`.failed`,
  `.reason`) instead of raising, so callers declare that a step may fail
  rather than wrapping manager calls in `try`/`except`, and the log says a
  failure was handled instead of showing what looks like a fatal error.

### Changed
* `aivm vm creds add` no longer requires the GitHub CLI. Registering a deploy
  key is automation, not a prerequisite: only `ssh` and `ssh-keygen` are
  required, and a missing, outdated, or signed-out `gh` routes into the same
  handoff used when the provider refuses.
* The credential feature no longer sits on the shared CLI option path.
  `cli._common` has no credential imports; it publishes which config store is
  active and `credentials.policy` resolves its own setting from it. VM
  lifecycle code reaches the feature only through `credentials.guards`. The
  audit boundary is documented in `aivm/credentials/__init__.py` and enforced
  by `tests/test_credentials_boundary.py`.
* `aivm vm creds add` now takes `--access read|write` (default `read`) instead
  of the `--write` flag, matching the `--access` option already used by
  `vm attach` and `vm code` and the `read`/`write` values already reported by
  `creds list` and `creds status`. `ro` and `rw` are accepted as aliases.
  `--write` is gone rather than deprecated because it was never released.
* Credential storage directory mode concerns now follow
  ``behavior.credential_directory_permission_policy``: ``warn`` by default,
  ``error`` for strict enforcement, or ``ignore``. The policy covers the AIVM
  application-data root, VM data directory, credential parent, and credential
  leaf directory. Ownership, symlink, file-type, and key-file permission
  checks remain strict failures in every policy mode.


## Version 0.5.0 - Released 2026-07-18

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
* Privilege-aware operation. A new `behavior.privilege_mode` config knob
  controls when aivm invokes sudo: `as-needed` or `always`, defaulting to
  `as-needed`. The default probes what already works without sudo (libvirt
  group membership for `qemu:///system`, user-writable image trees) and
  escalates only where required; `always` escalates every privileged-capable
  operation. Unknown values, including the experimental `never` value, are
  rejected rather than silently changing the privilege policy. A global
  no-sudo guarantee is not advertised because managed nftables and new host
  bind mounts still require root on the supported runtime.

  Enforcement keys on the command actually being run, never on the feature
  requesting it: a `persistent` attachment needs `mount --bind` only when
  the bind is missing, so reconciling an established attachment issues no
  privileged command and is refused in no mode. Likewise the sudo decision
  for each command is made against the specific path it touches, so on a
  user-owned `paths.base_dir` the bind-mount export directories are created,
  inspected, and removed without privileges; establishing a shared-root
  attachment drops from four privileged commands to one (`mount --bind`).

  State-changing hypervisor commands (`virsh`/`virt-install` with
  role=modify) keep their interactive approval prompt even when they run
  without sudo, so libvirt-group access does not silently drop the
  confirmation contract for destructive operations.
* `aivm host permissions check` reports host permission readiness (libvirt group, live
  libvirt access without sudo, user-writable VM storage, libvirt-qemu
  traversal ACLs, firewall compatibility) and `aivm host permissions setup`
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
