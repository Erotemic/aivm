# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Venv
- use: /home/agent/.local/uv/envs/uvpy3.13.2/bin/python

### Setup and Installation
- Install package: `uv pip install .`

### Testing and Quality
- Run all tests: `python run_tests.py`
- Run linter: `./run_linter.sh`
- Run type checks: `./run_type_checks.sh`
- Run doctests: `./run_doctests.sh`
- Build docs: `./run_docs.sh` (warnings are errors; catches dangling `:doc:`/toctree targets)
- Run E2E tests: `./run_e2e_tests.sh` (Note: requires `AIVM_E2E=1` or `AIVM_E2E_BOOTSTRAP=1` and a host with libvirt/KVM and sudo privileges)

### Test conventions

Tests live flat in `tests/`, one module per source module (`test_vm_domain.py`
covers `aivm/vm/domain.py`). E2E tests live in `tests/e2e/`, carry
`pytestmark = pytest.mark.e2e`, and are deselected by `-m 'not e2e'` in
`run_tests.py` and CI -- never gate them by putting `-m` in `addopts`, which
would also deselect them when the e2e runner names them by path.

`tests/helpers.py` is the suite's shared vocabulary. Reach for it before
writing a fake:

- `command_recorder(monkeypatch, routes)` fakes `subprocess.run`, records what
  ran, and normalizes away the `sudo -n` / `virsh -c qemu:///system` prefixes.
  Assert on `rec.normalized`. It is **strict by default** -- an unrouted
  command raises. Only pass `default=` when the test genuinely does not care
  what else ran. It also stubs `confirm_sudo_scope`, so a test that asserts on
  approval *prompts* wants `patch_command_runtime` instead.
  Note it drops the `run()` kwargs: a test asserting on `timeout=`/`check=`
  needs its own fake.
- `patch_ns(monkeypatch, 'aivm.vm.create_ops', {...})` with the `noop`,
  `returns(v)`, `records(sink)` stubs, for the long same-namespace stub runs.
- `make_cfg(tmp_path, **{'vm.name': ...})`, `write_store`, `written_cfg` (also
  the `cfg_path` fixture), and `run_cli(argv)` for CLI scaffolding.

When several tests differ only by a literal, parametrize them and carry the old
function name into `pytest.param(..., id=...)` so failures stay greppable.

**Assert on artifacts, not on call shapes.** Do not stub an internal function
and then assert it was called. Fake only the true process boundary and let the
real code run. Nearly everything -- ssh, virsh, rsync, mount, nft -- funnels
through `aivm.commands.subprocess.run`, so one `command_recorder` is usually the
whole fake. Redirect `aivm.config_store.paths._appdir` at `tmp_path` to catch
state files. Then assert on one of exactly four artifacts:

1. config-store contents -- `load_store(cfg_path)` after the call;
2. files on disk under `tmp_path`;
3. the recorder's command log (`rec.normalized`, `rec.only(...)`);
4. captured log output (`capture_logs`).

There is **no intent log**: `CommandManager` pops every `IntentFrame` and
`CommandPlan` and drains `_loose_commands` before returning, so nothing records
what it intended after the fact. Don't design an assertion around one.

Keep a stub only for a genuine boundary (a live guest, the developer's real
`~/.ssh/config`, `time.sleep`, an interactive prompt) or when the stubbed thing
is the subject of a different test file. Say which in a comment.

### Common CLI Usage (for testing)
- Initialize config: `aivm config init`
- Create VM: `aivm vm create`
- Check status: `aivm status` or `aivm status --sudo`
- List resources: `aivm list`
- Open code in VM: `aivm code .`

## Architecture Overview

`aivm` is a Python-based CLI tool designed to manage isolated Ubuntu 24.04 VMs via libvirt/KVM, specifically tailored for AI coding agents.

### High-Level Structure
- `aivm/cli/`: Implements the command-line interface. Commands are grouped by functional area (config, host, net, firewall, vm).
- `aivm/vm/`: Handles the VM lifecycle, including creation (`create_ops.py`), drift detection and updates (`update/`), and disk/image/share management.
- `aivm/attachments/`: Manages folder sharing between the host and guest. It supports four modes:
    - `persistent`: Bind-mount staged under the VM's export root, replayed in-guest (default).
    - `shared-root`: A single virtiofs mapping fed by per-folder host bind-mounts.
    - `direct-virtiofs`: Its own virtiofs device per folder. The only mode needing no host bind-mount, hence the only one a caller without sudo can create -- but each device costs one of the guest's limited PCIe slots, which is what the name is for. Was called `shared`; the old name is rejected rather than aliased.
    - `git`: Syncs via host/guest Git remotes. Never shares the folder, so it is the mode for repos whose contents must not reach the guest. Never select it implicitly.
- `aivm/host.py`, `aivm/net.py`, `aivm/firewall.py`: Provide abstractions for interacting with the host system's networking, libvirt, and nftables firewall.
- `aivm/config_store/` & `aivm/config.py`: Manage the global configuration store located at `~/.config/aivm/config.toml`.
- `aivm/machine_store.py`: Owns where the 0.6 machine store lives (shared vs personal root), its permissions, and the globally ordered resource locks.

### Key Design Patterns
- **Command Manager**: Subprocess execution is centralized through a command manager that organizes logs into semantic steps and handles sudo approvals.
- **Reconciliation Flow**: Many operations (like `aivm code .`) use a reconcile flow that ensures the VM, network, and folder attachments are in the desired state before proceeding.
- **Privilege Model**: The tool distinguishes between read-only probes (often auto-approved) and state-changing operations that require explicit user confirmation.
- **The machine store has two roots, not two implementations**: `resolve_machine_store_root` picks the host-wide group-owned `/var/lib/aivm/machine` when the host has one, and a caller-owned `~/.local/share/aivm/machine` when it does not. That choice sets the root path, the owning gid, and the modes -- nothing else. The documents, lock order, and every consumer are identical, because `MachineStoreLayout` was already a parameter everywhere; classify a path with `machine_root_is_shared` rather than reintroducing a mode flag. **Sudo cannot substitute for the group**: `flock` scopes need a descriptor held open in-process, atomic replacement sets modes through file descriptors, and a root-written `2770` store stays unreadable to a non-member afterwards, so escalating one write would commit every later read to escalating too. A host that declines trusted-group membership therefore gets its own store, never a privileged path into the shared one.
- **A shared store that exists always wins, and never silently forks**: when `/var/lib/aivm/machine` is present but unreadable, resolution raises `MachineStoreAccessError` instead of falling back. Falling back is the one genuinely unsafe outcome of two layouts: the shared store already claims this host's domains, so a private store beside it would claim them twice. Refusing is recoverable (join the group); forking is not.
- **Domain ownership lives on the domain**: `aivm/domain_authority.py` stamps the owning store root into libvirt `<metadata>`, and `_load_context_with_path` -- the one place every post-creation command resolves a VM -- refuses a domain another store claims. "One authoritative record per domain" used to be emergent from there being one store per host; it is now checked. An unstamped domain predates the marker and is accepted, and a host with only one store root on disk skips the probe entirely, so the guard costs nothing in the common case.
- **Enforce privilege at the command, not the feature**: whether an operation needs root is a property of the command being run, not of the feature requesting it. A `persistent` attachment needs `mount --bind` only when the bind is missing. Gate on the command (`CommandManager._reject_sudo_if_forbidden` sees every one) rather than refusing a feature that *might* need root.
- **Declare a fallible step, don't hand-roll `try`/`except`**: when a failure is an expected outcome you can recover from, say so with `mgr.attempt(...)` and read the result off the yielded `Attempt` (`.failed`, `.reason`). Business logic then states *what* it is doing rather than *how* it copes, the manager knows the failure is handled, and the logs say so instead of showing an ERROR line that reads as fatal. A bare `try`/`except` around manager calls hides that intent from both the manager and the reader.
- **An attempted command is never re-attempted**: `PlannedCommand.attempted` is set immediately *before* execution, because a command that raised has still been attempted. Both queues rely on that single flag; do not reintroduce a cursor or a pop-after-execute, which cannot express it (a raise skips whatever bookkeeping follows the call, leaving the command queued for an unrelated later flush to re-run and re-raise somewhere inexplicable).
- **A handle owns its outcome; reading one never causes work**: every submitted command reaches exactly one terminal state (`succeeded` / `failed` / `not-executed`), stored on the `CommandHandle`. `result()` calls `flush_through` *only* while pending; afterwards it replays the result, re-raises the stored exception, or raises `CommandNotExecutedError`. Marking the queue entry attempted is not enough — the handle must be told too, or a failed one stays pending and re-reading it flushes the queue again and runs whatever unrelated command is sitting there. `abort_plan` resolves every command it abandons. Retry means a new `submit()`.
- **`sudo` on the command line is always called out**: the user is made aware
  of anything with the potential to perform an unbounded privileged sudo op,
  *even if we know what the program being called is*. Merely invoking `sudo` on
  the command line is strong enough of a thing that it needs to be called out.
  So a privileged read logs at INFO next to every state-changing command, and
  only a command that escalates nothing is held back for `--verbose 2`. Do not
  "simplify" this to role alone: `qemu-img info` is read-only and still prints,
  because what is announced is the escalation, not the read. Visibility keys on
  whether the `sudo` prefix was actually applied rather than on `spec.sudo`,
  because a caller passes `sudo=True` speculatively under
  `privilege_mode='as-needed'` and no `sudo` reaches the command line when
  already root. This is a deliberate policy, not an oversight to optimize away.
- **A refusal is not a failure**: `CommandControlError` (user declined, approval unavailable, sudo forbidden, never executed) says the user did not authorize the work; `CommandError` says the work did not succeed. Best-effort machinery — `mgr.attempt(...)`, `except AIVMError`, `except Exception` — routinely recovers from the second and must never recover from the first, because continuing past it contradicts the user's own decision. `attempt()` re-raises every `CommandControlError` regardless of `catch`, and broad handlers wrapping manager calls re-raise it explicitly. When adding one, ask what it does to a declined prompt.