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
    - `shared`: Direct per-folder virtiofs mappings. The only mode needing no host bind-mount, hence no sudo.
    - `git`: Syncs via host/guest Git remotes. Never shares the folder, so it is the mode for repos whose contents must not reach the guest. Never select it implicitly.
- `aivm/host.py`, `aivm/net.py`, `aivm/firewall.py`: Provide abstractions for interacting with the host system's networking, libvirt, and nftables firewall.
- `aivm/config_store/` & `aivm/config.py`: Manage the global configuration store located at `~/.config/aivm/config.toml`.

### Key Design Patterns
- **Command Manager**: Subprocess execution is centralized through a command manager that organizes logs into semantic steps and handles sudo approvals.
- **Reconciliation Flow**: Many operations (like `aivm code .`) use a reconcile flow that ensures the VM, network, and folder attachments are in the desired state before proceeding.
- **Privilege Model**: The tool distinguishes between read-only probes (often auto-approved) and state-changing operations that require explicit user confirmation.
- **Enforce privilege at the command, not the feature**: whether an operation needs root is a property of the command being run, not of the feature requesting it. A `persistent` attachment needs `mount --bind` only when the bind is missing. Gate on the command (`CommandManager._reject_sudo_if_sudoless` sees every one) rather than refusing a feature that *might* need root.