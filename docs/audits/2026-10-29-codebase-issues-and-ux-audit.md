# Codebase and User Experience Audit

**Date:** 2026-10-29  
**Repository:** `aivm` (dev/0.6.2)  
**Auditor:** Antigravity  
**Target Document:** `docs/audits/2026-10-29-codebase-issues-and-ux-audit.md`

---

## 1. Executive Summary

This comprehensive audit of the `aivm` repository evaluated the codebase across two primary dimensions:
1. **Potential Issues & Defects**: Core runtime bugs, edge cases, privilege boundaries, architectural invariants, and test/dev tooling health.
2. **User Experience (UX) Enhancements**: CLI discoverability, first-run ergonomics, flag consistency, status observability, interactive prompts, and actionable error guidance.

AIVM provides a robust, carefully considered virtualization and sandboxing harness for coding agents. Its trust model, auditable command manager, fine-grained privilege handling, and resilient attachment subsystem demonstrate exceptional architecture. However, several critical runtime defects, unintended state mutations in read-only commands, dry-run crashes, and UX papercuts were identified.

---

## 2. Audit Scope & Methodology

- **Test Suite Execution**: Full `pytest -q` sweep across 1,688 unit/integration tests and typecheck validation (`ty check aivm`).
- **Architecture & Invariant Verification**: Cross-referencing against specifications in `AGENTS.md`, `docs/architecture/`, and `docs/reference/`.
- **Command Surface Audit**: Dynamic inspection of all CLI entrypoints (`aivm`, `status`, `list`, `code`, `ssh`, `attach`, `detach`, `config`, `vm`, `host`).
- **Subsystem Deep Dives**:
  - Config Store & Placement (`aivm/config_store/`, `aivm/scoped_store.py`, `aivm/machine_store.py`)
  - Attachment Lifecycle & Replay (`aivm/attachments/`, `aivm/rc/`)
  - VM Lifecycle & Discovery (`aivm/vm/`, `aivm/cli/vm_*.py`)
  - Host Privilege & Security Model (`aivm/privilege.py`, `aivm/commands.py`, `aivm/domain_authority.py`)
  - Guest Tooling & Provisioning (`aivm/vm/guest_tools.py`, `aivm/vm/provision.py`, `aivm/status.py`)
  - Scoped Repository Credentials (`aivm/credentials/`)

---

## 3. Potential Issues & Defects

### 3.1 Critical & Architectural Invariant Issues

#### Issue 1: Unintended Persistent Store Creation in Read-Only Commands (`config show` & `config discover`)
- **Location:** `aivm/cli/config/show.py:65-72`, `aivm/cli/config/discover.py:96-101`
- **Description:**  
  In `aivm/cli/config/show.py`, if no store exists on disk (`not loaded.sources`), `ConfigShowCLI.main` calls:
  ```python
  save_scope_store(scope, store, reason='Create empty config document for display.')
  ```
  Similarly, in `aivm/cli/config/discover.py`, `save_scope_store` is invoked unconditionally on non-dry-run runs, even when `added == 0 and updated == 0`.
- **Impact:**  
  Violates a foundational rule in `AGENTS.md`:
  > *"Fresh implicit 0.6 installations must explicitly resolve machine-store placement before writing defaults: shared host authority under `/var/lib/aivm/machine`, or a personal machine authority under the user data directory. Interactive bootstrap exposes that choice... Once either authority exists, never silently switch to the other -- changing placement is a migration."*
  Running a read-only command (`aivm config show` or `aivm config discover`) on a fresh install writes an empty split config store under `~/.local/share/aivm/machine`, freezing the machine authority onto personal storage without ever asking the user.
- **Recommended Remedy:**  
  - In `ConfigShowCLI`: Render the empty in-memory store directly using `render_store_defaults_toml` or output a clean *"No config store found at <path>"* message without calling `save_scope_store`.
  - In `ConfigDiscoverCLI`: Guard `save_scope_store` with `if added > 0 or updated > 0:`.

#### Issue 2: Silent Adoption of Unmanaged Libvirt Domains During `aivm vm create`
- **Location:** `aivm/vm/create_ops.py:442-497`, `aivm/vm/create.py:260-291`
- **Description:**  
  While `aivm config init` strictly checks `if domain_is_defined(canonical_vm_name): raise AIVMError('Refusing to adopt or overwrite an unmanaged domain...')`, `create_vm_from_defaults` checks only `find_vm(reg, cfg.vm.name)`.  
  If a domain with that name already exists in libvirt but is not registered in `reg` (e.g., an unmanaged domain, or a VM created via virt-manager/minikube/third-party tools):
  1. `create_or_start_vm` observes `vm_exists(cfg) is True` and treats it as an existing stopped VM, starting it.
  2. `create_vm_from_defaults` stamps domain authority on the domain and inserts a new VM record into `reg`.
- **Impact:**  
  Direct violation of safety principles: *"Discovery/import should be explicit and user-confirmed for unmanaged VMs. Never ... silently adopt an unmanaged same-name domain."*
- **Recommended Remedy:**  
  In `create_vm_from_defaults`, check `if domain_is_defined(cfg.vm.name) and existing is None:`. If true, refuse with an error directing the user to `aivm config discover` or `aivm vm create --vm <different-name>`.

#### Issue 3: Multi-User Authority Blindspot in `_competing_store_possible`
- **Location:** `aivm/domain_authority.py:158-171`
- **Description:**  
  `_competing_store_possible(layout)` checks only `candidate_machine_store_roots()`, which evaluates only `/var/lib/aivm/machine` and the *current caller's* personal root `~/.local/share/aivm/machine`.  
  On a host without `/var/lib/aivm/machine`, if User A has a personal store and creates domain `alpha`, and User B runs `aivm` with their personal store, `_competing_store_possible` returns `False` for User B. Consequently, `require_domain_authority` skips domain inspection, allowing User B's store to drive or adopt User A's domain without checking libvirt metadata.
- **Recommended Remedy:**  
  When checking domain authority for a domain that already exists in libvirt, always read the domain's `<metadata>` stamp if the domain exists, or do not skip `read_domain_authority` merely because the caller only sees one local root.

---

### 3.2 High & Medium Severity Functional Defects

#### Issue 4: Unhandled `FileNotFoundError` in `aivm config lint`
- **Location:** `aivm/cli/config/lint.py:73-76`
- **Description:**  
  When no config store exists, `load_config_document` returns `LoadedStore(..., sources=[], layout='missing', source_text='')`.  
  Because `loaded.source_text` is `''` (falsy), the code executes the right side of `or`:
  ```python
  source_text = loaded.source_text or path.read_text(encoding='utf-8')
  ```
  Since `path` does not exist, `path.read_text()` raises an unhandled `FileNotFoundError`, crashing before reaching line 74 (`if not sources:`).
- **Reproduction:**
  ```bash
  $ rm -rf ~/.local/share/aivm/machine
  $ aivm config lint
  ERROR: Unhandled aivm error: [Errno 2] No such file or directory: '.../config.toml'
  ```
- **Recommended Remedy:**  
  Check `if not loaded.sources:` *before* referencing `source_text` or `path.read_text()`.

#### Issue 5: Crash in `aivm config discover --dry-run`
- **Location:** `aivm/cli/config/discover.py:54-60`
- **Description:**  
  In dry-run mode, `mgr.run(virsh_cmd('list', '--all', '--name'), check=False)` does not execute the command, resulting in `names_res.code != 0`.  
  The fallback logic then executes:
  ```python
  names_res = mgr.run(..., sudo=True, check=True)
  ```
  With `check=True` in dry-run mode, `CommandManager` raises `CommandDryRunError`:
  `Command was previewed but not executed because this is a dry run: virsh -c qemu:///system list --all --name`.
- **Impact:**  
  `aivm config discover -n` crashes with exit code 2 and an error trace instead of previewing.
- **Recommended Remedy:**  
  Check `mgr.dry_run` before escalating with `check=True`, and return an empty or previewed discovery outcome.

#### Issue 6: `aivm code --dry-run` and `ssh --dry-run` Block on Interactive Input or Crash in Non-Interactive Shells
- **Location:** `aivm/cli/vm_connect.py:80-92`
- **Description:**  
  When running `aivm code --dry-run` on a directory without an active VM, `_bootstrap_vm_for_folder` unconditionally prompts:
  ```
  No managed VM found for this folder.
  Run `aivm config init` and `aivm vm create` now? [Y/n]:
  ```
  In automated pipelines or scripts where `sys.stdin.isatty()` is `False`, it immediately raises `AIVMError: No managed VM found for this folder. Re-run with --yes to create one automatically.` even though the user specified `--dry-run`.
- **Recommended Remedy:**  
  If `args.dry_run` is True, do not prompt for initialization or abort; preview that `aivm config init` and `aivm vm create` would be triggered.

#### Issue 7: `aivm status` False-Negative for Guest Tools (`claude`, `codex`, `uv`, `rust`) in Non-Login SSH
- **Location:** `aivm/status.py:564-580`, `aivm/vm/guest_tools.py`
- **Description:**  
  `probe_provisioned` runs a probe script over SSH:
  `ssh ... <remote>` where `<remote>` runs `command -v <tool>`.  
  Non-login SSH sessions do not execute `~/.profile` and do not include `$HOME/.local/bin` or `$HOME/.cargo/bin` on `$PATH`.  
  `antigravity` recently added a custom `status_check`:
  `[ -x "$HOME/.local/bin/agy" ] || command -v agy ...`  
  However, `claude`, `codex`, `uv`, and `rust` rely on bare `required_commands=('claude',)` without custom checks. Consequently, `aivm status` falsely reports `one or more configured packages/tools missing` even after successful provisioning.
- **Recommended Remedy:**  
  In `aivm/status.py:probe_provisioned`, prepend:
  ```bash
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  ```
  to `checks` before evaluating `definition.required_commands`.

---

### 3.3 Low Severity & Developer Tooling Issues

#### Issue 8: Test Failure Due to Stale Compatibility Inventory
- **Location:** `docs/architecture/generated/compatibility-inventory.md`, `tests/test_architecture_docs.py:383`
- **Description:**  
  Recent commits (`5143fd7`, `c0378d0`) added `AgentVMConfig` references to `host_bind.py`, `session.py`, and `guest_tools.py` without regenerating architecture docs. As a result:
  `pytest tests/test_architecture_docs.py` fails with:
  `ArchitectureError: stale generated file: docs/architecture/generated/compatibility-inventory.md`.
- **Fix:**  
  Run `python dev/devcheck/architecture_docs.py generate`.

#### Issue 9: Hardcoded User Scratchpad Path in `dev/devcheck/make_command_audit.py`
- **Location:** `dev/devcheck/make_command_audit.py:8-12`
- **Description:**  
  Contains hardcoded paths:
  ```python
  SITES = Path('/tmp/claude-1000/-home-joncrall-code-aivm/96cc7661-f780-4162-9e18-e885857992d0/scratchpad/sites.json')
  OUT = Path('/home/joncrall/code/aivm/docs/planning/command-approval-audit.md')
  ```
  Running this script crashes with `FileNotFoundError`.
- **Fix:**  
  Parameterize `SITES` via CLI argument or resolve relative to the repository root.

#### Issue 10: Missing Post-Save Validation in `config edit` and `vm edit`
- **Location:** `aivm/cli/config/edit.py`, `aivm/cli/vm_config.py`
- **Description:**  
  Unlike `config init` (which parses and validates TOML syntax after editor exit, offering to re-edit on error), `config edit` and `vm edit` launch `$EDITOR` without post-save validation. Saving invalid TOML corrupts store fragments and breaks subsequent CLI operations.
- **Recommended Remedy:**  
  Validate the edited fragment with `tomllib.loads` or `parse_store_toml` upon editor exit. If invalid, display the syntax error and prompt to reopen the editor or discard changes.

---

## 4. Potential User Experience (UX) Enhancements

### 4.1 First-Run Workflow & Command Hierarchy

#### UX-1: Align `aivm help plan` with Core CLI UX Principles
- **Current Behavior:**  
  `aivm help plan` outputs a 9-step manual lifecycle:
  1. `aivm config init`
  2. `aivm host doctor`, `aivm status`
  3. `aivm host net create`
  4. `aivm host fw apply`
  5. `aivm host image_fetch`
  6. `aivm vm create`, `wait_ip`, `update`
  7. `aivm vm ssh_config`
  8. `aivm vm provision`
  9. `aivm vm code --host_src .`
- **Friction Points:**
  - `AGENTS.md` explicitly mandates:
    > *"Prefer simple defaults: `aivm code .`, `aivm ssh .`"*
  - Recommending `aivm vm code --host_src .` is verbose and counter-intuitive.
  - `aivm ssh` is completely omitted from the suggested plan.
  - New users are given the impression that 9 manual commands are required before opening a workspace, when `aivm code .` or `aivm ssh .` already auto-bootstraps missing networks and VMs in one step.
- **Enhancement:**  
  Update `aivm help plan` to highlight the **Single-Command Quickstart** first:
  ```text
  🚀 Quickstart:
     aivm code .       # Open current folder in VS Code (auto-bootstraps VM if needed)
     aivm ssh .        # SSH into VM attached to current folder
  
  🛠️  Detailed / Step-by-Step Lifecycle:
     [1..8 manual steps for operators]
  ```

#### UX-2: Live Status and IP in `aivm list`
- **Current Behavior:**  
  `aivm list` displays static store records:
  ```text
  Managed VMs
    - aivm-2404 | network=aivm-net | strict_firewall=yes | access=1/1 active | store=...
  ```
  It does not show whether VMs are `running`, `shut off`, or their current IP address. Users must run `aivm vm status --vm <name>` separately for every VM.
- **Enhancement:**  
  Add an optional or default live-status column to `aivm list` (e.g. `state=running | ip=192.168.100.42`), similar to standard tools (`virsh list`, `docker ps`, `multipass list`). If libvirt access is available without sudo, show live status automatically; otherwise, gracefully display `state=(unprobed; run with --sudo or status)`.

---

### 4.2 Discoverability & Documentation Consistency

#### UX-3: Demystify Sudo in `aivm help raw`
- **Current Behavior:**  
  `aivm help raw` prints direct system commands equivalent to AIVM checks, but hardcodes `sudo` on all `virsh` commands:
  ```bash
  sudo virsh list
  sudo virsh dominfo aivm-2404
  ```
- **Friction Points:**  
  One of AIVM’s flagship capabilities is **sudoless VM management** via the `libvirt` group (`aivm host permissions check`). Instructing users to run `sudo virsh` teaches root escalation where unprivileged access is expected and creates root-owned libvirt cache files.
- **Enhancement:**  
  Dynamically check `virsh_needs_sudo()`. If unprivileged libvirt access works, omit `sudo` from the printed `virsh` commands, showing `sudo` only when genuinely required.

#### UX-4: Network Creation Semantics in `aivm host net create`
- **Current Behavior:**  
  `aivm host net create [network]` requires the network name to already be defined in the config store (`require_network(reg, net_name)`). Attempting to create an undeclared network fails with `Unable to resolve a managed network`.
- **Enhancement:**  
  Clarify in `--help` that `net create` realizes an existing stored network definition in libvirt. Alternatively, support flags (e.g. `--subnet`, `--bridge`) to allow `net create` to define and create a new network in one step.

#### UX-5: Firewall Targeting Options (`--network` / `--vm`)
- **Current Behavior:**  
  `aivm host fw apply`, `status`, and `remove` take no `--network` or `--vm` flag. They always fall back to the default VM/network.
- **Enhancement:**  
  Add `--network` and `--vm` options to `FirewallApplyCLI`, `FirewallStatusCLI`, and `FirewallRemoveCLI` so multi-network hosts can inspect or manage individual firewall tables.

---

### 4.3 CLI Formatting & Flag Consistency

#### UX-6: Clean POSIX Kebab-Case Formatting in `--help`
- **Current Behavior:**  
  `kwconf` flags currently render in `--help` with underscores and optional brackets:
  `--admin_override [ADMIN_OVERRIDE]`  
  `--dry_run [DRY_RUN]`  
  `--yes_sudo [YES_SUDO]`
- **Enhancement:**  
  Ensure primary documented flag names in `--help` use canonical POSIX kebab-case (`--dry-run`, `--admin-override`, `--yes-sudo`), and render boolean flags without confusing `[FLAG_NAME]` argument brackets.

---

## 5. Audit Summary Matrix

| ID | Category | Severity | Component | Summary |
|---|---|---|---|---|
| **ISSUE-1** | Architecture / Defect | **High** | `config show` / `discover` | Read-only commands write empty config store to disk, violating placement invariant |
| **ISSUE-2** | Security / Safety | **High** | `vm create` | Silently starts and adopts unmanaged libvirt domains without user confirmation |
| **ISSUE-3** | Security / Invariant | **Medium** | `domain_authority` | `_competing_store_possible` does not detect other local users' personal stores |
| **ISSUE-4** | Runtime Defect | **Medium** | `config lint` | Unhandled `FileNotFoundError` when `config.toml` does not exist |
| **ISSUE-5** | Runtime Defect | **Medium** | `config discover` | `--dry-run` crashes with `CommandDryRunError` due to `check=True` |
| **ISSUE-6** | Ergonomics / Defect | **Medium** | `code` / `ssh` | `--dry-run` prompts interactively for VM bootstrap or crashes in non-tty shells |
| **ISSUE-7** | Observability / Defect | **Medium** | `status` / `guest_tools` | `probe_provisioned` reports missing tools in non-login SSH due to unexported PATH |
| **ISSUE-8** | Maintenance / Tests | **Low** | `architecture_docs` | Stale `compatibility-inventory.md` causes `test_current_architecture_documentation_is_current` failure |
| **ISSUE-9** | Tooling | **Low** | `make_command_audit` | Hardcoded `/tmp/claude-1000/...` path causes immediate crash |
| **ISSUE-10** | Robustness | **Low** | `config edit` / `vm edit` | Missing post-save TOML syntax validation leaves corrupt configs on disk |
| **UX-1** | Ergonomics | **Medium** | `help plan` | 9-step manual plan obscures simple `aivm code .` / `aivm ssh .` quickstart |
| **UX-2** | Observability | **Medium** | `list` | VM listing shows store records but lacks live runtime state and IP |
| **UX-3** | Guidance | **Low** | `help raw` | Hardcodes `sudo virsh` even when sudoless libvirt is configured and active |
| **UX-4** | Discoverability | **Low** | `host net create` | Fails on undeclared network names without clear guidance |
| **UX-5** | Flexibility | **Low** | `host fw` | Missing `--network` / `--vm` flags prevents targeting non-default firewall tables |
| **UX-6** | Interface | **Low** | CLI Options | Help text renders snake_case and awkward argument brackets for boolean flags |

---

## 6. Suggested Action Plan

1. **Immediate Stability Fixes (Sprint 1)**:
   - Fix `aivm config lint` `FileNotFoundError` (Issue 4).
   - Prevent `aivm config show` and `aivm config discover` from calling `save_scope_store` when no records were added/modified (Issue 1).
   - Fix `aivm config discover --dry-run` crash (Issue 5).
   - Update `docs/architecture/generated/compatibility-inventory.md` via `python dev/devcheck/architecture_docs.py generate` to restore test suite green status (Issue 8).
2. **Safety & Security Tightening (Sprint 2)**:
   - Add explicit check in `create_vm_from_defaults` to reject existing unmanaged libvirt domains (Issue 2).
   - Export `$HOME/.local/bin` and `$HOME/.cargo/bin` in `probe_provisioned` script in `aivm/status.py` (Issue 7).
   - Fix `--dry-run` behavior in `_bootstrap_vm_for_folder` so it previews rather than prompting or aborting (Issue 6).
3. **UX & Ergonomics Polish (Sprint 3)**:
   - Overhaul `aivm help plan` to showcase `aivm code .` and `aivm ssh .` as primary quickstart flows (UX-1).
   - Add live VM state/IP inspection in `aivm list` (UX-2).
   - Add post-edit TOML validation in `aivm config edit` and `aivm vm edit` (Issue 10).
   - Make `aivm help raw` respect `virsh_needs_sudo()` (UX-3).
