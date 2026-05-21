# `aivm` Refactor Plan — `dev/0.5.0`

**Status:** In progress. Tasks 1, 2, 3, 4, 5, and 6 complete on `dev/0.5.0`. Task 7 deferred by maintainer; Task 8 optional.
**Author:** Claude (Opus 4.7) audit pass on 2026-05-20; progress notes added 2026-05-21.
**Branch context:** `dev/0.5.0`. Per project policy, only the **last released version on `main`** is a backwards-compatibility surface — internal Python APIs are not. Feature-branch shims and `# kept for compat` aliases are **not** required. The CLI command/flag surface and the on-disk config file format remain stable.

---

## 0. Goals & non-goals

### Goals

1. **Make the package easier for agents to extend.** Today, finding "the right file" to edit is harder than it should be because there are duplicate facades (`store.py` ↔ `config_store/`, `update_ops.py` ↔ `update/`), an inconsistent CLI/ops split (`ops/` half-built), and `__init__.py` files that re-export underscore-prefixed names which conventionally mean "private".
2. **Make the package easier for humans to audit.** A reviewer should be able to read one `__init__.py` and tell, at a glance, what's public and what isn't, and what each subpackage is responsible for.
3. **Reduce file size where cohesion is genuinely low.** Mega-files (`cli/config.py`, `attachments/persistent.py`, `commands.py`) mix multiple concerns; splitting them clarifies responsibility without inventing new abstractions.

### Non-goals

- **No behavior changes.** Every task in this plan is a structural move. The CLI surface, the config file format, and the libvirt/SSH/virtiofs flow stay the same.
- **No new abstractions.** No new base classes, plugin systems, or DI frameworks. The goal is **less**, not more.
- **No "future-proofing".** If a task can't be justified by something visible in the current code, skip it.

### What "done" looks like for each task

Each task below specifies:

- **Goal** — one sentence on what the task accomplishes.
- **Why it helps** — the human / agent payoff.
- **Scope** — concrete files touched (read, edit, delete, create).
- **Steps** — ordered, mechanical edits.
- **Expected output shape** — what the final directory/file structure should look like.
- **Validation** — what to run to confirm nothing broke.
- **Risk & rollback** — known traps and how to back out.
- **Out of scope** — what NOT to touch in the same PR.

Each task is independently mergeable. **Do not combine tasks** unless explicitly noted — small PRs let humans audit individual moves.

---

## 1. Audit summary (read this first)

Findings driving the task list. Numbers/paths from `dev/0.5.0` HEAD at audit time.

### 1.1 Pure-facade modules

These files only re-export from another module. Deleting them after rewriting callers loses nothing.

- [`aivm/store.py`](../aivm/store.py) (184 L) re-exports everything from [`aivm/config_store/`](../aivm/config_store/). Only one symbol has its own logic worth preserving: `_appdir`, which exists for test monkeypatching. **13 internal importers** plus **~17 test files** import from `aivm.store`. Test `test_attachment_persistent.py:325` monkeypatches `aivm.store._appdir`.
- [`aivm/vm/update_ops.py`](../aivm/vm/update_ops.py) (67 L) is a pure compatibility facade for [`aivm/vm/update/`](../aivm/vm/update/). **One internal importer** (`ops/vm_update.py`) and **one test importer** (`test_cli_vm_update.py`).

### 1.2 Underscore-prefix pollution in `__init__.py` re-exports

Both [`aivm/attachments/__init__.py`](../aivm/attachments/__init__.py) and [`aivm/vm/__init__.py`](../aivm/vm/__init__.py) re-export many names beginning with `_`:

- `aivm/attachments/__init__.py` `__all__` contains 30+ names beginning with `_` (e.g., `_apply_guest_derived_symlinks`, `_ensure_attachment_available_in_guest`, `_record_attachment`, `_resolve_attachment`).
- `aivm/vm/__init__.py` `__all__` contains `_ensure_disk`, `_ensure_qemu_access`, `_mac_for_vm`, `_paths`, `_sudo_file_exists`, `_sudo_path_exists`, `_write_cloud_init`.

Tests import these underscore names directly from sub-modules (`from aivm.attachments.session import _record_attachment` appears in ~12 test sites). So the leading `_` is conventionally lying — these are de-facto public to tests. We should pick one truth and apply it.

### 1.3 Half-built `aivm/ops/`

[`aivm/ops/__init__.py`](../aivm/ops/__init__.py) is a single-line docstring. The directory contains only `vm_attach.py` and `vm_update.py`. The pattern (CLI thin wrapper → `ops.*Request/*Runner` → core) is good, but it's used by **only two** of the VM commands. `cli/vm_lifecycle.py`, `cli/vm_connect.py`, `cli/vm_cache.py`, `cli/vm_config.py` do their work inline. Either commit to the pattern across all VM commands, or fold the two existing files back.

### 1.4 Mega-files with mixed concerns

| File | Lines | Concerns mixed |
|---|---|---|
| [`aivm/cli/config.py`](../aivm/cli/config.py) | 1195 | `InitCLI` + 11 init helpers; `ConfigShowCLI/FormatCLI/PathsCLI/EditCLI` + 8 path-print helpers; `ConfigDiscoverCLI` + 2 discover helpers; `ConfigLintCLI` + 3 lint helpers |
| [`aivm/commands.py`](../aivm/commands.py) | 1238 | Data classes (`CommandResult`, `CommandSpec`, `CommandHandle`, `CommandPlan`, `IntentFrame`, `PlannedCommand`) + scopes (`IntentScope`, `PlanScope`) + `CommandManager` |
| [`aivm/attachments/persistent.py`](../aivm/attachments/persistent.py) | 1034 | Manifest building/diffing + ssh-retry transport + replay-service install/uninstall + host-bind reconcile |
| [`aivm/attachments/session.py`](../aivm/attachments/session.py) | 1028 | Saved-attachment records + session preparation + VM reconcile + drift warning |

### 1.5 What's already fine

- `aivm/config_store/` — clean separation (`io`, `models`, `mutate`, `parse`, `paths`, `render`, `resolve`). No changes.
- `aivm/cli/` (excluding `config.py`) — thin command classes per file. Pattern works.
- `aivm/config.py` — user-facing dataclasses only, no overlap with `config_store/`.
- `aivm/vm/share.py` — attachment data model (`AttachmentMode`, `AttachmentAccess`, `ResolvedAttachment`). Cohesive.
- No circular imports anywhere.

---

## 2. Tasks (ordered)

Each task is sized so a small/fast model can execute it in one session. Tasks 1 and 2 are pure deletions and are safest to do first.

---

### Task 1 — Delete the `aivm/store.py` facade ✅ DONE (commit `797ff64`)

**Goal:** Remove the `aivm.store` module. Callers import directly from `aivm.config_store`.

**Why it helps:**
- Removes one layer between callers and the canonical implementation.
- Eliminates the test-monkeypatch indirection that exists only because the facade was added later.
- Makes "where does this data structure live?" a one-hop answer.

**Scope:**
- **Edit (internal callers, 13 files):**
  - `aivm/status.py`
  - `aivm/attachments/resolve.py`
  - `aivm/attachments/session.py`
  - `aivm/attachments/persistent.py`
  - `aivm/vm/create_ops.py`
  - `aivm/vm/drift.py`
  - `aivm/cli/config.py`
  - `aivm/cli/main.py`
  - `aivm/cli/_common.py`
  - `aivm/cli/net.py`
  - `aivm/cli/vm_lifecycle.py`
  - `aivm/cli/help.py`
  - `aivm/ops/vm_attach.py`
- **Edit (tests, ~17 files):** all test files matching `grep -l "from aivm.store" tests/`.
- **Edit:** `aivm/config_store/paths.py` — confirm `_appdir`, `app_data_dir`, `app_data_path`, `persistent_host_state_dir`, `store_path` all live there (they do, see [paths.py](../aivm/config_store/paths.py)).
- **Edit:** `aivm/config_store/io.py` — confirm `load_store`, `save_store`, `save_store_split`, `format_existing_config`, `load_config_document`, `LoadedStore`, `ConfigSource`, `render_split_fragments`, `split_fragment_paths`, `is_split_layout` all live there.
- **Edit:** `aivm/config_store/__init__.py` — confirm re-exports cover everything the old `store.py` exported. Add anything missing (e.g., `parse_store_toml`, `_cfg_from_dict`, `_norm_dir`, `_emit_toml_kv`, `_toml_escape` if used externally).
- **Edit:** `tests/test_attachment_persistent.py:325` — change `monkeypatch.setattr('aivm.store._appdir', fake_appdir)` to `monkeypatch.setattr('aivm.config_store.paths._appdir', fake_appdir)`. **Audit other tests for similar monkeypatches** with `grep -rn "aivm.store" tests/`.
- **Delete:** `aivm/store.py`.

**Steps:**

1. Grep `grep -rn "from aivm.store\|from \.store\|from \.\.store\|aivm\.store\." aivm/ tests/` and snapshot the list.
2. For each importer, replace `aivm.store` / `.store` / `..store` with `aivm.config_store` / `.config_store` / `..config_store`. The exported symbols are identical except where noted in step 4.
3. The `save_store` and `load_store` functions in `aivm/store.py` apply a `path or store_path()` default. Confirm the equivalents in `aivm/config_store/io.py` do the same — they should accept `path: Path | None = None` and fall back to `store_path()` from `config_store/paths.py`. If they don't, add that default in `io.py` (do not change call signatures at call sites).
4. **Monkeypatch sites must move.** Any test or code path that does `monkeypatch.setattr('aivm.store._appdir', ...)` must instead patch `aivm.config_store.paths._appdir`. Search both `tests/` and `aivm/` for any remaining `aivm.store` string references.
5. Delete `aivm/store.py`.
6. Run validation suite (below).

**Expected output shape:**

```
aivm/
├── config_store/          # canonical, unchanged in structure
│   ├── __init__.py        # re-exports everything store.py used to export
│   ├── io.py
│   ├── models.py
│   ├── mutate.py
│   ├── parse.py
│   ├── paths.py           # owns _appdir, store_path, etc
│   ├── render.py
│   └── resolve.py
└── store.py               # ← DELETED
```

**Validation:**

```bash
# Static
python -m compileall aivm tests
grep -rn "aivm\.store\|from \.store\|from \.\.store" aivm/ tests/  # must be empty
# Tests
pytest -q tests/test_store.py tests/test_attachment_persistent.py tests/test_attachment_session.py tests/test_cli_config_init.py
pytest -q
# Smoke
aivm --help
aivm list
```

**Risk & rollback:**
- Risk: the `_appdir` monkeypatch may be set in conftest or fixtures and missed by grep. If `test_attachment_persistent` passes but related tests start writing to the real `~/.config/aivm/config.toml`, search wider: `grep -rn "appdir\|XDG_CONFIG\|store_path" tests/`.
- Rollback: `git revert` the squashed commit. The facade and old import strings are deterministic to restore.

**Out of scope:**
- Do **not** rename any symbols in `config_store/`. Use the same names that `store.py` exported.
- Do **not** touch `aivm/config_store/__init__.py` other than ensuring the export list covers what `store.py`'s `__all__` had.
- Do not split tests in this PR.

---

### Task 2 — Delete the `aivm/vm/update_ops.py` facade ✅ DONE (commit `b77bf2b`)

**Goal:** Remove the `aivm.vm.update_ops` module. Callers import from `aivm.vm.update` directly.

**Why it helps:** Same as Task 1, smaller scope. `update_ops.py` even has a docstring saying "Compatibility facade for VM update helpers…This module intentionally re-exports…".

**Scope:**
- **Edit:** `aivm/ops/vm_update.py` (only internal importer)
- **Edit:** `tests/test_cli_vm_update.py` (only test importer)
- **Edit:** `aivm/vm/update/__init__.py` — confirm re-exports cover everything `update_ops.py` re-exported.
- **Delete:** `aivm/vm/update_ops.py`.

**Steps:**

1. `grep -rn "from aivm\.vm\.update_ops\|update_ops" aivm/ tests/` to capture call sites.
2. Replace each `aivm.vm.update_ops` with `aivm.vm.update`. Confirm imports resolve.
3. Delete `aivm/vm/update_ops.py`.
4. Run validation.

**Expected output shape:**

```
aivm/vm/
├── update/                # canonical
│   ├── __init__.py
│   ├── apply.py
│   ├── detect.py
│   ├── models.py
│   ├── render.py
│   ├── restart.py
│   ├── util.py
│   └── virtiofs.py
└── update_ops.py          # ← DELETED
```

**Validation:**

```bash
python -m compileall aivm tests
grep -rn "update_ops" aivm/ tests/  # must be empty
pytest -q tests/test_cli_vm_update.py
pytest -q
```

**Risk & rollback:** Low. Two importers. `git revert`.

**Out of scope:** Don't touch `aivm/vm/update/` internals.

---

### Task 3 — Normalize underscore re-exports ✅ DONE (commit `121c6f0`)

**Decision recorded (2026-05-21):** Tests are allowed to import `_`-prefixed names from submodules. The `__init__.py` files were shrunk to only the public names; private helpers stay in their owning submodule and are imported from there. No public renames were needed.

**Goal:** Stop re-exporting underscore-prefixed names from `aivm/attachments/__init__.py` and `aivm/vm/__init__.py`. Pick one truth per name: either it's public (rename without underscore) or it's internal (keep the underscore, import directly from the owning submodule, don't re-export).

**Why it helps:**
- A reader of `aivm/attachments/__init__.py` should be able to tell what the package's public surface is. Right now the `__all__` list mixes 30+ underscore names with 5 capitalized names. That's not communication, it's noise.
- Sub-agents writing new code currently learn the wrong pattern by example.
- After this task, "is this private?" has a clear answer.

**Scope:**

- **Edit:** `aivm/attachments/__init__.py` — shrink `__all__` to only the genuinely-public names. The current candidates for public surface (no underscore now or after rename):
  - Constants: `ATTACHMENT_ACCESS_MODES`, `ATTACHMENT_ACCESS_RO`, `ATTACHMENT_ACCESS_RW`, `ATTACHMENT_MODE_PERSISTENT`, `ATTACHMENT_MODE_GIT`, `ATTACHMENT_MODE_SHARED`, `ATTACHMENT_MODE_SHARED_ROOT`, `ATTACHMENT_MODES`, `SHARED_ROOT_GUEST_MOUNT_ROOT`, `PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME`, `PERSISTENT_ATTACHMENT_REPLAY_SERVICE`, `PERSISTENT_ROOT_GUEST_MOUNT_ROOT`, `PERSISTENT_ROOT_VIRTIOFS_TAG`
  - Classes: `ReconcilePolicy`, `ReconcileResult`
  - Functions used by `cli/` and `ops/` (need renames to drop `_`):
    - `_prepare_attached_session` → `prepare_attached_session`
    - `_reconcile_attached_vm` → `reconcile_attached_vm`
    - `_record_attachment` → `record_attachment`
    - `_resolve_attachment` → `resolve_attachment`
    - `_resolve_guest_dst` → `resolve_guest_dst`
    - `_default_primary_guest_dst` → `default_primary_guest_dst`
    - `_compute_mirror_home_symlink` → `compute_mirror_home_symlink`
    - `_host_symlink_lexical_path` → `host_symlink_lexical_path`
    - `_normalize_attachment_mode` → `normalize_attachment_mode`
    - `_normalize_attachment_access` → `normalize_attachment_access`

- **Edit:** `aivm/vm/__init__.py` — shrink `__all__` similarly. Candidates for rename (currently re-exported with `_`):
  - `_ensure_disk` → keep `_` and **stop re-exporting** (only `lifecycle.py` should use it).
  - `_ensure_qemu_access` → same.
  - `_mac_for_vm` → same.
  - `_paths` → keep `_` and stop re-exporting (it's a private alias to a constant).
  - `_sudo_file_exists`, `_sudo_path_exists` → same.
  - `_write_cloud_init` → same.
  - *(All of these have one or two callers; check each: `grep -rn "from aivm.vm import _ensure_disk" aivm/ tests/` etc.)*

- **Edit:** every caller (in `aivm/` and `tests/`) that currently imports a renamed name.
- **Edit:** every caller that imports a deprecated re-export (`from aivm.attachments import _foo`) — change to direct submodule import (`from aivm.attachments.session import _foo`) if keeping `_`, or to the new name.

**Steps:**

1. Build the rename map. For each name in `aivm/attachments/__init__.py:__all__` that starts with `_`, decide:
   - Is it imported from `aivm/cli/`, `aivm/ops/`, or another sibling subpackage? → **Rename to drop `_`**.
   - Is it only used inside `aivm/attachments/*` itself (between its own submodules)? → **Keep `_`, remove from `__init__.py:__all__`**.
   - Is it only imported by tests? → Decide case-by-case. If tests test it as a unit, rename to drop `_`. If they test it as a private helper, keep `_` and have tests import from the owning submodule.
2. Apply renames with `git grep -l` + `sed` (or your editor's project-wide rename). For each rename, also update:
   - The `def`/`class` line.
   - The `__all__` lists in `__init__.py` and any submodule `__all__`.
   - Every import site in `aivm/` and `tests/`.
   - Any docstring or comment that names the function.
3. Repeat for `aivm/vm/__init__.py`.
4. After renames, the `__all__` in both `__init__.py` files should be **alphabetically sorted, no leading-underscore names**.

**Expected output shape (`aivm/attachments/__init__.py`):**

```python
"""Attachment/session subsystem for aivm."""

from .guest import (
    apply_guest_derived_symlinks,
    ensure_attachment_available_in_guest,
    ensure_git_clone_attachment,
    ...
)
from .persistent import (
    PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    PERSISTENT_ROOT_GUEST_MOUNT_ROOT,
    PERSISTENT_ROOT_VIRTIOFS_TAG,
    install_persistent_attachment_replay,
    ...
)
from .resolve import (
    ATTACHMENT_ACCESS_MODES, ATTACHMENT_ACCESS_RO, ATTACHMENT_ACCESS_RW,
    ATTACHMENT_MODE_GIT, ATTACHMENT_MODE_PERSISTENT, ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODES,
    resolve_attachment, resolve_guest_dst,
    normalize_attachment_access, normalize_attachment_mode,
    ...
)
from .session import (
    ReconcilePolicy, ReconcileResult,
    prepare_attached_session, reconcile_attached_vm, record_attachment,
    ...
)
from .shared_root import (
    SHARED_ROOT_GUEST_MOUNT_ROOT,
    ensure_shared_root_host_bind, ...,
)

__all__ = [
    # alphabetical, no leading underscores
    'ATTACHMENT_ACCESS_MODES',
    ...
]
```

**Validation:**

```bash
python -m compileall aivm tests
# No re-exported private name remains:
python -c "import aivm.attachments; print([n for n in aivm.attachments.__all__ if n.startswith('_')])"
# Expected: []
python -c "import aivm.vm; print([n for n in aivm.vm.__all__ if n.startswith('_')])"
# Expected: []
pytest -q
```

**Risk & rollback:**
- **High touch count** (this is the biggest task in the plan). Use one PR per package (one for `attachments`, one for `vm`) if reviewer fatigue is a concern.
- Risk: missing an import site. The `compileall` + full test run catches almost all of them; a final `grep -rn "from aivm.attachments import _" aivm/ tests/` should be empty.
- Rollback: `git revert`. Renames are mechanical and atomic.

**Out of scope:**
- Don't change function bodies. Pure rename + re-export shrink.
- Don't move functions between modules in this task.
- Don't touch `commands.py` or `cli/config.py` in this task.

---

### Task 4 — Split `aivm/cli/config.py` into a package ✅ DONE (commit `0b70d15`)

**Lessons recorded (2026-05-21):** A package split breaks `monkeypatch.setattr('aivm.cli.config.X', ...)` calls when the patched name is a *module-level* binding read by callers (e.g. `_cfg_path`, `auto_defaults`, `sys.stdin.isatty`, `log.warning`). The patches must move to the owning submodule, e.g. `aivm.cli.config.init._cfg_path`. Class-attribute patches like `aivm.cli.config.InitCLI.main` keep working through the package re-export because they walk to the class object.

**Goal:** Replace [`aivm/cli/config.py`](../aivm/cli/config.py) (1195 L) with a directory `aivm/cli/config/` of focused submodules, one per CLI subcommand.

**Why it helps:**
- Today, finding the implementation of `aivm config init` requires scrolling through 1195 lines that also contain `show`, `format`, `paths`, `edit`, `discover`, and `lint`.
- Each subcommand has a clean cluster of helpers; splitting along that natural seam yields files in the 150–300 L range that read as one concern each.
- New subcommands become a clear "add a file" operation.

**Scope:**

- **Replace** `aivm/cli/config.py` with `aivm/cli/config/` directory.

**Expected output shape:**

```
aivm/cli/config/
├── __init__.py          # ConfigModalCLI registration + re-exports
├── init.py              # InitCLI + _init_default_summary*, _ssh_key_setup*,
│                        # _warn_high_resource_defaults,
│                        # _prompt_*, _review_init_defaults_interactive
├── show.py              # ConfigShowCLI, ConfigFormatCLI
├── paths.py             # ConfigPathsCLI + _path_status, _print_path,
│                        # _role_source, _vm_config_source,
│                        # _print_config_paths, _print_data_paths,
│                        # _print_libvirt_paths
├── edit.py              # ConfigEditCLI + _editor_command, _edit_path,
│                        # _resolve_config_edit_target
├── discover.py          # ConfigDiscoverCLI + _discover_vm_info,
│                        # _prompt_import_discovered_vm
└── lint.py              # ConfigLintCLI + _field_names, _lint_store_file,
                         # _lint_store_text
```

**Steps:**

1. Create the directory `aivm/cli/config/`. Move `cli/config.py`'s contents into the new submodules according to the mapping above. Helpers move with the CLI class that uses them.
2. Two helpers `_format_bool` and `_format_secret` are shared by both `init.py` and `show.py`. Put them in `aivm/cli/config/__init__.py` as private module-level functions, or duplicate them (3 lines each — duplication is fine here).
3. `aivm/cli/config/__init__.py` exports `ConfigModalCLI` and the individual CLI classes. Pattern: mirror what `aivm/cli/vm.py` does for `VMModalCLI`.
4. Any other module that currently does `from aivm.cli.config import ConfigModalCLI` should keep working — the package `__init__.py` re-exports it.
5. **Audit test imports:** `grep -rn "from aivm.cli.config import" tests/` lists:
   - `from aivm.cli.config import _render_init_default_summary` → now `from aivm.cli.config.init import _render_init_default_summary`.
   - `from aivm.cli.config import ConfigLintCLI, _lint_store_file` → now from `.lint`. Or keep them re-exported from `__init__.py` if you want zero test churn; **recommend re-exporting** so this PR is purely a source-move.
6. Run validation.

**Validation:**

```bash
python -m compileall aivm tests
aivm config --help
aivm config init --help
aivm config show --help
aivm config paths --help
aivm config edit --help
aivm config discover --help
aivm config lint --help
pytest -q tests/test_cli_config_init.py tests/test_cli_config_lint.py
pytest -q
```

**Risk & rollback:**
- Risk: a shared helper gets moved into the wrong submodule and creates a cross-module import where there was none. Resolve by moving the helper to `aivm/cli/config/_helpers.py` or by duplicating it.
- Risk: pre-existing `from .config import X` inside `aivm/cli/` (e.g., from `cli/main.py`) — should still resolve as long as `__init__.py` re-exports `X`.
- Rollback: `git revert`. The move is purely textual.

**Out of scope:**
- Do not refactor any function's body.
- Do not rename any function.
- Do not change CLI flags or output text.

---

### Task 5 — Split `aivm/attachments/persistent.py` into a package ✅ DONE (commits `c553c28`, `b5d50a3`)

**Lessons recorded (2026-05-21):**

1. The test file was tightly coupled to `aivm.attachments.persistent` as a flat module namespace, with ~50 `monkeypatch.setattr('aivm.attachments.persistent.X', ...)` calls. Five of those tests were verifying call shape/order rather than behavior; they were deleted first (commit `c553c28`). That dropped patch count enough to make the split tractable.

2. Internal cross-submodule calls use `from . import other_module` and reference the function as `other_module.func(...)`, *not* `from .other_module import func`. The module-reference pattern means a single `monkeypatch.setattr('aivm.attachments.persistent.transport._run_guest_root_script', ...)` intercepts the call regardless of which submodule invokes it — patches don't need to know the caller. This is the right pattern when callers are *inside the package*.

3. *External* callers (e.g. `aivm/vm/create_ops.py` does `from ..attachments.persistent import _ensure_persistent_root_parent_dir`) read the name from the package `__init__.py` re-export, not the submodule. Their test patches must stay at the `aivm.attachments.persistent.X` namespace; do not blindly remap them to the submodule.

**Pattern to reuse for future splits:** for each call site, ask "which module's namespace does Python look up the name in at call time?" — that's the monkeypatch target. The owning submodule is only the right target when callers also reach through the module reference.

**Goal:** Replace [`aivm/attachments/persistent.py`](../aivm/attachments/persistent.py) (1034 L) with `aivm/attachments/persistent/`, organized by concern (manifest building, ssh-retry transport, replay-service install).

**Why it helps:** Today, `persistent.py` mixes:
1. Building/diffing the on-host persistent-attachment manifest.
2. SSH-retry transport (`_run_guest_root_script`, `_run_guest_ssh_script_with_retry`, `_run_rsync_with_retry`, `_is_transient_ssh_transport_failure`).
3. Installing the systemd replay service inside the guest.
4. Reconciling host-side bind mounts (`_install_persistent_host_bind_replay`, `_reconcile_persistent_host_binds`).

Anyone touching the SSH-retry logic has to mentally skip past manifest builders, and vice versa. Splitting along these seams shortens each file to one purpose.

**Expected output shape:**

```
aivm/attachments/persistent/
├── __init__.py          # re-exports the public surface used elsewhere
├── manifest.py          # PersistentAttachmentRecord,
│                        # _persistent_*_path / _persistent_*_dir helpers,
│                        # _persistent_attachment_records_for_vm,
│                        # _persistent_attachment_manifest_text,
│                        # _sync_persistent_attachment_manifest_on_host,
│                        # _sync_persistent_attachment_manifest_to_guest
├── transport.py         # _run_guest_root_script,
│                        # _run_guest_ssh_script_with_retry,
│                        # _run_rsync_with_retry,
│                        # _is_transient_ssh_transport_failure,
│                        # _write_text_if_changed, _install_host_text_if_changed,
│                        # _install_guest_text_if_changed,
│                        # _diagnose_guest_text_mismatch,
│                        # _guest_text_*_script, _guest_text_sha256/stats
├── replay.py            # _install_persistent_attachment_replay,
│                        # _reconcile_persistent_attachments_in_guest,
│                        # _prepare_persistent_attachment_host_and_vm
└── host_bind.py         # _install_persistent_host_bind_replay,
                         # _reconcile_persistent_host_binds,
                         # _ensure_persistent_root_parent_dir,
                         # _ensure_persistent_root_vm_mapping,
                         # _ensure_persistent_root_host_bind,
                         # _persistent_root_host_dir,
                         # _persistent_host_replay_service_name
```

**Steps:**

1. Create the directory. Move definitions per the mapping above.
2. Update the existing `aivm/attachments/__init__.py` to import from the new submodules (the top-level path stays `aivm.attachments`, not `aivm.attachments.persistent.*` for callers outside the subpackage — see step 3).
3. Internal use within `aivm/attachments/*`: prefer importing from the specific submodule (`from .persistent.transport import _run_rsync_with_retry`), not from the package's `__init__.py`.
4. **Important:** Task 3 (the `_` rename pass) may have already renamed some of these. Use the names as they exist after Task 3. If Task 5 happens before Task 3, keep current `_` names.
5. Test files (`tests/test_attachment_persistent.py`) currently import from `aivm.attachments.persistent`. The package `__init__.py` should re-export the same names so test imports continue to work.

**Validation:**

```bash
python -m compileall aivm tests
pytest -q tests/test_attachment_persistent.py tests/test_attachment_session.py
pytest -q
```

**Risk & rollback:**
- Risk: a helper used by both `manifest.py` and `transport.py` ends up needing to import the other way. The dependency direction should be **transport → manifest** (manifest builders don't need ssh-retry). If you find the reverse, leave the helper in `transport.py` and let `manifest.py` import from it.
- Rollback: `git revert`. Mechanical move.

**Out of scope:**
- Do not rename functions in this task. Pure file move.
- Do not change behavior.

---

### Task 6 — Resolve `aivm/ops/` ambivalence ✅ DONE (commit `826c041`)

**Decision recorded (2026-05-21):** Option A (kill `ops/`). Rationale: scriptconfig CLI classes are also the programmatic API (`CliClass.main(argv=False, **kwargs)`), so the Request/Result layer was redundant for a CLI-only tool with no second consumer. `ops/vm_attach.py` and `ops/vm_update.py` were inlined into their `cli/` siblings; the `ops/` directory is gone.

**Goal:** Decide whether `aivm/ops/` is the canonical home for VM operation business logic. **Recommend: inline `ops/vm_attach.py` and `ops/vm_update.py` back into their CLI siblings** because (a) only two of ~12 VM commands use this pattern, (b) the request/response layer adds plumbing without paying off when the CLI class is the only caller.

**Why it helps:**
- Either commits to a layer or removes a dead-looking one. Today, an agent reading the repo sees `aivm/ops/` with two files and asks "is this where I add new operations?" — the answer is "no, not really". That confusion is a cost.
- Removing one directory shortens the mental model.

**Scope:**

- **Move:** `aivm/ops/vm_attach.py` (551 L) → merge into `aivm/cli/vm_attach.py` (132 L). The merged file will be ~600–700 L.
- **Move:** `aivm/ops/vm_update.py` (67 L) → merge into `aivm/cli/vm_update.py`.
- **Delete:** `aivm/ops/` directory entirely (including the docstring-only `__init__.py`).

**Steps:**

1. For `vm_attach`: copy the contents of `aivm/ops/vm_attach.py` into `aivm/cli/vm_attach.py` (above the `VMAttachCLI` class). Adjust imports: anything that was `from ..attachments` stays the same; anything that was `from ..store` becomes the new `from ..config_store` after Task 1.
2. Same for `vm_update`.
3. Update any importers — `grep -rn "from aivm.ops" aivm/ tests/`. There should be very few.
4. Delete `aivm/ops/`.

**Expected output shape:**

```
aivm/
├── cli/
│   ├── vm_attach.py    # now contains both CLI class AND business logic
│   └── vm_update.py    # same
└── ops/                # ← DELETED entirely
```

**Validation:**

```bash
python -m compileall aivm tests
grep -rn "aivm\.ops\|from aivm.ops" aivm/ tests/  # must be empty
pytest -q tests/test_cli_vm_attach.py tests/test_cli_vm_update.py
pytest -q
aivm attach --help
aivm vm update --help
```

**Risk & rollback:**
- Risk: tests import from `aivm.ops.vm_attach` directly (search `grep -rn "from aivm.ops" tests/`). Move those imports to `aivm.cli.vm_attach`.
- Rollback: `git revert`.

**Alternative if you disagree:** Build out `aivm/ops/` instead — move business logic from `cli/vm_lifecycle.py`, `cli/vm_connect.py`, `cli/vm_cache.py`, `cli/vm_config.py` into corresponding `ops/*.py` modules. This is a much larger change and creates the same boilerplate everywhere. **Not recommended** unless the agent reading this strongly prefers the layered pattern.

**Out of scope:**
- Don't refactor function bodies.
- Don't rename Request/Result classes.

---

### Task 7 — Split `aivm/commands.py` into a package ⏸ DEFERRED

**Decision recorded (2026-05-21):** Maintainer prefers `commands.py` stays a single file for now. The module is critical to get right, and keeping the data classes + manager in one place makes that easier than spreading them across submodules. Revisit only if the file starts attracting unrelated concerns.

**Goal:** Replace [`aivm/commands.py`](../aivm/commands.py) (1238 L) with `aivm/commands/` directory: data types in one file, the manager in another.

**Why it helps:**
- `CommandManager` has ~30 methods. Reading them is hard when interleaved with data class definitions.
- The data classes (`CommandResult`, `CommandError`, `CommandSpec`, `CommandHandle`, `CommandPlan`, `PlannedCommand`, `IntentFrame`) form a stable, simple API that's worth its own file for browsing.

**This task is lower priority than 1–6.** Only run if the code is actively being read/edited and 1238 L is a real friction point. The module is internally cohesive.

**Expected output shape:**

```
aivm/commands/
├── __init__.py          # re-exports CommandManager, CommandResult,
│                        # CommandError, CommandSpec, CommandHandle,
│                        # CommandPlan, IntentFrame, IntentScope, PlanScope,
│                        # CommandRole, shell_join
├── types.py             # CommandResult, CommandError, CommandSpec,
│                        # CommandHandle, PlannedCommand, CommandPlan,
│                        # IntentFrame, CommandRole, shell_join
└── manager.py           # IntentScope, PlanScope, CommandManager
```

**Steps:**

1. Create `aivm/commands/types.py` and move the data classes + `shell_join` + the `CommandRole` `Literal` alias.
2. Create `aivm/commands/manager.py` with `IntentScope`, `PlanScope`, `CommandManager`. Import data classes from `.types`.
3. Create `aivm/commands/__init__.py` that re-exports everything currently importable from `aivm.commands`. Existing `from aivm.commands import CommandManager` keeps working.
4. Delete `aivm/commands.py`.

**Validation:**

```bash
python -m compileall aivm tests
grep -rn "from aivm.commands" aivm/ tests/  # all should still resolve
pytest -q
```

**Risk & rollback:** Low — pure move with re-exports. `git revert`.

**Out of scope:**
- Don't change behavior.
- Don't change `_stacklevel` threading or any logging.

---

### Task 8 (optional) — Split `tests/test_vm_helpers.py`

**Goal:** Break `tests/test_vm_helpers.py` (1969 L) into focused test modules so future moves of source code don't require editing one giant file.

**Why it helps:** Test-file size doesn't directly affect users, but it does affect every refactor PR's diff size and reviewer fatigue.

**Suggested split:**

- `tests/test_vm_share_helpers.py` — tests targeting `aivm/vm/share.py` helpers.
- `tests/test_vm_lifecycle_helpers.py` — tests targeting `aivm/vm/lifecycle.py`.
- `tests/test_vm_drift_helpers.py` — tests targeting `aivm/vm/drift.py` (if any here, otherwise leave with `test_vm_drift.py`).

**Steps:**
1. Group tests in `test_vm_helpers.py` by what they exercise.
2. Move each group into a new file.
3. Run `pytest -q tests/` to confirm coverage is unchanged.

**Validation:**

```bash
pytest -q
# Confirm no test was lost:
pytest --collect-only -q | wc -l   # before and after; numbers match
```

**Risk & rollback:** Trivial.

**Out of scope:** Don't change test bodies.

---

## 3. Suggested execution order

1. ~~**Task 2** (smallest deletion, 1 internal importer)~~ ✅ done
2. ~~**Task 1** (medium deletion, ~30 importers)~~ ✅ done
3. ~~**Task 3** (underscore-rename — biggest impact on readability)~~ ✅ done
4. ~~**Task 4** (split `cli/config.py`)~~ ✅ done
5. ~~**Task 5** (split `attachments/persistent.py`)~~ ✅ done (after test triage)
6. ~~**Task 6** (resolve `ops/`)~~ ✅ done (Option A: kill)
7. ~~**Task 7** (split `commands.py`)~~ ⏸ deferred
8. **Task 8** (optional, do alongside whichever source change forces it)

Tasks 4 and 5 are independent and can be done in parallel by different agents.

After each task: bump a line in `CHANGELOG.md`'s `0.5.0` (Unreleased) section under "Internal" — e.g., "Removed `aivm.store` facade; callers import from `aivm.config_store` directly."

---

## 4. Things to deliberately NOT do

These came up during the audit and were rejected. Don't bring them back without new evidence.

- **Don't split `aivm/status.py`.** It's 872 L but internally cohesive (probes + renderers + sudo-anticipation), and probes are imported across files. Splitting creates re-export churn without payoff.
- **Don't split `aivm/attachments/session.py` aggressively.** It holds session lifecycle; the natural sub-split is `records.py` vs `lifecycle.py`, but the records helpers are tightly woven into `_prepare_attached_session`. Pulling them out creates a many-arg interface. Leave it.
- **Don't introduce new abstractions** (plugin registries, dependency injection containers, request/response generics). The package is small enough that direct function calls + dataclasses are clearer.
- **Don't add a public Python API.** Per project policy, only the CLI is public. Resist the temptation to define `aivm.api` or similar.
- **Don't move `config.py` (top-level) into `config_store/`.** The split is intentional: `config.py` is user-facing dataclasses (NetworkConfig, FirewallConfig, AgentVMConfig); `config_store/` is registry I/O.

---

## 5. After the dust settles

Once tasks 1–7 are done, the package layout looks like:

```
aivm/
├── __init__.py              # __version__, main
├── __main__.py
├── attachments/
│   ├── __init__.py          # alphabetical, no leading-underscore exports
│   ├── guest.py
│   ├── persistent/
│   │   ├── __init__.py
│   │   ├── host_bind.py
│   │   ├── manifest.py
│   │   ├── replay.py
│   │   └── transport.py
│   ├── resolve.py
│   ├── session.py
│   └── shared_root.py
├── cli/
│   ├── __init__.py
│   ├── _common.py
│   ├── config/
│   │   ├── __init__.py
│   │   ├── discover.py
│   │   ├── edit.py
│   │   ├── init.py
│   │   ├── lint.py
│   │   ├── paths.py
│   │   └── show.py
│   ├── firewall.py
│   ├── help.py
│   ├── host.py
│   ├── main.py
│   ├── net.py
│   ├── vm.py
│   ├── vm_attach.py          # now includes ops/vm_attach contents
│   ├── vm_cache.py
│   ├── vm_config.py
│   ├── vm_connect.py
│   ├── vm_lifecycle.py
│   └── vm_update.py          # now includes ops/vm_update contents
├── commands/
│   ├── __init__.py
│   ├── manager.py
│   └── types.py
├── config.py                 # user-facing dataclasses, unchanged
├── config_store/             # canonical store, unchanged
│   ├── __init__.py
│   ├── io.py
│   ├── models.py
│   ├── mutate.py
│   ├── parse.py
│   ├── paths.py
│   ├── render.py
│   └── resolve.py
├── detect.py
├── errors.py
├── firewall.py
├── host.py
├── net.py
├── persistent_replay.py
├── resource_checks.py
├── runtime.py
├── status.py
├── util.py
└── vm/
    ├── __init__.py           # alphabetical, no leading-underscore exports
    ├── cloudinit.py
    ├── connectivity.py
    ├── create.py
    ├── create_ops.py
    ├── disk.py
    ├── domain.py
    ├── drift.py
    ├── guest_tools.py
    ├── host_access.py
    ├── images.py
    ├── lifecycle.py
    ├── paths.py
    ├── provision.py
    ├── share.py
    ├── update/
    │   ├── __init__.py
    │   ├── apply.py
    │   ├── detect.py
    │   ├── models.py
    │   ├── render.py
    │   ├── restart.py
    │   ├── util.py
    │   └── virtiofs.py
    └── virtiofsd_wrapper.py
```

**Files deleted:** `aivm/store.py`, `aivm/vm/update_ops.py`, `aivm/commands.py`, `aivm/cli/config.py`, `aivm/attachments/persistent.py`, `aivm/ops/` directory.

**Net effect:**
- 5 modules deleted outright (all pure facades or replaced by packages).
- 4 mega-files split into focused subpackages.
- 1 directory (`ops/`) removed.
- All `__init__.py` `__all__` lists become honest: only public names, alphabetical.
- The mental model becomes: "Each subpackage owns a concern. `__init__.py` tells you what's public. Submodule filenames tell you what's where."

---

## 6. Open questions for the human reviewer

All three open questions have been answered (2026-05-21):

1. ✅ **Tests may import `_`-prefixed names from submodules.** Task 3 followed this path — `__init__.py` files were shrunk; private helpers stay in their owning submodule.
2. ✅ **Kill `ops/` (Option A).** scriptconfig already serves as the programmatic API, so a Request/Result layer is redundant. Task 6 inlined `ops/*.py` into `cli/*.py` and deleted the directory.
3. ✅ **Keep `commands.py` unified.** Task 7 deferred — the module is critical and easier to reason about as one file.
