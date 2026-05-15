# VM update refactor checkpoint

Written: 2026-05-15
Baseline source snapshot: `5c7effe87377ca29b832eeeda76e2da0f0e37b20`

## Goal

Make VM update easier to reason about without touching the command execution
engine.  This keeps `aivm/commands.py`, sudo prompting, dry-run command
execution, and command rendering out of scope.

The old `aivm/vm/update_ops.py` file mixed several concerns:

- drift model definitions
- hardware/disk/XML drift detection
- virtiofs binary cleanup detection and application
- plan rendering
- drift application
- restart prompting/execution

## Current split

`aivm/vm/update_ops.py` is now a compatibility facade.  The implementation lives
under `aivm/vm/update/`:

- `models.py`
  - `RestartKind`
  - `VirtiofsBinaryDrift`
  - `VMUpdateDrift`
  - `_escalate`

- `util.py`
  - byte formatting helpers
  - qemu-img JSON parsing
  - libvirt XML path/network parsing
  - domblkinfo capacity parsing

- `detect.py`
  - `_vm_update_drift`
  - disk path resolution
  - qemu-img/domblkinfo probes
  - network drift notes

- `virtiofs.py`
  - `_virtiofs_binary_drift`
  - `_apply_virtiofs_binary_drift`
  - cleanup-only handling for legacy AIVM-generated virtiofsd wrapper paths

- `render.py`
  - `_print_vm_update_plan`

- `apply.py`
  - `_apply_vm_update`

- `restart.py`
  - `_maybe_restart_vm_after_update`

## Operation layer

`aivm/ops/vm_update.py` now owns the high-level update workflow.  The CLI builds
`VMUpdateRequest` and calls `run_vm_update(...)`.

This gives us a seam for future workflow testing without re-coupling tests to
private CLI globals.

## Rules going forward

- Keep `aivm/commands.py` unchanged until the command/logging refactor is
  explicitly resumed.
- Keep `aivm/vm/update_ops.py` as a re-export facade while tests and callers
  migrate gradually.
- Put new update detection helpers in `aivm/vm/update/detect.py`.
- Put new update application helpers in `aivm/vm/update/apply.py` or
  `aivm/vm/update/virtiofs.py`, depending on scope.
- Do not reintroduce generated host-side virtiofsd wrappers.  Current virtiofs
  update support is cleanup-only for stale wrapper XML.

## Suggested validation

```bash
python -m py_compile $(find aivm -name '*.py' | sort)
pytest tests/test_cli_vm_update.py tests/test_virtiofsd_wrapper.py
```
