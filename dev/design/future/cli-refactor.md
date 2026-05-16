# VM CLI split checkpoint

Written: 2026-05-15
Baseline source snapshot: `5c7effe87377ca29b832eeeda76e2da0f0e37b20`

## Goal

Reduce the size and responsibility of `aivm/cli/vm.py` before deeper
operation-layer, logging, attachment, and runtime-backend refactors.

The CLI is the public interface.  Private Python import paths are internal and
should not drive the design.  Tests may import or monkeypatch private helpers,
but those tests should patch the helper at its owning module rather than force
`aivm.cli.vm` to preserve historical private names.

## Current module split

`aivm/cli/vm.py` is now only a ModalCLI registration point plus public command
class re-exports used by the top-level CLI.

Focused modules:

- `aivm/cli/vm_lifecycle.py`
  - `VMUpCLI`
  - `VMDownCLI`
  - `VMRestartCLI`
  - `VMCreateCLI`
  - `VMStatusCLI`
  - `VMDestroyCLI`
  - `VMProvisionCLI`
  - `VMListCLI`

- `aivm/cli/vm_connect.py`
  - `VMWaitIPCLI`
  - `VMSshConfigCLI`
  - `VMCodeCLI`
  - `VMSSHCLI`
  - VS Code remote helper functions

- `aivm/cli/vm_attach.py`
  - `VMAttachCLI`
  - `VMDetachCLI`
  - `VMPersistentHostReplayCLI`
  - `VMInstallPersistentHostReplayServiceCLI`

- `aivm/cli/vm_config.py`
  - `VMEditCLI`

- `aivm/cli/vm_update.py`
  - `VMUpdateCLI`

## No private compatibility facade

The first CLI split briefly used a `_vm_compat` proxy so split modules could
resolve dependencies through `aivm.cli.vm` and keep old private monkeypatch paths
working.  That was intentionally removed.

Reasoning:

- `aivm.cli.vm` is not a public Python API.
- The CLI command behavior is the compatibility boundary.
- A proxy layer hides dependencies and makes the split modules harder to read.
- Tests should patch the module that owns the dependency now that the code is
  split.

Rule going forward:

- `aivm/cli/vm.py` should remain small.
- Do not reintroduce a broad private compatibility shim.
- If a helper is needed in multiple CLI modules, move it to a clear owner such
  as `_common.py`, an attachment module, or a future operation module.

## Next high-value follow-up

Extract operation functions from the focused CLI modules, starting with attach
and update:

- `aivm/ops/vm_attach.py`
- `aivm/ops/vm_detach.py`
- `aivm/ops/vm_code.py`
- `aivm/ops/vm_update.py`

The target shape is:

1. CLI modules parse arguments and format command output.
2. Operation modules own workflows such as attach, detach, code, and update.
3. Tests patch operation-layer seams rather than CLI module private globals.
4. `aivm.cli.vm` remains only the ModalCLI registration facade.

## Suggested validation

```bash
python -m py_compile $(find aivm -name '*.py' | sort)
pytest tests/test_cli_vm_create.py \
       tests/test_cli_vm_code.py \
       tests/test_cli_vm_detach.py \
       tests/test_cli_vm_update.py \
       tests/test_attachment_session.py \
       tests/test_attachment_shared_root.py \
       tests/test_cli_helpers.py
```

## Checkpoint: VM update operation extraction

The next CLI cleanup step moved the update workflow out of
`aivm/cli/vm_update.py` and into `aivm/ops/vm_update.py`.

Current ownership:

- `aivm/cli/vm_update.py`
  - parses CLI arguments
  - validates the `--restart` option via the operation helper
  - loads the selected VM config
  - calls `run_vm_update(...)`

- `aivm/ops/vm_update.py`
  - owns the high-level update workflow
  - computes drift
  - renders the update plan
  - applies drift inside the update intent
  - handles post-update restart policy

This keeps the CLI command public behavior unchanged while making the workflow
usable by future non-CLI callers and easier to test at the operation layer.
Private tests should patch `aivm.ops.vm_update.*` for update workflow seams.

## Checkpoint: VM attach/detach operation extraction

The attach/detach CLI workflow has now been moved out of
`aivm/cli/vm_attach.py` and into `aivm/ops/vm_attach.py`.

Current ownership:

- `aivm/cli/vm_attach.py`
  - parses CLI arguments
  - builds request dataclasses
  - delegates to operation functions

- `aivm/ops/vm_attach.py`
  - owns attach, detach, persistent host replay, and persistent replay service
    workflows
  - resolves config for attach/detach operations
  - probes VM state
  - records/removes attachment intent
  - reconciles guest and host attachment state

This keeps CLI behavior unchanged while reducing CLI module size and creating a
clear seam for future attachment-internal refactors.  Tests that need to patch
private attach/detach workflow helpers should patch `aivm.ops.vm_attach.*`, not
`aivm.cli.vm_attach.*`.
