# VM CLI split checkpoint

Written: 2026-05-15
Baseline source snapshot: `5c7effe87377ca29b832eeeda76e2da0f0e37b20`

## Goal

Reduce the size and responsibility of `aivm/cli/vm.py` before deeper
operation-layer, logging, attachment, and runtime-backend refactors.

This checkpoint is intentionally behavior-preserving.  It moves VM command
classes into focused modules but keeps the existing public import surface and
legacy private monkeypatch targets available through `aivm.cli.vm`.

## Current module split

`aivm/cli/vm.py` is now a compatibility facade and ModalCLI registration point.
It re-exports the VM command classes and a few helper functions that tests and
callers have historically imported from this module.

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
  - `VMConfigPathCLI`
  - `VMEditCLI`

- `aivm/cli/vm_update.py`
  - `VMUpdateCLI`

- `aivm/cli/_vm_compat.py`
  - Temporary dependency proxy used by split modules to keep old
    `aivm.cli.vm.<private-helper>` monkeypatch targets working during the
    compatibility phase.

## Intentional compatibility shim

The split command modules currently resolve many private helper dependencies
through `aivm.cli.vm` at call time.  This is not the final architecture, but it
keeps the first split low-risk by preserving existing tests and callers that
patch private helpers on the old module.

This shim should disappear after the next operation-layer refactor.  The target
shape is:

1. CLI modules parse arguments and format command output.
2. Operation modules own workflows such as attach, detach, code, and update.
3. Tests patch operation-layer seams rather than private globals on
   `aivm.cli.vm`.
4. `aivm.cli.vm` remains only the ModalCLI registration facade.

## Next high-value follow-up

Extract operation functions from the focused CLI modules, starting with attach
and update:

- `aivm/ops/vm_attach.py`
- `aivm/ops/vm_detach.py`
- `aivm/ops/vm_code.py`
- `aivm/ops/vm_update.py`

Once those exist, remove the `_vm_compat` proxy layer and update tests to patch
the narrower operation seams.

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
