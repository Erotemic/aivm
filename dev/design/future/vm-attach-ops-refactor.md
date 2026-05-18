# VM attach operation refactor checkpoint

Written: 2026-05-15
Baseline source snapshot: `5c7effe87377ca29b832eeeda76e2da0f0e37b20`

## Goal

Move attach/detach orchestration out of the CLI layer without touching the
command execution engine.  This keeps `aivm/commands.py`, sudo prompting,
dry-run execution, and command rendering out of scope.

## Current split

`aivm/cli/vm_attach.py` is now a thin CLI entrypoint.  It owns scriptconfig
argument declarations and converts parsed arguments into request dataclasses.

The workflow implementation lives in `aivm/ops/vm_attach.py`:

- `VMAttachRequest`
- `VMDetachRequest`
- `VMPersistentHostReplayRequest`
- `VMInstallPersistentHostReplayServiceRequest`
- `run_vm_attach(...)`
- `run_vm_detach(...)`
- `run_persistent_host_replay(...)`
- `run_install_persistent_host_replay_service(...)`

The operation module currently still uses common config-resolution helpers from
`aivm.cli._common`.  That is acceptable for this checkpoint because the goal is
to move workflow code out of the command class, not to fully separate all CLI
support helpers yet.

## Rules going forward

- Keep `aivm/cli/vm_attach.py` thin.
- Patch private attach/detach workflow seams at `aivm.ops.vm_attach.*` in tests.
- Do not reintroduce `aivm.cli.vm_attach` as the owner of attachment workflow
  internals.
- Do not touch `aivm/commands.py` as part of attachment operation cleanup.

## Suggested next cleanup

The operation extraction exposes the next useful seam: split attachment internals
by responsibility rather than by CLI flow.  Candidate modules include:

- `aivm/attachments/host_exports.py`
- `aivm/attachments/guest_mounts.py`
- `aivm/attachments/persistent_manifest.py`
- `aivm/attachments/virtiofs_mapping.py`

## Suggested validation

```bash
python -m py_compile $(find aivm -name '*.py' | sort)
pytest tests/test_attachment_session.py \
       tests/test_attachment_shared_root.py \
       tests/test_cli_vm_detach.py
```
