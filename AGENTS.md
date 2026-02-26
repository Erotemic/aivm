# AGENTS.md

## Purpose
Guidance for contributors (human or AI agents) working in this repository.

## Project Context
- Package / CLI name: `aivm`
- Primary goal: manage local libvirt/KVM VMs for agent workflows.
- Config model:
  - User/global registry + per-VM config under app config dir via `ub.Path.appdir('aivm', type='config')`
  - Optional per-directory metadata: `.aivm-dir.toml`

## Core CLI UX Principles
- Prefer simple defaults:
  - `aivm code .`
  - `aivm ssh .`
- Ask before privileged operations unless `--yes` is provided.
- Status should be safe and informative by default; privileged checks are opt-in via `--sudo`.
- Discovery/import should be explicit and user-confirmed for unmanaged VMs.

## Safety Expectations
- Do not silently broaden VM host-path exposure.
- Avoid attaching the same host folder to multiple VMs unless user forces it.
- Surface clear diagnostics for share/network/firewall mismatches.
- Prefer live libvirt metadata when config may be stale (bridge/network details).

## Development Notes
- Keep changes focused and incremental.
- Preserve non-interactive usability (`--yes`, `--dry_run`).
- Keep docs updated when CLI behavior or command tree changes.

## Useful Local Commands
- Lint/type/test (as available in environment):
  - `python -m py_compile aivm/*.py`
  - `pytest -q`
  - `ty check aivm`
- CLI help and structure:
  - `aivm --help`
  - `aivm help tree`

## Packaging
- Source of truth is `pyproject.toml`.
- Runtime dependencies must be declared in `[project].dependencies`.

## Experimental Status
This project was written with GPT-5.3 Codex and is still being evaluated for correctness and safety. It is currently for experimental use only.
