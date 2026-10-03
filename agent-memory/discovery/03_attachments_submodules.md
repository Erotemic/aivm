# Historical attachments discovery note

This file was an exploratory snapshot from before the current attachment model
settled. It used the old `shared` mode name and predates the default
`persistent` backend, principal-owned attachment records, persistent replay,
and the current foreground-session invariants.

For current attachment behavior, use:

- `README.rst` and `docs/source/workflows.rst` for operator-facing modes;
- `docs/source/virtiofs.rst` for the long-lived virtiofs guard and operational
  guidance;
- `docs/architecture/generated/flow-attachments.mmd` for the validated runtime
  flow;
- `docs/architecture/generated/state-ownership.mmd` for attachment ownership;
- `aivm/attachments/` for implementation details.

Current mode names are `persistent`, `shared-root`, `direct-virtiofs`, and
`git`. The old `shared` spelling is intentionally rejected rather than kept as
an alias.
