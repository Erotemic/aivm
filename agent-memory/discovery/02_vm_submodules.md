# Historical VM-submodules discovery note

This file was an exploratory snapshot from the pre-0.6 codebase. It referenced
retired VM modules and settings-synchronization workflows, so it is
intentionally no longer used as current architecture documentation.

For the current VM/network/host lifecycle structure, use:

- `docs/architecture/README.md`;
- `docs/architecture/architecture.yaml`;
- `docs/architecture/generated/component-edges.json`;
- `docs/architecture/generated/flow-create-machine.mmd`;
- `docs/architecture/generated/flow-vm-deletion.mmd`;
- `docs/source/workflows.rst`.

Regenerate/check architecture documentation with
`python dev/devcheck/architecture_docs.py check` rather than maintaining a
second handwritten module inventory here.
