# AIVM Roadmap

Updated: 2026-07-15

This directory contains active forward-looking design documents. Completed,
removed, and superseded implementation plans belong in git history rather than
this index.

## Major efforts

| # | Effort | Doc | Status |
|---|--------|-----|--------|
| 1 | Externally-managed virtiofsd backend | [external-virtiofsd.md](external-virtiofsd.md) | Designed; not started |
| 2 | Egress allowlist networking | [egress-allowlist.md](egress-allowlist.md) | Designed; not started |
| 3 | Snapshots, rollback, ephemeral clones | [snapshots-and-clones.md](snapshots-and-clones.md) | Designed; not started |
| 4 | E2E suites in CI | [ci-e2e.md](ci-e2e.md) | Designed; not started |

The external virtiofsd and E2E efforts should ideally advance together because
share-backend changes need lifecycle coverage on a real libvirt host. Egress
policy and snapshots are independent of those efforts and of each other.

## Supporting design note

- [flexible-folder-sharing.md](flexible-folder-sharing.md) documents the current
  attachment backends, device-slot scaling, and the unresolved long-lived
  virtiofs file-descriptor problem.

## Smaller tracked improvements

1. **Command policy model.** Replace the overloaded `read`/`modify` role with a
   model that separately represents mutation, privilege boundary, and command
   target. The top-of-file TODO in `aivm/commands.py` is the current anchor.
2. **Digest-addressed image cache.** Cached images are checksum-verified, but
   cache identity is still name-based. Add digest-keyed lookup and storage while
   preserving named-path compatibility.
3. **QEMU guest agent.** Add the guest-agent channel and prefer it for readiness,
   IP discovery, and diagnostics before falling back to SSH/libvirt leases.
4. **Unified host diagnostics.** Fold the useful checks from
   `aivm host sudoless check` into `aivm host doctor` so operators have one
   readiness entry point.
5. **Test infrastructure.** Introduce a recording command-manager fixture,
   favor observable-artifact assertions over call-shape mocks, and split the
   oversized `tests/test_vm_helpers.py` module.
