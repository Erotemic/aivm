# AIVM Roadmap

Updated: 2026-07-16

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

## Supporting design notes

- [flexible-folder-sharing.md](flexible-folder-sharing.md) documents the current
  attachment backends, device-slot scaling, and the unresolved long-lived
  virtiofs file-descriptor problem.
- [guest-os-abstraction.md](guest-os-abstraction.md) — **Brainstorm; not
  designed, not started.** A guest-OS seam so aivm can boot something other
  than Ubuntu 24.04, with NixOS as the deliberately-hostile second profile.
  Records a research session: NixOS *does* support the NoCloud seed-ISO path
  (nixpkgs CI proves it), but `/etc/systemd/system` is a read-only store
  symlink, which breaks how both guest agents install themselves. Argues the
  seam must be capability-shaped rather than a data record of nullable
  fields, since `sshd_dropin_dir: None` silently drops ssh hardening. Also
  records why no existing library (libosinfo, mkosi, cloud-init's `distros/`,
  distrobuilder) carries the abstraction, and why image fetching cannot use
  pooch/`grabdata` (the transport must stay inside `CommandManager`). Has
  open questions that must be closed before it is executable.

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
