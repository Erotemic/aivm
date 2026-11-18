# November 2026 documentation relocation

This is a path-level reorganization of existing plans, designs and reviews.
The relocated documents retain their original prose and design decisions;
relative links were corrected where necessary. Moving a proposal to planning
is **not** approval, and moving a completed roadmap to history does not mean
that every follow-up item is closed.

| Previous location | Current location |
| --- | --- |
| `docs/planning/shared-machine-roadmap.md` | [`docs/history/shared-machine-roadmap.md`](shared-machine-roadmap.md) |
| `docs/planning/personal-machine-store.md` | [`docs/reference/personal-machine-store.md`](../reference/personal-machine-store.md) |
| `docs/planning/released-store-migration-plan.md` | [`docs/reference/released-store-migration-plan.md`](../reference/released-store-migration-plan.md) |
| `docs/planning/multi-user-onboarding-preflight-2026-10.md` | [`docs/audits/multi-user-onboarding-preflight-2026-10.md`](../audits/multi-user-onboarding-preflight-2026-10.md) |
| `docs/planning/command-approval-audit.md` | [`docs/audits/command-approval-audit.md`](../audits/command-approval-audit.md) |
| `dev/design/future/README.md` | [`docs/history/2026-07-future-design-roadmap.md`](2026-07-future-design-roadmap.md) |
| `dev/design/future/ci-e2e.md` | [`docs/planning/ci-e2e.md`](../planning/ci-e2e.md) |
| `dev/design/future/egress-allowlist.md` | [`docs/planning/egress-allowlist.md`](../planning/egress-allowlist.md) |
| `dev/design/future/external-virtiofsd.md` | [`docs/planning/external-virtiofsd.md`](../planning/external-virtiofsd.md) |
| `dev/design/future/flexible-folder-sharing.md` | [`docs/planning/flexible-folder-sharing.md`](../planning/flexible-folder-sharing.md) |
| `dev/design/future/guest-os-abstraction.md` | [`docs/planning/candidate_ideas/guest-os-abstraction.md`](../planning/candidate_ideas/guest-os-abstraction.md) |
| `dev/design/future/snapshots-and-clones.md` | [`docs/planning/snapshots-and-clones.md`](../planning/snapshots-and-clones.md) |

References in historical changelog/journal entries continue to describe the
paths that existed when those entries were written. The two EMFILE incident
record sets under `dev/devcheck/` were deliberately not deduplicated in this
pass because their content differs. Deletion or consolidation of source prose
requires a separate review.
