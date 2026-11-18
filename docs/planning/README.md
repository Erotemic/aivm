# AIVM planning index

This is the single index for **unfinished design, research, and implementation
planning**. A document's own status controls whether it is an approved plan;
appearance in this index does not imply approval or that an older implementation
status has been revalidated. Especially for the July 2026 designs, confirm
current code and CI before starting work.

Implemented behavior and operational contracts belong under
[`../architecture/`](../architecture/README.md) and
[`../reference/`](../reference/README.md). Dated reviews belong under
[`../audits/`](../audits/README.md), and completed/superseded plans under
[`../history/`](../history/README.md). The original July 2026 future-design
roadmap is preserved [here](../history/2026-07-future-design-roadmap.md).

## Forward-looking AIVM designs

| Subject | Document | Status recorded in document |
| --- | --- | --- |
| External virtiofsd backend | [external-virtiofsd.md](external-virtiofsd.md) | Designed; implementation not started at time of writing |
| Egress allowlist networking | [egress-allowlist.md](egress-allowlist.md) | Designed; implementation not started at time of writing |
| Snapshots, rollback, and clones | [snapshots-and-clones.md](snapshots-and-clones.md) | Designed; implementation not started at time of writing |
| E2E suites in CI | [ci-e2e.md](ci-e2e.md) | Designed; implementation not started at time of writing |
| Flexible folder sharing | [flexible-folder-sharing.md](flexible-folder-sharing.md) | Partly implemented; exploratory alternatives remain |
| Firewall lifecycle and delegation | [firewall-lifecycle-and-delegation-2026-10.md](firewall-lifecycle-and-delegation-2026-10.md) | Proposal; see its decision boundaries |
| Privileged operations broker | [privileged-operations-broker-proposal-2026-10.md](privileged-operations-broker-proposal-2026-10.md) | Exploratory; **not approved** |

## AIVM Secrets research and remediation

These documents retain their source status; no new decision or assertion of
completion is made by this reorganization. AIVM Secrets is a separate
experimental sibling project, so ownership of these documents merits a later
review, not a mechanical relocation now.

- [October 2026 remediation plan](aivm-secrets-2026-10-remediation.md)
- [Formal assurance and refinement plan](aivm-secrets-formal-assurance.md)
- [Modular proof architecture](aivm-secrets-modular-proof-architecture.md)
- [Garrett rollback and clone policy](aivm-secrets-garrett-rollback-clone-policy.md)
- [Garrett vTPM policy](aivm-secrets-garrett-vtpm-policy.md)

## Candidates and deferred approaches

- **Candidate, not approved:** [nftables sudoers rule](candidate_ideas/nft-nopasswd-sudoers.md)
- **Brainstorm, not approved:** [guest OS abstraction](candidate_ideas/guest-os-abstraction.md)
- **Previously implemented then removed:** [rootless session runtime](deferred/session-runtime.md), deferred pending external virtiofsd and security reconsideration

## Related records (not active planning)

- [Shared-machine implementation roadmap](../history/shared-machine-roadmap.md) — completed roadmap preserved as written
- [Personal machine-store decision](../reference/personal-machine-store.md) — implemented rationale
- [Released-store migration plan and commands](../reference/released-store-migration-plan.md) — operational reference
- [Multi-user onboarding review](../audits/multi-user-onboarding-preflight-2026-10.md) — dated review
- [Command approval audit](../audits/command-approval-audit.md) — generated review snapshot
- [October codebase/UX audit](../audits/2026-10-29-codebase-issues-and-ux-audit.md) — findings and follow-up

The next pass can reconcile overlapping content, current implementation, and
open work. **This pass only relocates and indexes source documents; it does
not approve proposals, delete reasoning, or declare remediations complete.**
