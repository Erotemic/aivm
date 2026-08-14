# AGENTS.md

## Purpose
Guidance for contributors (human or AI agents) working in this repository.

## Project Context
- Package / CLI name: `aivm`
- Primary goal: manage local libvirt/KVM VMs for agent workflows.
- Config model:
  - Existing released per-user stores remain readable and are not silently
    migrated.
  - Fresh implicit 0.6 installations use the machine-global store under
    `/var/lib/aivm` plus a private XDG user profile.
  - Managed VMs persist host-to-guest principals. `aivm config init` joins a
    later user only when the hostname-qualified name exactly matches a managed
    record, then enrolls through the forced `aivm-guestctl` bootstrap channel.
    Never reintroduce shadow machine stores, silently adopt an unmanaged
    same-name domain, or use the bootstrap key for interactive access.
  - Machine-store attachments are globally visible but principal-owned. New
    records must carry the selected principal, ordinary path resolution and
    session restoration must remain caller-scoped, and another owner's record
    requires an explicit administrative override to mutate or detach.
  - Machine-store repository credentials are principal-owned. Metadata may be
    shown machine-wide, but private host keys, provider authentication,
    guest-home installation, revocation, and abandonment must execute only as
    the owning host principal. Never treat trusted-host administration as
    permission to borrow another user's secrets.
  - Released per-user stores are migrated only through an explicit reviewed
    plan. Migration planning must remain read-only, fingerprint every source,
    and fail closed on multiple stores claiming one VM. Do not silently merge,
    rewrite, or delete released stores.
  - New operator-facing text calls a persisted host-to-guest principal an
    “access identity”; keep the internal schema names stable until a separate
    terminology change is chosen.
  - Disabling an access identity removes only its recorded guest public key and
    AIVM sudoers fragment. Retain the guest account/home, unrelated keys,
    attachments, credentials, and provider revocation metadata.
  - Removing an access identity is forbidden while attachment or credential
    records refer to it. Never silently transfer ownership or delete those
    records as a side effect.
  - VM/network lifecycle commands on a machine store must make their global
    effect visible. Ownership fields guard ordinary operation, but unrestricted
    root and system-libvirt administrators are outside AIVM's enforcement
    boundary.
  - Authorization identities come from kernel UID/GID plus the passwd database;
    never use `USER`, `LOGNAME`, or `SUDO_USER` to select an access identity.
  - Privileged persistent mounts must operate on held, no-symlink directory
    descriptors and verify the approved filesystem identity.
  - Destructive lifecycle operations must retain durable recovery coordinates
    until all external cleanup and final state persistence succeed.
  - Optional per-directory metadata: `.aivm-dir.toml`

## Core CLI UX Principles
- Prefer simple defaults:
  - `aivm code .`
  - `aivm ssh .`
- Ask before privileged operations unless `--yes` is provided.
- Status should be safe and informative by default; privileged checks are opt-in via `--sudo`.
- Discovery/import should be explicit and user-confirmed for unmanaged VMs.
- Treat ``aivm ssh`` and every ``aivm code`` launcher as one foreground-session
  workflow. They must source VM/attachment/startup checks from the same shared
  preparation function; launcher-specific behavior begins only after that
  preparation succeeds.
- Foreground entry into an already-running VM is non-destructive. It may verify
  or add the requested attachment, but it must not unmount, remount, replace,
  or globally reconcile an existing live workspace. Diagnose genuine conflicts
  and leave live state untouched; destructive convergence belongs to explicit
  attach/maintenance/lifecycle operations.
- Launcher-specific preparation starts only after the shared foreground session
  pipeline. In particular, ``aivm code --tunnel`` treats the tunnel request as
  a one-shot opt-in to install only missing tunnel prerequisites; it must not
  rerun full provisioning or make ``aivm ssh`` carry editor-specific checks.
- Keep reusable guest launcher logic inspectable. The VS Code tunnel controller
  lives at ``/usr/local/libexec/aivm/code-tunnel`` and normal logs should invoke
  that helper with ordinary arguments instead of sending an anonymous shell
  program over SSH.

## Auditability by Imitation
AIVM's command logging is part of its trust model. The goal is not merely to
report that an operation happened; a user reading the normal logs should be
able to understand the concrete host/guest operations and, where practical,
copy the shown commands and perform the equivalent work without AIVM.

- Treat concrete command visibility as a product feature. Do not replace useful
  command lines with opaque summaries just to make normal output shorter. Step
  titles, rationale, and semantic descriptions should contextualize commands,
  not hide them.
- Prefer commands that are themselves understandable and reproducible. If an
  operation requires substantial shell/Python logic, install that logic as a
  stable, inspectable AIVM-owned helper (for example under
  `/usr/local/libexec/aivm/`) and log the helper path plus ordinary arguments.
  A named helper invocation is more auditable than repeatedly sending a large
  anonymous inline script over SSH.
- `Elided(value, label)` is a readability affordance, not a secrecy mechanism.
  Use it intentionally for large payloads whose literal contents would obscure
  the surrounding command, give the payload a useful label, and preserve a
  higher-verbosity path that reveals the literal value. An automatically
  omitted *unmarked* argument is a call-site defect and should be fixed rather
  than normalized away.
- Keep INFO useful for imitation: show the exact executable, meaningful
  arguments, privilege boundary, and relevant paths. DEBUG/TRACE may add hashes,
  transport details, generated content, and literal elided payloads, but should
  not be the only place where the user can discover what operation AIVM chose.
- When generated files or helper programs are part of the operation, make their
  installed location discoverable and keep their update/install commands
  visible. Users should be able to inspect the exact code AIVM asks root or a
  guest to execute.
- Auditability never overrides secret handling. Continue to redact credentials,
  private keys, tokens, and other sensitive values; expose the operation and
  destination without leaking the secret material.

## Safety Expectations
- Do not silently broaden VM host-path exposure.
- Avoid attaching the same host folder to multiple VMs unless user forces it.
- Surface clear diagnostics for share/network/firewall mismatches.
- Prefer live libvirt metadata when config may be stale (bridge/network details).

## Development Notes
- Keep changes focused and incremental.
- Treat the latest released CLI and on-disk config format as the
  backwards-compatibility surface. Unreleased feature-branch internals do
  not need compatibility shims.
- Put compatibility for released versions before 0.6.0 under
  `aivm.legacy.pre_0_6_0`. Production imports from that namespace must make
  the supported version boundary obvious. Move substantial compatibility
  logic there; use its `@compatibility_surface` marker only for mixed core
  functions/classes that are genuinely impractical to extract.
- Put tests and frozen fixtures that exist only for that support window under
  `tests/legacy/pre_0_6_0`. Ordinary tests must build canonical contexts and
  must not import the versioned compatibility package as generic scaffolding.
- Preserve non-interactive usability (`--yes`, `--dry_run`).
- Keep docs updated when CLI behavior or command tree changes.
- Write code first for correctness/clarity, then do a short second pass to add
  concise comments that help humans understand the high-level flow, motivation,
  and non-obvious steps.
- Do not over-comment; prefer intent-level comments that quickly explain what
  is going on and why, rather than line-by-line narration.

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

## Style

* When using multiline strings use textwrap to keep indentation nice.
* Comment code so the motivation and intent is readable for humans and agents.
* Prefer explicit context-manager classes with `__enter__` and `__exit__`; do not use `contextlib.contextmanager`.

## Developer journal
Keep a running journal at `dev/journals/<agent_name>.md` (e.g.
`dev/journals/codex.md`) to capture the story of the work (decisions, progress,
challenges). This is not a changelog.  Write at a high level for future
maintainers: enough context for someone to pick up where you left off.

- Format: Each entry starts with `## YYYY-MM-DD HH:MM:SS -ZZZZ` (local time).
- Must include: what you were working on, a substantive entry about your state of mind / reflections, uncertainties/risks, tradeoffs, what might break, what you're confident about.
- May include: what happened, rationale, testing notes, next steps, open questions.
- Rules: Prefer append-only. You may edit only the most recent entry *during the same session* (use timestamp + context to judge); never modify the timestamp line; once a new session starts, create a new entry. Never modify older entries. Avoid large diffs; reference files/modules/issues instead.

<!-- BEGIN llm_resource_tally v0.3.0 (managed block — regenerated by `install`; edits below will be overwritten) -->
## LLM resource accounting
A git post-commit hook — and Claude Code hooks when wired — records the measured token and model
usage this repository costs. It is automatic bookkeeping and is not part of whatever task you were
given.

- Rows and mutable rollups are written under `.llm_resource_tally/local/`, which is gitignored.
  Recording therefore never modifies a tracked file and never blocks a commit, merge, rebase, or
  stash.
- Never hand-edit, hand-count, revert, or clean up ledger rows, and never let accounting block the
  repository work you were asked to do. Recording is best-effort by design.
- **Publish before you hand off substantial work.** Run
  `python3 .llm_resource_tally/tool publish`: it snapshots local rows onto the tracked append-only
  ledger under `.llm_resource_tally/ledger/` and refreshes the tracked `lifetime-totals.json` and
  `badge.json`. Stage and commit what it writes, preferably as its own commit so accounting stays
  out of unrelated diffs. This is routine — nobody should have to remember to ask you for it, and
  unpublished rows exist only on this machine.
- If accounting itself looks unhealthy, run `python3 .llm_resource_tally/tool doctor` — it checks
  hook wiring, backends, transcript retention, and ledger health, and names what to fix. Otherwise
  continue the repository task normally.
- After a fresh clone, run `python3 .llm_resource_tally/tool install` once to arm git-local hooks.
  It is offline and idempotent, and it reads the committed `.llm_resource_tally/settings.json`
  policy.
<!-- END llm_resource_tally -->
