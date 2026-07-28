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
    effect visible. The current trust mode assumes mutually trusted host users;
    ownership fields are not a hostile-user isolation boundary.
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
- Treat the latest released CLI and on-disk config format as the
  backwards-compatibility surface. Unreleased feature-branch internals do
  not need compatibility shims.
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

## Developer journal
Keep a running journal at `dev/journals/<agent_name>.md` (e.g.
`dev/journals/codex.md`) to capture the story of the work (decisions, progress,
challenges). This is not a changelog.  Write at a high level for future
maintainers: enough context for someone to pick up where you left off.

- Format: Each entry starts with `## YYYY-MM-DD HH:MM:SS -ZZZZ` (local time).
- Must include: what you were working on, a substantive entry about your state of mind / reflections, uncertainties/risks, tradeoffs, what might break, what you're confident about.
- May include: what happened, rationale, testing notes, next steps, open questions.
- Rules: Prefer append-only. You may edit only the most recent entry *during the same session* (use timestamp + context to judge); never modify the timestamp line; once a new session starts, create a new entry. Never modify older entries. Avoid large diffs; reference files/modules/issues instead.
