"""Safety checks for VM attachment requests.

This module guards against two classes of attachment mistake:

1. Mounting a host directory that contains (or *is*) a credential-carrying
   location such as ``~``, ``~/.ssh``, ``~/.gnupg``, ``~/.aws``, ``~/.kube``,
   ``~/.docker``, ``~/.config/gh``, ``~/.config/gcloud``, ``~/.azure``,
   ``~/.password-store``, ``/root``, or ``/etc/ssh``. Exposing those paths to
   a sandbox VM defeats the isolation the VM is meant to provide.

2. Mounting a host directory that is the parent or child of a directory
   already attached to the same VM. Overlapping mounts cause confusing
   shadowing and double-write paths.

The prompts always run when stdin is a TTY; ``yes=True`` bypasses with a
loud warning so script-driven flows still see the risk in their logs.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from loguru import logger as log

from ..config_store import AttachmentEntry

_SENSITIVE_HOME_RELATIVE: tuple[str, ...] = (
    '.ssh',
    '.gnupg',
    '.aws',
    '.azure',
    '.kube',
    '.docker',
    '.config/gh',
    '.config/gcloud',
    '.config/op',
    '.config/sops',
    '.password-store',
    '.netrc',
    '.pypirc',
    '.npmrc',
)

_SENSITIVE_ABSOLUTE: tuple[str, ...] = (
    '/root',
    '/etc/ssh',
)


@dataclass(frozen=True)
class SensitiveHit:
    """A reason ``host_src`` should not be attached to a VM."""

    sensitive_path: Path
    relation: str  # 'is', 'parent-of', 'child-of'
    label: str  # human-readable label e.g. 'home directory', '~/.ssh'


@dataclass(frozen=True)
class OverlapHit:
    """An existing attachment that overlaps with ``host_src``."""

    other_path: Path
    relation: str  # 'parent-of' (other is parent of host_src), 'child-of'
    vm_name: str
    guest_dst: str


def _sensitive_candidates() -> list[tuple[Path, str]]:
    """Build the (resolved-absolute path, label) list of sensitive locations."""
    out: list[tuple[Path, str]] = []
    try:
        home = Path.home()
    except RuntimeError:
        home = None  # type: ignore[assignment]
    if home is not None:
        out.append((home, 'home directory'))
        for rel in _SENSITIVE_HOME_RELATIVE:
            out.append((home / rel, f'~/{rel}'))
    for abs_path in _SENSITIVE_ABSOLUTE:
        out.append((Path(abs_path), abs_path))
    return out


def _canonical_path(path: Path) -> Path:
    """Return the filesystem path that an attachment will actually export.

    Policy checks must follow symlinks because attachment resolution and
    libvirt do.  ``strict=False`` keeps diagnostics useful for paths whose
    final component disappears between validation and reporting.
    """
    return Path(path).expanduser().resolve(strict=False)


def _is_same_or_under(child: Path, ancestor: Path) -> bool:
    """Return True if ``child`` equals ``ancestor`` or is contained in it."""
    try:
        return child == ancestor or child.is_relative_to(ancestor)
    except ValueError:
        return False


def detect_sensitive_paths(host_src: Path) -> list[SensitiveHit]:
    """Return the list of sensitive locations touched by ``host_src``.

    A path is considered touched when:

    * ``host_src`` equals the sensitive path, or
    * ``host_src`` is an ancestor of the sensitive path (mounting ``host_src``
      would expose the sensitive subdirectory), or
    * ``host_src`` is a descendant of the sensitive path (e.g. attaching
      ``~/.ssh/keys`` is still attaching key material).

    Only sensitive paths that actually exist on disk are reported, with one
    exception: the home directory itself is always reported so attempting to
    attach ``~`` always trips the guard even on minimally provisioned hosts.

    The home directory is also treated specially in the *other* direction:
    being merely *inside* ``~`` (e.g. ``~/code/myproject``) is not by itself
    sensitive, so the ``child-of`` relation is suppressed for ``~``. Specific
    credential subdirs like ``~/.ssh`` still trip ``child-of`` because
    descending into them is itself attaching key material.
    """
    host_src = _canonical_path(host_src)
    hits: list[SensitiveHit] = []
    seen: set[Path] = set()
    for candidate, label in _sensitive_candidates():
        try:
            candidate_abs = _canonical_path(candidate)
        except (OSError, RuntimeError):
            continue
        if candidate_abs in seen:
            continue
        is_home = label == 'home directory'
        if not candidate_abs.exists() and not is_home:
            continue
        if host_src == candidate_abs:
            relation = 'is'
        elif _is_same_or_under(candidate_abs, host_src):
            relation = 'parent-of'  # host_src is the parent of candidate
        elif not is_home and _is_same_or_under(host_src, candidate_abs):
            relation = 'child-of'  # host_src is inside candidate
        else:
            continue
        seen.add(candidate_abs)
        hits.append(
            SensitiveHit(
                sensitive_path=candidate_abs,
                relation=relation,
                label=label,
            )
        )
    return hits


def detect_overlapping_attachments(
    host_src: Path,
    existing: list[AttachmentEntry],
    vm_name: str,
) -> list[OverlapHit]:
    """Return existing attachments that are parent/child of ``host_src``.

    Exact-match attachments are NOT reported here because the attach flow
    already treats them as idempotent updates rather than overlaps. Only
    strict parent/child relationships within the same VM are flagged.
    """
    host_src = _canonical_path(host_src)
    hits: list[OverlapHit] = []
    for att in existing:
        if att.vm_name != vm_name:
            continue
        if not att.host_path:
            continue
        other = _canonical_path(Path(att.host_path))
        if other == host_src:
            continue
        if _is_same_or_under(host_src, other):
            relation = 'child-of'  # host_src lives inside other
        elif _is_same_or_under(other, host_src):
            relation = 'parent-of'  # other lives inside host_src
        else:
            continue
        hits.append(
            OverlapHit(
                other_path=other,
                relation=relation,
                vm_name=att.vm_name,
                guest_dst=att.guest_dst or '',
            )
        )
    return hits


def _format_sensitive_warning(host_src: Path, hits: list[SensitiveHit]) -> str:
    lines = [
        '',
        '!!! SENSITIVE PATH WARNING !!!',
        f'  host_src: {host_src}',
        '  This attachment would expose credential-bearing host paths to a sandbox VM:',
    ]
    for hit in hits:
        if hit.relation == 'is':
            lines.append(
                f'    - host_src IS {hit.label} ({hit.sensitive_path})'
            )
        elif hit.relation == 'parent-of':
            lines.append(
                f'    - host_src CONTAINS {hit.label} ({hit.sensitive_path})'
            )
        else:
            lines.append(
                f'    - host_src is INSIDE {hit.label} ({hit.sensitive_path})'
            )
    lines.append(
        '  Anything running in the guest (or any process the agent invokes) '
        'will be able to read these files.'
    )
    return '\n'.join(lines)


def _format_overlap_warning(host_src: Path, hits: list[OverlapHit]) -> str:
    lines = [
        '',
        '!!! OVERLAPPING ATTACHMENT WARNING !!!',
        f'  host_src: {host_src}',
        '  Overlaps with attachments already registered on this VM:',
    ]
    for hit in hits:
        rel = (
            'is a parent of' if hit.relation == 'parent-of' else 'is a child of'
        )
        guest = f' (guest_dst={hit.guest_dst})' if hit.guest_dst else ''
        lines.append(f'    - host_src {rel} {hit.other_path}{guest}')
    lines.append(
        '  Overlapping mounts cause confusing shadowing and double-write '
        'paths inside the guest.'
    )
    return '\n'.join(lines)


def confirm_sensitive_attach(
    host_src: Path,
    hits: list[SensitiveHit],
    *,
    yes: bool,
) -> bool:
    """Show a strong warning and require explicit confirmation.

    Returns True if the attach should proceed, False otherwise.

    With ``yes=True`` the warning is still logged but no prompt is shown, so
    automated callers stay non-interactive. The interactive prompt requires
    the user to type ``yes`` exactly (not just press enter) because a
    misclicked attach of ``~`` or ``~/.ssh`` is a real failure mode.
    """
    if not hits:
        return True
    msg = _format_sensitive_warning(host_src, hits)
    log.warning('{}', msg)
    if yes:
        log.warning(
            '--yes was provided; proceeding with sensitive attachment for {} '
            'without interactive confirmation.',
            host_src,
        )
        return True
    if not sys.stdin.isatty():
        print(msg, file=sys.stderr)
        print(
            'Refusing to attach sensitive path without confirmation; rerun '
            'interactively or pass --yes to override.',
            file=sys.stderr,
        )
        return False
    print(msg, file=sys.stderr)
    ans = input(
        'Type "yes" exactly to attach this sensitive path, anything else to abort: '
    ).strip()
    return ans == 'yes'


@dataclass(frozen=True)
class AttachmentSafetyReport:
    """Aggregated result of the attachment preflight checks."""

    sensitive_hits: list[SensitiveHit]
    overlap_hits: list[OverlapHit]


# Process-level cache: once the user has approved a sensitive host_src, we
# trust that approval for the remainder of the process so a single flow
# (e.g. `aivm code .`) that calls the preflight more than once does not
# re-prompt. The same approval is treated as valid across (host_src, vm_name)
# pairs since the credential-exposure risk is a property of host_src alone.
_APPROVED_SENSITIVE_HOSTS: set[Path] = set()


def _reset_sensitive_approval_cache() -> None:
    """Clear the in-process sensitive-attach approval cache. Test helper."""
    _APPROVED_SENSITIVE_HOSTS.clear()


def attachment_safety_preflight(
    host_src: Path,
    *,
    existing_attachments: list[AttachmentEntry] | None = None,
    vm_name: str | None = None,
    yes: bool,
    dry_run: bool = False,
) -> tuple[bool, AttachmentSafetyReport]:
    """Run every attachment-safety check the project requires, in one place.

    This is the single chokepoint every code path that registers or applies a
    host->guest attachment must call before doing so. Centralizing the
    sequence here means callers cannot accidentally enforce the sensitive
    check while skipping the overlap check (or vice versa), and ensures any
    future safety guard added here lights up for every entry point.

    Sensitive-path approvals are cached in-process: a single flow that calls
    the preflight twice (e.g. once before VM bootstrap, once after) only
    prompts once. Overlap checks always re-run because the store state can
    change between calls.

    Args:
        host_src: The host directory being attached.
        existing_attachments: The store's attachment list. If ``None``, the
            overlap check is skipped (use this only when no store has been
            loaded yet — e.g. before a fresh VM bootstrap).
        vm_name: Target VM name for overlap scoping. Required if
            ``existing_attachments`` is provided.
        yes: Bypass interactive prompts (still logs the warning).
        dry_run: When True, log hits as warnings but never prompt or refuse.

    Returns:
        ``(ok, report)``. When ``ok`` is False the caller MUST abort —
        the user declined, or the environment is non-interactive and lacked
        ``--yes``. In dry-run mode ``ok`` is always True.
    """
    host_src_abs = _canonical_path(host_src)
    sensitive_hits = detect_sensitive_paths(host_src_abs)
    if existing_attachments is not None and vm_name is not None:
        overlap_hits = detect_overlapping_attachments(
            host_src_abs, existing_attachments, vm_name
        )
    else:
        overlap_hits = []
    report = AttachmentSafetyReport(
        sensitive_hits=sensitive_hits, overlap_hits=overlap_hits
    )
    if dry_run:
        if sensitive_hits:
            log.warning(
                'DRYRUN: real attach would warn about sensitive path(s) at {}: {}',
                host_src,
                ', '.join(hit.label for hit in sensitive_hits),
            )
        if overlap_hits:
            log.warning(
                'DRYRUN: real attach would warn about overlapping attachment(s) for {}: {}',
                host_src,
                ', '.join(str(hit.other_path) for hit in overlap_hits),
            )
        return True, report
    if sensitive_hits and host_src_abs in _APPROVED_SENSITIVE_HOSTS:
        pass  # already approved earlier in this process
    elif not confirm_sensitive_attach(host_src, sensitive_hits, yes=yes):
        return False, report
    else:
        if sensitive_hits:
            _APPROVED_SENSITIVE_HOSTS.add(host_src_abs)
    if not confirm_overlapping_attach(host_src, overlap_hits, yes=yes):
        return False, report
    return True, report


def confirm_overlapping_attach(
    host_src: Path,
    hits: list[OverlapHit],
    *,
    yes: bool,
) -> bool:
    """Show an overlap warning and offer an off-ramp.

    Returns True if the attach should proceed, False otherwise. The
    interactive prompt defaults to "no" when the user just presses enter,
    making "cancel" the safe default.
    """
    if not hits:
        return True
    msg = _format_overlap_warning(host_src, hits)
    log.warning('{}', msg)
    if yes:
        log.warning(
            '--yes was provided; proceeding with overlapping attachment for '
            '{}.',
            host_src,
        )
        return True
    if not sys.stdin.isatty():
        print(msg, file=sys.stderr)
        print(
            'Refusing to add an overlapping attachment without confirmation; '
            'rerun interactively or pass --yes to override.',
            file=sys.stderr,
        )
        return False
    print(msg, file=sys.stderr)
    ans = input('Continue with overlapping attachment? [y/N]: ').strip().lower()
    return ans in {'y', 'yes'}


__all__ = [
    'AttachmentSafetyReport',
    'OverlapHit',
    'SensitiveHit',
    'attachment_safety_preflight',
    'confirm_overlapping_attach',
    'confirm_sensitive_attach',
    'detect_overlapping_attachments',
    'detect_sensitive_paths',
]
