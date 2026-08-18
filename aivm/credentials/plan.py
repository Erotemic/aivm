"""Editable YAML plans for granting credentials across a checkout graph."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..commands import CommandManager
from ..errors import AIVMError
from . import providers
from .schema import CredentialAccess, normalize_credential_access

PLAN_VERSION = 1


@dataclass(frozen=True)
class CredentialPlanEntry:
    """One active repository grant from an edited credential plan."""

    path: str
    access: CredentialAccess
    remote: str
    provider: providers.CredentialProvider


@dataclass(frozen=True)
class CredentialPlanCandidate:
    """One checkout discovered while building a credential plan."""

    path: str
    access: CredentialAccess
    provider: providers.CredentialProvider
    remotes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class CredentialPlanDocument:
    """A validated credential plan."""

    root: Path
    entries: tuple[CredentialPlanEntry, ...]


def _git_capture(
    checkout: Path,
    args: list[str],
    *,
    manager: CommandManager,
    check: bool = False,
) -> str:
    result = manager.run(
        ['git', '-C', str(checkout), *args],
        sudo=False,
        role='read',
        check=check,
        capture=True,
        summary='Inspect Git checkout',
        detail=f'checkout={checkout}',
    )
    if result.code != 0:
        return ''
    return result.stdout.strip()


def repository_root(checkout: Path, *, manager: CommandManager) -> Path:
    """Return the top-level directory for a local Git checkout."""
    root = _git_capture(
        checkout,
        ['rev-parse', '--show-toplevel'],
        manager=manager,
    )
    if not root:
        raise AIVMError(f'Not a Git checkout: {checkout}')
    return Path(root).resolve()


def _initialized_submodule_paths(
    root: Path, *, manager: CommandManager
) -> tuple[str, ...]:
    """Return initialized submodules, including nested submodules."""
    result = manager.run(
        [
            'git',
            '-C',
            str(root),
            'submodule',
            'foreach',
            '--quiet',
            '--recursive',
            'printf "%s\\0" "$displaypath"',
        ],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        summary='Discover initialized Git submodules',
        detail=f'checkout={root}',
    )
    if result.code != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            'Could not discover initialized Git submodules: '
            f'{detail or "git submodule foreach failed"}'
        )
    paths = [item for item in result.stdout.split('\0') if item]
    return tuple(sorted(dict.fromkeys(paths)))


def discover_credential_candidates(
    checkout: Path,
    *,
    access: object = 'read',
    provider: object = 'auto',
    manager: CommandManager,
) -> tuple[Path, list[CredentialPlanCandidate]]:
    """Discover the checkout root and initialized submodules."""
    root = repository_root(checkout, manager=manager)
    normalized_access = normalize_credential_access(access)
    normalized_provider = providers.normalize_provider(provider)
    relative_paths = ('.', *_initialized_submodule_paths(root, manager=manager))

    candidates: list[CredentialPlanCandidate] = []
    for relative in relative_paths:
        candidate_path = root if relative == '.' else root / relative
        remote_text = _git_capture(candidate_path, ['remote'], manager=manager)
        remote_names = sorted(line for line in remote_text.splitlines() if line)
        remotes = tuple(
            (
                remote,
                _git_capture(
                    candidate_path,
                    ['remote', 'get-url', remote],
                    manager=manager,
                ),
            )
            for remote in remote_names
        )
        candidates.append(
            CredentialPlanCandidate(
                path=relative,
                access=normalized_access,
                provider=normalized_provider,
                remotes=remotes,
            )
        )
    return root, candidates


def _plan_access_spelling(access: CredentialAccess) -> str:
    return 'rw' if access == 'write' else 'ro'


def _render_repository_mapping(
    candidate: CredentialPlanCandidate, remote: str
) -> str:
    # JSON flow mappings are valid YAML and keep each choice on one editable line.
    return json.dumps(
        {
            'path': candidate.path,
            'access': _plan_access_spelling(candidate.access),
            'remote': remote,
            'provider': candidate.provider,
        },
        ensure_ascii=False,
    )


def _automatic_remote(candidate: CredentialPlanCandidate) -> str | None:
    """Choose a remote only when the choice cannot change the destination."""
    if len(candidate.remotes) == 1:
        return candidate.remotes[0][0]
    if not candidate.remotes:
        return None

    urls = [url for _, url in candidate.remotes]
    if not all(urls) or len(set(urls)) != 1:
        return None
    names = [name for name, _ in candidate.remotes]
    return 'origin' if 'origin' in names else names[0]


def _remote_comment(url: str) -> str:
    return url or '(remote URL unavailable)'


def render_credential_plan(
    candidates: list[CredentialPlanCandidate], *, root: Path
) -> str:
    """Render the comment/uncomment YAML interface."""
    if not candidates:
        raise AIVMError('Credential discovery produced no checkout candidates.')

    lines = [
        '# aivm credential plan',
        '#',
        '# Active list items are grants. Comment a row out to skip it.',
        '# For multiple distinct remotes, uncomment exactly one offered row.',
        '# Edit access on any row to ro or rw before applying.',
        '# Each row is self-contained; there are no hidden access defaults.',
        f'version: {PLAN_VERSION}',
        f'root: {json.dumps(str(root), ensure_ascii=False)}',
        '',
        'repositories:',
    ]

    for candidate in candidates:
        if not candidate.remotes:
            lines.extend(
                [
                    f'  # {candidate.path}',
                    '  # No Git remotes are configured; no grant is active.',
                ]
            )
            continue

        selected = _automatic_remote(candidate)
        if selected is None:
            lines.extend(
                [
                    f'  # {candidate.path}',
                    '  # Multiple distinct remote destinations are available.',
                    '  # Uncomment exactly one line, or leave all commented to skip.',
                ]
            )
        elif len(candidate.remotes) > 1:
            lines.extend(
                [
                    f'  # {candidate.path}',
                    '  # These remote names resolve to the same destination.',
                ]
            )

        for remote, url in candidate.remotes:
            mapping = _render_repository_mapping(candidate, remote)
            if remote == selected:
                lines.append(f'  - {mapping}  # {_remote_comment(url)}')
            else:
                lines.append(f'  # - {mapping}  # {_remote_comment(url)}')

    return '\n'.join(lines) + '\n'


def _require_string(
    record: dict[str, Any], field: str, *, row: int
) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AIVMError(
            f'Credential plan repository row {row} field {field!r} '
            'must be a non-empty string.'
        )
    return value


def parse_credential_plan_document(text: str) -> CredentialPlanDocument:
    """Parse and validate the one supported credential-plan format."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as ex:
        raise AIVMError(f'Credential plan is not valid YAML: {ex}') from ex

    if not isinstance(data, dict):
        raise AIVMError('Credential plan must be a YAML mapping.')
    allowed_top = {'version', 'root', 'repositories'}
    unknown_top = set(data) - allowed_top
    if unknown_top:
        names = ', '.join(sorted(map(str, unknown_top)))
        raise AIVMError(f'Credential plan has unknown top-level field(s): {names}.')
    if data.get('version') != PLAN_VERSION:
        raise AIVMError(
            f'Credential plan version must be {PLAN_VERSION}; '
            f'got {data.get("version")!r}.'
        )

    root_text = data.get('root')
    if not isinstance(root_text, str) or not root_text.strip():
        raise AIVMError('Credential plan root must be a non-empty path string.')
    root = Path(root_text).expanduser()
    if not root.is_absolute():
        raise AIVMError('Credential plan root must be an absolute path.')

    raw_entries = data.get('repositories')
    if not isinstance(raw_entries, list) or not raw_entries:
        raise AIVMError('Credential plan contains no active repository grants.')

    entries: list[CredentialPlanEntry] = []
    seen_paths: set[str] = set()
    required_fields = {'path', 'access', 'remote', 'provider'}
    for row, record in enumerate(raw_entries, start=1):
        if not isinstance(record, dict):
            raise AIVMError(
                f'Credential plan repository row {row} must be a mapping.'
            )
        fields = set(record)
        missing = required_fields - fields
        unknown = fields - required_fields
        if missing:
            names = ', '.join(sorted(missing))
            raise AIVMError(
                f'Credential plan repository row {row} is missing field(s): {names}.'
            )
        if unknown:
            names = ', '.join(sorted(map(str, unknown)))
            raise AIVMError(
                f'Credential plan repository row {row} has unknown field(s): {names}.'
            )

        path = _require_string(record, 'path', row=row)
        path_obj = Path(path)
        if path_obj.is_absolute() or '..' in path_obj.parts:
            raise AIVMError(
                f'Credential plan repository row {row} path must stay relative '
                f'to the plan root: {path!r}.'
            )
        if path in seen_paths:
            raise AIVMError(
                f'Credential plan repository row {row} repeats checkout path '
                f'{path!r}; comment all but one remote choice.'
            )
        seen_paths.add(path)

        access_text = _require_string(record, 'access', row=row)
        if access_text not in {'ro', 'rw'}:
            raise AIVMError(
                f'Credential plan repository row {row} access must be ro or rw.'
            )
        remote = _require_string(record, 'remote', row=row)
        provider_text = _require_string(record, 'provider', row=row)

        entries.append(
            CredentialPlanEntry(
                path=path,
                access=normalize_credential_access(access_text),
                remote=remote,
                provider=providers.normalize_provider(provider_text),
            )
        )

    return CredentialPlanDocument(root=root, entries=tuple(entries))
