"""Tests for editable multi-repository credential plans."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aivm.commands import CommandManager
from aivm.credentials.plan import (
    discover_credential_candidates,
    parse_credential_plan_document,
    render_credential_plan,
)
from aivm.errors import AIVMError


def _git(path: Path, *args: str) -> None:
    subprocess.run(
        ['git', '-C', str(path), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True)
    _git(path, 'init', '-q')
    _git(path, 'config', 'user.name', 'AIVM Test')
    _git(path, 'config', 'user.email', 'aivm@example.invalid')
    (path / 'README').write_text('test\n', encoding='utf-8')
    _git(path, 'add', 'README')
    _git(path, 'commit', '-qm', 'initial')


def test_parse_plan_rows_are_self_contained() -> None:
    text = """\
version: 1
root: "/tmp/example root"
repositories:
  - {path: ".", access: rw, remote: origin, provider: auto}
  - {path: "module", access: ro, remote: upstream, provider: gitlab}
"""
    document = parse_credential_plan_document(text)
    assert document.root == Path('/tmp/example root')
    assert [
        (e.path, e.access, e.remote, e.provider, e.backend)
        for e in document.entries
    ] == [
        ('.', 'write', 'origin', 'auto', 'auto'),
        ('module', 'read', 'upstream', 'gitlab', 'auto'),
    ]



def test_plan_accepts_explicit_ssh_agent_backend() -> None:
    text = """\
version: 1
root: "/tmp/root"
repositories:
  - {path: ".", access: rw, remote: origin, provider: auto, backend: ssh-agent}
"""
    document = parse_credential_plan_document(text)
    assert document.entries[0].backend == 'ssh-agent'


def test_plan_rejects_duplicate_active_remote_choices() -> None:
    text = """\
version: 1
root: "/tmp/root"
repositories:
  - {path: "submodules/aiq-magnet", access: rw, remote: Erotemic, provider: auto}
  - {path: "submodules/aiq-magnet", access: ro, remote: origin, provider: auto}
"""
    with pytest.raises(AIVMError, match='comment all but one remote choice'):
        parse_credential_plan_document(text)


def test_plan_requires_explicit_row_access() -> None:
    text = """\
version: 1
root: "/tmp/root"
repositories:
  - {path: ".", remote: origin, provider: auto}
"""
    with pytest.raises(AIVMError, match='missing field.*access'):
        parse_credential_plan_document(text)


def test_ambiguous_remotes_render_as_commented_choices(tmp_path: Path) -> None:
    root = tmp_path / 'root'
    _init_repo(root)
    erodemic_url = 'git@github.com:Erotemic/aiq-magnet.git'
    kitware_url = 'git@github.com:AIQ-Kitware/aiq-magnet.git'
    _git(root, 'remote', 'add', 'Erotemic', erodemic_url)
    _git(root, 'remote', 'add', 'origin', kitware_url)

    manager = CommandManager(yes=True)
    found_root, candidates = discover_credential_candidates(
        root,
        access='rw',
        manager=manager,
    )
    rendered = render_credential_plan(candidates, root=found_root)

    erodemic_row = (
        '  # - {"path": ".", "access": "rw", "remote": "Erotemic", '
        f'"provider": "auto", "backend": "auto"}}  # {erodemic_url}'
    )
    kitware_row = (
        '  # - {"path": ".", "access": "rw", "remote": "origin", '
        f'"provider": "auto", "backend": "auto"}}  # {kitware_url}'
    )
    assert erodemic_row in rendered
    assert kitware_row in rendered
    assert 'Multiple distinct remote destinations are available.' in rendered

    # Selection is one uncomment plus an optional access edit on the same row.
    selected = rendered.replace(
        kitware_row,
        kitware_row.replace('  # -', '  -').replace('"access": "rw"', '"access": "ro"'),
    )
    document = parse_credential_plan_document(selected)
    assert len(document.entries) == 1
    assert document.entries[0].remote == 'origin'
    assert document.entries[0].access == 'read'


def test_same_destination_aliases_keep_one_active_choice(tmp_path: Path) -> None:
    root = tmp_path / 'root'
    _init_repo(root)
    shared_url = 'git@github.com:AIQ-Kitware/project.git'
    _git(root, 'remote', 'add', 'mirror', shared_url)
    _git(root, 'remote', 'add', 'origin', shared_url)

    manager = CommandManager(yes=True)
    found_root, candidates = discover_credential_candidates(root, manager=manager)
    rendered = render_credential_plan(candidates, root=found_root)

    assert (
        '  - {"path": ".", "access": "ro", "remote": "origin", '
        f'"provider": "auto", "backend": "auto"}}  # {shared_url}'
    ) in rendered
    assert (
        '  # - {"path": ".", "access": "ro", "remote": "mirror", '
        f'"provider": "auto", "backend": "auto"}}  # {shared_url}'
    ) in rendered


def test_discovery_includes_nested_initialized_submodules(tmp_path: Path) -> None:
    leaf = tmp_path / 'leaf'
    _init_repo(leaf)

    child = tmp_path / 'child'
    _init_repo(child)
    subprocess.run(
        [
            'git',
            '-c',
            'protocol.file.allow=always',
            '-C',
            str(child),
            'submodule',
            'add',
            '-q',
            str(leaf),
            'deps/leaf',
        ],
        check=True,
    )
    _git(child, 'commit', '-qam', 'add leaf')

    root = tmp_path / 'root'
    _init_repo(root)
    subprocess.run(
        [
            'git',
            '-c',
            'protocol.file.allow=always',
            '-C',
            str(root),
            'submodule',
            'add',
            '-q',
            str(child),
            'modules/child',
        ],
        check=True,
    )
    subprocess.run(
        [
            'git',
            '-c',
            'protocol.file.allow=always',
            '-C',
            str(root),
            'submodule',
            'update',
            '--init',
            '--recursive',
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    manager = CommandManager(yes=True)
    _, candidates = discover_credential_candidates(root, manager=manager)
    assert [candidate.path for candidate in candidates] == [
        '.',
        'modules/child',
        'modules/child/deps/leaf',
    ]
