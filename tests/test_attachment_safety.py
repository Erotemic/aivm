"""Tests for sensitive-path and overlap guards in attachment safety."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.attachments.safety import (
    OverlapHit,
    SensitiveHit,
    confirm_overlapping_attach,
    confirm_sensitive_attach,
    detect_overlapping_attachments,
    detect_sensitive_paths,
)
from aivm.config_store import AttachmentEntry


def test_detect_sensitive_paths_flags_home_directly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / 'home' / 'agent'
    fake_home.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    hits = detect_sensitive_paths(fake_home)

    assert any(
        hit.relation == 'is' and hit.label == 'home directory' for hit in hits
    )


def test_detect_sensitive_paths_flags_subdir_of_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / 'home' / 'agent'
    ssh_dir = fake_home / '.ssh'
    ssh_dir.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    sub = ssh_dir / 'keys'
    sub.mkdir()

    hits = detect_sensitive_paths(sub)
    labels = {hit.label for hit in hits}

    assert '~/.ssh' in labels


def test_detect_sensitive_paths_flags_parent_that_contains_aws(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / 'home' / 'agent'
    aws_dir = fake_home / '.aws'
    aws_dir.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    hits = detect_sensitive_paths(fake_home)
    labels = {hit.label for hit in hits}

    # Both home itself and the .aws subdir should be reported.
    assert 'home directory' in labels
    assert '~/.aws' in labels


def test_detect_sensitive_paths_ignores_unrelated_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / 'home' / 'agent'
    fake_home.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    unrelated = tmp_path / 'projects' / 'demo'
    unrelated.mkdir(parents=True)

    assert detect_sensitive_paths(unrelated) == []


def test_detect_overlapping_attachments_finds_child(tmp_path: Path) -> None:
    parent = tmp_path / 'work'
    child = parent / 'subproj'
    parent.mkdir()
    child.mkdir()

    existing = [
        AttachmentEntry(
            host_path=str(parent),
            vm_name='vm-a',
            guest_dst='/mnt/work',
        )
    ]

    hits = detect_overlapping_attachments(child, existing, vm_name='vm-a')

    assert len(hits) == 1
    assert hits[0].relation == 'child-of'
    assert hits[0].other_path == parent


def test_detect_overlapping_attachments_finds_parent(tmp_path: Path) -> None:
    parent = tmp_path / 'work'
    child = parent / 'subproj'
    parent.mkdir()
    child.mkdir()

    existing = [
        AttachmentEntry(
            host_path=str(child),
            vm_name='vm-a',
            guest_dst='/mnt/subproj',
        )
    ]

    hits = detect_overlapping_attachments(parent, existing, vm_name='vm-a')

    assert len(hits) == 1
    assert hits[0].relation == 'parent-of'
    assert hits[0].other_path == child


def test_detect_overlapping_ignores_other_vms(tmp_path: Path) -> None:
    parent = tmp_path / 'work'
    child = parent / 'sub'
    parent.mkdir()
    child.mkdir()

    existing = [
        AttachmentEntry(host_path=str(parent), vm_name='other-vm'),
    ]

    assert detect_overlapping_attachments(child, existing, vm_name='vm-a') == []


def test_detect_overlapping_ignores_exact_match(tmp_path: Path) -> None:
    folder = tmp_path / 'work'
    folder.mkdir()

    existing = [
        AttachmentEntry(host_path=str(folder), vm_name='vm-a'),
    ]

    assert detect_overlapping_attachments(folder, existing, vm_name='vm-a') == []


def test_confirm_sensitive_attach_yes_flag_bypasses(tmp_path: Path) -> None:
    hits = [
        SensitiveHit(
            sensitive_path=tmp_path / '.ssh',
            relation='child-of',
            label='~/.ssh',
        )
    ]
    assert (
        confirm_sensitive_attach(tmp_path, hits, yes=True) is True
    )


def test_confirm_sensitive_attach_no_hits_passes(tmp_path: Path) -> None:
    assert confirm_sensitive_attach(tmp_path, [], yes=False) is True


def test_confirm_sensitive_attach_rejects_when_non_tty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _NonTTY:
        @staticmethod
        def isatty() -> bool:
            return False

    monkeypatch.setattr('aivm.attachments.safety.sys.stdin', _NonTTY())
    hits = [
        SensitiveHit(
            sensitive_path=tmp_path / '.ssh',
            relation='child-of',
            label='~/.ssh',
        )
    ]
    assert (
        confirm_sensitive_attach(tmp_path, hits, yes=False) is False
    )


def test_confirm_sensitive_attach_requires_exact_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _TTY:
        @staticmethod
        def isatty() -> bool:
            return True

    monkeypatch.setattr('aivm.attachments.safety.sys.stdin', _TTY())
    hits = [
        SensitiveHit(
            sensitive_path=tmp_path / '.ssh',
            relation='child-of',
            label='~/.ssh',
        )
    ]
    monkeypatch.setattr('builtins.input', lambda *_a, **_k: 'y')
    assert (
        confirm_sensitive_attach(tmp_path, hits, yes=False) is False
    )
    monkeypatch.setattr('builtins.input', lambda *_a, **_k: 'yes')
    assert (
        confirm_sensitive_attach(tmp_path, hits, yes=False) is True
    )


def test_confirm_overlap_off_ramp_default_no(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _TTY:
        @staticmethod
        def isatty() -> bool:
            return True

    monkeypatch.setattr('aivm.attachments.safety.sys.stdin', _TTY())
    hits = [
        OverlapHit(
            other_path=tmp_path / 'sibling',
            relation='parent-of',
            vm_name='vm-a',
            guest_dst='/mnt/x',
        )
    ]
    monkeypatch.setattr('builtins.input', lambda *_a, **_k: '')
    assert confirm_overlapping_attach(tmp_path, hits, yes=False) is False
    monkeypatch.setattr('builtins.input', lambda *_a, **_k: 'y')
    assert confirm_overlapping_attach(tmp_path, hits, yes=False) is True


def test_run_vm_attach_aborts_on_declined_sensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aivm.config import AgentVMConfig
    from aivm.cli.vm_attach import VMAttachRequest, run_vm_attach
    from aivm.config_store import Store, save_store, upsert_vm

    fake_home = tmp_path / 'home' / 'agent'
    ssh_dir = fake_home / '.ssh'
    ssh_dir.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    cfg_path = tmp_path / 'config.toml'
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-sense'
    store = Store()
    upsert_vm(store, cfg)
    save_store(store, cfg_path)

    # Force the prompt to refuse, simulating an interactive abort.
    monkeypatch.setattr(
        'aivm.cli.vm_attach.confirm_sensitive_attach',
        lambda *_a, **_k: False,
    )
    # The other guard shouldn't even be reached.
    monkeypatch.setattr(
        'aivm.cli.vm_attach.confirm_overlapping_attach',
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError('overlap prompt should not run')
        ),
    )

    rc = run_vm_attach(
        VMAttachRequest(
            config_opt=str(cfg_path),
            vm_opt='vm-sense',
            host_src=ssh_dir,
            yes=False,
        )
    )
    assert rc == 2


def test_run_vm_attach_aborts_on_declined_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aivm.config import AgentVMConfig
    from aivm.cli.vm_attach import VMAttachRequest, run_vm_attach
    from aivm.config_store import Store, save_store, upsert_vm

    parent = tmp_path / 'work'
    child = parent / 'subproj'
    parent.mkdir()
    child.mkdir()

    cfg_path = tmp_path / 'config.toml'
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-overlap'
    store = Store()
    upsert_vm(store, cfg)
    store.attachments.append(
        AttachmentEntry(
            host_path=str(parent),
            vm_name='vm-overlap',
            guest_dst='/mnt/work',
        )
    )
    save_store(store, cfg_path)

    monkeypatch.setattr(
        'aivm.cli.vm_attach.confirm_sensitive_attach',
        lambda *_a, **_k: True,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.confirm_overlapping_attach',
        lambda *_a, **_k: False,
    )

    rc = run_vm_attach(
        VMAttachRequest(
            config_opt=str(cfg_path),
            vm_opt='vm-overlap',
            host_src=child,
            yes=False,
        )
    )
    assert rc == 2
