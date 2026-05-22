"""Tests for sensitive-path and overlap guards in attachment safety."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.attachments.safety import (
    OverlapHit,
    SensitiveHit,
    _reset_sensitive_approval_cache,
    attachment_safety_preflight,
    confirm_overlapping_attach,
    confirm_sensitive_attach,
    detect_overlapping_attachments,
    detect_sensitive_paths,
)
from aivm.config_store import AttachmentEntry


@pytest.fixture(autouse=True)
def _clear_safety_cache() -> Any:
    """Reset the in-process sensitive-approval cache between tests."""
    _reset_sensitive_approval_cache()
    yield
    _reset_sensitive_approval_cache()


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


def test_detect_sensitive_paths_does_not_flag_plain_subdir_of_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A normal project directory inside ``~`` (e.g. ``~/code/foo``) must NOT
    trip the home-directory guard. Only credential subdirs (``~/.ssh`` etc.)
    should flag, and the home directory only when attached *as* home or as a
    parent of home.
    """
    fake_home = tmp_path / 'home' / 'agent'
    project = fake_home / 'code' / 'myproject'
    project.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    assert detect_sensitive_paths(project) == []


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
        'aivm.attachments.safety.confirm_sensitive_attach',
        lambda *_a, **_k: False,
    )
    # The other guard shouldn't even be reached.
    monkeypatch.setattr(
        'aivm.attachments.safety.confirm_overlapping_attach',
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


def test_attachment_safety_preflight_caches_sensitive_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second call with the same host_src must not re-prompt the user."""
    fake_home = tmp_path / 'home' / 'agent'
    ssh_dir = fake_home / '.ssh'
    ssh_dir.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    class _TTY:
        @staticmethod
        def isatty() -> bool:
            return True

    monkeypatch.setattr('aivm.attachments.safety.sys.stdin', _TTY())

    prompts: list[str] = []

    def _record_prompt(*_a: Any, **_k: Any) -> str:
        prompts.append('asked')
        return 'yes'

    monkeypatch.setattr('builtins.input', _record_prompt)

    ok1, _ = attachment_safety_preflight(ssh_dir, yes=False)
    ok2, _ = attachment_safety_preflight(ssh_dir, yes=False)

    assert ok1 is True
    assert ok2 is True
    # User should have been prompted exactly once across the two calls.
    assert prompts == ['asked']


def test_attachment_safety_preflight_dry_run_does_not_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / 'home' / 'agent'
    ssh_dir = fake_home / '.ssh'
    ssh_dir.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    def _boom(*_a: Any, **_k: Any) -> str:
        raise AssertionError('dry-run must not prompt')

    monkeypatch.setattr('builtins.input', _boom)

    ok, report = attachment_safety_preflight(ssh_dir, yes=False, dry_run=True)
    assert ok is True
    assert any(hit.label == '~/.ssh' for hit in report.sensitive_hits)


def test_prepare_attached_session_aborts_on_declined_sensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shared session preflight (used by `aivm code`) must enforce the
    sensitive-path guard — not only the `aivm vm attach` CLI path.
    """
    from aivm.attachments.session import _prepare_attached_session

    fake_home = tmp_path / 'home' / 'agent'
    ssh_dir = fake_home / '.ssh'
    ssh_dir.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: fake_home))

    monkeypatch.setattr(
        'aivm.attachments.safety.confirm_sensitive_attach',
        lambda *_a, **_k: False,
    )

    with pytest.raises(RuntimeError, match='declined to attach sensitive path'):
        _prepare_attached_session(
            config_opt=str(tmp_path / 'config.toml'),
            vm_opt='vm-x',
            host_src=ssh_dir,
            guest_dst_opt='',
            recreate_if_needed=False,
            ensure_firewall_opt=False,
            dry_run=False,
            yes=False,
        )


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
        'aivm.attachments.safety.confirm_sensitive_attach',
        lambda *_a, **_k: True,
    )
    monkeypatch.setattr(
        'aivm.attachments.safety.confirm_overlapping_attach',
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
