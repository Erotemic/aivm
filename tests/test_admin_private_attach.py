"""A host administrator must not need ACL access to another user's folder."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.cli.vm_attach import (
    VMAttachRequest,
    _validate_host_directory,
    run_vm_attach,
)
from aivm.config import AgentVMConfig
from aivm.fs_identity import FilesystemIdentity
from aivm.vm.share import AttachmentMode, ResolvedAttachment


def _private_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    target = tmp_path / 'benjamin.fenelon' / 'aiq-super-repo'
    real_stat = Path.stat

    def denied(path: Path, *args: object, **kwargs: object):
        if path == target:
            raise PermissionError(13, 'Permission denied', str(target))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'stat', denied)
    return target


def test_foreign_private_directory_uses_privileged_pinned_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    target = _private_path(monkeypatch, tmp_path)
    identity = FilesystemIdentity(dev=123, ino=456)
    calls: list[object] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.host_bind._ensure_persistent_host_replay_helper',
        lambda *, dry_run: calls.append(('install', dry_run)),
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.host_bind._probe_persistent_source_identity_as_root',
        lambda path: calls.append(('probe', path)) or identity,
    )
    result = _validate_host_directory(target, privileged_foreign_probe=True)
    assert result == identity
    assert calls == [('install', False), ('probe', target)]


def test_private_directory_without_admin_authority_does_not_elevate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    target = _private_path(monkeypatch, tmp_path)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError('unauthorized privileged operation')

    monkeypatch.setattr(
        'aivm.attachments.persistent.host_bind._ensure_persistent_host_replay_helper',
        forbidden,
    )
    from aivm.errors import AIVMError

    with pytest.raises(AIVMError, match='current user permissions'):
        _validate_host_directory(target, privileged_foreign_probe=False)


def test_dry_run_never_installs_root_helper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    target = _private_path(monkeypatch, tmp_path)
    assert _validate_host_directory(
        target, privileged_foreign_probe=True, dry_run=True,
    ) is None


def test_admin_attach_passes_probed_identity_to_recording(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404-aiq-gpu'
    path = tmp_path / 'config.toml'
    target = tmp_path / 'benjamin.fenelon' / 'aiq-super-repo'
    identity = FilesystemIdentity(dev=123, ino=456)
    att = ResolvedAttachment(
        vm_name=cfg.vm.name, mode=AttachmentMode.PERSISTENT,
        source_dir=str(target), guest_dst=str(target),
        tag='hostcode-ben-test', owner_principal_id='principal-ben',
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_attach_context',
        lambda req, src: (SimpleNamespace(effective_cfg=cfg), path),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attachment_owner_for_context',
        lambda *args: 'principal-jon',
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_attachment',
        lambda *args, **kwargs: att,
    )
    validated: list[dict[str, object]] = []

    def validate(src: Path, **kwargs: object) -> FilesystemIdentity:
        assert src == target
        validated.append(kwargs)
        return identity

    monkeypatch.setattr('aivm.cli.vm_attach._validate_host_directory', validate)
    monkeypatch.setattr(
        'aivm.cli.vm_attach.load_store',
        lambda path: SimpleNamespace(principals=[], attachments=[]),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.warn_shared_home_attachment',
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attachment_safety_preflight',
        lambda *args, **kwargs: (True, None),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.record_vm', lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._ensure_attachment_in_vm_definition',
        lambda *args, **kwargs: (att, False, False),
    )
    recorded: dict[str, object] = {}

    def record(*args: object, **kwargs: object) -> Path:
        recorded.update(kwargs)
        return path

    monkeypatch.setattr('aivm.cli.vm_attach._record_attachment', record)
    for name in (
        '_sync_persistent_attachment_manifest_on_host',
        '_sync_persistent_host_replay_manifest',
        '_reconcile_persistent_host_binds',
        '_print_attach_result',
    ):
        monkeypatch.setattr(
            f'aivm.cli.vm_attach.{name}', lambda *args, **kwargs: None,
        )
    assert run_vm_attach(
        VMAttachRequest(
            config_opt=None, vm_opt=cfg.vm.name, host_src=target,
            mode='persistent', owner_principal='principal-ben',
            admin_override=True,
        )
    ) == 0
    assert validated == [{'privileged_foreign_probe': True, 'dry_run': False}]
    assert recorded['source_identity'] == identity
    assert recorded['owner_principal_id'] == 'principal-ben'


def test_record_attachment_reuses_privileged_identity_without_retraversal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from aivm.attachments.session import _record_attachment
    from aivm.config_store import Store

    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404-aiq-gpu'
    source = tmp_path / 'aiq-super-repo'
    source.mkdir()
    identity = FilesystemIdentity(dev=147, ino=258)
    captured: dict[str, object] = {}

    def fake_update(mutate, path, **kwargs):  # type: ignore[no-untyped-def]
        reg = Store()
        mutate(reg)
        captured['reg'] = reg
        return reg

    def refuse_retraversal(path):  # type: ignore[no-untyped-def]
        raise AssertionError('must reuse the source identity pinned by root')

    monkeypatch.setattr(
        'aivm.attachments.session.update_store', fake_update,
    )
    monkeypatch.setattr(
        'aivm.attachments.session.directory_identity', refuse_retraversal,
    )
    _record_attachment(
        cfg, tmp_path / 'config.toml', host_src=source,
        mode='persistent', access='rw', guest_dst='/home/ben/aiq-super-repo',
        tag='ben-aivm-test', owner_principal_id='principal-ben',
        source_identity=identity,
    )
    reg = captured['reg']
    saved = reg.attachments[0]
    assert (saved.source_dev, saved.source_ino) == (147, 258)
    assert saved.owner_principal_id == 'principal-ben'
