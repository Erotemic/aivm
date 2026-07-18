"""Tests for _resolve_attachment mode/access/guest_dst policy.

These exercise how a requested attachment is reconciled against any saved
record: which mode/access is reused or rejected, what the default guest
destination is per mode, and how existing tags are preserved. The pure
path/tag helpers live in ``test_attachment_paths.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.attachments.resolve import _resolve_attachment
from aivm.config import AgentVMConfig
from aivm.config_store import (
    AttachmentEntry,
    Store,
    save_store,
)
from aivm.vm.share import AttachmentAccess, AttachmentMode


def seed_saved_attachment(
    cfg_path: Path,
    host_src: Path,
    *,
    vm_name: str,
    mode: Any,
    guest_dst: str,
    tag: str = '',
    access: Any = None,
) -> None:
    """Save a single-attachment store keyed on ``host_src``'s resolved path.

    The ``_resolve_attachment`` tests repeatedly stand up a ``Store`` with
    one ``AttachmentEntry`` and persist it; this collapses that block.
    """
    entry_kwargs: dict[str, Any] = {
        'host_path': str(host_src.resolve()),
        'vm_name': vm_name,
        'mode': mode,
        'guest_dst': guest_dst,
        'tag': tag,
    }
    if access is not None:
        entry_kwargs['access'] = access
    store = Store()
    store.attachments.append(AttachmentEntry(**entry_kwargs))
    save_store(store, cfg_path)


def test_resolve_attachment_uses_saved_git_mode(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'repo'
    host_src.mkdir()

    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.GIT,
        guest_dst='/workspace/repo',
        tag='ignored-for-git',
    )

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', '')

    assert resolved.mode == AttachmentMode.GIT
    assert resolved.guest_dst == '/workspace/repo'
    assert resolved.tag == ''


def test_resolve_attachment_defaults_for_new_folder(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-default'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', '')

    assert resolved.mode == AttachmentMode.PERSISTENT
    assert resolved.tag


def test_resolve_attachment_accepts_persistent_mode_for_new_folder(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-default'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    resolved = _resolve_attachment(
        cfg,
        cfg_path,
        host_src,
        '',
        'persistent',
    )

    assert resolved.mode == AttachmentMode.PERSISTENT
    assert resolved.tag


def test_resolve_attachment_reuses_saved_shared_mode_when_mode_omitted(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared-existing'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', '')

    assert resolved.mode == AttachmentMode.SHARED
    assert resolved.guest_dst == '/workspace/proj'
    assert resolved.tag == 'hostcode-proj'


def test_resolve_attachment_reuses_saved_access_when_access_omitted(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared-access-existing'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        access=AttachmentAccess.RO,
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', '')

    assert resolved.mode == AttachmentMode.SHARED
    assert resolved.access == AttachmentAccess.RO


def test_resolve_attachment_rejects_mode_change_for_existing_attachment(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    msg = ''
    try:
        _resolve_attachment(cfg, cfg_path, host_src, '', 'git')
    except RuntimeError as ex:
        msg = str(ex)
    else:
        raise AssertionError('Expected mode-mismatch RuntimeError')

    assert 'Attachment mode mismatch' in msg
    assert 'detach + reattach' in msg


def test_resolve_attachment_rejects_access_change_for_existing_attachment(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared-access'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        access=AttachmentAccess.RW,
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    with pytest.raises(RuntimeError, match='Attachment access mismatch'):
        _resolve_attachment(
            cfg,
            cfg_path,
            host_src,
            '',
            '',
            AttachmentAccess.RO,
        )


def test_resolve_attachment_accepts_ro_for_shared_root_mode(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-ro-shared-root'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    resolved = _resolve_attachment(
        cfg,
        cfg_path,
        host_src,
        '',
        AttachmentMode.SHARED_ROOT,
        AttachmentAccess.RO,
    )
    assert resolved.mode == AttachmentMode.SHARED_ROOT
    assert resolved.access == AttachmentAccess.RO


def test_resolve_attachment_ro_not_implemented_for_git_mode(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-ro-mode'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    with pytest.raises(
        NotImplementedError,
        match='Read-only attachments are currently only implemented',
    ):
        _resolve_attachment(
            cfg,
            cfg_path,
            host_src,
            '',
            AttachmentMode.GIT,
            AttachmentAccess.RO,
        )


def test_resolve_attachment_git_defaults_to_exact_host_path(
    tmp_path: Path,
) -> None:
    """New behaviour: git mode defaults to the exact lexical host path, not guest-home-relative."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'repo'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', 'git')

    assert resolved.mode == AttachmentMode.GIT
    # Default is now the exact (lexical absolute) host path, not guest-home-relative
    assert resolved.guest_dst == str(host_src.expanduser().absolute())


def test_resolve_attachment_git_preserves_saved_guest_dst(
    tmp_path: Path,
) -> None:
    """Existing saved guest_dst is preserved unchanged — no auto-migration occurs."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'repo'
    host_src.mkdir()
    saved_guest_dst = '/home/agent/code/repo'

    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.GIT,
        guest_dst=saved_guest_dst,
        tag='',
    )

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', '')

    assert resolved.mode == AttachmentMode.GIT
    # Saved guest_dst is preserved; no migration to exact host path
    assert resolved.guest_dst == saved_guest_dst


@pytest.mark.parametrize(
    'mode',
    [
        pytest.param(
            AttachmentMode.SHARED, id='shared_defaults_to_exact_host_path'
        ),
        pytest.param(
            AttachmentMode.SHARED_ROOT,
            id='shared_root_defaults_to_exact_host_path',
        ),
    ],
)
def test_resolve_attachment_defaults_to_exact_host_path(
    tmp_path: Path, mode: AttachmentMode
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-{mode.value}-exact'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', mode)

    assert resolved.mode == mode
    assert resolved.guest_dst == str(host_src.expanduser().absolute())


def test_resolve_attachment_explicit_guest_dst_is_preserved(
    tmp_path: Path,
) -> None:
    """Explicit --guest_dst overrides the default for all modes."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-custom-dst'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(Store(), cfg_path)

    for mode in (
        AttachmentMode.SHARED,
        AttachmentMode.SHARED_ROOT,
        AttachmentMode.GIT,
    ):
        resolved = _resolve_attachment(
            cfg, cfg_path, host_src, '/custom/path', mode
        )
        assert resolved.guest_dst == '/custom/path'


def test_resolve_attachment_preserves_existing_saved_tag(
    tmp_path: Path,
) -> None:
    """Existing saved tags are preserved; no forced re-generation."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-tag-preserve'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    saved_tag = 'my-old-custom-tag'
    seed_saved_attachment(
        cfg_path,
        host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        guest_dst='/workspace/proj',
        tag=saved_tag,
    )

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '', '')
    assert resolved.tag == saved_tag
