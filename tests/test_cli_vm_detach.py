"""Tests for explicit vm detach behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from pytest import MonkeyPatch

from aivm.cli.vm_attach import VMDetachCLI
from aivm.config_store import (
    AttachmentEntry,
    Store,
    find_attachment_for_vm,
    load_store,
)
from aivm.status import ProbeOutcome
from aivm.vm.share import AttachmentMode
from tests.helpers import (
    make_cfg,
    patch_ns,
    records,
    resolved_test_context,
    returns,
)


def _forbidden(message: str) -> Callable[..., Any]:
    """Build a stub that fails the test if it is ever called."""

    def _stub(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise AssertionError(message)

    return _stub


def _record_remove(
    store: Store, saved: list[Path]
) -> Callable[[Any, Path, AttachmentEntry], bool]:
    """Remove the exact record from the in-memory store and record its path."""

    def _stub(cfg: Any, path: Path, attachment: AttachmentEntry) -> bool:
        del cfg
        saved.append(path)
        store.attachments.remove(attachment)
        return True

    return _stub


def test_vm_detach_shared_removes_store_and_detaches_mapping(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(None, **{'vm.name': 'vm-shared'})
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str(host_src.resolve()),
            vm_name=cfg.vm.name,
            mode=AttachmentMode.SHARED,
            guest_dst='/workspace/proj',
            tag='hostcode-proj',
        )
    )

    detached: list[Any] = []
    saved: list[Path] = []
    patch_ns(
        monkeypatch,
        'aivm.cli.vm_attach',
        {
            'resolve_context_for_code': returns(
                (resolved_test_context(cfg), cfg_path)
            ),
            'load_store': returns(store),
            'probe_vm_state': returns((ProbeOutcome(True, 'running'), True)),
            'detach_vm_share': records(detached, True),
            '_remove_attachment_record': _record_remove(store, saved),
        },
    )

    rc = VMDetachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 0
    assert len(detached) == 1
    assert saved == [cfg_path]
    assert find_attachment_for_vm(store, host_src, cfg.vm.name) is None


def test_vm_detach_git_only_updates_store(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(None, **{'vm.name': 'vm-git'})
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'repo'
    host_src.mkdir()

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str(host_src.resolve()),
            vm_name=cfg.vm.name,
            mode=AttachmentMode.GIT,
            guest_dst='/workspace/repo',
            tag='',
        )
    )

    saved: list[Path] = []
    patch_ns(
        monkeypatch,
        'aivm.cli.vm_attach',
        {
            'resolve_context_for_code': returns(
                (resolved_test_context(cfg), cfg_path)
            ),
            'load_store': returns(store),
            'probe_vm_state': returns((ProbeOutcome(False, 'shut off'), True)),
            'detach_vm_share': _forbidden(
                'detach_vm_share should not be called for git mode'
            ),
            '_remove_attachment_record': _record_remove(store, saved),
        },
    )

    rc = VMDetachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 0
    assert saved == [cfg_path]
    assert find_attachment_for_vm(store, host_src, cfg.vm.name) is None


def test_vm_detach_shared_root_unbinds_guest_and_host(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(None, **{'vm.name': 'vm-shared-root'})
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str(host_src.resolve()),
            vm_name=cfg.vm.name,
            mode=AttachmentMode.SHARED_ROOT,
            guest_dst='/workspace/proj',
            tag='hostcode-proj',
        )
    )

    guest_detaches: list[Any] = []
    host_detaches: list[Any] = []
    saved: list[Path] = []
    patch_ns(
        monkeypatch,
        'aivm.cli.vm_attach',
        {
            'resolve_context_for_code': returns(
                (resolved_test_context(cfg), cfg_path)
            ),
            'load_store': returns(store),
            'probe_vm_state': returns((ProbeOutcome(True, 'running'), True)),
            '_resolve_ip_for_ssh_ops': returns('10.77.0.42'),
            '_detach_shared_root_guest_bind': records(guest_detaches),
            '_detach_shared_root_host_bind': records(host_detaches),
            'detach_vm_share': _forbidden(
                'detach_vm_share should not be called for shared-root mode'
            ),
            '_remove_attachment_record': _record_remove(store, saved),
        },
    )

    rc = VMDetachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 0
    assert len(guest_detaches) == 1
    assert len(host_detaches) == 1


def test_vm_detach_persistent_prunes_host_and_guest_before_record_removal(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.config_store import save_store

    cfg = make_cfg(None, **{'vm.name': 'vm-persistent-detach'})
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    reg = Store()
    reg.attachments.append(
        AttachmentEntry(
            host_path=str(host_src.resolve()),
            vm_name=cfg.vm.name,
            mode='persistent',
            access='ro',
            guest_dst='/workspace/proj',
            tag='hostcode-proj',
        )
    )
    save_store(reg, cfg_path)

    syncs: list[Any] = []
    replay_syncs: list[Any] = []
    host_replays: list[Any] = []
    guest_replays: list[Any] = []
    artifact_cleanups: list[Any] = []
    replay_order: list[str] = []

    def record_guest_replay(*args: Any, **kwargs: Any) -> None:
        guest_replays.append((args, kwargs))
        replay_order.append('guest')

    def record_host_replay(*args: Any, **kwargs: Any) -> None:
        host_replays.append((args, kwargs))
        replay_order.append('host')

    patch_ns(
        monkeypatch,
        'aivm.cli.vm_attach',
        {
            'resolve_context_for_code': returns(
                (resolved_test_context(cfg), cfg_path)
            ),
            'probe_vm_state': returns(
                (
                    ProbeOutcome(True, 'vm-persistent-detach state=running'),
                    True,
                )
            ),
            '_resolve_ip_for_ssh_ops': returns('10.0.0.11'),
            '_detach_shared_root_host_bind': _forbidden(
                'persistent detach should not tear down host bind'
            ),
            '_detach_shared_root_guest_bind': _forbidden(
                'persistent detach should use replay reconcile instead'
            ),
            '_sync_persistent_attachment_manifest_on_host': records(
                syncs, cfg_path
            ),
            # The root-owned replay manifest sync escalates for real; the
            # seam is the subject of test_persistent_host.py.
            '_sync_persistent_host_replay_manifest': records(
                replay_syncs, cfg_path
            ),
            '_reconcile_persistent_attachments_in_guest': record_guest_replay,
            '_reconcile_persistent_host_binds': record_host_replay,
            '_cleanup_persistent_host_replay_artifacts': records(
                artifact_cleanups, True
            ),
        },
    )

    rc = VMDetachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )

    assert rc == 0
    assert len(syncs) == 2
    assert len(replay_syncs) == 1
    assert len(host_replays) == 1
    assert len(guest_replays) == 1
    assert replay_order == ['guest', 'host']
    assert guest_replays[0][1]['reconcile_host'] is False
    assert len(artifact_cleanups) == 1
    assert (
        find_attachment_for_vm(load_store(cfg_path), host_src, cfg.vm.name)
        is None
    )


def test_persistent_detach_retains_detaching_record_when_host_prune_fails(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.config_store import save_store

    cfg = make_cfg(None, **{'vm.name': 'vm-persistent-failure'})
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    save_store(
        Store(
            attachments=[
                AttachmentEntry(
                    host_path=str(host_src.resolve()),
                    vm_name=cfg.vm.name,
                    mode='persistent',
                    guest_dst='/workspace/proj',
                    tag='hostcode-proj',
                )
            ]
        ),
        cfg_path,
    )
    patch_ns(
        monkeypatch,
        'aivm.cli.vm_attach',
        {
            'resolve_context_for_code': returns(
                (resolved_test_context(cfg), cfg_path)
            ),
            'probe_vm_state': returns((ProbeOutcome(False, 'shut off'), True)),
            '_sync_persistent_attachment_manifest_on_host': records(
                [], cfg_path
            ),
            '_sync_persistent_host_replay_manifest': records([], cfg_path),
            '_reconcile_persistent_host_binds': lambda *a, **k: (
                _ for _ in ()
            ).throw(RuntimeError('simulated busy host bind')),
        },
    )

    rc = VMDetachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 2
    retained = find_attachment_for_vm(
        load_store(cfg_path), host_src, cfg.vm.name
    )
    assert retained is not None
    assert retained.state == 'detaching'


def test_detach_matches_deleted_source_lexically(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.config_store import save_store

    cfg = make_cfg(None, **{'vm.name': 'vm-missing-source'})
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'gone'
    save_store(
        Store(
            attachments=[
                AttachmentEntry(
                    host_path=str(host_src),
                    vm_name=cfg.vm.name,
                    mode='git',
                    guest_dst='/workspace/gone',
                )
            ]
        ),
        cfg_path,
    )
    patch_ns(
        monkeypatch,
        'aivm.cli.vm_attach',
        {
            'resolve_context_for_code': returns(
                (resolved_test_context(cfg), cfg_path)
            ),
            'probe_vm_state': returns((ProbeOutcome(False, 'shut off'), True)),
        },
    )
    rc = VMDetachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 0
    assert (
        find_attachment_for_vm(load_store(cfg_path), host_src, cfg.vm.name)
        is None
    )
