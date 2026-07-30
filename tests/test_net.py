"""Tests for ``aivm.net`` libvirt network setup, teardown, and route checks."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest
from pytest import MonkeyPatch

from aivm.cli.net import NetDestroyCLI
from aivm.config import AgentVMConfig
from aivm.config_store import (
    Store,
    find_network,
    save_store,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.errors import AIVMError
from aivm.net import (
    _route_overlap,
    destroy_network,
    ensure_network,
    network_status,
)
from aivm.scoped_store import (
    StoreScope,
    load_scope_store,
    resolve_store_scope,
    save_scope_store,
)
from aivm.util import CmdResult
from tests.helpers import FakeProc, activate_manager


def test_route_overlap_none_without_ip(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.net.which', lambda cmd: None)
    assert _route_overlap('10.77.0.0/24') is None


def test_route_overlap_detects_conflict(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.net.which', lambda cmd: '/usr/sbin/ip')
    monkeypatch.setattr(
        'aivm.net.CommandManager.run',
        lambda self, *a, **k: CmdResult(
            0,
            '10.77.0.0/24 dev virbr0\n10.78.0.0/24 dev virbr1\n',
            '',
        ),
    )
    assert _route_overlap('10.77.0.7/24') is None
    assert _route_overlap('10.77.0.0/23') == '10.77.0.0/24'


def test_ensure_network_bridge_len_and_overlap_errors(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.network.bridge = 'this-bridge-name-is-too-long'
    with pytest.raises(RuntimeError):
        ensure_network(cfg)
    cfg.network.bridge = 'virbr-aivm'
    monkeypatch.setattr('aivm.net._route_overlap', lambda _s: '10.1.0.0/16')
    with pytest.raises(RuntimeError):
        ensure_network(cfg)


def test_ensure_network_existing_not_recreate(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    calls = []

    activate_manager(monkeypatch, yes_sudo=False, euid=0)
    monkeypatch.setattr('aivm.net._route_overlap', lambda _s: None)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append(cmd) or FakeProc(),
    )
    ensure_network(cfg, recreate=False, dry_run=False)
    assert calls == [
        ['virsh', '-c', 'qemu:///system', 'net-info', cfg.network.name]
    ]


def test_network_status_and_destroy(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    calls = []

    info_calls = 0

    def fake_run_cmd(self, cmd: list[str], **kwargs: Any):  # type: ignore[no-untyped-def]
        nonlocal info_calls
        calls.append(cmd)
        if cmd[3] == 'net-info':
            info_calls += 1
            if info_calls <= 2:
                return CmdResult(0, 'INFO', '')
            return CmdResult(1, '', 'error: failed to get network')
        if cmd[3] == 'net-dumpxml':
            return CmdResult(0, '<network/>', '')
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.net.CommandManager.run', fake_run_cmd)
    out = network_status(cfg)
    assert 'INFO' in out
    assert '<network/>' in out
    destroy_network(cfg, dry_run=False)
    assert [
        'virsh',
        '-c',
        'qemu:///system',
        'net-destroy',
        cfg.network.name,
    ] in calls
    assert [
        'virsh',
        '-c',
        'qemu:///system',
        'net-undefine',
        cfg.network.name,
    ] in calls


@pytest.mark.parametrize(
    ('failing_action', 'detail', 'match'),
    [
        ('net-destroy', 'error: permission denied', 'Could not stop'),
        (
            'net-undefine',
            'error: network has active consumers',
            'Could not undefine',
        ),
    ],
)
def test_destroy_network_rejects_unrecognized_libvirt_failures(
    monkeypatch: MonkeyPatch,
    failing_action: str,
    detail: str,
    match: str,
) -> None:
    cfg = AgentVMConfig()
    calls: list[str] = []

    def fake_run(self, cmd: list[str], **kwargs: Any):  # type: ignore[no-untyped-def]
        del self, kwargs
        action = cmd[3]
        calls.append(action)
        if action == 'net-info':
            return CmdResult(0, 'defined', '')
        if action == failing_action:
            return CmdResult(1, '', detail)
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.net.CommandManager.run', fake_run)
    with pytest.raises(AIVMError, match=match):
        destroy_network(cfg)

    if failing_action == 'net-destroy':
        assert 'net-undefine' not in calls


def test_destroy_network_fails_closed_when_net_info_fails(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    calls: list[str] = []

    def fake_run(self, cmd: list[str], **kwargs: Any):  # type: ignore[no-untyped-def]
        del self, kwargs
        calls.append(cmd[3])
        return CmdResult(1, '', 'error: failed to connect to the hypervisor')

    monkeypatch.setattr('aivm.net.CommandManager.run', fake_run)
    with pytest.raises(AIVMError, match='Could not determine'):
        destroy_network(cfg)
    assert calls == ['net-info']


def test_destroy_network_fails_when_final_absence_check_fails(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    info_calls = 0

    def fake_run(self, cmd: list[str], **kwargs: Any):  # type: ignore[no-untyped-def]
        nonlocal info_calls
        del self, kwargs
        action = cmd[3]
        if action == 'net-info':
            info_calls += 1
            if info_calls == 1:
                return CmdResult(0, 'defined', '')
            return CmdResult(1, '', 'error: failed to connect to hypervisor')
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.net.CommandManager.run', fake_run)
    with pytest.raises(AIVMError, match='Could not determine'):
        destroy_network(cfg)


def test_destroy_network_accepts_definitively_absent_network(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    calls: list[str] = []

    def fake_run(self, cmd: list[str], **kwargs: Any):  # type: ignore[no-untyped-def]
        del self, kwargs
        calls.append(cmd[3])
        return CmdResult(1, '', 'error: failed to get network')

    monkeypatch.setattr('aivm.net.CommandManager.run', fake_run)
    destroy_network(cfg)
    assert calls == ['net-info']


def _machine_network_store() -> tuple[StoreScope, AgentVMConfig]:
    scope = resolve_store_scope(None)
    assert scope.is_machine
    cfg = AgentVMConfig()
    reg = Store(store_kind='machine', schema_version=11)
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    save_store(reg, scope.store_path)
    return scope, cfg


@pytest.mark.parametrize(
    'detail',
    [
        'net-destroy failed',
        'net-undefine failed',
        'net-info failed',
    ],
)
def test_net_destroy_cli_preserves_store_on_external_failure(
    monkeypatch: MonkeyPatch,
    detail: str,
) -> None:
    scope, cfg = _machine_network_store()
    monkeypatch.setattr(
        'aivm.cli.net.destroy_network',
        lambda *args, **kwargs: (_ for _ in ()).throw(AIVMError(detail)),
    )

    with pytest.raises(AIVMError, match=detail):
        NetDestroyCLI.main(
            argv=False,
            config=None,
            network=cfg.network.name,
            force=False,
            dry_run=False,
        )

    assert find_network(load_scope_store(scope), cfg.network.name) is not None


def test_net_destroy_cli_removes_record_for_already_absent_network(
    monkeypatch: MonkeyPatch,
) -> None:
    scope, cfg = _machine_network_store()
    monkeypatch.setattr(
        'aivm.cli.net.destroy_network', lambda *args, **kwargs: None
    )

    assert (
        NetDestroyCLI.main(
            argv=False,
            config=None,
            network=cfg.network.name,
            force=False,
            dry_run=False,
        )
        == 0
    )

    assert find_network(load_scope_store(scope), cfg.network.name) is None


def test_net_destroy_reloads_under_lock_and_rejects_concurrent_vm(
    monkeypatch: MonkeyPatch,
) -> None:
    scope, cfg = _machine_network_store()
    initial = load_scope_store(scope)
    concurrent = load_scope_store(scope)
    upsert_vm_with_network(concurrent, cfg, network_name=cfg.network.name)
    stores = iter((initial, concurrent))
    destroy_calls: list[str] = []
    lock_args: list[tuple[bool, tuple[str, ...]]] = []

    monkeypatch.setattr(
        'aivm.cli.net.load_scope_store', lambda _scope: next(stores)
    )
    monkeypatch.setattr(
        'aivm.cli.net.destroy_network',
        lambda selected, **kwargs: destroy_calls.append(selected.network.name),
    )

    @contextmanager
    def fake_locks(
        layout: object,
        *,
        group_gid: int,
        include_store: bool,
        networks: tuple[str, ...],
        **kwargs: object,
    ) -> Iterator[None]:
        del layout, group_gid, kwargs
        lock_args.append((include_store, tuple(networks)))
        yield

    monkeypatch.setattr('aivm.cli.net.machine_resource_locks', fake_locks)
    with pytest.raises(AIVMError, match='referenced by managed VMs'):
        NetDestroyCLI.main(
            argv=False,
            config=None,
            network=cfg.network.name,
            force=False,
            dry_run=False,
        )

    assert lock_args == [(True, (cfg.network.name,))]
    assert destroy_calls == []


def test_net_destroy_save_failure_is_retryable_after_external_deletion(
    monkeypatch: MonkeyPatch,
) -> None:
    scope, cfg = _machine_network_store()
    external = {'defined': True}
    destroy_calls: list[bool] = []
    real_save = save_scope_store
    failures = {'remaining': 1}

    def fake_destroy(selected: AgentVMConfig, *, dry_run: bool = False) -> None:
        del selected, dry_run
        destroy_calls.append(external['defined'])
        external['defined'] = False

    def flaky_save(
        selected_scope: StoreScope, reg: Store, *, reason: str
    ) -> Path:
        if failures['remaining']:
            failures['remaining'] -= 1
            raise OSError('simulated store save failure')
        return real_save(selected_scope, reg, reason=reason)

    monkeypatch.setattr('aivm.cli.net.destroy_network', fake_destroy)
    monkeypatch.setattr('aivm.cli.net.save_scope_store', flaky_save)

    with pytest.raises(OSError, match='store save failure'):
        NetDestroyCLI.main(
            argv=False,
            config=None,
            network=cfg.network.name,
            force=False,
            dry_run=False,
        )
    assert find_network(load_scope_store(scope), cfg.network.name) is not None

    assert (
        NetDestroyCLI.main(
            argv=False,
            config=None,
            network=cfg.network.name,
            force=False,
            dry_run=False,
        )
        == 0
    )
    assert destroy_calls == [True, False]
    assert find_network(load_scope_store(scope), cfg.network.name) is None
