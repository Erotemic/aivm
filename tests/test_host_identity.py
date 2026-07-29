"""Kernel-derived caller identity and principal matching tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aivm.config_store import PrincipalEntry, Store, find_principal_for_host_identity
from aivm.errors import AIVMError
from aivm.host_identity import HostIdentity, current_host_identity


def test_current_host_identity_ignores_login_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('LOGNAME', 'mallory')
    monkeypatch.setenv('USER', 'mallory')
    monkeypatch.setenv('SUDO_USER', 'mallory')
    monkeypatch.setattr('aivm.host_identity.os.getuid', lambda: 1001)
    monkeypatch.setattr('aivm.host_identity.os.getgid', lambda: 1002)
    monkeypatch.setattr(
        'aivm.host_identity.pwd.getpwuid',
        lambda uid: SimpleNamespace(pw_name='alice'),
    )
    assert current_host_identity() == HostIdentity(
        uid=1001, gid=1002, username='alice'
    )


def _store_with_principal() -> Store:
    return Store(
        principals=[
            PrincipalEntry(
                id='principal-alice',
                vm_name='vm',
                host_user='alice',
                host_uid=1001,
                host_gid=1002,
                guest_user='alice-agent',
                ssh_public_key='ssh-ed25519 AAAA alice',
            )
        ]
    )


def test_principal_identity_requires_uid_and_username() -> None:
    reg = _store_with_principal()
    principal = find_principal_for_host_identity(
        reg,
        vm_name='vm',
        identity=HostIdentity(uid=1001, gid=1002, username='alice'),
    )
    assert principal is not None and principal.id == 'principal-alice'


def test_principal_identity_reports_account_rename() -> None:
    with pytest.raises(AIVMError, match='account rename'):
        find_principal_for_host_identity(
            _store_with_principal(),
            vm_name='vm',
            identity=HostIdentity(uid=1001, gid=1002, username='alice-renamed'),
        )


def test_principal_identity_reports_uid_reuse() -> None:
    with pytest.raises(AIVMError, match='account recreation|UID reuse'):
        find_principal_for_host_identity(
            _store_with_principal(),
            vm_name='vm',
            identity=HostIdentity(uid=2001, gid=2002, username='alice'),
        )
