"""Guest-side restricted enrollment helper tests."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from aivm.guestctl import (
    GuestAccessRequest,
    GuestEnrollmentError,
    GuestEnrollmentRequest,
    restricted_bootstrap_authorized_key,
)
from aivm.rc.guest import guestctl as guestctl_program

ChownPath = guestctl_program.ChownPath
reconcile_guest_principal = guestctl_program.reconcile_guest_principal


class FakeGuestSystem:
    """Small getent/useradd/groupadd model for idempotence tests."""

    def __init__(self) -> None:
        self.groups: dict[str, int] = {'docker': 998}
        self.users: dict[str, dict[str, Any]] = {}
        self.commands: list[list[str]] = []

    def __call__(
        self, argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        cmd = [str(x) for x in argv]
        self.commands.append(cmd)
        if cmd[:2] == ['getent', 'group']:
            key = cmd[2]
            if key.isdigit():
                group_found = next(
                    (
                        (name, gid)
                        for name, gid in self.groups.items()
                        if gid == int(key)
                    ),
                    None,
                )
            else:
                group_found = (
                    (key, self.groups[key]) if key in self.groups else None
                )
            if group_found:
                name, gid = group_found
                return subprocess.CompletedProcess(
                    cmd, 0, f'{name}:x:{gid}:\n', ''
                )
            return subprocess.CompletedProcess(cmd, 2, '', '')
        if cmd[:2] == ['getent', 'passwd']:
            key = cmd[2]
            if key.isdigit():
                user_found = next(
                    (
                        (name, info)
                        for name, info in self.users.items()
                        if info['uid'] == int(key)
                    ),
                    None,
                )
            else:
                user_found = (
                    (key, self.users[key]) if key in self.users else None
                )
            if user_found:
                name, info = user_found
                line = (
                    f'{name}:x:{info["uid"]}:{info["gid"]}::{info["home"]}:'
                    f'{info["shell"]}\n'
                )
                return subprocess.CompletedProcess(cmd, 0, line, '')
            return subprocess.CompletedProcess(cmd, 2, '', '')
        if cmd[0] == 'groupadd':
            self.groups[cmd[-1]] = int(cmd[2])
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if cmd[0] == 'useradd':
            name = cmd[-1]
            self.users[name] = {
                'uid': int(cmd[cmd.index('-u') + 1]),
                'gid': int(cmd[cmd.index('-g') + 1]),
                'home': cmd[cmd.index('-d') + 1],
                'shell': cmd[cmd.index('-s') + 1],
            }
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if cmd[:2] == ['usermod', '-g']:
            self.users[cmd[-1]]['gid'] = int(cmd[2])
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if cmd[:2] == ['usermod', '-s']:
            self.users[cmd[-1]]['shell'] = cmd[2]
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if cmd[:2] == ['usermod', '-aG']:
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if cmd[:2] == ['visudo', '-cf']:
            return subprocess.CompletedProcess(cmd, 0, '', '')
        raise AssertionError(f'unexpected guest command: {cmd!r}')


def test_restricted_bootstrap_key_forces_guestctl() -> None:
    entry = restricted_bootstrap_authorized_key(
        'ssh-ed25519 AAAATEST bootstrap@test'
    )
    forced = 'command="/usr/bin/sudo -n /usr/local/sbin/aivm-guestctl --forced"'
    assert forced in entry
    assert 'no-port-forwarding' in entry
    assert 'no-agent-forwarding' in entry
    assert 'no-X11-forwarding' in entry
    assert 'no-pty' in entry
    assert entry.endswith('ssh-ed25519 AAAATEST bootstrap@test')


def test_guest_enrollment_is_idempotent(tmp_path: Path) -> None:
    system = FakeGuestSystem()
    request = guestctl_program.GuestEnrollmentRequest(
        guest_user='edward-wang-agent',
        uid=1201,
        gid=1201,
        public_key='ssh-ed25519 AAAAEDWARD edward@test',
    )

    def no_chown(path: ChownPath, uid: int, gid: int) -> None:
        del path, uid, gid

    first = reconcile_guest_principal(
        request,
        runner=system,
        home_root=tmp_path / 'home',
        sudoers_root=tmp_path / 'sudoers',
        chown=no_chown,
    )
    second = reconcile_guest_principal(
        request,
        runner=system,
        home_root=tmp_path / 'home',
        sudoers_root=tmp_path / 'sudoers',
        chown=no_chown,
    )

    assert first == second
    assert first['guest_user'] == 'edward-wang-agent'
    authorized = (
        tmp_path / 'home' / 'edward-wang-agent' / '.ssh' / 'authorized_keys'
    )
    assert authorized.read_text().splitlines() == [request.public_key]
    sudoers_path = tmp_path / 'sudoers' / 'aivm-principal-edward-wang-agent'
    assert sudoers_path.read_text() == (
        'edward-wang-agent ALL=(ALL) NOPASSWD:ALL\n'
    )
    assert sum(cmd[0] == 'groupadd' for cmd in system.commands) == 1
    assert sum(cmd[0] == 'useradd' for cmd in system.commands) == 1


def test_guest_enrollment_rejects_uid_collision(tmp_path: Path) -> None:
    system = FakeGuestSystem()
    system.users['somebody-else'] = {
        'uid': 1201,
        'gid': 1201,
        'home': '/home/somebody-else',
        'shell': '/bin/bash',
    }
    request = guestctl_program.GuestEnrollmentRequest(
        guest_user='edward-wang-agent',
        uid=1201,
        gid=1201,
        public_key='ssh-ed25519 AAAAEDWARD edward@test',
    )
    with pytest.raises(
        guestctl_program.GuestEnrollmentError, match='uid 1201 is already used'
    ):
        reconcile_guest_principal(
            request,
            runner=system,
            home_root=tmp_path / 'home',
            sudoers_root=tmp_path / 'sudoers',
            chown=lambda *args: None,
        )


@pytest.mark.parametrize(
    'guest_user',
    ['Edward.Agent', 'bad user', '-agent', 'x' * 33],
)
def test_guest_enrollment_rejects_invalid_usernames(guest_user: str) -> None:
    with pytest.raises(GuestEnrollmentError, match='invalid guest username'):
        GuestEnrollmentRequest(
            guest_user=guest_user,
            uid=1001,
            gid=1001,
            public_key='ssh-ed25519 AAAATEST user@test',
        ).validated()


def test_guest_disable_removes_only_selected_key_and_sudoers(
    tmp_path: Path,
) -> None:
    GuestAccessRequest = guestctl_program.GuestAccessRequest
    disable_guest_principal = guestctl_program.disable_guest_principal

    system = FakeGuestSystem()
    enrollment = guestctl_program.GuestEnrollmentRequest(
        guest_user='edward-wang-agent',
        uid=1201,
        gid=1201,
        public_key='ssh-ed25519 AAAAEDWARD edward@test',
    )
    reconcile_guest_principal(
        enrollment,
        runner=system,
        home_root=tmp_path / 'home',
        sudoers_root=tmp_path / 'sudoers',
        chown=lambda *args: None,
    )
    authorized = (
        tmp_path / 'home' / 'edward-wang-agent' / '.ssh' / 'authorized_keys'
    )
    unrelated = 'ssh-ed25519 AAAAOTHER other@test'
    authorized.write_text(
        enrollment.public_key + '\n' + unrelated + '\n', encoding='utf-8'
    )

    report = disable_guest_principal(
        GuestAccessRequest(
            operation='disable-principal',
            guest_user=enrollment.guest_user,
            public_key=enrollment.public_key,
        ),
        runner=system,
        home_root=tmp_path / 'home',
        sudoers_root=tmp_path / 'sudoers',
        chown=lambda *args: None,
    )

    assert report['authorized_key_removed'] is True
    assert authorized.read_text(encoding='utf-8').splitlines() == [unrelated]
    assert not (
        tmp_path / 'sudoers' / 'aivm-principal-edward-wang-agent'
    ).exists()
    assert (tmp_path / 'home' / 'edward-wang-agent').is_dir()


def test_guest_access_request_rejects_unknown_operation() -> None:
    GuestAccessRequest = guestctl_program.GuestAccessRequest

    with pytest.raises(
        guestctl_program.GuestEnrollmentError, match='unsupported guest access'
    ):
        GuestAccessRequest.from_json(
            '{"operation":"delete-home","guest_user":"agent",'
            '"public_key":"ssh-ed25519 AAAATEST user@test"}'
        )



def test_host_and_guest_enrollment_protocols_round_trip_identically() -> None:
    host_request = GuestEnrollmentRequest(
        guest_user='edward-wang-agent',
        uid=1201,
        gid=1201,
        public_key='ssh-ed25519 AAAAEDWARD edward@test',
        allow_sudo=False,
        groups=('docker', 'video'),
    )
    guest_request = guestctl_program.GuestEnrollmentRequest.from_json(
        host_request.to_json()
    )
    assert guest_request.to_json() == host_request.to_json()


def test_host_and_guest_access_protocols_round_trip_identically() -> None:
    host_request = GuestAccessRequest(
        operation='disable-principal',
        guest_user='edward-wang-agent',
        public_key='ssh-ed25519 AAAAEDWARD edward@test',
    )
    guest_request = guestctl_program.GuestAccessRequest.from_json(
        host_request.to_json()
    )
    assert guest_request.to_json() == host_request.to_json()
