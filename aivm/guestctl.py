#!/usr/bin/env python3
"""Restricted guest-side principal enrollment helper.

This module is intentionally stdlib-only because its own source is installed
inside managed guests as ``/usr/local/sbin/aivm-guestctl``.  The bootstrap SSH
key is forced to invoke ``--forced`` and can do nothing except submit one JSON
enrollment request on standard input.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Literal, Sequence

BOOTSTRAP_GUEST_USER = 'aivm-bootstrap'
GUESTCTL_PATH = '/usr/local/sbin/aivm-guestctl'
BOOTSTRAP_SUDOERS_PATH = '/etc/sudoers.d/aivm-bootstrap'

_GUEST_USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
_ALLOWED_KEY_PREFIXES = (
    'ssh-ed25519 ',
    'sk-ssh-ed25519@openssh.com ',
    'ecdsa-sha2-nistp256 ',
    'sk-ecdsa-sha2-nistp256@openssh.com ',
    'ssh-rsa ',
)


class GuestEnrollmentError(RuntimeError):
    """Raised for an invalid request or conflicting guest state."""


@dataclass(frozen=True)
class GuestEnrollmentRequest:
    """One idempotent host-principal enrollment request."""

    guest_user: str
    uid: int
    gid: int
    public_key: str
    allow_sudo: bool = True
    groups: tuple[str, ...] = ('docker',)

    def validated(self) -> 'GuestEnrollmentRequest':
        user = self.guest_user.strip()
        if not _GUEST_USER_RE.fullmatch(user):
            raise GuestEnrollmentError(
                f'invalid guest username {user!r}; expected a lowercase POSIX '
                'login containing only letters, digits, underscores, or hyphens'
            )
        uid = int(self.uid)
        gid = int(self.gid)
        if uid <= 0 or gid <= 0:
            raise GuestEnrollmentError(
                'guest uid/gid must be positive non-root values'
            )
        key = self.public_key.strip()
        if (
            '\n' in key
            or '\r' in key
            or not key.startswith(_ALLOWED_KEY_PREFIXES)
        ):
            raise GuestEnrollmentError(
                'public_key must be one supported single-line SSH key'
            )
        groups = tuple(
            item.strip()
            for item in self.groups
            if item.strip() and _GUEST_USER_RE.fullmatch(item.strip())
        )
        return GuestEnrollmentRequest(
            guest_user=user,
            uid=uid,
            gid=gid,
            public_key=key,
            allow_sudo=bool(self.allow_sudo),
            groups=groups,
        )

    def to_json(self) -> str:
        payload = asdict(self.validated())
        payload['groups'] = list(payload['groups'])
        return json.dumps(payload, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> 'GuestEnrollmentRequest':
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as ex:
            raise GuestEnrollmentError(f'invalid enrollment JSON: {ex}') from ex
        if not isinstance(raw, dict):
            raise GuestEnrollmentError(
                'enrollment payload must be a JSON object'
            )
        try:
            request = cls(
                guest_user=str(raw['guest_user']),
                uid=int(raw['uid']),
                gid=int(raw['gid']),
                public_key=str(raw['public_key']),
                allow_sudo=bool(raw.get('allow_sudo', True)),
                groups=tuple(str(x) for x in raw.get('groups', ['docker'])),
            )
        except (KeyError, TypeError, ValueError) as ex:
            raise GuestEnrollmentError(
                f'invalid enrollment fields: {ex}'
            ) from ex
        return request.validated()


@dataclass(frozen=True)
class GuestAccessRequest:
    """Restricted request that removes one persisted access key."""

    operation: Literal['disable-principal']
    guest_user: str
    public_key: str

    def validated(self) -> 'GuestAccessRequest':
        if self.operation != 'disable-principal':
            raise GuestEnrollmentError(
                f'unsupported guest access operation {self.operation!r}'
            )
        user = self.guest_user.strip()
        if not _GUEST_USER_RE.fullmatch(user):
            raise GuestEnrollmentError(
                f'invalid guest username {user!r}; expected a lowercase POSIX '
                'login containing only letters, digits, underscores, or hyphens'
            )
        key = self.public_key.strip()
        if (
            '\n' in key
            or '\r' in key
            or not key.startswith(_ALLOWED_KEY_PREFIXES)
        ):
            raise GuestEnrollmentError(
                'public_key must be one supported single-line SSH key'
            )
        return GuestAccessRequest(
            operation='disable-principal',
            guest_user=user,
            public_key=key,
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self.validated()), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> 'GuestAccessRequest':
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as ex:
            raise GuestEnrollmentError(f'invalid access JSON: {ex}') from ex
        if not isinstance(raw, dict):
            raise GuestEnrollmentError('access payload must be a JSON object')
        try:
            operation_raw = str(raw['operation'])
            if operation_raw != 'disable-principal':
                raise GuestEnrollmentError(
                    f'unsupported guest access operation {operation_raw!r}'
                )
            operation: Literal['disable-principal'] = 'disable-principal'
            request = cls(
                operation=operation,
                guest_user=str(raw['guest_user']),
                public_key=str(raw['public_key']),
            )
        except (KeyError, TypeError, ValueError) as ex:
            raise GuestEnrollmentError(f'invalid access fields: {ex}') from ex
        return request.validated()


Runner = Callable[..., subprocess.CompletedProcess[str]]
ChownPath = str | bytes | os.PathLike[str] | os.PathLike[bytes]
Chown = Callable[[ChownPath, int, int], None]


def guestctl_source() -> str:
    """Return the exact standalone source installed in the guest."""
    return Path(__file__).read_text(encoding='utf-8')


def restricted_bootstrap_authorized_key(public_key: str) -> str:
    """Return an authorized_keys entry that can invoke only guest enrollment."""
    key = public_key.strip()
    if '\n' in key or '\r' in key or not key.startswith(_ALLOWED_KEY_PREFIXES):
        raise GuestEnrollmentError('invalid bootstrap SSH public key')
    forced = f'/usr/bin/sudo -n {GUESTCTL_PATH} --forced'
    options = (
        'no-agent-forwarding,no-port-forwarding,no-X11-forwarding,'
        f'no-pty,no-user-rc,command="{forced}"'
    )
    return f'{options} {key}'


def _run(
    runner: Runner,
    argv: Sequence[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = runner(
        [str(x) for x in argv],
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise GuestEnrollmentError(
            f'guest enrollment command failed ({" ".join(argv)}): {detail}'
        )
    return result


def _getent(runner: Runner, database: str, key: str) -> str | None:
    result = _run(runner, ['getent', database, key], check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    if result.returncode == 2:
        return None
    detail = (result.stderr or result.stdout or '').strip()
    raise GuestEnrollmentError(f'getent {database} {key} failed: {detail}')


def _ensure_group(request: GuestEnrollmentRequest, runner: Runner) -> str:
    by_gid = _getent(runner, 'group', str(request.gid))
    if by_gid:
        return by_gid.split(':', 1)[0]
    by_name = _getent(runner, 'group', request.guest_user)
    if by_name:
        fields = by_name.split(':')
        existing_gid = int(fields[2]) if len(fields) > 2 else -1
        if existing_gid != request.gid:
            raise GuestEnrollmentError(
                f'group {request.guest_user!r} already uses gid '
                f'{existing_gid}, '
                f'not requested gid {request.gid}'
            )
        return request.guest_user
    _run(runner, ['groupadd', '-g', str(request.gid), request.guest_user])
    return request.guest_user


def _ensure_user(
    request: GuestEnrollmentRequest,
    runner: Runner,
    *,
    home_root: Path,
) -> Path:
    by_name = _getent(runner, 'passwd', request.guest_user)
    by_uid = _getent(runner, 'passwd', str(request.uid))
    if by_uid and by_uid.split(':', 1)[0] != request.guest_user:
        raise GuestEnrollmentError(
            f'uid {request.uid} is already used by {by_uid.split(":", 1)[0]!r}'
        )
    home = home_root / request.guest_user
    if by_name:
        fields = by_name.split(':')
        existing_uid = int(fields[2]) if len(fields) > 2 else -1
        existing_gid = int(fields[3]) if len(fields) > 3 else -1
        if existing_uid != request.uid:
            raise GuestEnrollmentError(
                f'user {request.guest_user!r} already uses uid {existing_uid}, '
                f'not requested uid {request.uid}'
            )
        if existing_gid != request.gid:
            _run(
                runner,
                ['usermod', '-g', str(request.gid), request.guest_user],
            )
        if len(fields) > 6 and fields[6] != '/bin/bash':
            _run(runner, ['usermod', '-s', '/bin/bash', request.guest_user])
    else:
        _run(
            runner,
            [
                'useradd',
                '-m',
                '-u',
                str(request.uid),
                '-g',
                str(request.gid),
                '-d',
                str(home),
                '-s',
                '/bin/bash',
                request.guest_user,
            ],
        )
    return home


def _atomic_text(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        'w', encoding='utf-8', dir=str(path.parent), delete=False
    ) as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
        tmp = Path(file.name)
    try:
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        os.chmod(path, mode)
    finally:
        tmp.unlink(missing_ok=True)


def _public_key_identity(line: str) -> tuple[str, str] | None:
    """Return OpenSSH algorithm/blob while ignoring optional comments."""
    parts = str(line or '').strip().split()
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _same_public_key(left: str, right: str) -> bool:
    identity = _public_key_identity(left)
    return identity is not None and identity == _public_key_identity(right)


def _ensure_authorized_key(
    request: GuestEnrollmentRequest,
    *,
    home: Path,
    chown: Chown,
) -> None:
    ssh_dir = home / '.ssh'
    ssh_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    authorized = ssh_dir / 'authorized_keys'
    lines = []
    if authorized.exists():
        lines = authorized.read_text(encoding='utf-8').splitlines()
    matching = [line for line in lines if _same_public_key(line, request.public_key)]
    if not matching:
        lines.append(request.public_key)
    elif len(matching) > 1:
        # Collapse duplicates while preserving the first enrolled spelling.
        kept = False
        deduped = []
        for line in lines:
            if _same_public_key(line, request.public_key):
                if kept:
                    continue
                kept = True
            deduped.append(line)
        lines = deduped
    _atomic_text(authorized, '\n'.join(lines).rstrip() + '\n', 0o600)
    chown(ssh_dir, request.uid, request.gid)
    chown(authorized, request.uid, request.gid)
    chown(home, request.uid, request.gid)


def _ensure_sudo(
    request: GuestEnrollmentRequest,
    runner: Runner,
    *,
    sudoers_root: Path,
) -> None:
    path = sudoers_root / f'aivm-principal-{request.guest_user}'
    if not request.allow_sudo:
        path.unlink(missing_ok=True)
        return
    content = f'{request.guest_user} ALL=(ALL) NOPASSWD:ALL\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        'w', encoding='utf-8', dir=str(path.parent), delete=False
    ) as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())
        tmp = Path(file.name)
    try:
        os.chmod(tmp, 0o440)
        _run(runner, ['visudo', '-cf', str(tmp)])
        os.replace(tmp, path)
        os.chmod(path, 0o440)
    finally:
        tmp.unlink(missing_ok=True)


def reconcile_guest_principal(
    request: GuestEnrollmentRequest,
    *,
    runner: Runner = subprocess.run,
    home_root: Path = Path('/home'),
    sudoers_root: Path = Path('/etc/sudoers.d'),
    chown: Chown = os.chown,
) -> dict[str, object]:
    """Create or repair one guest account and return a non-secret report."""
    request = request.validated()
    _ensure_group(request, runner)
    home = _ensure_user(request, runner, home_root=home_root)
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o750)
    _ensure_authorized_key(request, home=home, chown=chown)
    _ensure_sudo(request, runner, sudoers_root=sudoers_root)
    joined_groups: list[str] = []
    for group in request.groups:
        if _getent(runner, 'group', group):
            _run(runner, ['usermod', '-aG', group, request.guest_user])
            joined_groups.append(group)
    return {
        'status': 'ok',
        'guest_user': request.guest_user,
        'uid': request.uid,
        'gid': request.gid,
        'home': str(home),
        'sudo': request.allow_sudo,
        'groups': joined_groups,
    }



def disable_guest_principal(
    request: GuestAccessRequest,
    *,
    runner: Runner = subprocess.run,
    home_root: Path = Path('/home'),
    sudoers_root: Path = Path('/etc/sudoers.d'),
    chown: Chown = os.chown,
) -> dict[str, object]:
    """Remove one AIVM key and sudoers fragment without deleting the home."""
    request = request.validated()
    passwd = _getent(runner, 'passwd', request.guest_user)
    account_present = passwd is not None
    removed_key = False
    if passwd is not None:
        fields = passwd.split(':')
        uid = int(fields[2]) if len(fields) > 2 else -1
        gid = int(fields[3]) if len(fields) > 3 else -1
        home = (
            Path(fields[5])
            if len(fields) > 5 and fields[5]
            else home_root / request.guest_user
        )
        authorized = home / '.ssh' / 'authorized_keys'
        if authorized.exists():
            original = authorized.read_text(encoding='utf-8').splitlines()
            retained = [
                line
                for line in original
                if not _same_public_key(line, request.public_key)
            ]
            removed_key = retained != original
            _atomic_text(
                authorized,
                ('\n'.join(retained).rstrip() + '\n') if retained else '',
                0o600,
            )
            if uid >= 0 and gid >= 0:
                chown(authorized, uid, gid)
    sudoers = sudoers_root / f'aivm-principal-{request.guest_user}'
    removed_sudoers = sudoers.exists()
    sudoers.unlink(missing_ok=True)
    if sudoers.exists():
        raise GuestEnrollmentError(
            f'could not remove AIVM sudoers fragment for {request.guest_user!r}'
        )
    if passwd is not None:
        fields = passwd.split(':')
        home = (
            Path(fields[5])
            if len(fields) > 5 and fields[5]
            else home_root / request.guest_user
        )
        authorized = home / '.ssh' / 'authorized_keys'
        if authorized.exists():
            remaining = authorized.read_text(encoding='utf-8').splitlines()
            if any(_same_public_key(line, request.public_key) for line in remaining):
                raise GuestEnrollmentError(
                    f'could not verify SSH key revocation for {request.guest_user!r}'
                )
    return {
        'status': 'ok',
        'operation': request.operation,
        'guest_user': request.guest_user,
        'account_present': account_present,
        'authorized_key_removed': removed_key,
        'sudoers_removed': removed_sudoers,
        'home_retained': True,
    }

def _forced_main() -> int:
    if os.geteuid() != 0:
        print('aivm-guestctl --forced must run as root', file=sys.stderr)
        return 77
    text = sys.stdin.read()
    try:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as ex:
            raise GuestEnrollmentError(f'invalid request JSON: {ex}') from ex
        if not isinstance(raw, dict):
            raise GuestEnrollmentError('request payload must be a JSON object')
        operation = str(raw.get('operation', 'enroll-principal'))
        if operation == 'enroll-principal':
            request = GuestEnrollmentRequest.from_json(text)
            report = reconcile_guest_principal(request)
        elif operation == 'disable-principal':
            access_request = GuestAccessRequest.from_json(text)
            report = disable_guest_principal(access_request)
        else:
            raise GuestEnrollmentError(
                f'unsupported guestctl operation {operation!r}'
            )
    except GuestEnrollmentError as ex:
        print(
            json.dumps({'status': 'error', 'error': str(ex)}),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ['--forced']:
        return _forced_main()
    print(
        'aivm-guestctl is only available through the restricted bootstrap key',
        file=sys.stderr,
    )
    return 64


if __name__ == '__main__':
    raise SystemExit(main())
