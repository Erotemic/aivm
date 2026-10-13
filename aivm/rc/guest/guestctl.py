#!/usr/bin/env python3
"""Restricted guest-side principal enrollment helper.

This module is intentionally stdlib-only because its own source is installed
inside managed guests as ``/usr/local/sbin/aivm-guestctl``.  The bootstrap SSH
key is forced to invoke ``--forced`` and can do nothing except submit one JSON
enrollment request on standard input.
"""

from __future__ import annotations

import json
import pwd
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
            allow_sudo=self.allow_sudo,
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


@dataclass(frozen=True)
class GuestIdentityCSRRequest:
    """Only the host's forced bootstrap SSH identity can request this CSR.

    The nonce is an exchange-binding challenge, not a claim of hardware
    attestation. The private key belongs to the ordinary guest user.
    """

    operation: Literal['identity-csr', 'identity-key-rotate-csr']
    guest_user: str
    uid: int
    nonce: str

    @classmethod
    def from_json(cls, text: str) -> 'GuestIdentityCSRRequest':
        try:
            raw = json.loads(text)
        except (ValueError, TypeError):
            raise GuestEnrollmentError('invalid CSR request') from None
        if (not isinstance(raw, dict) or set(raw) != {
                'operation', 'guest_user', 'uid', 'nonce'} or
                raw['operation'] not in ('identity-csr', 'identity-key-rotate-csr') or
                not isinstance(raw['guest_user'], str) or
                not _GUEST_USER_RE.fullmatch(raw['guest_user']) or
                type(raw['uid']) is not int or raw['uid'] <= 0 or
                type(raw['nonce']) is not str or
                not re.fullmatch(r'[0-9a-f]{32}', raw['nonce'])):
            raise GuestEnrollmentError('invalid CSR request')
        return cls(raw['operation'], raw['guest_user'], raw['uid'], raw['nonce'])

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def _csr_child_env() -> dict[str, str]:
    """Minimal environment for fixed bootstrap subprocesses.

    The privileged forced helper must not inherit loader, OpenSSL provider,
    or language startup settings from its caller. All executables are absolute.
    """
    return {'PATH': '/usr/sbin:/usr/bin:/bin', 'LC_ALL': 'C'}


def _run_as_guest(user: str, argv: list[str]) -> bytes:
    """Execute only fixed absolute programs under the non-root guest UID."""
    try:
        result = subprocess.run(
            ['/usr/sbin/runuser', '-u', user, '--', *argv],
            capture_output=True, timeout=30, check=False,
            env=_csr_child_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GuestEnrollmentError('CSR operation failed') from None
    if result.returncode or len(result.stdout) > 8192:
        raise GuestEnrollmentError('CSR operation failed')
    return result.stdout


def _guest_succeeds(user: str, argv: list[str]) -> bool:
    """Run one fixed program as the guest and report only whether it worked.

    For a command whose ordinary failure is an expected answer (``ln`` onto
    a name that already exists), not an error.
    """
    try:
        result = subprocess.run(
            ['/usr/sbin/runuser', '-u', user, '--', *argv],
            capture_output=True, timeout=30, check=False,
            env=_csr_child_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GuestEnrollmentError('CSR operation failed') from None
    return result.returncode == 0


def _publish_new_key(user: str, *, key: Path, key_scratch: Path,
                     csr_scratch: Path) -> bool:
    """Generate a fresh P-256 key and CSR, then publish the key under ``key``.

    Both are written under per-request scratch names first. ``ln`` (link(2))
    refuses a name that already exists, so of two concurrent requests exactly
    one publishes its key; the other learns it lost and gets ``False``, with
    its scratch files removed. A key is therefore never overwritten, and a
    published key is never paired with another request's CSR.
    """
    _run_as_guest(user, [
        '/usr/bin/openssl', 'req', '-new', '-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
        '-keyout', str(key_scratch), '-out', str(csr_scratch),
        '-subj', '/CN=aivm-guest',
    ])
    _run_as_guest(user, ['/usr/bin/chmod', '0600', str(key_scratch),
                         str(csr_scratch)])
    published = _guest_succeeds(user, ['/usr/bin/ln', str(key_scratch), str(key)])
    # After a successful link the key lives on under its published name.
    _run_as_guest(user, ['/usr/bin/rm', '-f', str(key_scratch)])
    if not published:
        _run_as_guest(user, ['/usr/bin/rm', '-f', str(csr_scratch)])
    return published


def _regenerate_csr(user: str, *, key: Path, csr_scratch: Path) -> None:
    """Sign a fresh CSR with the key that is actually installed.

    ``client.csr`` is only a cache of the last request. Identity key rotation
    activates a new ``client.key``; a guest restored from a snapshot, or one
    whose CSR was written by an older helper, can hold a CSR for a key it no
    longer uses. Never hand that cache out: the host would certify a key the
    guest has retired, which is exactly what rotation was meant to retire.
    """
    _run_as_guest(user, [
        '/usr/bin/openssl', 'req', '-new', '-key', str(key),
        '-subj', '/CN=aivm-guest', '-out', str(csr_scratch),
    ])
    _run_as_guest(user, ['/usr/bin/chmod', '0600', str(csr_scratch)])


def prepare_guest_identity_csr(request: GuestIdentityCSRRequest) -> dict[str, object]:
    """Return a CSR signed by the guest-owned P-256 key via the forced channel.

    ``identity-csr`` signs a fresh CSR with the existing ``client.key``, or
    creates that key first if the guest has none. ``identity-key-rotate-csr``
    stages a new ``client.rotate.key``. The reply is always the CSR this call
    produced, never a file left behind by an earlier one.

    All path writes and CSR reads execute as the target unprivileged user.
    The root-owned bootstrap helper never opens a guest-writable pathname.
    """
    if type(request) is not GuestIdentityCSRRequest:
        raise GuestEnrollmentError('invalid CSR request')
    try:
        account = pwd.getpwnam(request.guest_user)
    except KeyError:
        raise GuestEnrollmentError('unknown guest user') from None
    if account.pw_uid != request.uid or account.pw_uid == 0:
        raise GuestEnrollmentError('guest account mismatch')
    home = Path(account.pw_dir)
    if not home.is_absolute() or str(home) == '/':
        raise GuestEnrollmentError('invalid guest home')
    directory = home / '.config' / 'aivm' / 'identity'
    rotating = request.operation == 'identity-key-rotate-csr'
    key = directory / ('client.rotate.key' if rotating else 'client.key')
    csr = directory / ('client.rotate.csr' if rotating else 'client.csr')
    # Per-request scratch names. The nonce is validated as 32 lowercase hex
    # digits, so it is a fixed-alphabet path component, and it keeps two
    # concurrent requests from writing the same temporary file.
    key_scratch = directory / f'{key.name}.{request.nonce}'
    csr_scratch = directory / f'{csr.name}.{request.nonce}'
    user = request.guest_user
    _run_as_guest(user,
                  ['/usr/bin/install', '-d', '-m', '0700', str(directory)])
    # Never overwrite a key. Query existence without treating /usr/bin/test's
    # normal 'false' as an error. Every file name is under the account's own
    # writable directory.
    def present(path: Path) -> bool:
        try:
            result = subprocess.run(
                ['/usr/sbin/runuser', '-u', request.guest_user, '--',
                 '/usr/bin/test', '-f', str(path)],
                capture_output=True, timeout=10, check=False,
                env=_csr_child_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            raise GuestEnrollmentError('CSR operation failed') from None
        if result.returncode not in (0, 1):
            raise GuestEnrollmentError('CSR operation failed')
        return result.returncode == 0
    key_exists, csr_exists = present(key), present(csr)
    if rotating:
        # Existing identity must be installed, and a pending rotation must
        # never be overwritten automatically. On failure, an operator must
        # explicitly reconcile/remove the pending files before retrying.
        if not present(directory / 'client.key') or not present(directory / 'client.pem'):
            raise GuestEnrollmentError('cannot rotate an uninstalled identity')
        if key_exists or csr_exists:
            raise GuestEnrollmentError('pending key rotation exists; manual repair required')
        if not _publish_new_key(user, key=key, key_scratch=key_scratch,
                                csr_scratch=csr_scratch):
            # A concurrent request staged its own rotation key first.
            raise GuestEnrollmentError('pending key rotation exists; manual repair required')
    elif key_exists != csr_exists:
        raise GuestEnrollmentError('incomplete guest identity; manual repair required')
    else:
        published = not key_exists and _publish_new_key(
            user, key=key, key_scratch=key_scratch, csr_scratch=csr_scratch)
        if not published:
            # The installed key -- or, after losing a first-generation race,
            # the winner's key -- is the one this guest will present.
            _regenerate_csr(user, key=key, csr_scratch=csr_scratch)
    # Reply with the CSR made above, then keep it as the cached copy.
    data = _run_as_guest(user, ['/usr/bin/cat', str(csr_scratch)])
    if (not data.startswith(b'-----BEGIN CERTIFICATE REQUEST-----') or
            len(data) > 8192):
        raise GuestEnrollmentError('invalid guest CSR')
    try:
        pem = data.decode('ascii')
    except UnicodeDecodeError:
        raise GuestEnrollmentError('invalid guest CSR') from None
    _run_as_guest(user, ['/usr/bin/mv', '-f', str(csr_scratch), str(csr)])
    return {'status': 'ok', 'operation': request.operation,
            'nonce': request.nonce, 'guest_user': request.guest_user,
            'uid': request.uid, 'csr': pem}


Runner = Callable[..., subprocess.CompletedProcess[str]]
ChownPath = str | bytes | os.PathLike[str] | os.PathLike[bytes]
Chown = Callable[[ChownPath, int, int], None]



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
    matching = [
        line for line in lines if _same_public_key(line, request.public_key)
    ]
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
            if any(
                _same_public_key(line, request.public_key) for line in remaining
            ):
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
    text = sys.stdin.read(16385)
    try:
        if len(text) > 16384:
            raise GuestEnrollmentError('request too large')
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
        elif operation in ('identity-csr', 'identity-key-rotate-csr'):
            csr_request = GuestIdentityCSRRequest.from_json(text)
            report = prepare_guest_identity_csr(csr_request)
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
