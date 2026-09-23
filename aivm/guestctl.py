"""Host-side protocol for the standalone guest enrollment helper."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from importlib import resources
from typing import Literal

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
    """Raised for an invalid guest enrollment or access request."""


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


ChownPath = str | bytes | os.PathLike[str] | os.PathLike[bytes]


def guestctl_source() -> str:
    """Return the standalone helper source installed in managed guests."""
    return (
        resources.files('aivm')
        .joinpath('rc', 'guest', 'guestctl.py')
        .read_text(encoding='utf-8')
    )


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
