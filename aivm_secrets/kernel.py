"""Service-neutral, side-effect-free authorization kernel.

Future Rust/Aeneas extraction seam: concrete facts are normalized outside this
module; the kernel only sees immutable, typed values and explicit clock facts.
No provider names, network routes, credential lookup or subprocesses live here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import SecretsError


def exact_keys(value: Any, required: set[str], optional: set[str] | None = None,
               *, code: str = 'invalid_request') -> dict[str, Any]:
    if type(value) is not dict or not required <= value.keys() or (
        value.keys() - required - (optional or set())
    ):
        raise SecretsError(code)
    return value


def integer(value: Any, low: int, high: int, *, code: str = 'invalid_request') -> int:
    if type(value) is not int or not low <= value <= high:
        raise SecretsError(code)
    return value


def text(value: Any, limit: int, *, code: str = 'invalid_request') -> str:
    if type(value) is not str:
        raise SecretsError(code)
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        raise SecretsError(code) from None
    if not 1 <= size <= limit or '\x00' in value:
        raise SecretsError(code)
    return value


@dataclass(frozen=True)
class Binding:
    """Host-established identity; never obtained from an agent request."""
    owner_uid: int
    access_identity: str
    vm: str
    channel: str

    @classmethod
    def parse(cls, value: Any) -> Binding:
        value = exact_keys(value, {'owner_uid', 'access_identity', 'vm', 'channel'})
        return cls(integer(value['owner_uid'], 0, 2**32 - 1),
                   text(value['access_identity'], 128), text(value['vm'], 128),
                   text(value['channel'], 128))


@dataclass(frozen=True)
class Claims:
    binding: Binding
    policy_digest: str
    grant_id: str
    issued_at: int
    expires_at: int

    @classmethod
    def parse(cls, value: Any) -> Claims:
        value = exact_keys(value, {'binding', 'policy_digest', 'grant_id',
                                  'issued_at', 'expires_at'})
        issued = integer(value['issued_at'], 0, 2**63 - 3601)
        expires = integer(value['expires_at'], issued + 1, issued + 3600)
        digest = text(value['policy_digest'], 64)
        grant_id = text(value['grant_id'], 64)
        if not re.fullmatch(r'[a-f0-9]{64}', digest) or not re.fullmatch(r'[a-f0-9]{32}', grant_id):
            raise SecretsError('invalid_request')
        return cls(Binding.parse(value['binding']), digest, grant_id, issued, expires)


@dataclass(frozen=True)
class State:
    active: bool = True
    used: int = 0


def reserve(policy_digest: str, max_requests: int, max_body_bytes: int,
            claims: Claims, binding: Binding, state: State, *, now: int,
            monotonic_live: bool, operation: str, allowed_operations: frozenset[str],
            is_write: bool, allow_writes: bool, body_bytes: int) -> State:
    """Authorize and reserve one operation regardless of provider or CLI.

    Service policy validation and route construction are distinct trusted steps.
    No caller may dispatch a credentialed effect without this reservation.
    """
    if not state.active:
        raise SecretsError('revoked')
    if claims.binding != binding or claims.policy_digest != policy_digest:
        raise SecretsError('wrong_binding')
    if not monotonic_live or not claims.issued_at <= now < claims.expires_at:
        raise SecretsError('expired')
    if state.used >= max_requests:
        raise SecretsError('exhausted')
    if operation not in allowed_operations or (is_write and not allow_writes):
        raise SecretsError('denied')
    if body_bytes > max_body_bytes:
        raise SecretsError('denied')
    return State(True, state.used + 1)
