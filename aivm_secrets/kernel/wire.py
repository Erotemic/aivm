"""Protocol version 1: one JSON object per connection, in each direction.

A guest frame carries a sealed capability and exactly one verb. The verb set
is closed; there is no verb that names a host program, a URL, or another
grant's identifier.

==========  ===================================================  ============
verb        payload                                              spends
==========  ===================================================  ============
request     an operation and typed arguments                     one request
describe    ``true``                                             an attempt
delegate    a :class:`~.scope.Narrowing`                         an attempt
renounce    ``true``                                             an attempt
==========  ===================================================  ============

Replies are ``{"version": 1, "ok": true, ...}`` or a failure carrying one
fixed code. Failure text is chosen by the host from a closed table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import SecretsError
from . import grammar

VERSION = 1
VERBS = ('request', 'describe', 'delegate', 'renounce')
MAX_CAPABILITY = 32768
# One reply is a bounded provider response plus a bounded envelope.
MAX_RESPONSE = 2 * 1024 * 1024
MAX_REPLY = MAX_RESPONSE + 65536


@dataclass(frozen=True)
class Frame:
    verb: str
    capability: str
    payload: Any


def parse_frame(value: Any) -> Frame:
    if type(value) is not dict:
        raise SecretsError('invalid_request')
    verbs = [verb for verb in VERBS if verb in value]
    if len(verbs) != 1:
        raise SecretsError('invalid_request')
    verb = verbs[0]
    value = grammar.exact_keys(
        value, frozenset({'version', 'capability', verb})
    )
    grammar.integer(value['version'], VERSION, VERSION)
    capability = value['capability']
    if type(capability) is not str or len(capability) > MAX_CAPABILITY:
        raise SecretsError('invalid_request')
    payload = value[verb]
    if verb in ('describe', 'renounce') and payload is not True:
        raise SecretsError('invalid_request')
    return Frame(verb, capability, payload)


def success(**fields: Any) -> dict[str, Any]:
    return {'version': VERSION, 'ok': True, **fields}


def failure(error: SecretsError, **fields: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {'code': error.code, 'message': str(error)}
    if error.status:
        detail['status'] = error.status
    return {'version': VERSION, 'ok': False, 'error': detail, **fields}
