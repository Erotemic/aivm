"""Closed data shared by the kernel, the service specs and the host shell.

These are the value types of the planned ``secrets-kernel`` crate: frozen,
structurally compared, and free of handles to anything outside the process.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ..errors import SecretsError
from . import codec, grammar, graphql

Value = int | str
Arguments = tuple[tuple[str, Value], ...]

METHODS = ('GET', 'POST', 'PATCH')
RESPONSES = ('json', 'text')
AUTHENTICATIONS = ('bearer', 'x-api-key')
MAX_ARGUMENTS = 16
MAX_LIFETIME = 3600

# Headers the executor owns. A manifest may pin additional static headers
# (an API version, say) but may never restate, shadow or smuggle these.
RESERVED_HEADERS = frozenset(
    {
        'accept',
        'accept-encoding',
        'authorization',
        'connection',
        'content-encoding',
        'content-length',
        'content-type',
        'cookie',
        'expect',
        'forwarded',
        'host',
        'keep-alive',
        'proxy-authorization',
        'proxy-connection',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
        'user-agent',
        'via',
        'x-api-key',
    }
)


@dataclass(frozen=True)
class Binding:
    """Host-established identity; never obtained from an agent request."""

    owner_uid: int
    access_identity: str
    vm: str
    channel: str

    @classmethod
    def parse(cls, value: Any) -> Binding:
        value = grammar.exact_keys(
            value,
            frozenset({'owner_uid', 'access_identity', 'vm', 'channel'}),
        )
        return cls(
            grammar.integer(value['owner_uid'], 0, 2**32 - 1),
            grammar.text(value['access_identity'], 128),
            grammar.text(value['vm'], 128),
            grammar.text(value['channel'], 128),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'owner_uid': self.owner_uid,
            'access_identity': self.access_identity,
            'vm': self.vm,
            'channel': self.channel,
        }


@dataclass(frozen=True)
class Claims:
    """What a sealed capability asserts. Authenticated, but not yet authorized.

    A claim names a grant held in kernel state; it carries no scope of its
    own, so a guest cannot widen authority by presenting different bytes.
    """

    binding: Binding
    policy_digest: str
    grant_id: str
    issued_at: int
    expires_at: int

    @classmethod
    def parse(cls, value: Any) -> Claims:
        value = grammar.exact_keys(
            value,
            frozenset(
                {
                    'binding',
                    'policy_digest',
                    'grant_id',
                    'issued_at',
                    'expires_at',
                }
            ),
        )
        issued = grammar.integer(
            value['issued_at'], 0, 2**63 - MAX_LIFETIME - 1
        )
        expires = grammar.integer(
            value['expires_at'], issued + 1, issued + MAX_LIFETIME
        )
        return cls(
            Binding.parse(value['binding']),
            grammar.hex_string(value['policy_digest'], 64),
            grammar.hex_string(value['grant_id'], 32),
            issued,
            expires,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'binding': self.binding.to_dict(),
            'policy_digest': self.policy_digest,
            'grant_id': self.grant_id,
            'issued_at': self.issued_at,
            'expires_at': self.expires_at,
        }


@dataclass(frozen=True)
class Clock:
    """One explicit time sample. The kernel never reads a clock itself.

    ``wall`` bounds validity for humans and audit; ``mono`` is the local
    monotonic reading that keeps a wall-clock rollback from extending a
    grant (TIME-01). Both are whole seconds.
    """

    wall: int
    mono: int


def parse_arguments(value: Any) -> Arguments:
    """A bounded object of integers and strings, in canonical (sorted) order."""
    if type(value) is not dict or len(value) > MAX_ARGUMENTS:
        raise SecretsError('invalid_request')
    items: list[tuple[str, Value]] = []
    for key, item in value.items():
        grammar.argument_name(key)
        if type(item) is int:
            grammar.integer(item, 0, grammar.MAX_INT)
        else:
            grammar.text(item, grammar.MAX_TEXT)
        items.append((key, item))
    return tuple(sorted(items))


@dataclass(frozen=True)
class Request:
    """One named operation with typed arguments, in canonical form.

    Nothing here can name a host, URL, method, header or credential: those
    are properties of the operator's service spec, not of a request.
    """

    operation: str
    arguments: Arguments = field(default=(), repr=False)

    @classmethod
    def parse(cls, value: Any) -> Request:
        value = grammar.exact_keys(
            value, frozenset({'operation'}), frozenset({'arguments'})
        )
        return cls(
            grammar.operation_name(value['operation']),
            parse_arguments(value.get('arguments', {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {'operation': self.operation, 'arguments': dict(self.arguments)}

    @property
    def digest(self) -> str:
        return codec.digest(self.to_dict())

    def get(self, name: str) -> Value | None:
        for key, value in self.arguments:
            if key == name:
                return value
        return None


@dataclass(frozen=True)
class Effect:
    """A fully constructed provider request, minus destination and secret.

    The destination is fixed by the service spec's :class:`Egress`; the
    credential is attached only by the executor. ``body`` is a flat object of
    strings, which is the entire request-body language of this protocol.
    """

    method: str
    path: str
    query: tuple[tuple[str, str], ...] = ()
    accept: str = 'application/json'
    response: str = 'json'
    body: tuple[tuple[str, str], ...] | None = field(default=None, repr=False)
    graphql: bool = False

    @property
    def is_write(self) -> bool:
        return self.method != 'GET' and not self.graphql

    @property
    def target(self) -> str:
        """The HTTP request target. No escaping is needed or performed."""
        if not self.query:
            return self.path
        return self.path + '?' + '&'.join(f'{k}={v}' for k, v in self.query)


def check_effect(effect: Effect) -> Effect:
    """The effect grammar (ROUTE-01). Total; refuses rather than repairs.

    The kernel checks every effect it authorizes and the executor checks it
    again, so a defect in a service compiler cannot reach the network as a
    malformed or redirected request.
    """
    code = 'denied'
    if type(effect) is not Effect or effect.method not in METHODS:
        raise SecretsError(code)
    if effect.response not in RESPONSES:
        raise SecretsError(code)
    grammar.media_type(effect.accept, code=code)
    if type(effect.path) is not str or not 2 <= len(effect.path) <= 1024:
        raise SecretsError(code)
    if effect.path[0] != '/':
        raise SecretsError(code)
    for part in effect.path[1:].split('/'):
        grammar.segment(part, code=code)
    if len(effect.query) > MAX_ARGUMENTS:
        raise SecretsError(code)
    seen: set[str] = set()
    for key, value in effect.query:
        grammar.argument_name(key, code=code)
        grammar.segment(value, code=code)
        if key in seen:
            raise SecretsError(code)
        seen.add(key)
    if type(effect.graphql) is not bool:
        raise SecretsError(code)
    if effect.graphql and (effect.method != 'POST' or effect.response != 'json'
                           or effect.query or effect.body is None):
        raise SecretsError(code)
    if (effect.method == 'GET') != (effect.body is None):
        raise SecretsError(code)
    if effect.body is not None:
        if not 1 <= len(effect.body) <= MAX_ARGUMENTS:
            raise SecretsError(code)
        names: set[str] = set()
        for key, value in effect.body:
            grammar.argument_name(key, code=code)
            grammar.text(value, grammar.MAX_TEXT, code=code)
            if key in names:
                raise SecretsError(code)
            names.add(key)
    if effect.graphql:
        body = dict(effect.body or ())
        if set(body) != {'query', 'operation_name', 'variables'}:
            raise SecretsError(code)
        graphql.validate(body['query'], body['operation_name'], code=code)
        variables = codec.loads(body['variables'], code=code)
        if type(variables) is not dict or len(variables) > MAX_ARGUMENTS:
            raise SecretsError(code)
        for key, value in variables.items():
            grammar.argument_name(key, code=code)
            if type(value) is str:
                grammar.text(value, grammar.MAX_TEXT, code=code)
            elif type(value) is int:
                grammar.integer(value, 0, grammar.MAX_INT, code=code)
            else:
                raise SecretsError(code)
    return effect


def _absolute_path(value: Any, *, code: str) -> str:
    path = grammar.text(value, 4096, code=code)
    if path[0] != '/' or path == '/':
        raise SecretsError(code)
    for part in path[1:].split('/'):
        if part in ('', '.', '..'):
            raise SecretsError(code)
    return path


def absolute_path(value: Any, *, code: str = 'invalid_policy') -> str:
    """A normalized absolute path: no empty, ``.`` or ``..`` component."""
    return _absolute_path(value, code=code)


def parse_headers(value: Any) -> tuple[tuple[str, str], ...]:
    """Operator-pinned static headers; never an authentication mechanism."""
    code = 'invalid_policy'
    if type(value) is not dict or len(value) > 8:
        raise SecretsError(code)
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for name, content in value.items():
        grammar.header_name(name, code=code)
        folded = grammar.lowered(name)
        if folded in RESERVED_HEADERS or folded in seen:
            raise SecretsError(code)
        if folded.startswith(('proxy-', 'sec-', 'x-forwarded-')):
            raise SecretsError(code)
        seen.add(folded)
        result.append((name, grammar.header_value(content, code=code)))
    return tuple(sorted(result))


@dataclass(frozen=True)
class Egress:
    """The one destination a service's effects may reach (PLUGIN-01).

    ``host`` is always the name TLS authenticates. ``address`` optionally
    pins where the connection is opened, removing DNS from the trusted
    base; ``ca_file`` optionally replaces the system roots with a single
    operator-chosen trust anchor, as a private deployment needs.
    """

    host: str
    port: int = 443
    address: str = ''
    ca_file: str = ''
    authentication: str = 'bearer'
    headers: tuple[tuple[str, str], ...] = ()

    @classmethod
    def parse(
        cls, host: Any, authentication: Any, pins: Any, headers: Any
    ) -> Egress:
        code = 'invalid_policy'
        grammar.hostname(host, code=code)
        if type(authentication) is not str:
            raise SecretsError(code)
        if authentication not in AUTHENTICATIONS:
            raise SecretsError(code)
        pins = grammar.exact_keys(
            pins,
            frozenset(),
            frozenset({'port', 'address', 'ca_file'}),
            code=code,
        )
        port = grammar.integer(pins.get('port', 443), 1, 65535, code=code)
        address = ''
        if 'address' in pins:
            address = grammar.text(pins['address'], 64, code=code)
            try:
                canonical = str(ipaddress.ip_address(address))
            except ValueError:
                raise SecretsError(code) from None
            if canonical != address:
                raise SecretsError(code)
        ca_file = ''
        if 'ca_file' in pins:
            ca_file = _absolute_path(pins['ca_file'], code=code)
        return cls(
            host, port, address, ca_file, authentication, parse_headers(headers)
        )

    def pins(self) -> dict[str, Any]:
        result: dict[str, Any] = {'port': self.port}
        if self.address:
            result['address'] = self.address
        if self.ca_file:
            result['ca_file'] = self.ca_file
        return result
