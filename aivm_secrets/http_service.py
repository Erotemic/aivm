"""Declarative, host-controlled HTTPS service adapter (policy schema 2).

A service is a fixed TLS hostname and a finite set of named, typed effects.
Guest requests supply ONLY named arguments from the operator's allowlists,
never an arbitrary URL, HTTP method, credential, header, or command line.
"""

from __future__ import annotations

import hashlib
import ipaddress
import http.client
import re
import ssl
from dataclasses import dataclass, field
from typing import Any

from .core import Route
from .errors import SecretsError
from .kernel import exact_keys, integer, text
from .wire import dumps, loads

MAX_RESPONSE = 2 * 1024 * 1024
NAME = re.compile(r'[a-z][a-z0-9_.-]{0,63}\Z')
ARG_NAME = re.compile(r'[a-z][a-z0-9_]{0,31}\Z')
HOST_NAME = re.compile(r'(?=.{4,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z')
SEGMENT = re.compile(r'[A-Za-z0-9._~-]+|\{[a-z][a-z0-9_]{0,31}\}\Z')
METHODS = frozenset({'GET', 'POST', 'PATCH'})


def name(value: Any, regex=NAME) -> str:
    if type(value) is not str or not regex.fullmatch(value):
        raise SecretsError('invalid_policy')
    return value


def _path_template(value: Any) -> tuple[str, ...]:
    path = text(value, 1024, code='invalid_policy')
    if not path.startswith('/') or path.startswith('//'):
        raise SecretsError('invalid_policy')
    segments = path[1:].split('/')
    if not segments or any(not SEGMENT.fullmatch(part) or part in {'.', '..'} for part in segments):
        raise SecretsError('invalid_policy')
    return tuple(segments)


def _value_spec(value: Any) -> tuple[int | str, ...]:
    if type(value) is not list or not 1 <= len(value) <= 256:
        raise SecretsError('invalid_policy')
    if all(type(v) is int and 0 <= v <= 2**31 - 1 for v in value):
        pass
    elif all(type(v) is str and len(v) <= 128 and
             re.fullmatch(r'[A-Za-z0-9_.~-]+', v) and v not in {'.', '..'} for v in value):
        pass
    else:
        raise SecretsError('invalid_policy')
    if len(set(value)) != len(value):
        raise SecretsError('invalid_policy')
    return tuple(sorted(value))


@dataclass(frozen=True)
class HTTPOperation:
    name: str
    method: str
    path: str
    parameters: tuple[tuple[str, tuple[int | str, ...]], ...] = ()
    body_fields: tuple[tuple[str, int], ...] = ()
    response: str = 'json'

    @classmethod
    def parse(cls, value: Any) -> HTTPOperation:
        value = exact_keys(value, {'name', 'method', 'path'},
                           {'parameters', 'body_fields', 'response'}, code='invalid_policy')
        op_name = name(value['name'])
        method = value['method']
        if type(method) is not str or method not in METHODS:
            raise SecretsError('invalid_policy')
        segments = _path_template(value['path'])
        parameters = value.get('parameters', {})
        body_fields = value.get('body_fields', {})
        if type(parameters) is not dict or len(parameters) > 16 or type(body_fields) is not dict or len(body_fields) > 16:
            raise SecretsError('invalid_policy')
        for key in list(parameters) + list(body_fields):
            name(key, ARG_NAME)
        required = {s[1:-1] for s in segments if s.startswith('{') and s.endswith('}')}
        if required != set(parameters) or set(parameters) & set(body_fields):
            raise SecretsError('invalid_policy')
        if (method == 'GET' and body_fields) or (method != 'GET' and not body_fields):
            raise SecretsError('invalid_policy')
        fields = []
        for field_name, cap in body_fields.items():
            fields.append((field_name, integer(cap, 1, 16384, code='invalid_policy')))
        response = value.get('response', 'json')
        if response not in ('json', 'text'):
            raise SecretsError('invalid_policy')
        return cls(op_name, method, '/' + '/'.join(segments),
                   tuple(sorted((key, _value_spec(v)) for key, v in parameters.items())),
                   tuple(sorted(fields)), response)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {'name': self.name, 'method': self.method,
                                  'path': self.path, 'response': self.response}
        if self.parameters:
            result['parameters'] = {k: list(v) for k, v in self.parameters}
        if self.body_fields:
            result['body_fields'] = dict(self.body_fields)
        return result


@dataclass(frozen=True)
class HTTPPolicy:
    service: str
    host: str
    authentication: str
    credential_source: dict[str, Any] = field(repr=False)
    definitions: tuple[HTTPOperation, ...] = ()
    lifetime_seconds: int = 1800
    max_requests: int = 200
    max_body_bytes: int = 8192

    @classmethod
    def parse(cls, value: Any) -> HTTPPolicy:
        value = exact_keys(value, {'schema', 'adapter', 'service', 'host',
                                  'authentication', 'credential_source', 'operations'},
                           {'lifetime_seconds', 'max_requests', 'max_body_bytes'},
                           code='invalid_policy')
        integer(value['schema'], 2, 2, code='invalid_policy')
        if value['adapter'] != 'https':
            raise SecretsError('invalid_policy')
        service = name(value['service'])
        host = text(value['host'], 253, code='invalid_policy')
        if not HOST_NAME.fullmatch(host) or host != host.lower() or host.endswith('.local'):
            raise SecretsError('invalid_policy')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise SecretsError('invalid_policy')
        authentication = value['authentication']
        if authentication not in ('bearer', 'x-api-key'):
            raise SecretsError('invalid_policy')
        # Validate host-only credential source, without executing it.
        from .sources import parse_source
        source = parse_source(value['credential_source'])
        ops = value['operations']
        if type(ops) is not list or not 1 <= len(ops) <= 64:
            raise SecretsError('invalid_policy')
        parsed = [HTTPOperation.parse(op) for op in ops]
        if len({op.name for op in parsed}) != len(parsed):
            raise SecretsError('invalid_policy')
        return cls(service, host, authentication, source,
                   tuple(sorted(parsed, key=lambda op: op.name)),
                   integer(value.get('lifetime_seconds', 1800), 1, 3600, code='invalid_policy'),
                   integer(value.get('max_requests', 200), 1, 1000, code='invalid_policy'),
                   integer(value.get('max_body_bytes', 8192), 1, 16384, code='invalid_policy'))

    def to_dict(self) -> dict[str, Any]:
        return {'schema': 2, 'adapter': 'https', 'service': self.service,
                'host': self.host, 'authentication': self.authentication,
                'credential_source': self.credential_source,
                'operations': [op.to_dict() for op in self.definitions],
                'lifetime_seconds': self.lifetime_seconds,
                'max_requests': self.max_requests,
                'max_body_bytes': self.max_body_bytes}

    @property
    def digest(self) -> str:
        return hashlib.sha256(dumps(self.to_dict())).hexdigest()

    @property
    def operations(self) -> tuple[str, ...]:
        return tuple(op.name for op in self.definitions)


@dataclass(frozen=True)
class HTTPRequest:
    operation: str
    arguments: tuple[tuple[str, Any], ...] = field(repr=False)

    @classmethod
    def parse(cls, value: Any) -> HTTPRequest:
        value = exact_keys(value, {'operation'}, {'arguments'})
        op = value['operation']
        if type(op) is not str or not NAME.fullmatch(op):
            raise SecretsError('invalid_request')
        arguments = value.get('arguments', {})
        if type(arguments) is not dict or len(arguments) > 32:
            raise SecretsError('invalid_request')
        if any(type(k) is not str or not ARG_NAME.fullmatch(k) for k in arguments):
            raise SecretsError('invalid_request')
        return cls(op, tuple(sorted(arguments.items())))


class HTTPAdapter:
    """Declarative service plugin; safe routing is constructed from host policy."""

    def __init__(self, policy: HTTPPolicy):
        self.policy = policy
        self._operations = {op.name: op for op in policy.definitions}

    def parse(self, raw: Any) -> HTTPRequest:
        request = HTTPRequest.parse(raw)
        self.check_scope(request)
        return request

    def check_scope(self, request: HTTPRequest) -> None:
        op = self._operations.get(request.operation)
        if op is None:
            raise SecretsError('denied')
        args = dict(request.arguments)
        specs = dict(op.parameters)
        fields = dict(op.body_fields)
        if args.keys() != specs.keys() | fields.keys():
            raise SecretsError('invalid_request')
        for key, choices in specs.items():
            if type(args[key]) is not type(choices[0]) or args[key] not in choices:
                raise SecretsError('denied')
        for key, max_bytes in fields.items():
            text(args[key], max_bytes)

    def is_write(self, request: HTTPRequest) -> bool:
        return self._operations[request.operation].method != 'GET'

    def body_bytes(self, request: HTTPRequest) -> int:
        op = self._operations[request.operation]
        args = dict(request.arguments)
        return sum(len(args[key].encode('utf-8')) for key, _ in op.body_fields)

    def preflight(self, request: HTTPRequest) -> None:
        return None

    def effect(self, request: HTTPRequest, facts: Any) -> Route:
        self.check_scope(request)
        op = self._operations[request.operation]
        args = dict(request.arguments)
        segments = []
        for segment in op.path[1:].split('/'):
            if segment.startswith('{'):
                segment = str(args[segment[1:-1]])
            segments.append(segment)
        body = {key: args[key] for key, _ in op.body_fields} if op.body_fields else None
        return Route(op.method, '/' + '/'.join(segments), op.response, body)

    def pagination(self, request: HTTPRequest, result: Any) -> None:
        return None


class HTTPSProvider:
    """Fixed-origin TLS egress. Does not honor proxy environment or redirects."""

    def __init__(self, policy: HTTPPolicy):
        self.host = policy.host
        self.authentication = policy.authentication

    def execute(self, route: Route, credential: str) -> Any:
        if (route.method not in METHODS or route.media not in ('json', 'text')
                or not route.path.startswith('/') or '//' in route.path
                or any(c in route.path for c in ('\r', '\n', '#', '\\', '%', ':', '?'))):
            raise SecretsError('denied')
        if any(segment in ('.', '..') for segment in route.path.split('/')):
            raise SecretsError('denied')
        body = dumps(route.body) if route.body is not None else None
        if (route.method == 'GET' and body is not None) or (route.method != 'GET' and body is None):
            raise SecretsError('denied')
        headers = {'Accept': 'application/json' if route.media == 'json' else 'text/plain',
                   'Accept-Encoding': 'identity', 'User-Agent': 'aivm-secrets/0.2'}
        if self.authentication == 'bearer':
            headers['Authorization'] = 'Bearer ' + credential
        else:
            headers['X-API-Key'] = credential
        if body is not None:
            headers['Content-Type'] = 'application/json'
        connection = http.client.HTTPSConnection(self.host, timeout=15,
                                                 context=ssl.create_default_context())
        dispatched_write = route.method != 'GET'
        try:
            connection.request(route.method, route.path, body=body, headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise SecretsError('upstream_error')
            if response.getheader('Content-Encoding', 'identity') != 'identity':
                raise SecretsError('upstream_response')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise SecretsError('upstream_response')
            if route.media == 'text':
                return data.decode('utf-8')
            return loads(data, limit=MAX_RESPONSE)
        except SecretsError:
            if dispatched_write:
                raise SecretsError('outcome_unknown') from None
            raise
        except Exception:
            raise SecretsError('outcome_unknown' if dispatched_write else 'upstream_error') from None
        finally:
            connection.close()
