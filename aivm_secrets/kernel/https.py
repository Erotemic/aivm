"""Declarative HTTPS services: policy schema 2.

A service is one fixed TLS destination and a finite list of named operations.
Each operation is a method, a path template, optional fixed or typed query
parameters and an optional flat body of bounded strings. A guest request can
select an operation and supply values from the operator's allowlists; it can
never supply a URL, method, header, credential or body shape.

Everything in this module is data plus total functions over it, so a new
service is a reviewed manifest rather than trusted code (PLUGIN-01, ROUTE-01).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..errors import SecretsError
from . import codec, grammar
from .model import MAX_ARGUMENTS, MAX_LIFETIME, Effect, Egress, Request
from .scope import (
    MAX_OPERATIONS,
    FieldSpec,
    IntSet,
    OperationScope,
    ParamSpec,
    Scope,
    StrSet,
    param_to_wire,
    parse_param_spec,
)
from .source import parse_source

SCHEMA = 2
MAX_PARAMETER_VALUES = 256
_CODE = 'invalid_policy'


def _placeholder(part: str) -> str | None:
    """``{name}`` -> ``name``; any other use of a brace is malformed."""
    if part.startswith('{') and part.endswith('}'):
        return grammar.argument_name(part[1:-1], code=_CODE)
    if '{' in part or '}' in part:
        raise SecretsError(_CODE)
    return None


def _template(value: Any) -> tuple[str, ...]:
    path = grammar.text(value, 1024, code=_CODE)
    if path[0] != '/':
        raise SecretsError(_CODE)
    parts = tuple(path[1:].split('/'))
    for part in parts:
        if _placeholder(part) is None:
            grammar.segment(part, code=_CODE)
    return parts


def _parameter(value: Any) -> ParamSpec:
    """A path or query parameter: every permitted value is a safe segment."""
    spec = parse_param_spec(value, code=_CODE)
    if isinstance(spec, (IntSet, StrSet)):
        if len(spec.values) > MAX_PARAMETER_VALUES:
            raise SecretsError(_CODE)
    if isinstance(spec, StrSet):
        for item in spec.values:
            grammar.segment(item, code=_CODE)
    return spec


@dataclass(frozen=True)
class HTTPOperation:
    name: str
    method: str
    template: tuple[str, ...]
    parameters: tuple[tuple[str, ParamSpec], ...] = ()
    query: tuple[tuple[str, str], ...] = ()
    body_fields: tuple[tuple[str, int], ...] = ()
    response: str = 'json'
    accept: str = 'application/json'

    @classmethod
    def parse(cls, value: Any) -> HTTPOperation:
        value = grammar.exact_keys(
            value,
            frozenset({'name', 'method', 'path'}),
            frozenset(
                {'parameters', 'query', 'body_fields', 'response', 'accept'}
            ),
            code=_CODE,
        )
        name = grammar.operation_name(value['name'], code=_CODE)
        method = value['method']
        if type(method) is not str or method not in ('GET', 'POST', 'PATCH'):
            raise SecretsError(_CODE)
        template = _template(value['path'])
        raw_parameters = value.get('parameters', {})
        raw_query = value.get('query', {})
        raw_fields = value.get('body_fields', {})
        for mapping in (raw_parameters, raw_query, raw_fields):
            if type(mapping) is not dict or len(mapping) > MAX_ARGUMENTS:
                raise SecretsError(_CODE)
        parameters = tuple(
            sorted(
                (grammar.argument_name(key, code=_CODE), _parameter(spec))
                for key, spec in raw_parameters.items()
            )
        )
        used = {
            reference
            for reference in map(_placeholder, template)
            if reference is not None
        }
        query = []
        for key, item in sorted(raw_query.items()):
            grammar.argument_name(key, code=_CODE)
            if type(item) is not str:
                raise SecretsError(_CODE)
            reference = _placeholder(item)
            if reference is None:
                grammar.segment(item, code=_CODE)
            else:
                used.add(reference)
            query.append((key, item))
        fields = tuple(
            sorted(
                (
                    grammar.argument_name(key, code=_CODE),
                    grammar.integer(cap, 1, grammar.MAX_TEXT, code=_CODE),
                )
                for key, cap in raw_fields.items()
            )
        )
        declared = {key for key, _ in parameters}
        # Every declared parameter is used and every placeholder is declared:
        # nothing reaches the request target without an explicit allowlist.
        if used != declared or declared & {key for key, _ in fields}:
            raise SecretsError(_CODE)
        if (method == 'GET') != (not fields):
            raise SecretsError(_CODE)
        response = value.get('response', 'json')
        if type(response) is not str or response not in ('json', 'text'):
            raise SecretsError(_CODE)
        default = 'application/json' if response == 'json' else 'text/plain'
        accept = grammar.media_type(value.get('accept', default), code=_CODE)
        return cls(
            name,
            method,
            template,
            parameters,
            tuple(query),
            fields,
            response,
            accept,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            'name': self.name,
            'method': self.method,
            'path': '/' + '/'.join(self.template),
            'response': self.response,
            'accept': self.accept,
        }
        if self.parameters:
            result['parameters'] = {
                key: param_to_wire(spec) for key, spec in self.parameters
            }
        if self.query:
            result['query'] = dict(self.query)
        if self.body_fields:
            result['body_fields'] = dict(self.body_fields)
        return result

    def scope(self) -> OperationScope:
        return OperationScope(
            self.name,
            self.method != 'GET',
            self.parameters,
            tuple(FieldSpec(key, cap) for key, cap in self.body_fields),
        )

    def effect(self, request: Request) -> Effect:
        given = dict(request.arguments)
        body = None
        if self.body_fields:
            body = tuple((key, str(given[key])) for key, _ in self.body_fields)
        return Effect(
            self.method,
            '/' + '/'.join(_fill(part, given) for part in self.template),
            tuple((key, _fill(item, given)) for key, item in self.query),
            self.accept,
            self.response,
            body,
        )


def _fill(part: str, given: dict[str, Any]) -> str:
    """A literal stays itself; ``{name}`` becomes that argument's value."""
    reference = _placeholder(part)
    return part if reference is None else str(given[reference])


@dataclass(frozen=True)
class HTTPSpec:
    service: str
    egress: Egress
    credential_source: dict[str, Any] = field(repr=False)
    operations: tuple[HTTPOperation, ...] = ()
    lifetime_seconds: int = 1800
    max_requests: int = 200
    max_body_bytes: int = 8192

    @classmethod
    def parse(cls, value: Any) -> HTTPSpec:
        value = grammar.exact_keys(
            value,
            frozenset(
                {
                    'schema',
                    'adapter',
                    'service',
                    'host',
                    'authentication',
                    'credential_source',
                    'operations',
                }
            ),
            frozenset(
                {
                    'egress',
                    'headers',
                    'lifetime_seconds',
                    'max_requests',
                    'max_body_bytes',
                }
            ),
            code=_CODE,
        )
        grammar.integer(value['schema'], SCHEMA, SCHEMA, code=_CODE)
        if value['adapter'] != 'https':
            raise SecretsError(_CODE)
        raw = value['operations']
        if type(raw) is not list or not 1 <= len(raw) <= MAX_OPERATIONS:
            raise SecretsError(_CODE)
        operations = tuple(
            sorted((HTTPOperation.parse(item) for item in raw), key=_name)
        )
        if len({item.name for item in operations}) != len(operations):
            raise SecretsError(_CODE)
        return cls(
            grammar.operation_name(value['service'], code=_CODE),
            Egress.parse(
                value['host'],
                value['authentication'],
                value.get('egress', {}),
                value.get('headers', {}),
            ),
            parse_source(value['credential_source']),
            operations,
            grammar.integer(
                value.get('lifetime_seconds', 1800), 1, MAX_LIFETIME, code=_CODE
            ),
            grammar.integer(
                value.get('max_requests', 200), 1, 1000, code=_CODE
            ),
            grammar.integer(
                value.get('max_body_bytes', 8192),
                1,
                grammar.MAX_TEXT,
                code=_CODE,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema': SCHEMA,
            'adapter': 'https',
            'service': self.service,
            'host': self.egress.host,
            'authentication': self.egress.authentication,
            'egress': self.egress.pins(),
            'headers': dict(self.egress.headers),
            'credential_source': self.credential_source,
            'operations': [item.to_dict() for item in self.operations],
            'lifetime_seconds': self.lifetime_seconds,
            'max_requests': self.max_requests,
            'max_body_bytes': self.max_body_bytes,
        }

    @property
    def digest(self) -> str:
        return codec.digest(self.to_dict())

    @property
    def client_aliases(self) -> tuple[str, ...]:
        """A declarative service never shadows another CLI's name."""
        return ()

    def scope(self) -> Scope:
        return tuple(item.scope() for item in self.operations)

    def parse_request(self, value: Any) -> Request:
        return Request.parse(value)

    def _operation(self, request: Request) -> HTTPOperation:
        for item in self.operations:
            if item.name == request.operation:
                return item
        raise SecretsError('denied')

    def preflight(self, request: Request) -> Effect | None:
        """Schema 2 has no trusted-fact preflight: one request, one effect."""
        self._operation(request)
        return None

    def final(self, request: Request, facts: Any) -> Effect | None:
        return self._operation(request).effect(request)

    def reply_meta(
        self, request: Request, result: Any
    ) -> dict[str, Any] | None:
        return None


def _name(item: HTTPOperation) -> str:
    return item.name


__all__ = ['HTTPOperation', 'HTTPSpec', 'SCHEMA']
