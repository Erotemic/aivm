"""Declarative HTTPS services: the one general service mechanism.

A service is one fixed TLS destination and a finite list of named operations.
An operation is data: a method, a path template, typed query parameters, a
flat body of bounded strings, and an explicit statement of whether it can
change anything. A guest request selects an operation and supplies values
from the operator's allowlists; it can never supply a URL, method, header,
credential or body shape.

Three further pieces of data make this enough to express a real provider
without provider-specific code. The built-in services in :mod:`.presets`
are manifests in this format, not modules of their own:

``checks``
    Named *fact checks*. An operation that ``requires`` one first fetches a
    resource and must find stated facts in it -- this PR has this author,
    this base repository -- before its own request is even constructed. A
    check can also ``bind`` a validated fact (a commit hash) for use in the
    operation's path.

``effect``
    ``read`` or ``write``, declared per operation and never inferred from
    the HTTP method. A ``GET`` that changes state is a write and must say so.

``cli``
    Tables that let the guest client answer to another tool's name by
    translating its command line into an ordinary request. They
    are a convenience for the untrusted side and carry no authority.

Everything here is data plus total functions over it, so adding a service is
reviewing a manifest rather than trusting new code (PLUGIN-01, ROUTE-01).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..errors import SecretsError
from . import codec, grammar
from .model import MAX_ARGUMENTS, MAX_LIFETIME, Effect, Egress, Request, Value
from .scope import (
    MAX_OPERATIONS,
    FieldSpec,
    IntRange,
    IntSet,
    OperationScope,
    ParamSpec,
    Scope,
    StrSet,
    contains,
    param_to_wire,
    parse_param_spec,
)
from .source import parse_source

SCHEMA = 2
MAX_PARAMETER_VALUES = 256
MAX_POINTER = 8
MAX_PAGE = 1000
EFFECTS = ('read', 'write')
FORMATS = ('hex', 'integer', 'segment')
# Names a command table may not take over: the client's own verbs, and the
# programs the client is itself started through. The client's directory comes
# first on the guest's PATH, so an alias called ``python3`` would be what its
# own ``#!/usr/bin/env python3`` line found.
RESERVED_ALIASES = (
    'aivm',
    'as',
    'invoke',
    'operations',
    'delegate',
    'renounce',
    'env',
    'python',
    'python3',
    'sh',
)
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


def _references(template: tuple[str, ...]) -> list[str]:
    found = []
    for part in template:
        reference = _placeholder(part)
        if reference is not None:
            found.append(reference)
    return found


def _pointer(value: Any) -> tuple[str, ...]:
    """A path of object keys into a JSON document. Arrays are not indexed."""
    if type(value) is not list or len(value) > MAX_POINTER:
        raise SecretsError(_CODE)
    return tuple(grammar.text(key, 64, code=_CODE) for key in value)


def lookup(document: Any, pointer: tuple[str, ...], *, code: str) -> Any:
    """Follow ``pointer`` through nested objects, or fail with ``code``."""
    current = document
    for key in pointer:
        if type(current) is not dict or key not in current:
            raise SecretsError(code)
        current = current[key]
    return current


def _path_value(value: str) -> None:
    """A string usable in a path: safe segments, possibly several."""
    for part in value.split('/'):
        grammar.segment(part, code=_CODE)


def _parameter(value: Any, *, in_query: bool) -> ParamSpec:
    """A typed parameter. Every permitted value is safe where it is used.

    A string used in a query must be a single segment. One used only in a
    path may be several segments (``owner/name``): the operator listed the
    exact strings, and each segment is still individually safe.
    """
    spec = parse_param_spec(value, code=_CODE)
    if isinstance(spec, (IntSet, StrSet)):
        if len(spec.values) > MAX_PARAMETER_VALUES:
            raise SecretsError(_CODE)
    if isinstance(spec, StrSet):
        for item in spec.values:
            if in_query:
                grammar.segment(item, code=_CODE)
            else:
                _path_value(item)
    return spec


@dataclass(frozen=True)
class Requirement:
    """One fact that must hold: a value at ``at`` equals an expectation.

    The expectation is a literal from the manifest or the value of one of
    the request's own (already allowlisted) parameters. Types must match
    exactly; ``fold`` compares strings without regard to ASCII case.
    """

    at: tuple[str, ...]
    literal: Value | None
    parameter: str
    fold: bool

    @classmethod
    def parse(cls, value: Any) -> Requirement:
        if type(value) is not dict:
            raise SecretsError(_CODE)
        if ('equals' in value) == ('equals_parameter' in value):
            raise SecretsError(_CODE)
        value = grammar.exact_keys(
            value,
            frozenset({'at'}),
            frozenset({'equals', 'equals_parameter', 'fold'}),
            code=_CODE,
        )
        fold = value.get('fold', False)
        if type(fold) is not bool:
            raise SecretsError(_CODE)
        literal: Value | None = None
        parameter = ''
        if 'equals' in value:
            literal = value['equals']
            if type(literal) is int:
                grammar.integer(literal, 0, grammar.MAX_INT, code=_CODE)
            else:
                grammar.text(literal, 256, code=_CODE)
        else:
            parameter = grammar.argument_name(
                value['equals_parameter'], code=_CODE
            )
        if fold and type(literal) is int:
            raise SecretsError(_CODE)
        return cls(_pointer(value['at']), literal, parameter, fold)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {'at': list(self.at), 'fold': self.fold}
        if self.parameter:
            result['equals_parameter'] = self.parameter
        else:
            result['equals'] = self.literal
        return result

    def holds(self, facts: Any, request: Request) -> bool:
        found = lookup(facts, self.at, code='resource_mismatch')
        expected = (
            request.get(self.parameter) if self.parameter else self.literal
        )
        if type(found) is not type(expected):
            return False
        if self.fold and type(found) is str:
            return grammar.lowered(found) == grammar.lowered(str(expected))
        return bool(found == expected)


@dataclass(frozen=True)
class Capture:
    """A fact bound to a name, validated before it may enter a path."""

    name: str
    at: tuple[str, ...]
    format: str

    @classmethod
    def parse(cls, name: Any, value: Any) -> Capture:
        value = grammar.exact_keys(
            value, frozenset({'at', 'format'}), code=_CODE
        )
        chosen = value['format']
        if type(chosen) is not str or chosen not in FORMATS:
            raise SecretsError(_CODE)
        return cls(
            grammar.argument_name(name, code=_CODE),
            _pointer(value['at']),
            chosen,
        )

    def extract(self, facts: Any) -> str:
        """The bound value as a safe path segment, or ``resource_mismatch``."""
        code = 'resource_mismatch'
        found = lookup(facts, self.at, code=code)
        if self.format == 'integer':
            return str(grammar.integer(found, 0, grammar.MAX_INT, code=code))
        if type(found) is not str:
            raise SecretsError(code)
        if self.format == 'hex':
            folded = grammar.lowered(found)
            if len(folded) not in (40, 64):
                raise SecretsError(code)
            return grammar.hex_string(folded, len(folded), code=code)
        return grammar.segment(found, code=code)


@dataclass(frozen=True)
class Check:
    """A read-only fact fetch and what its answer must contain."""

    name: str
    template: tuple[str, ...]
    accept: str
    require: tuple[Requirement, ...]
    bind: tuple[Capture, ...] = ()

    @classmethod
    def parse(cls, name: Any, value: Any) -> Check:
        value = grammar.exact_keys(
            value,
            frozenset({'path', 'require'}),
            frozenset({'accept', 'bind'}),
            code=_CODE,
        )
        raw = value['require']
        bound = value.get('bind', {})
        if type(raw) is not list or not 1 <= len(raw) <= MAX_ARGUMENTS:
            raise SecretsError(_CODE)
        if type(bound) is not dict or len(bound) > MAX_ARGUMENTS:
            raise SecretsError(_CODE)
        return cls(
            grammar.argument_name(name, code=_CODE),
            _template(value['path']),
            grammar.media_type(
                value.get('accept', 'application/json'), code=_CODE
            ),
            tuple(Requirement.parse(item) for item in raw),
            tuple(
                sorted(
                    (Capture.parse(key, item) for key, item in bound.items()),
                    key=_capture_name,
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            'path': '/' + '/'.join(self.template),
            'accept': self.accept,
            'require': [item.to_dict() for item in self.require],
        }
        if self.bind:
            result['bind'] = {
                item.name: {'at': list(item.at), 'format': item.format}
                for item in self.bind
            }
        return result

    def parameters(self) -> set[str]:
        """Every request parameter this check reads."""
        names = set(_references(self.template))
        for item in self.require:
            if item.parameter:
                names.add(item.parameter)
        return names

    def effect(self, request: Request) -> Effect:
        given = dict(request.arguments)
        return Effect(
            'GET',
            '/' + '/'.join(_fill(part, given) for part in self.template),
            accept=self.accept,
        )

    def verify(self, request: Request, facts: Any) -> dict[str, str]:
        """Require every stated fact; return the bound values.

        The second denial class of AUTH-01: it happens after one authorized
        read, and a failure here must prevent every later effect.
        """
        for item in self.require:
            if not item.holds(facts, request):
                raise SecretsError('resource_mismatch')
        return {item.name: item.extract(facts) for item in self.bind}


def _capture_name(item: Capture) -> str:
    return item.name


def _field(name: Any, value: Any) -> FieldSpec:
    """``"body": 4096`` or ``"body": {"max_bytes": 4096, "optional": true}``."""
    grammar.argument_name(name, code=_CODE)
    if type(value) is int:
        return FieldSpec(
            name, grammar.integer(value, 1, grammar.MAX_TEXT, code=_CODE)
        )
    value = grammar.exact_keys(
        value, frozenset({'max_bytes'}), frozenset({'optional'}), code=_CODE
    )
    optional = value.get('optional', False)
    if type(optional) is not bool:
        raise SecretsError(_CODE)
    return FieldSpec(
        name,
        grammar.integer(value['max_bytes'], 1, grammar.MAX_TEXT, code=_CODE),
        not optional,
    )


@dataclass(frozen=True)
class HTTPOperation:
    name: str
    write: bool
    requires: str = ''
    returns_check: bool = False
    method: str = ''
    template: tuple[str, ...] = ()
    parameters: tuple[tuple[str, ParamSpec], ...] = ()
    query: tuple[tuple[str, str], ...] = ()
    body_fields: tuple[FieldSpec, ...] = ()
    response: str = 'json'
    accept: str = 'application/json'
    defaults: tuple[tuple[str, Value], ...] = ()
    fold: tuple[str, ...] = ()
    page_size: int = 0
    page_at: tuple[str, ...] = ()
    page_parameter: str = ''

    @classmethod
    def parse(cls, value: Any, checks: tuple[Check, ...]) -> HTTPOperation:
        value = grammar.exact_keys(
            value,
            frozenset({'name', 'effect'}),
            frozenset(
                {
                    'method',
                    'path',
                    'parameters',
                    'query',
                    'body_fields',
                    'response',
                    'accept',
                    'requires',
                    'returns',
                    'defaults',
                    'fold',
                    'page',
                }
            ),
            code=_CODE,
        )
        name = grammar.operation_name(value['name'], code=_CODE)
        effect = value['effect']
        if type(effect) is not str or effect not in EFFECTS:
            raise SecretsError(_CODE)
        write = effect == 'write'

        check = None
        requires = ''
        if 'requires' in value:
            requires = grammar.argument_name(value['requires'], code=_CODE)
            check = _find_check(checks, requires)
            if check is None:
                raise SecretsError(_CODE)
        returns = value.get('returns', 'response')
        if type(returns) is not str or returns not in ('response', 'check'):
            raise SecretsError(_CODE)
        returns_check = returns == 'check'

        raw_parameters = value.get('parameters', {})
        raw_query = value.get('query', {})
        raw_fields = value.get('body_fields', {})
        raw_defaults = value.get('defaults', {})
        for mapping in (raw_parameters, raw_query, raw_fields, raw_defaults):
            if type(mapping) is not dict or len(mapping) > MAX_ARGUMENTS:
                raise SecretsError(_CODE)

        method = ''
        template: tuple[str, ...] = ()
        response = 'json'
        accept = 'application/json'
        if returns_check:
            # The checked facts are the answer: there is no second request,
            # so nothing about one may be stated, and nothing can be changed.
            forbidden = ('method', 'path', 'query', 'body_fields', 'response')
            if check is None or write:
                raise SecretsError(_CODE)
            for key in forbidden + ('accept', 'page'):
                if key in value:
                    raise SecretsError(_CODE)
        else:
            if 'method' not in value or 'path' not in value:
                raise SecretsError(_CODE)
            method = value['method']
            if type(method) is not str:
                raise SecretsError(_CODE)
            if method not in ('GET', 'POST', 'PATCH'):
                raise SecretsError(_CODE)
            template = _template(value['path'])
            response = value.get('response', 'json')
            if type(response) is not str or response not in ('json', 'text'):
                raise SecretsError(_CODE)
            default = 'application/json' if response == 'json' else 'text/plain'
            accept = grammar.media_type(
                value.get('accept', default), code=_CODE
            )
            # A method that sends a body can never be declared read-only. The
            # converse is deliberately allowed: a state-changing GET exists,
            # and the manifest is where that is said.
            if method != 'GET' and not write:
                raise SecretsError(_CODE)

        query = []
        in_query: set[str] = set()
        for key, item in sorted(raw_query.items()):
            grammar.argument_name(key, code=_CODE)
            if type(item) is not str:
                raise SecretsError(_CODE)
            reference = _placeholder(item)
            if reference is None:
                grammar.segment(item, code=_CODE)
            else:
                in_query.add(reference)
            query.append((key, item))

        parameters = tuple(
            sorted(
                (
                    grammar.argument_name(key, code=_CODE),
                    _parameter(spec, in_query=key in in_query),
                )
                for key, spec in raw_parameters.items()
            )
        )
        fields = tuple(
            sorted(
                (_field(key, item) for key, item in raw_fields.items()),
                key=_field_name,
            )
        )
        declared = {key for key, _ in parameters}
        captured = {item.name for item in check.bind} if check else set()
        named = {item.name for item in fields}
        if declared & named or declared & captured or named & captured:
            raise SecretsError(_CODE)
        # Every placeholder resolves to an allowlisted parameter or to a
        # validated fact, and every declared parameter is actually used:
        # nothing reaches a request target without an explicit allowlist.
        placed = set(_references(template)) | in_query
        if not placed <= declared | captured:
            raise SecretsError(_CODE)
        used = placed & declared
        if check is not None:
            if not check.parameters() <= declared:
                raise SecretsError(_CODE)
            used |= check.parameters()
        if used != declared:
            raise SecretsError(_CODE)
        if method == 'GET' and fields:
            raise SecretsError(_CODE)
        if method in ('POST', 'PATCH') and not fields:
            raise SecretsError(_CODE)

        specs = dict(parameters)
        defaults = []
        for key, item in sorted(raw_defaults.items()):
            if key not in specs or type(item) not in (int, str):
                raise SecretsError(_CODE)
            if not contains(specs[key], item):
                raise SecretsError(_CODE)
            defaults.append((key, item))
        raw_fold = value.get('fold', [])
        if type(raw_fold) is not list or len(raw_fold) > MAX_ARGUMENTS:
            raise SecretsError(_CODE)
        for key in raw_fold:
            # Folding is a normalization of the *request*; the allowlist
            # itself must already be in the folded form it will be met in.
            spec = specs.get(key) if type(key) is str else None
            if not isinstance(spec, StrSet) or raw_fold.count(key) != 1:
                raise SecretsError(_CODE)
            for item in spec.values:
                if grammar.lowered(item) != item:
                    raise SecretsError(_CODE)

        page_size = 0
        page_at: tuple[str, ...] = ()
        page_parameter = ''
        if 'page' in value:
            page = grammar.exact_keys(
                value['page'],
                frozenset({'size'}),
                frozenset({'at', 'parameter'}),
                code=_CODE,
            )
            if response != 'json':
                raise SecretsError(_CODE)
            page_size = grammar.integer(page['size'], 1, MAX_PAGE, code=_CODE)
            page_at = _pointer(page.get('at', []))
            if 'parameter' in page:
                page_parameter = grammar.argument_name(
                    page['parameter'], code=_CODE
                )
                if not isinstance(
                    specs.get(page_parameter), (IntSet, IntRange)
                ):
                    raise SecretsError(_CODE)
        return cls(
            name,
            write,
            requires,
            returns_check,
            method,
            template,
            parameters,
            tuple(query),
            fields,
            response,
            accept,
            tuple(defaults),
            tuple(sorted(raw_fold)),
            page_size,
            page_at,
            page_parameter,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            'name': self.name,
            'effect': 'write' if self.write else 'read',
        }
        if self.requires:
            result['requires'] = self.requires
        if self.returns_check:
            result['returns'] = 'check'
        else:
            result['method'] = self.method
            result['path'] = '/' + '/'.join(self.template)
            result['response'] = self.response
            result['accept'] = self.accept
        if self.parameters:
            result['parameters'] = {
                key: param_to_wire(spec) for key, spec in self.parameters
            }
        if self.query:
            result['query'] = dict(self.query)
        if self.body_fields:
            result['body_fields'] = {
                item.name: {
                    'max_bytes': item.max_bytes,
                    'optional': not item.required,
                }
                for item in self.body_fields
            }
        if self.defaults:
            result['defaults'] = dict(self.defaults)
        if self.fold:
            result['fold'] = list(self.fold)
        if self.page_size:
            page: dict[str, Any] = {
                'size': self.page_size,
                'at': list(self.page_at),
            }
            if self.page_parameter:
                page['parameter'] = self.page_parameter
            result['page'] = page
        return result

    def scope(self) -> OperationScope:
        return OperationScope(
            self.name, self.write, self.parameters, self.body_fields
        )

    def normalize(self, request: Request) -> Request:
        """Fold declared parameters and fill declared defaults.

        Normalization happens once, at the boundary, so that equal requests
        have equal digests and the scope check sees canonical values.
        """
        given = dict(request.arguments)
        for key in self.fold:
            if type(given.get(key)) is str:
                given[key] = grammar.lowered(str(given[key]))
        for key, item in self.defaults:
            if key not in given:
                given[key] = item
        return Request(request.operation, tuple(sorted(given.items())))

    def effect(self, request: Request, captured: dict[str, str]) -> Effect:
        given: dict[str, Any] = dict(request.arguments)
        given.update(captured)
        body = None
        if self.method != 'GET':
            body = tuple(
                (item.name, str(given[item.name]))
                for item in self.body_fields
                if item.name in given
            )
        return Effect(
            self.method,
            '/' + '/'.join(_fill(part, given) for part in self.template),
            tuple((key, _fill(item, given)) for key, item in self.query),
            self.accept,
            self.response,
            body,
        )


def _fill(part: str, given: dict[str, Any]) -> str:
    """A literal stays itself; ``{name}`` becomes that value."""
    reference = _placeholder(part)
    return part if reference is None else str(given[reference])


def _field_name(item: FieldSpec) -> str:
    return item.name


def _find_check(checks: tuple[Check, ...], name: str) -> Check | None:
    for item in checks:
        if item.name == name:
            return item
    return None


@dataclass(frozen=True)
class CLICommand:
    """One command line the guest client translates into a request."""

    words: tuple[str, ...]
    operation: str
    positional: tuple[str, ...] = ()
    options: tuple[tuple[str, str], ...] = ()
    output: str = 'reply'

    @classmethod
    def parse(
        cls, value: Any, operations: tuple[HTTPOperation, ...]
    ) -> CLICommand:
        value = grammar.exact_keys(
            value,
            frozenset({'command', 'operation'}),
            frozenset({'positional', 'options', 'output'}),
            code=_CODE,
        )
        words = value['command']
        positional = value.get('positional', [])
        options = value.get('options', {})
        if type(words) is not list or not 1 <= len(words) <= 4:
            raise SecretsError(_CODE)
        if type(positional) is not list or len(positional) > MAX_ARGUMENTS:
            raise SecretsError(_CODE)
        if type(options) is not dict or len(options) > 2 * MAX_ARGUMENTS:
            raise SecretsError(_CODE)
        word_tail = grammar.LOWER + grammar.DIGIT + '-'
        for word in words:
            grammar.token(word, grammar.LOWER, word_tail, 32, code=_CODE)
        target = None
        for item in operations:
            if item.name == value['operation']:
                target = item
        if target is None:
            raise SecretsError(_CODE)
        parameters = {key for key, _ in target.parameters}
        fields = {item.name for item in target.body_fields}
        for key in positional:
            if type(key) is not str or key not in parameters:
                raise SecretsError(_CODE)
        if len(set(positional)) != len(positional):
            raise SecretsError(_CODE)
        mapped = []
        for flag, destination in sorted(options.items()):
            if type(flag) is not str or type(destination) is not str:
                raise SecretsError(_CODE)
            if flag.startswith('--'):
                grammar.token(
                    flag[2:], grammar.LOWER, word_tail, 32, code=_CODE
                )
            elif (
                len(flag) != 2 or flag[0] != '-' or flag[1] not in grammar.ALNUM
            ):
                raise SecretsError(_CODE)
            # ``@name`` reads the value from a file: only for body fields.
            if destination.startswith('@'):
                if destination[1:] not in fields:
                    raise SecretsError(_CODE)
            elif destination not in parameters | fields:
                raise SecretsError(_CODE)
            mapped.append((flag, destination))
        output = value.get('output', 'reply')
        if type(output) is not str or output not in ('reply', 'result'):
            raise SecretsError(_CODE)
        return cls(
            tuple(words), target.name, tuple(positional), tuple(mapped), output
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'command': list(self.words),
            'operation': self.operation,
            'positional': list(self.positional),
            'options': dict(self.options),
            'output': self.output,
        }


def _parse_cli(
    value: Any, operations: tuple[HTTPOperation, ...]
) -> tuple[tuple[str, tuple[CLICommand, ...]], ...]:
    if type(value) is not dict or len(value) > 4:
        raise SecretsError(_CODE)
    tables = []
    for key, rows in sorted(value.items()):
        alias = grammar.token(
            key, grammar.LOWER, grammar.LOWER + grammar.DIGIT, 16, code=_CODE
        )
        # The client's own name and verbs are not available as aliases.
        if alias in RESERVED_ALIASES:
            raise SecretsError(_CODE)
        if type(rows) is not list or not 1 <= len(rows) <= 2 * MAX_OPERATIONS:
            raise SecretsError(_CODE)
        commands = tuple(CLICommand.parse(row, operations) for row in rows)
        if len({command.words for command in commands}) != len(commands):
            raise SecretsError(_CODE)
        tables.append((alias, commands))
    return tuple(tables)


@dataclass(frozen=True)
class HTTPSpec:
    service: str
    egress: Egress
    credential_source: dict[str, Any] = field(repr=False)
    operations: tuple[HTTPOperation, ...] = ()
    checks: tuple[Check, ...] = ()
    cli: tuple[tuple[str, tuple[CLICommand, ...]], ...] = ()
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
                    'checks',
                    'cli',
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
        raw_checks = value.get('checks', {})
        if type(raw_checks) is not dict or len(raw_checks) > MAX_ARGUMENTS:
            raise SecretsError(_CODE)
        checks = tuple(
            Check.parse(key, item) for key, item in sorted(raw_checks.items())
        )
        raw = value['operations']
        if type(raw) is not list or not 1 <= len(raw) <= MAX_OPERATIONS:
            raise SecretsError(_CODE)
        operations = tuple(
            sorted(
                (HTTPOperation.parse(item, checks) for item in raw), key=_name
            )
        )
        if len({item.name for item in operations}) != len(operations):
            raise SecretsError(_CODE)
        # A check nothing requires is a mistake, not a harmless extra.
        required = {item.requires for item in operations}
        for check in checks:
            if check.name not in required:
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
            checks,
            _parse_cli(value.get('cli', {}), operations),
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
            'checks': {item.name: item.to_dict() for item in self.checks},
            'operations': [item.to_dict() for item in self.operations],
            'cli': self.cli_tables(),
            'lifetime_seconds': self.lifetime_seconds,
            'max_requests': self.max_requests,
            'max_body_bytes': self.max_body_bytes,
        }

    @property
    def digest(self) -> str:
        return codec.digest(self.to_dict())

    @property
    def client_aliases(self) -> tuple[str, ...]:
        """Other names the guest client is installed under, from ``cli``."""
        return tuple(alias for alias, _ in self.cli)

    def cli_tables(self) -> dict[str, Any]:
        return {
            alias: [command.to_dict() for command in commands]
            for alias, commands in self.cli
        }

    def scope(self) -> Scope:
        return tuple(item.scope() for item in self.operations)

    def _operation(self, request: Request) -> HTTPOperation:
        for item in self.operations:
            if item.name == request.operation:
                return item
        raise SecretsError('denied')

    def _check(self, operation: HTTPOperation) -> Check | None:
        if not operation.requires:
            return None
        return _find_check(self.checks, operation.requires)

    def parse_request(self, value: Any) -> Request:
        """Wire request -> canonical request. Unknown operations pass through
        unchanged, to be refused by the scope check like any other."""
        request = Request.parse(value)
        for item in self.operations:
            if item.name == request.operation:
                return item.normalize(request)
        return request

    def preflight(self, request: Request) -> Effect | None:
        """The read-only fact fetch this request is conditioned on, if any."""
        check = self._check(self._operation(request))
        return None if check is None else check.effect(request)

    def final(self, request: Request, facts: Any) -> Effect | None:
        """Verify the facts, then construct the one final effect.

        ``None`` means the verified facts are themselves the answer.
        """
        operation = self._operation(request)
        check = self._check(operation)
        captured = {} if check is None else check.verify(request, facts)
        if operation.returns_check:
            return None
        return operation.effect(request, captured)

    def reply_meta(
        self, request: Request, result: Any
    ) -> dict[str, Any] | None:
        """Make truncation explicit: one page is never implied to be all."""
        operation = self._operation(request)
        if not operation.page_size:
            return None
        code = 'upstream_response'
        rows = lookup(result, operation.page_at, code=code)
        if type(rows) is not list or len(rows) > operation.page_size:
            raise SecretsError(code)
        meta: dict[str, Any] = {
            'per_page': operation.page_size,
            'possibly_more': len(rows) == operation.page_size,
        }
        if operation.page_parameter:
            meta['page'] = request.get(operation.page_parameter)
        return {'pagination': meta}


def _name(item: HTTPOperation) -> str:
    return item.name


__all__ = [
    'CLICommand',
    'Capture',
    'Check',
    'HTTPOperation',
    'HTTPSpec',
    'Requirement',
    'SCHEMA',
    'lookup',
]
