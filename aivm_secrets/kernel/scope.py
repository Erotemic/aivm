"""Authorization as data: what a grant permits, and when one grant is a subset.

A scope is a finite list of named operations. Each operation fixes, per
argument, the exact values a request may carry: a finite set of integers, an
integer interval, or a finite set of strings. There are no wildcards, patterns
or executable predicates, so both questions the kernel asks of a scope are
decidable by inspection:

* ``check_arguments`` -- does this request lie inside this operation? (AUTH-01)
* ``is_subset`` -- does this child scope permit nothing its parent does not?
  (ATTEN-01)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import SecretsError
from . import grammar
from .model import MAX_ARGUMENTS, Request, Value

MAX_VALUES = 512
MAX_OPERATIONS = 64


@dataclass(frozen=True)
class IntSet:
    values: tuple[int, ...]


@dataclass(frozen=True)
class IntRange:
    low: int
    high: int


@dataclass(frozen=True)
class StrSet:
    values: tuple[str, ...]


ParamSpec = IntSet | IntRange | StrSet


def parse_param_spec(value: Any, *, code: str) -> ParamSpec:
    """``[1, 2]``, ``["a", "b"]`` or ``{"min": 1, "max": 9}``; never mixed."""
    if type(value) is dict:
        value = grammar.exact_keys(value, frozenset({'min', 'max'}), code=code)
        low = grammar.integer(value['min'], 0, grammar.MAX_INT, code=code)
        high = grammar.integer(value['max'], low, grammar.MAX_INT, code=code)
        return IntRange(low, high)
    if type(value) is not list or not 1 <= len(value) <= MAX_VALUES:
        raise SecretsError(code)
    if type(value[0]) is int:
        numbers = tuple(
            grammar.integer(item, 0, grammar.MAX_INT, code=code)
            for item in value
        )
        if len(set(numbers)) != len(numbers):
            raise SecretsError(code)
        return IntSet(tuple(sorted(numbers)))
    strings = tuple(
        grammar.text(item, grammar.MAX_SEGMENT, code=code) for item in value
    )
    if len(set(strings)) != len(strings):
        raise SecretsError(code)
    return StrSet(tuple(sorted(strings)))


def param_to_wire(spec: ParamSpec) -> Any:
    if isinstance(spec, IntRange):
        return {'min': spec.low, 'max': spec.high}
    return list(spec.values)


def contains(spec: ParamSpec, value: Value) -> bool:
    """Type-exact membership: the string ``"23"`` is never the integer 23."""
    if isinstance(spec, StrSet):
        return type(value) is str and value in spec.values
    if type(value) is not int:
        return False
    if isinstance(spec, IntRange):
        return spec.low <= value <= spec.high
    return value in spec.values


def spec_subset(child: ParamSpec, parent: ParamSpec) -> bool:
    if isinstance(child, StrSet) or isinstance(parent, StrSet):
        return (
            isinstance(child, StrSet)
            and isinstance(parent, StrSet)
            and set(child.values) <= set(parent.values)
        )
    if isinstance(child, IntSet):
        return all(contains(parent, value) for value in child.values)
    if isinstance(parent, IntRange):
        return parent.low <= child.low and child.high <= parent.high
    # An interval inside a finite set: only possible when it is no larger.
    if child.high - child.low + 1 > len(parent.values):
        return False
    return all(
        value in parent.values for value in range(child.low, child.high + 1)
    )


@dataclass(frozen=True)
class FieldSpec:
    """One string body field and the most bytes a request may put in it."""

    name: str
    max_bytes: int
    required: bool = True


@dataclass(frozen=True)
class OperationScope:
    name: str
    write: bool
    parameters: tuple[tuple[str, ParamSpec], ...] = ()
    fields: tuple[FieldSpec, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'write': self.write,
            'parameters': {
                name: param_to_wire(spec) for name, spec in self.parameters
            },
            'fields': {
                item.name: {
                    'max_bytes': item.max_bytes,
                    'required': item.required,
                }
                for item in self.fields
            },
        }


Scope = tuple[OperationScope, ...]


def find(scope: Scope, name: str) -> OperationScope | None:
    for operation in scope:
        if operation.name == name:
            return operation
    return None


def check_arguments(operation: OperationScope, request: Request) -> int:
    """Require ``request`` to lie inside ``operation``; return its body size.

    A request that is not even shaped like the operation is
    ``invalid_request``. A well-shaped request for a value or a size the
    grant does not include is ``denied``.
    """
    parameters = dict(operation.parameters)
    fields = {item.name: item for item in operation.fields}
    given = dict(request.arguments)
    if len(given) != len(request.arguments) or len(given) > MAX_ARGUMENTS:
        raise SecretsError('invalid_request')
    for name in given:
        if name not in parameters and name not in fields:
            raise SecretsError('invalid_request')
    for name in parameters:
        if name not in given:
            raise SecretsError('invalid_request')
    present = 0
    for item in operation.fields:
        if item.name in given:
            present += 1
            if type(given[item.name]) is not str:
                raise SecretsError('invalid_request')
        elif item.required:
            raise SecretsError('invalid_request')
    if operation.write and present == 0:
        raise SecretsError('invalid_request')
    for name, spec in operation.parameters:
        if not contains(spec, given[name]):
            raise SecretsError('denied')
    total = 0
    for item in operation.fields:
        if item.name in given:
            size = grammar.byte_length(str(given[item.name]))
            if size > item.max_bytes:
                raise SecretsError('denied')
            total += size
    return total


def operation_subset(child: OperationScope, parent: OperationScope) -> bool:
    if child.name != parent.name or child.write != parent.write:
        return False
    parent_parameters = dict(parent.parameters)
    if set(dict(child.parameters)) != set(parent_parameters):
        return False
    for name, spec in child.parameters:
        if not spec_subset(spec, parent_parameters[name]):
            return False
    parent_fields = {item.name: item for item in parent.fields}
    if {item.name for item in child.fields} != set(parent_fields):
        return False
    for item in child.fields:
        wider = parent_fields[item.name]
        if item.max_bytes > wider.max_bytes or item.required != wider.required:
            return False
    return True


def is_subset(child: Scope, parent: Scope) -> bool:
    """Semantic attenuation: every request ``child`` admits, ``parent`` admits."""
    for operation in child:
        wider = find(parent, operation.name)
        if wider is None or not operation_subset(operation, wider):
            return False
    return True


@dataclass(frozen=True)
class Narrowing:
    """A guest's request for a smaller grant. Every field can only shrink."""

    operations: tuple[tuple[str, tuple[tuple[str, ParamSpec], ...]], ...]
    max_requests: int | None = None
    lifetime_seconds: int | None = None
    max_body_bytes: int | None = None

    @classmethod
    def parse(cls, value: Any) -> Narrowing:
        code = 'invalid_request'
        value = grammar.exact_keys(
            value,
            frozenset({'operations'}),
            frozenset({'max_requests', 'lifetime_seconds', 'max_body_bytes'}),
        )
        raw = value['operations']
        if type(raw) is not dict or not 1 <= len(raw) <= MAX_OPERATIONS:
            raise SecretsError(code)
        operations = []
        for name, narrowed in raw.items():
            grammar.operation_name(name)
            if type(narrowed) is not dict or len(narrowed) > MAX_ARGUMENTS:
                raise SecretsError(code)
            specs = []
            for parameter, spec in narrowed.items():
                grammar.argument_name(parameter)
                specs.append((parameter, parse_param_spec(spec, code=code)))
            operations.append((name, tuple(sorted(specs, key=_first))))
        limits = []
        for key, high in (
            ('max_requests', 1000),
            ('lifetime_seconds', 3600),
            ('max_body_bytes', grammar.MAX_TEXT),
        ):
            limits.append(
                grammar.integer(value[key], 1, high) if key in value else None
            )
        return cls(tuple(sorted(operations, key=_first)), *limits)


def _first(item: tuple[str, Any]) -> str:
    return item[0]


def narrow(parent: Scope, narrowing: Narrowing) -> Scope:
    """Build a child scope out of the parent's own operations.

    The child is assembled from parent operations with some parameters
    replaced by requested subsets, so it cannot name an operation, a
    parameter or a field the parent lacks. ``is_subset`` is then asserted on
    the result: the construction is the mechanism, the predicate is the
    specification, and a disagreement between them is a refusal.
    """
    result = []
    for name, requested in narrowing.operations:
        wider = find(parent, name)
        if wider is None:
            raise SecretsError('denied')
        replaced = dict(requested)
        known = dict(wider.parameters)
        for parameter in replaced:
            if parameter not in known:
                raise SecretsError('denied')
        parameters = tuple(
            (parameter, replaced.get(parameter, spec))
            for parameter, spec in wider.parameters
        )
        result.append(
            OperationScope(wider.name, wider.write, parameters, wider.fields)
        )
    child = tuple(result)
    if not is_subset(child, parent):
        raise SecretsError('denied')
    return child
