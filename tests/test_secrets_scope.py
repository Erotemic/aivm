"""Authorization as data: membership (AUTH-01) and attenuation (ATTEN-01)."""

from __future__ import annotations

import itertools
import random

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel.model import Request
from aivm_secrets.kernel.scope import (
    FieldSpec,
    IntRange,
    IntSet,
    Narrowing,
    OperationScope,
    StrSet,
    check_arguments,
    contains,
    is_subset,
    narrow,
    operation_subset,
    param_to_wire,
    parse_param_spec,
    spec_subset,
)

UNIVERSE = [0, 1, 2, 3, 4, 5, 6, 'a', 'b', 'c', '1', '']


def members(spec):
    """Extensional meaning of a spec over a small universe: the oracle."""
    return {value for value in UNIVERSE if contains(spec, value)}


SPECS = (
    [
        IntSet(tuple(c))
        for n in (1, 2, 3)
        for c in itertools.combinations(range(6), n)
    ]
    + [IntRange(lo, hi) for lo in range(6) for hi in range(lo, 6)]
    + [
        StrSet(tuple(c))
        for n in (1, 2)
        for c in itertools.combinations('abc1', n)
    ]
)


def test_membership_is_type_exact():
    assert contains(IntSet((1, 2)), 1) and not contains(IntSet((1, 2)), 3)
    assert contains(IntRange(1, 5), 5) and not contains(IntRange(1, 5), 6)
    assert contains(StrSet(('1',)), '1')
    # No coercion in either direction, and a bool is never an integer.
    assert not contains(IntSet((1,)), '1')
    assert not contains(IntRange(0, 9), '1')
    assert not contains(StrSet(('1',)), 1)
    assert not contains(IntSet((1,)), True)
    assert not contains(IntRange(0, 1), True)


def test_spec_subset_agrees_with_set_inclusion_exhaustively():
    """ATTEN-01 at the leaf: ``spec_subset`` is exactly ``members <=``."""
    checked = 0
    for child, parent in itertools.product(SPECS, repeat=2):
        assert spec_subset(child, parent) == (
            members(child) <= members(parent)
        ), (
            child,
            parent,
        )
        checked += 1
    assert checked == len(SPECS) ** 2 > 2000


def test_a_wide_interval_is_never_inside_a_finite_set():
    assert not spec_subset(IntRange(0, 2**31 - 1), IntSet(tuple(range(512))))
    assert spec_subset(IntRange(3, 5), IntSet((1, 3, 4, 5)))
    assert not spec_subset(IntRange(3, 6), IntSet((1, 3, 4, 5)))


@pytest.mark.parametrize(
    'wire,spec',
    [
        ([3, 1, 2], IntSet((1, 2, 3))),
        (['b', 'a'], StrSet(('a', 'b'))),
        ({'min': 1, 'max': 9}, IntRange(1, 9)),
        ({'min': 4, 'max': 4}, IntRange(4, 4)),
    ],
)
def test_param_spec_parses_to_one_canonical_form(wire, spec):
    assert parse_param_spec(wire, code='invalid_policy') == spec
    assert parse_param_spec(param_to_wire(spec), code='invalid_policy') == spec


@pytest.mark.parametrize(
    'wire',
    [
        [], [1, 1], ['a', 'a'], [1, 'a'], ['a', 1], [True], [1.5], [None], [-1],
        [2**31], [''], ['x' * 129], [[1]], list(range(513)), '*', 'any', 7, None,
        {'min': 5, 'max': 4}, {'min': -1, 'max': 4}, {'min': 1}, {'max': 1},
        {'min': 1, 'max': 2, 'step': 1}, {'min': '1', 'max': 2}, {'min': 1, 'max': 2**31},
        {'regex': '.*'}, {},
    ],
)  # fmt: skip
def test_no_wildcards_patterns_or_mixed_types(wire):
    with pytest.raises(SecretsError):
        parse_param_spec(wire, code='invalid_policy')


VIEW = OperationScope('issue.view', False, (('issue', IntSet((23, 24))),))
COMMENT = OperationScope(
    'issue.comment',
    True,
    (('issue', IntSet((23, 24))),),
    (FieldSpec('body', 10), FieldSpec('title', 5, required=False)),
)


def request(operation, **arguments):
    return Request(operation, tuple(sorted(arguments.items())))


def test_check_arguments_returns_body_bytes():
    assert check_arguments(VIEW, request('issue.view', issue=23)) == 0
    assert (
        check_arguments(
            COMMENT, request('issue.comment', issue=24, body='héllo')
        )
        == 6
    )
    both = request('issue.comment', issue=24, body='1234567890', title='12345')
    assert check_arguments(COMMENT, both) == 15


@pytest.mark.parametrize(
    'operation,arguments,code',
    [
        (VIEW, {}, 'invalid_request'),
        (VIEW, {'issue': 23, 'url': 'https://evil.invalid'}, 'invalid_request'),
        (VIEW, {'issue': 23, 'body': 'write on read'}, 'invalid_request'),
        (VIEW, {'issue': 25}, 'denied'),
        (VIEW, {'issue': '23'}, 'denied'),
        (COMMENT, {'issue': 23}, 'invalid_request'),
        (COMMENT, {'issue': 23, 'title': 'only'}, 'invalid_request'),
        (COMMENT, {'issue': 23, 'body': 7}, 'invalid_request'),
        (COMMENT, {'issue': 23, 'body': 'x' * 11}, 'denied'),
        (
            COMMENT,
            {'issue': 23, 'body': 'ééééée'},
            'denied',
        ),  # 11 bytes, 6 chars
        (COMMENT, {'issue': 23, 'body': 'ok', 'title': '123456'}, 'denied'),
        (COMMENT, {'issue': 99, 'body': 'ok'}, 'denied'),
    ],
)
def test_arguments_fail_closed(operation, arguments, code):
    with pytest.raises(SecretsError) as caught:
        check_arguments(operation, request(operation.name, **arguments))
    assert caught.value.code == code


def test_a_write_must_carry_content():
    optional = OperationScope(
        'pr.edit',
        True,
        (),
        (FieldSpec('body', 9, False), FieldSpec('title', 9, False)),
    )
    assert check_arguments(optional, request('pr.edit', title='t')) == 1
    with pytest.raises(SecretsError):
        check_arguments(optional, request('pr.edit'))


def admitted(scope, universe):
    """Every request from ``universe`` that ``scope`` admits: the oracle."""
    result = set()
    for candidate in universe:
        for operation in scope:
            if operation.name != candidate.operation:
                continue
            try:
                check_arguments(operation, candidate)
            except SecretsError:
                continue
            result.add((candidate, operation.write))
    return result


def test_scope_subset_means_admits_nothing_more():
    """ATTEN-01: ``is_subset(c, p)`` implies admitted(c) <= admitted(p).

    Generated scopes are compared against brute-force enumeration of every
    request over a small universe. The converse is checked too wherever the
    two scopes have the same shape, so the predicate is not vacuously strict.
    """
    rng = random.Random(20261009)
    universe = [
        request(name, **dict(zip(('n', 's', 'body'), values)))
        for name in ('read', 'write')
        for values in itertools.product(
            [0, 1, 2, 3], ['a', 'b'], ['', 'x', 'xx', 'xxx']
        )
    ]
    universe = [
        Request(r.operation, tuple(a for a in r.arguments if a[1] != ''))
        for r in universe
    ]

    def random_scope():
        result = []
        for name, write in (('read', False), ('write', True)):
            if rng.random() < 0.25:
                continue
            low = rng.randint(0, 3)
            number = rng.choice(
                [IntRange(low, rng.randint(low, 3)),
                 IntSet(tuple(sorted(rng.sample(range(4), rng.randint(1, 3)))))]
            )  # fmt: skip
            text = StrSet(tuple(sorted(rng.sample('ab', rng.randint(1, 2)))))
            fields = (FieldSpec('body', rng.randint(1, 3)),) if write else ()
            result.append(
                OperationScope(
                    name, write, (('n', number), ('s', text)), fields
                )
            )
        return tuple(result)

    implied = strict = 0
    for _ in range(4000):
        child, parent = random_scope(), random_scope()
        inside = admitted(child, universe) <= admitted(parent, universe)
        if is_subset(child, parent):
            assert inside, (child, parent)
            implied += 1
        else:
            # Same-shape scopes are exactly comparable, so a refusal here
            # must be explained by a request only the child admits.
            assert not inside, (child, parent)
            strict += 1
    assert implied > 200 and strict > 200


def test_subset_never_changes_what_kind_of_operation_it_is():
    assert operation_subset(VIEW, VIEW)
    for different in [
        OperationScope('issue.view', True, VIEW.parameters),
        OperationScope('issue.other', False, VIEW.parameters),
        OperationScope('issue.view', False, ()),
        OperationScope(
            'issue.view', False, VIEW.parameters + (('extra', IntSet((1,))),)
        ),
        OperationScope(
            'issue.view', False, VIEW.parameters, (FieldSpec('body', 1),)
        ),
    ]:
        assert not operation_subset(different, VIEW)
        assert not operation_subset(VIEW, different)
    larger = OperationScope(
        'issue.comment', True, COMMENT.parameters,
        (FieldSpec('body', 11), FieldSpec('title', 5, required=False)),
    )  # fmt: skip
    assert operation_subset(COMMENT, larger) and not operation_subset(
        larger, COMMENT
    )
    required = OperationScope(
        'issue.comment', True, COMMENT.parameters,
        (FieldSpec('body', 10), FieldSpec('title', 5, required=True)),
    )  # fmt: skip
    assert not operation_subset(required, COMMENT)


PARENT = (COMMENT, VIEW)


def test_narrowing_builds_only_from_the_parent():
    child = narrow(
        PARENT, Narrowing.parse({'operations': {'issue.view': {'issue': [23]}}})
    )
    assert child == (
        OperationScope('issue.view', False, (('issue', IntSet((23,))),)),
    )
    assert is_subset(child, PARENT) and not is_subset(PARENT, child)
    # An operation named without parameters inherits the parent's exactly.
    same = narrow(
        PARENT, Narrowing.parse({'operations': {'issue.comment': {}}})
    )
    assert same == (COMMENT,)


@pytest.mark.parametrize(
    'operations',
    [
        {'issue.merge': {}},
        {'issue.view': {'issue': [25]}},
        {'issue.view': {'issue': [23, 25]}},
        {'issue.view': {'issue': {'min': 0, 'max': 100}}},
        {'issue.view': {'issue': ['23']}},
        {'issue.view': {'project': [1]}},
        {'issue.comment': {'body': ['x']}},
    ],
)
def test_narrowing_cannot_widen(operations):
    with pytest.raises(SecretsError) as caught:
        narrow(PARENT, Narrowing.parse({'operations': operations}))
    assert caught.value.code == 'denied'


@pytest.mark.parametrize(
    'value',
    [
        {},
        {'operations': {}},
        {'operations': []},
        {'operations': {'Issue.View': {}}},
        {'operations': {'issue.view': []}},
        {'operations': {'issue.view': {'Issue': [1]}}},
        {'operations': {'issue.view': {'issue': '*'}}},
        {'operations': {'issue.view': {}}, 'max_requests': 0},
        {'operations': {'issue.view': {}}, 'max_requests': 1001},
        {'operations': {'issue.view': {}}, 'max_requests': True},
        {'operations': {'issue.view': {}}, 'lifetime_seconds': 3601},
        {'operations': {'issue.view': {}}, 'max_body_bytes': 16385},
        {'operations': {'issue.view': {}}, 'writes': 'allow'},
        {'operations': {'issue.view': {}}, 'parent': 'a' * 32},
        {'operations': {'issue.view': {}}, 'host': 'evil.invalid'},
        None,
    ],
)
def test_narrowing_wire_shape_is_closed(value):
    with pytest.raises(SecretsError) as caught:
        Narrowing.parse(value)
    assert caught.value.code == 'invalid_request'
