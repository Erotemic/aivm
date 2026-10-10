"""The closed sum of service specs (PLUGIN-01, EXT-01)."""

from __future__ import annotations

import inspect

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel import service
from aivm_secrets.kernel.github import GitHubSpec
from aivm_secrets.kernel.https import HTTPSpec
from aivm_secrets.kernel.service import parse_policy, reparse
from tests.secrets_helpers import github_policy, https_policy


def test_the_variant_is_selected_by_schema_number_only():
    assert isinstance(parse_policy(github_policy()), GitHubSpec)
    assert isinstance(parse_policy(https_policy()), HTTPSpec)
    # A schema-2 shape cannot be smuggled in under schema 1, or vice versa.
    for mixed in (
        dict(https_policy(), schema=1),
        dict(github_policy(), schema=2),
    ):
        with pytest.raises(SecretsError):
            parse_policy(mixed)


@pytest.mark.parametrize(
    'value',
    [None, [], 'policy', 7, {}, {'schema': 0}, {'schema': 3}, {'schema': '2'},
     {'schema': 2.0}, {'schema': True}, {'schema': [2]},
     {'adapter': 'https', 'module': 'os', 'entry_point': 'system'}],
)  # fmt: skip
def test_unknown_or_ambiguous_schemas_are_refused(value):
    with pytest.raises(SecretsError) as caught:
        parse_policy(value)
    assert caught.value.code == 'invalid_policy'


def test_reparse_is_idempotent_and_closed():
    for policy in (github_policy(), https_policy()):
        spec = parse_policy(policy)
        assert (
            reparse(spec) == spec
            and reparse(reparse(spec)).digest == spec.digest
        )
    for impostor in (
        object(),
        {'schema': 2},
        None,
        type('Spec', (), {'to_dict': dict})(),
    ):
        with pytest.raises(SecretsError):
            reparse(impostor)


def test_every_variant_offers_the_same_total_interface():
    """EXT-01: the kernel is written against exactly this surface."""
    surface = (
        'scope',
        'parse_request',
        'preflight',
        'final',
        'reply_meta',
        'to_dict',
    )
    attributes = (
        'digest', 'service', 'egress', 'credential_source', 'client_aliases',
        'lifetime_seconds', 'max_requests', 'max_body_bytes',
    )  # fmt: skip
    for policy in (github_policy(), https_policy()):
        spec = parse_policy(policy)
        for name in surface:
            assert callable(getattr(spec, name)), (type(spec).__name__, name)
        for name in attributes:
            assert getattr(spec, name) is not None, (type(spec).__name__, name)


def test_no_dynamic_loading_exists_in_the_service_registry():
    source = inspect.getsource(service)
    for forbidden in (
        'importlib',
        '__import__',
        'entry_points',
        'getattr(',
        'eval(',
        'exec(',
    ):
        assert forbidden not in source
