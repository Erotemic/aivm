"""The grammar of host-only credential sources (RESOLVER-01)."""

from __future__ import annotations

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel.source import FORBIDDEN_ENV, GH_SOURCE, parse_source


def test_sources_have_one_canonical_form():
    command = parse_source(
        {
            'kind': 'command',
            'argv': ['op', 'read', 'op://x'],
            'inherit_env': ['B', 'A'],
        }
    )
    assert command == {
        'kind': 'command',
        'argv': ['op', 'read', 'op://x'],
        'inherit_env': ['A', 'B'],
    }
    assert parse_source(command) == command
    assert (
        parse_source({'kind': 'command', 'argv': ['gh']})['inherit_env'] == []
    )
    path = {'kind': 'file', 'path': '/home/op/.config/token'}
    assert parse_source(path) == path
    assert parse_source(GH_SOURCE) == GH_SOURCE


@pytest.mark.parametrize(
    'invalid',
    [
        {'kind': 'command', 'argv': 'gh auth token'},
        {'kind': 'command', 'argv': []},
        {'kind': 'command', 'argv': ['x'] * 33},
        {'kind': 'command', 'argv': ['x', 7]},
        {'kind': 'command', 'argv': ['x', '']},
        {'kind': 'command', 'argv': ['x', 'a\x00b']},
        {'kind': 'command', 'argv': ['x' * 1025]},
        {'kind': 'command', 'argv': ['x' * 1024] * 9},
        {'kind': 'command', 'argv': ['x'], 'inherit_env': ['lower']},
        {'kind': 'command', 'argv': ['x'], 'inherit_env': ['A', 'A']},
        {'kind': 'command', 'argv': ['x'], 'inherit_env': ['1A']},
        {'kind': 'command', 'argv': ['x'], 'inherit_env': 'HOME'},
        {'kind': 'command', 'argv': ['x'], 'shell': True},
        {'kind': 'file', 'path': 'relative/token'},
        {'kind': 'file', 'path': '/a/../etc/shadow'},
        {'kind': 'file', 'path': '/a//b'},
        {'kind': 'file', 'path': '/a/./b'},
        {'kind': 'file', 'path': '/'},
        {'kind': 'file', 'path': '/a/'},
        {'kind': 'file', 'path': '/a', 'argv': ['x']},
        {'kind': 'file'},
        {'kind': 'shell', 'script': 'gh auth token'},
        {'kind': 'env', 'name': 'GH_TOKEN'},
        {},
        'gh',
        None,
    ],
)
def test_policy_rejects_unsafe_resolver_schema(invalid):
    with pytest.raises(SecretsError) as caught:
        parse_source(invalid)
    assert caught.value.code == 'invalid_policy'


@pytest.mark.parametrize('name', sorted(FORBIDDEN_ENV))
def test_a_resolver_cannot_inherit_code_loading_variables(name):
    with pytest.raises(SecretsError):
        parse_source({'kind': 'command', 'argv': ['x'], 'inherit_env': [name]})
