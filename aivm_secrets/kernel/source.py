"""The grammar of a host-only credential source.

Only the *description* of a source is validated here; nothing is executed or
opened. A source is operator configuration carried inside a policy, so it is
part of the policy digest, and it can never arrive in a guest request
(RESOLVER-01).
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError
from . import grammar
from .model import absolute_path

# Variables that change which code a resolver loads or where its diagnostics
# go. An operator who truly needs one can wrap the resolver in a script.
FORBIDDEN_ENV = frozenset(
    {
        'BASH_ENV',
        'ENV',
        'GH_DEBUG',
        'LD_AUDIT',
        'LD_LIBRARY_PATH',
        'LD_PRELOAD',
        'PYTHONHOME',
        'PYTHONPATH',
        'PYTHONSTARTUP',
    }
)


def _env_name(value: Any, *, code: str) -> str:
    upper_or_underscore = grammar.UPPER + '_'
    return grammar.token(
        value,
        upper_or_underscore,
        upper_or_underscore + grammar.DIGIT,
        64,
        code=code,
    )


def parse_source(value: Any) -> dict[str, Any]:
    """Return the canonical form of a ``file`` or ``command`` source."""
    code = 'invalid_policy'
    if type(value) is not dict:
        raise SecretsError(code)
    kind = value.get('kind')
    if kind == 'file':
        grammar.exact_keys(value, frozenset({'kind', 'path'}), code=code)
        return {'kind': 'file', 'path': absolute_path(value['path'], code=code)}
    if kind == 'command':
        grammar.exact_keys(
            value,
            frozenset({'kind', 'argv'}),
            frozenset({'inherit_env'}),
            code=code,
        )
        argv = value['argv']
        env = value.get('inherit_env', [])
        if type(argv) is not list or not 1 <= len(argv) <= 32:
            raise SecretsError(code)
        if type(env) is not list or len(env) > 32:
            raise SecretsError(code)
        argv = [grammar.text(arg, 1024, code=code) for arg in argv]
        if sum(grammar.byte_length(arg) for arg in argv) > 8192:
            raise SecretsError(code)
        env = [_env_name(name, code=code) for name in env]
        if len(set(env)) != len(env):
            raise SecretsError(code)
        if any(name in FORBIDDEN_ENV for name in env):
            raise SecretsError(code)
        return {'kind': 'command', 'argv': argv, 'inherit_env': sorted(env)}
    raise SecretsError(code)
