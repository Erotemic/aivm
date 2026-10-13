"""Pure, single-active-root authority transitions for the Python/Rust contract.

An authority has exactly ONE active trust anchor and ONE active TLS server
identity. No legacy fallback, dual-CA grace period, or automatic migration.
Callers must stage authenticated immutable material before atomically storing
an accepted transition. Old enrollment state is retired BEFORE CA activation.

This model cannot authenticate a root certificate, persist data, or prove that
an executing TLS context uses the selected roots: host adapters must establish
those implementation obligations separately.
"""
from __future__ import annotations

from typing import Any

from ...errors import SecretsError
from ...primitives import grammar

SCHEMA = 2
MAX_CA_GENERATIONS = 64
MAX_SERVER_GENERATIONS = 2048
MAX_TIME = 2**63 - 1
_FIELDS = frozenset({'schema', 'issuer', 'audience', 'created_at', 'ca', 'server'})
_CA = frozenset({'generation', 'sha256'})
_SERVER = frozenset({'generation', 'ca_generation'})


def validate(value: object) -> dict[str, Any]:
    value = grammar.exact_keys(value, _FIELDS, code='invalid_capability')
    if type(value['schema']) is not int or value['schema'] != SCHEMA:
        raise SecretsError('invalid_capability')
    from .claims import IdentityExpectation
    IdentityExpectation.parse({'issuer': value['issuer'],
                               'audience': value['audience'],
                               'subject': 'init', 'epoch': 0})
    grammar.integer(value['created_at'], 0, MAX_TIME, code='invalid_capability')
    ca = grammar.exact_keys(value['ca'], _CA, code='invalid_capability')
    server = grammar.exact_keys(value['server'], _SERVER,
                                code='invalid_capability')
    grammar.integer(ca['generation'], 1, MAX_CA_GENERATIONS,
                    code='invalid_capability')
    grammar.hex_string(ca['sha256'], 64, code='invalid_capability')
    grammar.integer(server['generation'], 1, MAX_SERVER_GENERATIONS,
                    code='invalid_capability')
    grammar.integer(server['ca_generation'], 1, ca['generation'],
                    code='invalid_capability')
    if server['ca_generation'] != ca['generation']:
        raise SecretsError('invalid_capability')
    return {'schema': SCHEMA, 'issuer': value['issuer'],
            'audience': value['audience'], 'created_at': value['created_at'],
            'ca': dict(ca), 'server': dict(server)}


def initial(*, issuer: str, audience: str, created_at: int,
            ca_sha256: str) -> dict[str, Any]:
    return validate({'schema': SCHEMA, 'issuer': issuer,
                     'audience': audience, 'created_at': created_at,
                     'ca': {'generation': 1, 'sha256': ca_sha256},
                     'server': {'generation': 1, 'ca_generation': 1}})


def activate_ca(value: object, *, ca_generation: int, ca_sha256: str,
                server_generation: int) -> dict[str, Any]:
    """One-way trust cutover: both active TLS and CA identities change.

    The host invalidates every old enrollment before committing this result.
    Skipped numbers permit an interrupted staging transaction to leave files
    without reusing filenames. No old CA is retained as an accepted root.
    """
    current = validate(value)
    grammar.integer(ca_generation, current['ca']['generation'] + 1,
                    MAX_CA_GENERATIONS, code='invalid_capability')
    grammar.integer(server_generation, current['server']['generation'] + 1,
                    MAX_SERVER_GENERATIONS, code='invalid_capability')
    grammar.hex_string(ca_sha256, 64, code='invalid_capability')
    if ca_sha256 == current['ca']['sha256']:
        raise SecretsError('denied')
    return validate({**current,
                     'ca': {'generation': ca_generation, 'sha256': ca_sha256},
                     'server': {'generation': server_generation,
                                'ca_generation': ca_generation}})


def activate_server(value: object, *, server_generation: int) -> dict[str, Any]:
    """Replace only the leaf server identity; keep the active CA unchanged."""
    current = validate(value)
    grammar.integer(server_generation, current['server']['generation'] + 1,
                    MAX_SERVER_GENERATIONS, code='invalid_capability')
    return validate({**current,
                     'server': {'generation': server_generation,
                                'ca_generation': current['ca']['generation']}})
