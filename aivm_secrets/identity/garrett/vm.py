"""Deterministic managed-VM binding contract for both Python and future Rust.

This module must not import AIVM, talk to libvirt, inspect paths, or consume
secrets. Its inputs are *attested by the trusted host adapter*, not by the
remote guest. The Rust backend will independently implement the same grammar.
"""

from __future__ import annotations

import hashlib
import uuid

from ...errors import SecretsError
from ...primitives import codec, grammar

SCHEMA = 1


def subject(value: object) -> str:
    """Bind an enrollment to an exact store, VM incarnation, and access owner."""
    data = grammar.exact_keys(value, frozenset({
        'schema', 'store', 'vm', 'domain_uuid', 'principal', 'host_uid',
        'guest_user',
    }), code='invalid_capability')
    if type(data['schema']) is not int or data['schema'] != SCHEMA:
        raise SecretsError('invalid_capability')
    # The store is a digest of an authoritative host config-store path. A
    # guest cannot supply or alter it through this API.
    grammar.hex_string(data['store'], 64, code='invalid_capability')
    for key in ('vm', 'principal', 'guest_user'):
        grammar.token(data[key], grammar.ALNUM + '_',
                      grammar.ALNUM + '_-.', 128, code='invalid_capability')
    grammar.integer(data['host_uid'], 1, 2**31 - 1, code='invalid_capability')
    try:
        supplied = data['domain_uuid']
        if type(supplied) is not str or str(uuid.UUID(supplied)) != supplied:
            raise ValueError('noncanonical UUID')
    except (ValueError, AttributeError, TypeError):
        raise SecretsError('invalid_capability') from None
    # Explicit version/domain separation prevents collision with manually
    # enrolled subjects and permits a future schema revision.
    digest = hashlib.sha256(b'aivm-secrets/managed-vm/v1\x00' + codec.dumps(data))
    return 'vm-' + digest.hexdigest()


__all__ = ['SCHEMA', 'subject']
