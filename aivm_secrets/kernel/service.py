"""Policies become service specs here, by one route.

There is a single service mechanism, :class:`~.https.HTTPSpec`: a
declarative manifest interpreted by the kernel. Nothing provider-specific is
compiled in beside it, and nothing here loads a module by name or accepts an
adapter from a request (PLUGIN-01, EXT-01).

Two policy schemas are accepted, and both end as the same type:

``schema: 2``  a manifest, parsed directly.
``schema: 1``  shorthand for the built-in GitHub pull-request preset. It is
               *expanded into a schema-2 manifest* by :mod:`.presets` and
               then parsed exactly like one an operator wrote by hand.

The spec provides the total functions the kernel is written against:

``scope()``                  the authorization view of the policy
``parse_request(value)``     wire request -> canonical :class:`Request`
``preflight(request)``       optional read-only fact fetch
``final(request, facts)``    the one final effect, or ``None``
``reply_meta(request, r)``   additional reply fields derived from a result
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError
from . import presets
from .https import HTTPSpec

ServiceSpec = HTTPSpec


def parse_policy(value: Any) -> ServiceSpec:
    """Select the form by its explicit schema number, never by shape."""
    if type(value) is not dict:
        raise SecretsError('invalid_policy')
    schema = value.get('schema')
    if type(schema) is int and schema == 1:
        return HTTPSpec.parse(presets.github_pr(value))
    if type(schema) is int and schema == 2:
        return HTTPSpec.parse(value)
    raise SecretsError('invalid_policy')


def reparse(spec: ServiceSpec) -> ServiceSpec:
    """Round-trip a spec through its canonical form.

    A spec built or edited in memory is forced back through the one parser
    before it can define a session, so every live spec is a parser output.
    """
    if type(spec) is not HTTPSpec:
        raise SecretsError('invalid_policy')
    return HTTPSpec.parse(spec.to_dict())
