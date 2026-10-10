"""The closed set of service specs.

``ServiceSpec`` is a sum type, not a plugin interface: the kernel and the
broker are written against exactly these variants, and adding one is a
reviewed change to this file (PLUGIN-01, EXT-01). Nothing here loads a module
by name or accepts an adapter from a request.

Each variant provides the same total functions:

``scope()``                  the authorization view of the policy
``parse_request(value)``     wire request -> canonical :class:`Request`
``preflight(request)``       optional read-only fact fetch
``final(request, facts)``    the one final effect, or ``None``
``reply_meta(request, r)``   additional reply fields derived from a result
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError
from .github import GitHubSpec
from .https import HTTPSpec

ServiceSpec = GitHubSpec | HTTPSpec


def parse_policy(value: Any) -> ServiceSpec:
    """Select the variant by its explicit schema number, never by shape."""
    if type(value) is not dict:
        raise SecretsError('invalid_policy')
    schema = value.get('schema')
    if type(schema) is int and schema == 1:
        return GitHubSpec.parse(value)
    if type(schema) is int and schema == 2:
        return HTTPSpec.parse(value)
    raise SecretsError('invalid_policy')


def reparse(spec: ServiceSpec) -> ServiceSpec:
    """Round-trip a spec through its canonical form.

    A spec built or edited in memory is forced back through the one parser
    before it can define a session, so every live spec is a parser output.
    """
    if not isinstance(spec, (GitHubSpec, HTTPSpec)):
        raise SecretsError('invalid_policy')
    return parse_policy(spec.to_dict())
