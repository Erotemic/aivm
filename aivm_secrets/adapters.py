"""Explicitly selected, host-trusted service adapters.

A credential source, service protocol and guest CLI syntax are independent.
External code adapters may be added in the future through an operator-approved
registry; guest-specified Python imports or executables must never be accepted.
"""

from __future__ import annotations

from typing import Any

from .core import (Policy as GitHubPolicy, PRFacts, Request, READ_OPERATIONS,
                   effect_route, metadata_route)
from .errors import SecretsError
from .http_service import HTTPAdapter, HTTPPolicy, HTTPSProvider
from .provider import GitHubProvider


class GitHubAdapter:
    """Legacy optional integration. No GitHub semantics live in the broker."""

    def __init__(self, policy: GitHubPolicy):
        self.policy = policy

    def parse(self, raw: Any) -> Request:
        return Request.parse(raw)

    def check_scope(self, request: Request) -> None:
        if request.repository != self.policy.repository or request.pr not in self.policy.pr_numbers:
            raise SecretsError('denied')

    def is_write(self, request: Request) -> bool:
        return request.operation not in READ_OPERATIONS

    def body_bytes(self, request: Request) -> int:
        return len(request.body.encode('utf-8')) if request.body is not None else 0

    def preflight(self, request: Request):
        return metadata_route(request)

    def effect(self, request: Request, facts: Any):
        return effect_route(self.policy, request, PRFacts.parse(facts))

    def pagination(self, request: Request, result: Any) -> dict[str, Any] | None:
        if request.operation in {'pr.comments', 'pr.reviews', 'pr.review-comments'}:
            if type(result) is not list or len(result) > 100:
                raise SecretsError('upstream_response')
            return {'page': request.page, 'per_page': 100, 'possibly_more': len(result) == 100}
        if request.operation == 'pr.checks':
            if (type(result) is not dict or type(result.get('check_runs')) is not list
                    or len(result['check_runs']) > 100):
                raise SecretsError('upstream_response')
            return {'page': request.page, 'per_page': 100,
                    'possibly_more': len(result['check_runs']) == 100}
        return None


def parse_policy(value: Any) -> GitHubPolicy | HTTPPolicy:
    if type(value) is not dict:
        raise SecretsError('invalid_policy')
    if value.get('schema') == 1:
        return GitHubPolicy.parse(value)
    if value.get('schema') == 2:
        return HTTPPolicy.parse(value)
    raise SecretsError('invalid_policy')


def build_adapter(policy: GitHubPolicy | HTTPPolicy, provider: Any = None):
    if isinstance(policy, HTTPPolicy):
        return HTTPAdapter(policy), provider if provider is not None else HTTPSProvider(policy)
    if isinstance(policy, GitHubPolicy):
        return GitHubAdapter(policy), provider if provider is not None else GitHubProvider()
    raise SecretsError('invalid_policy')
