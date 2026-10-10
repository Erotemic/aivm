"""Pure authorization and request construction: the Rust/Lean migration seam.

No filesystem, clock reads, HTTP, randomness, cryptography, or upstream secret
is available here. Inputs are normalized by the strict boundary parsers.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .errors import SecretsError
from .kernel import Binding, Claims, State, exact_keys, integer, text
from .wire import dumps

READ_OPERATIONS = frozenset({
    'pr.view', 'pr.diff', 'pr.comments', 'pr.reviews',
    'pr.review-comments', 'pr.checks',
})
WRITE_OPERATIONS = frozenset({'pr.comment', 'pr.edit'})
OPERATIONS = READ_OPERATIONS | WRITE_OPERATIONS
SCHEMA_VERSION = 1


def repository(value: Any, *, code: str = 'invalid_request') -> str:
    value = text(value, 140, code=code)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', value):
        raise SecretsError(code)
    if value.split('/')[1] in {'.', '..'}:
        raise SecretsError(code)
    return value.lower()


def login(value: Any, *, code: str = 'invalid_request') -> str:
    value = text(value, 39, code=code)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', value):
        raise SecretsError(code)
    return value.lower()


@dataclass(frozen=True)
class Policy:
    repository: str
    pr_numbers: tuple[int, ...]
    operations: tuple[str, ...]
    author: str
    head_repository: str
    lifetime_seconds: int = 1800
    max_requests: int = 200
    max_body_bytes: int = 8192

    @classmethod
    def parse(cls, value: Any) -> Policy:
        code = 'invalid_policy'
        value = exact_keys(value, {'schema', 'repository', 'pr_numbers',
                                  'operations', 'author', 'head_repository'},
                           {'lifetime_seconds', 'max_requests', 'max_body_bytes'}, code=code)
        integer(value['schema'], SCHEMA_VERSION, SCHEMA_VERSION, code=code)
        prs, ops = value['pr_numbers'], value['operations']
        if type(prs) is not list or not 1 <= len(prs) <= 512:
            raise SecretsError(code)
        numbers = tuple(integer(n, 1, 2**31 - 1, code=code) for n in prs)
        if len(set(numbers)) != len(numbers):
            raise SecretsError(code)
        if type(ops) is not list or not 1 <= len(ops) <= len(OPERATIONS):
            raise SecretsError(code)
        if any(type(op) is not str or op not in OPERATIONS for op in ops):
            raise SecretsError(code)
        if len(set(ops)) != len(ops):
            raise SecretsError(code)
        return cls(
            repository(value['repository'], code=code), tuple(sorted(numbers)),
            tuple(sorted(ops)), login(value['author'], code=code),
            repository(value['head_repository'], code=code),
            integer(value.get('lifetime_seconds', 1800), 1, 3600, code=code),
            integer(value.get('max_requests', 200), 1, 1000, code=code),
            integer(value.get('max_body_bytes', 8192), 1, 16384, code=code),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result['schema'] = SCHEMA_VERSION
        result['pr_numbers'] = list(self.pr_numbers)
        result['operations'] = list(self.operations)
        return result

    @property
    def digest(self) -> str:
        return hashlib.sha256(dumps(self.to_dict())).hexdigest()


def is_attenuation(child: Policy, parent: Policy) -> bool:
    """Executable subset contract; no guest delegation endpoint is provided."""
    return (
        child.repository == parent.repository
        and child.author == parent.author
        and child.head_repository == parent.head_repository
        and set(child.pr_numbers) <= set(parent.pr_numbers)
        and set(child.operations) <= set(parent.operations)
        and child.lifetime_seconds <= parent.lifetime_seconds
        and child.max_requests <= parent.max_requests
        and child.max_body_bytes <= parent.max_body_bytes
    )


@dataclass(frozen=True)
class Request:
    operation: str
    repository: str
    pr: int
    page: int = 1
    body: str | None = field(default=None, repr=False)
    title: str | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, value: Any) -> Request:
        value = exact_keys(value, {'operation', 'repository', 'pr'},
                           {'page', 'body', 'title'})
        op = value['operation']
        if type(op) is not str or op not in OPERATIONS:
            raise SecretsError('invalid_request')
        page = integer(value.get('page', 1), 1, 10000)
        paged = {'pr.comments', 'pr.reviews', 'pr.review-comments', 'pr.checks'}
        if 'page' in value and op not in paged:
            raise SecretsError('invalid_request')
        body = text(value['body'], 16384) if 'body' in value else None
        title = text(value['title'], 256) if 'title' in value else None
        if op in READ_OPERATIONS and (body is not None or title is not None):
            raise SecretsError('invalid_request')
        if op == 'pr.comment' and (body is None or title is not None):
            raise SecretsError('invalid_request')
        if op == 'pr.edit' and body is None and title is None:
            raise SecretsError('invalid_request')
        return cls(op, repository(value['repository']),
                   integer(value['pr'], 1, 2**31 - 1), page, body, title)


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    media: str = 'json'
    body: dict[str, str] | None = field(default=None, repr=False)


def authorize(policy: Policy, claims: Claims, binding: Binding, request: Request,
              state: State, *, now: int, monotonic_live: bool,
              allow_writes: bool) -> State:
    """Reserve one request. All clocks and authenticated facts are explicit."""
    if not state.active:
        raise SecretsError('revoked')
    if claims.binding != binding or claims.policy_digest != policy.digest:
        raise SecretsError('wrong_binding')
    if not monotonic_live or not claims.issued_at <= now < claims.expires_at:
        raise SecretsError('expired')
    if state.used >= policy.max_requests:
        raise SecretsError('exhausted')
    if request.repository != policy.repository or request.pr not in policy.pr_numbers:
        raise SecretsError('denied')
    if request.operation not in policy.operations:
        raise SecretsError('denied')
    if request.operation in WRITE_OPERATIONS and not allow_writes:
        raise SecretsError('denied')
    if request.body is not None and len(request.body.encode('utf-8')) > policy.max_body_bytes:
        raise SecretsError('denied')
    return State(active=True, used=state.used + 1)


def metadata_route(request: Request) -> Route:
    return Route('GET', f'/repos/{request.repository}/pulls/{request.pr}')


@dataclass(frozen=True)
class PRFacts:
    number: int
    repository: str
    author: str
    head_repository: str
    head_sha: str

    @classmethod
    def parse(cls, data: Any) -> PRFacts:
        try:
            # Provider fields, including URLs, are data, not routing authority.
            sha = data['head']['sha']
            if type(sha) is not str or not re.fullmatch(r'[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', sha):
                raise ValueError('invalid sha')
            return cls(integer(data['number'], 1, 2**31 - 1),
                       repository(data['base']['repo']['full_name']),
                       login(data['user']['login']),
                       repository(data['head']['repo']['full_name']), sha.lower())
        except (KeyError, TypeError, ValueError, SecretsError):
            raise SecretsError('resource_mismatch') from None


def effect_route(policy: Policy, request: Request, facts: PRFacts) -> Route | None:
    """Require fresh provider metadata even for reads, then construct a route."""
    if (facts.number != request.pr or facts.repository != policy.repository
            or facts.author != policy.author
            or facts.head_repository != policy.head_repository):
        raise SecretsError('resource_mismatch')
    base = f'/repos/{policy.repository}'
    pr = f'{base}/pulls/{request.pr}'
    issue = f'{base}/issues/{request.pr}'
    page = f'?per_page=100&page={request.page}'
    op = request.operation
    if op == 'pr.view':
        return None
    if op == 'pr.diff':
        return Route('GET', pr, 'diff')
    if op == 'pr.comments':
        return Route('GET', issue + '/comments' + page)
    if op == 'pr.reviews':
        return Route('GET', pr + '/reviews' + page)
    if op == 'pr.review-comments':
        return Route('GET', pr + '/comments' + page)
    if op == 'pr.checks':
        return Route('GET', f'{base}/commits/{facts.head_sha}/check-runs' + page)
    if op == 'pr.comment':
        assert request.body is not None
        return Route('POST', issue + '/comments', body={'body': request.body})
    if op == 'pr.edit':
        body = {k: v for k, v in [('body', request.body), ('title', request.title)] if v is not None}
        return Route('PATCH', pr, body=body)
    raise SecretsError('denied')
