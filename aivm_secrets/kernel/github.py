"""GitHub pull-request service: policy schema 1.

The original integration, kept as a closed service spec beside the
declarative one. It exists as code rather than as a manifest for one reason:
every operation is conditioned on *fresh provider facts*. Before any read or
write, the selected pull request is fetched and its number, base repository,
author and head repository must match the grant. That fact check is the
second denial class of AUTH-01: it happens after one authorized metadata
read and must prevent every later effect.

No GitHub semantics exist outside this module. The kernel sees only the
scope and the effects it returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import SecretsError
from . import codec, grammar
from .model import MAX_LIFETIME, Effect, Egress, Request, parse_arguments
from .scope import FieldSpec, IntRange, IntSet, OperationScope, Scope, StrSet
from .source import GH_SOURCE

SCHEMA = 1
HOST = 'api.github.com'
API_VERSION = '2026-03-10'
JSON_MEDIA = 'application/vnd.github+json'
DIFF_MEDIA = 'application/vnd.github.diff'

READ_OPERATIONS = (
    'pr.view',
    'pr.diff',
    'pr.comments',
    'pr.reviews',
    'pr.review-comments',
    'pr.checks',
)
WRITE_OPERATIONS = ('pr.comment', 'pr.edit')
OPERATIONS = READ_OPERATIONS + WRITE_OPERATIONS
PAGED = ('pr.comments', 'pr.reviews', 'pr.review-comments', 'pr.checks')
PAGE_SIZE = 100
MAX_PAGE = 10000
MAX_TITLE = 256
_CODE = 'invalid_policy'


def repository(value: Any, *, code: str = 'invalid_request') -> str:
    """``owner/name`` under GitHub's ASCII grammar, folded to lowercase."""
    value = grammar.text(value, 140, code=code)
    parts = value.split('/')
    if len(parts) != 2:
        raise SecretsError(code)
    owner, name = parts
    grammar.token(owner, grammar.ALNUM, grammar.ALNUM + '-', 39, code=code)
    grammar.token(
        name, grammar.ALNUM + '_.-', grammar.ALNUM + '_.-', 100, code=code
    )
    if name in ('.', '..'):
        raise SecretsError(code)
    return grammar.lowered(value)


def login(value: Any, *, code: str = 'invalid_request') -> str:
    grammar.token(value, grammar.ALNUM, grammar.ALNUM + '-', 39, code=code)
    return grammar.lowered(value)


@dataclass(frozen=True)
class PRFacts:
    """The provider facts a grant is conditioned on. URLs are never routes."""

    number: int
    repository: str
    author: str
    head_repository: str
    head_sha: str

    @classmethod
    def parse(cls, data: Any) -> PRFacts:
        try:
            sha = data['head']['sha']
            if type(sha) is not str or len(sha) not in (40, 64):
                raise ValueError('invalid sha')
            sha = grammar.lowered(sha)
            grammar.hex_string(sha, len(sha))
            return cls(
                grammar.integer(data['number'], 1, grammar.MAX_INT),
                repository(data['base']['repo']['full_name']),
                login(data['user']['login']),
                repository(data['head']['repo']['full_name']),
                sha,
            )
        except (KeyError, TypeError, ValueError, SecretsError):
            raise SecretsError('resource_mismatch') from None


@dataclass(frozen=True)
class GitHubSpec:
    repository: str
    pr_numbers: tuple[int, ...]
    operations: tuple[str, ...]
    author: str
    head_repository: str
    lifetime_seconds: int = 1800
    max_requests: int = 200
    max_body_bytes: int = 8192

    @classmethod
    def parse(cls, value: Any) -> GitHubSpec:
        value = grammar.exact_keys(
            value,
            frozenset(
                {
                    'schema',
                    'repository',
                    'pr_numbers',
                    'operations',
                    'author',
                    'head_repository',
                }
            ),
            frozenset({'lifetime_seconds', 'max_requests', 'max_body_bytes'}),
            code=_CODE,
        )
        grammar.integer(value['schema'], SCHEMA, SCHEMA, code=_CODE)
        numbers, operations = value['pr_numbers'], value['operations']
        if type(numbers) is not list or not 1 <= len(numbers) <= 512:
            raise SecretsError(_CODE)
        numbers = tuple(
            grammar.integer(item, 1, grammar.MAX_INT, code=_CODE)
            for item in numbers
        )
        if len(set(numbers)) != len(numbers):
            raise SecretsError(_CODE)
        if type(operations) is not list:
            raise SecretsError(_CODE)
        if not 1 <= len(operations) <= len(OPERATIONS):
            raise SecretsError(_CODE)
        for item in operations:
            if type(item) is not str or item not in OPERATIONS:
                raise SecretsError(_CODE)
        if len(set(operations)) != len(operations):
            raise SecretsError(_CODE)
        return cls(
            repository(value['repository'], code=_CODE),
            tuple(sorted(numbers)),
            tuple(sorted(operations)),
            login(value['author'], code=_CODE),
            repository(value['head_repository'], code=_CODE),
            grammar.integer(
                value.get('lifetime_seconds', 1800), 1, MAX_LIFETIME, code=_CODE
            ),
            grammar.integer(
                value.get('max_requests', 200), 1, 1000, code=_CODE
            ),
            grammar.integer(
                value.get('max_body_bytes', 8192),
                1,
                grammar.MAX_TEXT,
                code=_CODE,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema': SCHEMA,
            'repository': self.repository,
            'pr_numbers': list(self.pr_numbers),
            'operations': list(self.operations),
            'author': self.author,
            'head_repository': self.head_repository,
            'lifetime_seconds': self.lifetime_seconds,
            'max_requests': self.max_requests,
            'max_body_bytes': self.max_body_bytes,
        }

    @property
    def digest(self) -> str:
        return codec.digest(self.to_dict())

    @property
    def service(self) -> str:
        return self.repository

    @property
    def client_aliases(self) -> tuple[str, ...]:
        """Extra names the guest client is installed under: a gh-shaped one."""
        return ('gh',)

    @property
    def egress(self) -> Egress:
        return Egress(HOST, headers=(('X-GitHub-Api-Version', API_VERSION),))

    @property
    def credential_source(self) -> dict[str, Any]:
        return GH_SOURCE

    def scope(self) -> Scope:
        result = []
        for name in self.operations:
            parameters: list[tuple[str, Any]] = [
                ('pr', IntSet(self.pr_numbers)),
                ('repository', StrSet((self.repository,))),
            ]
            if name in PAGED:
                parameters.insert(0, ('page', IntRange(1, MAX_PAGE)))
            fields: tuple[FieldSpec, ...] = ()
            if name == 'pr.comment':
                fields = (FieldSpec('body', grammar.MAX_TEXT),)
            elif name == 'pr.edit':
                fields = (
                    FieldSpec('body', grammar.MAX_TEXT, required=False),
                    FieldSpec('title', MAX_TITLE, required=False),
                )
            result.append(
                OperationScope(
                    name, name in WRITE_OPERATIONS, tuple(parameters), fields
                )
            )
        return tuple(result)

    def parse_request(self, value: Any) -> Request:
        """Accept the generic shape or the original flat version-1 shape.

        Both normalize to one canonical request: the repository is folded to
        lowercase and a paged operation always carries an explicit page, so
        equal requests have equal digests.
        """
        if type(value) is dict and 'arguments' in value:
            request = Request.parse(value)
            name, given = request.operation, dict(request.arguments)
        else:
            value = grammar.exact_keys(
                value,
                frozenset({'operation', 'repository', 'pr'}),
                frozenset({'page', 'body', 'title'}),
            )
            name = value['operation']
            given = dict(
                parse_arguments(
                    {
                        key: item
                        for key, item in value.items()
                        if key != 'operation'
                    }
                )
            )
        if type(name) is not str or name not in OPERATIONS:
            raise SecretsError('invalid_request')
        if 'repository' in given:
            given['repository'] = repository(given['repository'])
        if name in PAGED:
            given.setdefault('page', 1)
        return Request(name, tuple(sorted(given.items())))

    def preflight(self, request: Request) -> Effect | None:
        return Effect(
            'GET',
            f'/repos/{self.repository}/pulls/{request.get("pr")}',
            accept=JSON_MEDIA,
        )

    def final(self, request: Request, facts: Any) -> Effect | None:
        """Check fresh provider facts, then construct the one final effect.

        ``None`` means the validated metadata is itself the answer.
        """
        known = PRFacts.parse(facts)
        if (
            known.number != request.get('pr')
            or known.repository != self.repository
            or known.author != self.author
            or known.head_repository != self.head_repository
        ):
            raise SecretsError('resource_mismatch')
        base = f'/repos/{self.repository}'
        pull = f'{base}/pulls/{known.number}'
        issue = f'{base}/issues/{known.number}'
        page = (
            ('per_page', str(PAGE_SIZE)),
            ('page', str(request.get('page'))),
        )
        name = request.operation
        if name == 'pr.view':
            return None
        if name == 'pr.diff':
            return Effect('GET', pull, accept=DIFF_MEDIA, response='text')
        if name == 'pr.comments':
            return Effect('GET', issue + '/comments', page, JSON_MEDIA)
        if name == 'pr.reviews':
            return Effect('GET', pull + '/reviews', page, JSON_MEDIA)
        if name == 'pr.review-comments':
            return Effect('GET', pull + '/comments', page, JSON_MEDIA)
        if name == 'pr.checks':
            return Effect(
                'GET',
                f'{base}/commits/{known.head_sha}/check-runs',
                page,
                JSON_MEDIA,
            )
        body = tuple(
            (key, str(item))
            for key, item in request.arguments
            if key in ('body', 'title')
        )
        if name == 'pr.comment':
            return Effect(
                'POST', issue + '/comments', accept=JSON_MEDIA, body=body
            )
        if name == 'pr.edit':
            return Effect('PATCH', pull, accept=JSON_MEDIA, body=body)
        raise SecretsError('denied')

    def reply_meta(
        self, request: Request, result: Any
    ) -> dict[str, Any] | None:
        """Make truncation explicit: one page is never implied to be all."""
        if request.operation not in PAGED:
            return None
        rows = result
        if request.operation == 'pr.checks':
            rows = result.get('check_runs') if type(result) is dict else None
        if type(rows) is not list or len(rows) > PAGE_SIZE:
            raise SecretsError('upstream_response')
        return {
            'pagination': {
                'page': request.get('page'),
                'per_page': PAGE_SIZE,
                'possibly_more': len(rows) == PAGE_SIZE,
            }
        }
