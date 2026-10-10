"""Built-in manifests: providers supported out of the box, as data.

A preset is a function from a few operator choices to an ordinary schema-2
manifest. It contains no behaviour of its own: the manifest it returns is
parsed and interpreted by exactly the code that handles a manifest an
operator wrote by hand, and ``aivm-secrets policy-check`` prints it in full.
Deleting this module would remove a convenience and nothing else.

``github_pr`` is what policy ``schema: 1`` means. It grants selected
pull-request operations on one repository, and conditions every one of them
on freshly fetched metadata: the PR's number, base repository, author and
head repository must match the policy before anything else is read or sent.
It also gives the guest client a ``gh``-shaped command table.
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError
from . import grammar
from .model import MAX_LIFETIME

GITHUB_HOST = 'api.github.com'
GITHUB_API_VERSION = '2026-03-10'
GITHUB_JSON = 'application/vnd.github+json'
GITHUB_DIFF = 'application/vnd.github.diff'
PAGE_SIZE = 100
# The operator's existing ``gh`` login. The inherited variables are the ones
# ``gh`` needs to find its configuration and the desktop keyring; no
# debugging or proxy variable is among them.
GH_SOURCE: dict[str, Any] = {
    'kind': 'command',
    'argv': ['gh', 'auth', 'token', '--hostname', 'github.com'],
    'inherit_env': [
        'DBUS_SESSION_BUS_ADDRESS',
        'GH_CONFIG_DIR',
        'XDG_CONFIG_HOME',
        'XDG_RUNTIME_DIR',
    ],
}
MAX_PAGE = 10000
MAX_TITLE = 256
_CODE = 'invalid_policy'

PR_READS = (
    'pr.view',
    'pr.diff',
    'pr.comments',
    'pr.reviews',
    'pr.review-comments',
    'pr.checks',
)
PR_WRITES = ('pr.comment', 'pr.edit')
PR_OPERATIONS = PR_READS + PR_WRITES


def repository(value: Any) -> str:
    """``owner/name`` under GitHub's ASCII grammar, folded to lowercase."""
    value = grammar.text(value, 140, code=_CODE)
    parts = value.split('/')
    if len(parts) != 2:
        raise SecretsError(_CODE)
    owner, name = parts
    grammar.token(owner, grammar.ALNUM, grammar.ALNUM + '-', 39, code=_CODE)
    grammar.token(
        name, grammar.ALNUM + '_.-', grammar.ALNUM + '_.-', 100, code=_CODE
    )
    if name in ('.', '..'):
        raise SecretsError(_CODE)
    return grammar.lowered(value)


def login(value: Any) -> str:
    grammar.token(value, grammar.ALNUM, grammar.ALNUM + '-', 39, code=_CODE)
    return grammar.lowered(value)


def _github_operations(repo: str, numbers: list[int]) -> dict[str, Any]:
    """Every PR operation of the preset, keyed by name, as manifest data."""
    base = '/repos/{repository}'
    pull = base + '/pulls/{pr}'
    issue = base + '/issues/{pr}'
    target = {'pr': numbers, 'repository': [repo]}
    paged = dict(target, page={'min': 1, 'max': MAX_PAGE})
    listing = {
        'effect': 'read',
        'method': 'GET',
        'accept': GITHUB_JSON,
        'requires': 'pull',
        'fold': ['repository'],
        'parameters': paged,
        'defaults': {'page': 1},
        'query': {'per_page': str(PAGE_SIZE), 'page': '{page}'},
        'page': {'size': PAGE_SIZE, 'parameter': 'page'},
    }
    single = {
        'requires': 'pull',
        'fold': ['repository'],
        'parameters': target,
    }
    return {
        'pr.view': dict(single, effect='read', returns='check'),
        'pr.diff': dict(
            single,
            effect='read',
            method='GET',
            path=pull,
            accept=GITHUB_DIFF,
            response='text',
        ),
        'pr.comments': dict(listing, path=issue + '/comments'),
        'pr.reviews': dict(listing, path=pull + '/reviews'),
        'pr.review-comments': dict(listing, path=pull + '/comments'),
        'pr.checks': dict(
            listing,
            path=base + '/commits/{head_sha}/check-runs',
            page={
                'size': PAGE_SIZE,
                'parameter': 'page',
                'at': ['check_runs'],
            },
        ),
        'pr.comment': dict(
            single,
            effect='write',
            method='POST',
            path=issue + '/comments',
            accept=GITHUB_JSON,
            body_fields={'body': grammar.MAX_TEXT},
        ),
        'pr.edit': dict(
            single,
            effect='write',
            method='PATCH',
            path=pull,
            accept=GITHUB_JSON,
            body_fields={
                'body': {'max_bytes': grammar.MAX_TEXT, 'optional': True},
                'title': {'max_bytes': MAX_TITLE, 'optional': True},
            },
        ),
    }


def _gh_command(name: str) -> dict[str, Any]:
    """The ``gh pr <word> NUMBER --repo OWNER/NAME`` shape for one operation."""
    options = {'--repo': 'repository', '-R': 'repository'}
    if name in ('pr.comments', 'pr.reviews', 'pr.review-comments', 'pr.checks'):
        options['--page'] = 'page'
    if name in PR_WRITES:
        options['--body'] = 'body'
        options['--body-file'] = '@body'
    if name == 'pr.edit':
        options['--title'] = 'title'
    command: dict[str, Any] = {
        'command': ['pr', name[len('pr.') :]],
        'operation': name,
        'positional': ['pr'],
        'options': options,
    }
    if name == 'pr.diff':
        command['output'] = 'result'
    return command


def github_pr(value: Any) -> dict[str, Any]:
    """Expand a ``schema: 1`` policy into the schema-2 manifest it stands for."""
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
    grammar.integer(value['schema'], 1, 1, code=_CODE)
    numbers, chosen = value['pr_numbers'], value['operations']
    if type(numbers) is not list or not 1 <= len(numbers) <= 256:
        raise SecretsError(_CODE)
    numbers = [
        grammar.integer(item, 1, grammar.MAX_INT, code=_CODE)
        for item in numbers
    ]
    if len(set(numbers)) != len(numbers):
        raise SecretsError(_CODE)
    if type(chosen) is not list or not 1 <= len(chosen) <= len(PR_OPERATIONS):
        raise SecretsError(_CODE)
    for item in chosen:
        if type(item) is not str or item not in PR_OPERATIONS:
            raise SecretsError(_CODE)
    if len(set(chosen)) != len(chosen):
        raise SecretsError(_CODE)
    repo = repository(value['repository'])
    available = _github_operations(repo, sorted(numbers))
    manifest: dict[str, Any] = {
        'schema': 2,
        'adapter': 'https',
        'service': 'github-pr',
        'host': GITHUB_HOST,
        'authentication': 'bearer',
        'headers': {'X-GitHub-Api-Version': GITHUB_API_VERSION},
        'credential_source': GH_SOURCE,
        'checks': {
            'pull': {
                'path': '/repos/{repository}/pulls/{pr}',
                'accept': GITHUB_JSON,
                'require': [
                    {'at': ['number'], 'equals_parameter': 'pr'},
                    {
                        'at': ['base', 'repo', 'full_name'],
                        'equals': repo,
                        'fold': True,
                    },
                    {
                        'at': ['user', 'login'],
                        'equals': login(value['author']),
                        'fold': True,
                    },
                    {
                        'at': ['head', 'repo', 'full_name'],
                        'equals': repository(value['head_repository']),
                        'fold': True,
                    },
                ],
                'bind': {'head_sha': {'at': ['head', 'sha'], 'format': 'hex'}},
            }
        },
        'operations': [
            dict(available[name], name=name) for name in sorted(chosen)
        ],
        'cli': {'gh': [_gh_command(name) for name in sorted(chosen)]},
        'lifetime_seconds': grammar.integer(
            value.get('lifetime_seconds', 1800), 1, MAX_LIFETIME, code=_CODE
        ),
        'max_requests': grammar.integer(
            value.get('max_requests', 200), 1, 1000, code=_CODE
        ),
        'max_body_bytes': grammar.integer(
            value.get('max_body_bytes', 8192), 1, grammar.MAX_TEXT, code=_CODE
        ),
    }
    return manifest
