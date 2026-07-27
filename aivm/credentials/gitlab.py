"""GitLab deploy-key backend implemented with the v4 REST API."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from email.message import Message
from http.client import HTTPMessage
from pathlib import Path
from types import TracebackType
from typing import IO, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..errors import AIVMError
from .models import ProviderDeployKey

_DEFAULT_TOKEN_ENV = 'GITLAB_TOKEN'
_DEFAULT_TIMEOUT = 30.0


class GitLabError(AIVMError):
    """Base class for GitLab provider failures."""


class GitLabAuthenticationError(GitLabError):
    """The configured token is missing, invalid, or unauthorized."""


class GitLabProviderRejectedError(GitLabError):
    """GitLab definitively rejected a request with a client error."""

    def __init__(self, message: str, *, status: int) -> None:
        self.status = status
        super().__init__(message)


class GitLabTransportError(GitLabError):
    """The outcome of a GitLab request is unknown due to transport failure."""


@dataclass(frozen=True)
class GitLabIdentity:
    """Authenticated GitLab user returned by ``GET /user``."""

    user_id: str
    username: str
    name: str


@dataclass(frozen=True)
class GitLabProject:
    """Resolved GitLab project identity, including nested namespaces."""

    project_id: str
    path_with_namespace: str
    web_url: str = ''

    @property
    def display(self) -> str:
        return self.path_with_namespace


@dataclass(frozen=True)
class _HTTPResponse:
    status: int
    headers: Message
    body: bytes


class _ResponseLike(Protocol):
    status: int
    headers: Message

    def read(self) -> bytes: ...

    def __enter__(self) -> '_ResponseLike': ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...


class _OpenerLike(Protocol):
    def open(self, request: Request, timeout: float) -> _ResponseLike: ...


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from forwarding the private token to another origin."""

    def __init__(self, api_url: str) -> None:
        super().__init__()
        parsed = urlparse(api_url)
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())

    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        parsed = urlparse(newurl)
        origin = (parsed.scheme.lower(), parsed.netloc.lower())
        if origin != self._origin:
            raise HTTPError(
                newurl,
                code,
                'Refusing a cross-origin GitLab API redirect',
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_api_url(host: str) -> str:
    """Return the conventional GitLab v4 API endpoint for a hostname."""
    clean = str(host or '').strip().strip('/')
    if not clean or '://' in clean or '/' in clean:
        raise GitLabError(f'Invalid GitLab hostname: {host!r}')
    return f'https://{clean}/api/v4'


def host_token_envvar(host: str, *, envvar: str = _DEFAULT_TOKEN_ENV) -> str:
    """Return the host-scoped spelling of a token variable.

    ``gitlab.example.com`` becomes ``GITLAB_TOKEN_GITLAB_EXAMPLE_COM``.
    """
    suffix = ''.join(
        char if char.isalnum() else '_' for char in str(host or '')
    ).upper()
    return f'{envvar}_{suffix}' if suffix else envvar


def token_from_env(
    host: str = '',
    *,
    envvar: str = _DEFAULT_TOKEN_ENV,
) -> str:
    """Read a GitLab API token without ever rendering it in an error.

    A host-scoped variable wins over the generic one. Tokens are per-instance
    -- a gitlab.com token is meaningless to a self-managed server and handing
    it over leaks it -- so anyone dealing with more than one instance needs a
    way to say which token belongs to which host.
    """
    scoped = host_token_envvar(host, envvar=envvar) if host else ''
    for name in (scoped, envvar):
        if not name:
            continue
        token = os.environ.get(name, '').strip()
        if token:
            return token
    wanted = f'{scoped} or {envvar}' if scoped and scoped != envvar else envvar
    raise GitLabAuthenticationError(
        f'GitLab API token is missing. Set {wanted} on the AIVM host.'
    )


def _project_selector(project: GitLabProject | str | int) -> str:
    if isinstance(project, GitLabProject):
        value = project.project_id
    else:
        value = str(project).strip()
    if not value:
        raise GitLabError('GitLab project selector is empty.')
    return quote(value, safe='')


def _json_object(raw: object, *, label: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise GitLabError(f'GitLab returned an unexpected response while {label}.')
    return cast(dict[str, object], raw)


def _json_list(raw: object, *, label: str) -> list[object]:
    if not isinstance(raw, list):
        raise GitLabError(f'GitLab returned an unexpected response while {label}.')
    return cast(list[object], raw)


def _parse_deploy_key(raw: object) -> ProviderDeployKey:
    item = _json_object(raw, label='reading deploy-key metadata')
    return ProviderDeployKey(
        key_id=str(item.get('id', '')).strip(),
        key=str(item.get('key', '')).strip(),
        title=str(item.get('title', '')).strip(),
        read_only=not bool(item.get('can_push', False)),
    )


def _error_message(body: bytes, *, fallback: str) -> str:
    """Extract GitLab's reason without exposing request headers or tokens."""
    text = body.decode('utf-8', errors='replace').strip()
    if not text:
        return fallback
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return ' '.join(text.split())[:500]
    if isinstance(raw, dict):
        message = raw.get('message', raw.get('error', fallback))
        if isinstance(message, dict):
            parts: list[str] = []
            for key, value in message.items():
                if isinstance(value, list):
                    detail = ', '.join(str(item) for item in value)
                else:
                    detail = str(value)
                parts.append(f'{key}: {detail}')
            return '; '.join(parts)[:500] or fallback
        if isinstance(message, list):
            return ', '.join(str(item) for item in message)[:500]
        return str(message)[:500]
    return fallback


class GitLabDeployKeyBackend:
    """Small token-authenticated GitLab deploy-key REST client.

    The caller owns token acquisition and storage. This backend keeps the token
    only in memory and sends it in GitLab's recommended ``PRIVATE-TOKEN``
    header. No token is placed in URLs, subprocess arguments, or error text.
    """

    def __init__(
        self,
        *,
        api_url: str,
        token: str,
        timeout: float = _DEFAULT_TIMEOUT,
        opener: _OpenerLike | None = None,
    ) -> None:
        clean_api_url = str(api_url or '').strip().rstrip('/')
        parsed = urlparse(clean_api_url)
        if (
            parsed.scheme not in {'https', 'http'}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise GitLabError(f'Invalid GitLab API URL: {api_url!r}')
        clean_token = str(token or '').strip()
        if not clean_token:
            raise GitLabAuthenticationError('GitLab API token is empty.')
        self.api_url = clean_api_url
        self.token = clean_token
        self.timeout = float(timeout)
        self._opener = opener or cast(
            _OpenerLike,
            build_opener(_SameOriginRedirectHandler(clean_api_url)),
        )

    @classmethod
    def for_host(
        cls,
        host: str,
        *,
        token: str,
        timeout: float = _DEFAULT_TIMEOUT,
        opener: _OpenerLike | None = None,
    ) -> 'GitLabDeployKeyBackend':
        return cls(
            api_url=default_api_url(host),
            token=token,
            timeout=timeout,
            opener=opener,
        )

    @classmethod
    def from_env(
        cls,
        host: str = 'gitlab.com',
        *,
        envvar: str = _DEFAULT_TOKEN_ENV,
        api_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        opener: _OpenerLike | None = None,
    ) -> 'GitLabDeployKeyBackend':
        return cls(
            api_url=api_url or default_api_url(host),
            token=token_from_env(host, envvar=envvar),
            timeout=timeout,
            opener=opener,
        )

    def _url(
        self,
        path: str,
        *,
        query: Mapping[str, str | int | bool] | None = None,
    ) -> str:
        url = self.api_url + '/' + path.lstrip('/')
        if query:
            url += '?' + urlencode(query)
        return url

    def _same_api_origin(self, url: str) -> bool:
        base = urlparse(self.api_url)
        candidate = urlparse(url)
        return (
            candidate.scheme.lower() == base.scheme.lower()
            and candidate.netloc.lower() == base.netloc.lower()
            and candidate.path.startswith(base.path.rstrip('/') + '/')
        )

    def _request_url(
        self,
        method: str,
        url: str,
        *,
        payload: Mapping[str, object] | None = None,
        expected: Collection[int],
    ) -> _HTTPResponse:
        if not self._same_api_origin(url):
            raise GitLabError(
                'Refusing to send the GitLab token to a URL outside the '
                f'configured API endpoint: {url}'
            )
        data = None
        headers = {
            'Accept': 'application/json',
            'PRIVATE-TOKEN': self.token,
            'User-Agent': 'aivm-gitlab-deploy-key-backend',
        }
        if payload is not None:
            data = json.dumps(dict(payload)).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read()
                result = _HTTPResponse(
                    status=int(response.status),
                    headers=response.headers,
                    body=body,
                )
        except HTTPError as ex:
            body = ex.read()
            reason = _error_message(body, fallback=str(ex.reason or 'request failed'))
            message = f'GitLab request failed: {reason} (HTTP {ex.code})'
            if ex.code == 401:
                raise GitLabAuthenticationError(message) from ex
            if 400 <= ex.code < 500:
                raise GitLabProviderRejectedError(message, status=ex.code) from ex
            raise GitLabTransportError(message) from ex
        except (URLError, TimeoutError, socket.timeout, OSError) as ex:
            raise GitLabTransportError(
                f'GitLab request did not complete: {ex}'
            ) from ex
        if result.status not in expected:
            reason = _error_message(
                result.body,
                fallback='unexpected response status',
            )
            raise GitLabError(
                f'GitLab request failed: {reason} (HTTP {result.status})'
            )
        return result

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, object] | None = None,
        query: Mapping[str, str | int | bool] | None = None,
        expected: Collection[int] = (200,),
    ) -> tuple[object, Message]:
        result = self._request_url(
            method,
            self._url(path, query=query),
            payload=payload,
            expected=expected,
        )
        if not result.body:
            return None, result.headers
        try:
            return json.loads(result.body.decode('utf-8')), result.headers
        except (UnicodeDecodeError, json.JSONDecodeError) as ex:
            raise GitLabError('GitLab returned invalid JSON.') from ex

    def check_auth(self) -> GitLabIdentity:
        raw, _ = self._request_json('GET', 'user')
        item = _json_object(raw, label='checking authentication')
        return GitLabIdentity(
            user_id=str(item.get('id', '')).strip(),
            username=str(item.get('username', '')).strip(),
            name=str(item.get('name', '')).strip(),
        )

    def resolve_project(self, project: str | int) -> GitLabProject:
        selector = _project_selector(project)
        raw, _ = self._request_json('GET', f'projects/{selector}')
        item = _json_object(raw, label='resolving a project')
        path = str(item.get('path_with_namespace', '')).strip()
        project_id = str(item.get('id', '')).strip()
        if not path or not project_id:
            raise GitLabError('GitLab project response omitted its identity.')
        return GitLabProject(
            project_id=project_id,
            path_with_namespace=path,
            web_url=str(item.get('web_url', '')).strip(),
        )

    def list_deploy_keys(
        self,
        project: GitLabProject | str | int,
    ) -> list[ProviderDeployKey]:
        selector = _project_selector(project)
        url = self._url(
            f'projects/{selector}/deploy_keys',
            query={'per_page': 100},
        )
        items: list[object] = []
        visited: set[str] = set()
        while url:
            if url in visited:
                raise GitLabError('GitLab pagination repeated a page URL.')
            visited.add(url)
            result = self._request_url('GET', url, expected={200})
            try:
                page = json.loads(result.body.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError) as ex:
                raise GitLabError('GitLab returned invalid deploy-key JSON.') from ex
            items.extend(_json_list(page, label='listing deploy keys'))
            url = self._next_page_url(result.headers, current_url=url)
        return [_parse_deploy_key(item) for item in items]

    def _next_page_url(self, headers: Message, *, current_url: str) -> str:
        link = headers.get('Link', '')
        for part in link.split(','):
            segment = part.strip()
            if 'rel="next"' not in segment and 'rel=next' not in segment:
                continue
            if not segment.startswith('<') or '>' not in segment:
                continue
            candidate = segment[1 : segment.index('>')]
            candidate = urljoin(current_url, candidate)
            if not self._same_api_origin(candidate):
                raise GitLabError(
                    'GitLab pagination attempted to leave the configured API '
                    'endpoint.'
                )
            return candidate
        next_page = headers.get('X-Next-Page', '').strip()
        if not next_page:
            return ''
        parsed = urlparse(current_url)
        query_items = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query_items['page'] = next_page
        return parsed._replace(query=urlencode(query_items)).geturl()

    def get_deploy_key(
        self,
        project: GitLabProject | str | int,
        key_id: str | int,
    ) -> ProviderDeployKey | None:
        selector = _project_selector(project)
        key_text = quote(str(key_id).strip(), safe='')
        path = f'projects/{selector}/deploy_keys/{key_text}'
        try:
            raw, _ = self._request_json('GET', path)
        except GitLabProviderRejectedError as ex:
            if ex.status == 404:
                return None
            raise
        return _parse_deploy_key(raw)

    def add_deploy_key(
        self,
        project: GitLabProject | str | int,
        *,
        public_key_path: Path,
        title: str,
        write: bool,
        expires_at: str | None = None,
    ) -> ProviderDeployKey:
        selector = _project_selector(project)
        public_key = public_key_path.read_text(encoding='utf-8').strip()
        payload: dict[str, object] = {
            'title': str(title),
            'key': public_key,
            'can_push': bool(write),
        }
        if expires_at:
            payload['expires_at'] = expires_at
        raw, _ = self._request_json(
            'POST',
            f'projects/{selector}/deploy_keys',
            payload=payload,
            expected={201},
        )
        return _parse_deploy_key(raw)

    def update_deploy_key(
        self,
        project: GitLabProject | str | int,
        key_id: str | int,
        *,
        title: str | None = None,
        write: bool | None = None,
    ) -> ProviderDeployKey:
        payload: dict[str, object] = {}
        if title is not None:
            payload['title'] = title
        if write is not None:
            payload['can_push'] = bool(write)
        if not payload:
            raise GitLabError('Deploy-key update has no requested changes.')
        selector = _project_selector(project)
        key_text = quote(str(key_id).strip(), safe='')
        raw, _ = self._request_json(
            'PUT',
            f'projects/{selector}/deploy_keys/{key_text}',
            payload=payload,
        )
        return _parse_deploy_key(raw)

    def delete_deploy_key(
        self,
        project: GitLabProject | str | int,
        key_id: str | int,
    ) -> None:
        selector = _project_selector(project)
        key_text = quote(str(key_id).strip(), safe='')
        self._request_json(
            'DELETE',
            f'projects/{selector}/deploy_keys/{key_text}',
            expected={204},
        )
