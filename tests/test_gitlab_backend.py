"""Unit tests for the independent GitLab deploy-key backend."""

from __future__ import annotations

import json
from email.message import Message
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from aivm.credentials.gitlab import (
    GitLabAuthenticationError,
    GitLabDeployKeyBackend,
    GitLabError,
    GitLabProviderRejectedError,
    GitLabTransportError,
    _SameOriginRedirectHandler,
    default_api_url,
    token_from_env,
)


class FakeResponse:
    def __init__(
        self,
        status: int,
        payload: object = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self._body = b'' if payload is None else json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> 'FakeResponse':
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[Request] = []

    def open(self, request: Request, timeout: float) -> FakeResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, FakeResponse)
        return response


def _backend(opener: FakeOpener) -> GitLabDeployKeyBackend:
    return GitLabDeployKeyBackend(
        api_url='https://gitlab.example/api/v4',
        token='secret-token',
        opener=opener,
    )


def _request_json(request: Request) -> dict[str, object]:
    assert request.data is not None
    return json.loads(request.data.decode())


def test_default_api_url() -> None:
    assert default_api_url('gitlab.com') == 'https://gitlab.com/api/v4'
    with pytest.raises(GitLabError):
        default_api_url('https://gitlab.com')


def test_check_auth_uses_private_token_header() -> None:
    opener = FakeOpener(
        [FakeResponse(200, {'id': 7, 'username': 'alice', 'name': 'Alice'})]
    )
    identity = _backend(opener).check_auth()
    assert identity.user_id == '7'
    assert identity.username == 'alice'
    request = opener.requests[0]
    assert request.full_url == 'https://gitlab.example/api/v4/user'
    assert request.get_header('Private-token') == 'secret-token'
    assert 'secret-token' not in request.full_url


def test_resolve_nested_project_path_is_url_encoded() -> None:
    opener = FakeOpener(
        [
            FakeResponse(
                200,
                {
                    'id': 42,
                    'path_with_namespace': 'group/subgroup/project',
                    'web_url': 'https://gitlab.example/group/subgroup/project',
                },
            )
        ]
    )
    project = _backend(opener).resolve_project('group/subgroup/project')
    assert project.project_id == '42'
    assert project.path_with_namespace == 'group/subgroup/project'
    assert opener.requests[0].full_url.endswith(
        '/projects/group%2Fsubgroup%2Fproject'
    )


def test_list_deploy_keys_follows_pagination() -> None:
    opener = FakeOpener(
        [
            FakeResponse(
                200,
                [
                    {
                        'id': 1,
                        'title': 'read',
                        'key': 'ssh-ed25519 AAAA',
                        'can_push': False,
                    }
                ],
                headers={
                    'Link': (
                        '<https://gitlab.example/api/v4/projects/42/'
                        'deploy_keys?per_page=100&page=2>; rel="next"'
                    )
                },
            ),
            FakeResponse(
                200,
                [
                    {
                        'id': 2,
                        'title': 'write',
                        'key': 'ssh-ed25519 BBBB',
                        'can_push': True,
                    }
                ],
            ),
        ]
    )
    keys = _backend(opener).list_deploy_keys(42)
    assert [key.key_id for key in keys] == ['1', '2']
    assert [key.read_only for key in keys] == [True, False]
    assert len(opener.requests) == 2


def test_rejects_cross_origin_pagination() -> None:
    opener = FakeOpener(
        [
            FakeResponse(
                200,
                [],
                headers={
                    'Link': '<https://attacker.example/api/v4/steal>; rel="next"'
                },
            )
        ]
    )
    with pytest.raises(GitLabError, match='pagination attempted to leave'):
        _backend(opener).list_deploy_keys(42)


def test_add_update_and_delete_deploy_key(tmp_path: Path) -> None:
    public_key = tmp_path / 'id_ed25519.pub'
    public_key.write_text('ssh-ed25519 AAAATEST aivm\n', encoding='utf-8')
    opener = FakeOpener(
        [
            FakeResponse(
                201,
                {
                    'id': 12,
                    'title': 'aivm key',
                    'key': 'ssh-ed25519 AAAATEST aivm',
                    'can_push': True,
                },
            ),
            FakeResponse(
                200,
                {
                    'id': 12,
                    'title': 'renamed',
                    'key': 'ssh-ed25519 AAAATEST aivm',
                    'can_push': False,
                },
            ),
            FakeResponse(204),
        ]
    )
    backend = _backend(opener)
    created = backend.add_deploy_key(
        42,
        public_key_path=public_key,
        title='aivm key',
        write=True,
    )
    assert created.key_id == '12'
    assert created.read_only is False
    assert _request_json(opener.requests[0]) == {
        'title': 'aivm key',
        'key': 'ssh-ed25519 AAAATEST aivm',
        'can_push': True,
    }

    updated = backend.update_deploy_key(42, 12, title='renamed', write=False)
    assert updated.title == 'renamed'
    assert updated.read_only is True
    backend.delete_deploy_key(42, 12)
    assert opener.requests[2].method == 'DELETE'


def test_get_missing_deploy_key_returns_none() -> None:
    request = Request('https://gitlab.example/api/v4/projects/42/deploy_keys/9')
    error = HTTPError(
        request.full_url,
        404,
        'Not Found',
        Message(),
        None,
    )
    error.fp = BytesIO(b'{"message":"404 Deploy Key Not Found"}')
    opener = FakeOpener([error])
    assert _backend(opener).get_deploy_key(42, 9) is None


def test_client_error_is_definitive_rejection_without_token_leak() -> None:
    request = Request('https://gitlab.example/api/v4/projects/42/deploy_keys')
    error = HTTPError(
        request.full_url,
        403,
        'Forbidden',
        Message(),
        None,
    )
    error.fp = BytesIO(b'{"message":"403 Forbidden"}')
    opener = FakeOpener([error])
    with pytest.raises(GitLabProviderRejectedError) as exc_info:
        _backend(opener).list_deploy_keys(42)
    assert exc_info.value.status == 403
    assert 'secret-token' not in str(exc_info.value)


def test_auth_and_transport_errors_are_distinct() -> None:
    auth_request = Request('https://gitlab.example/api/v4/user')
    auth_error = HTTPError(
        auth_request.full_url,
        401,
        'Unauthorized',
        Message(),
        None,
    )
    auth_error.fp = BytesIO(b'{"message":"401 Unauthorized"}')
    with pytest.raises(GitLabAuthenticationError):
        _backend(FakeOpener([auth_error])).check_auth()

    with pytest.raises(GitLabTransportError):
        _backend(FakeOpener([URLError('offline')])).check_auth()


def test_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('CUSTOM_GITLAB_TOKEN', 'token-value')
    assert token_from_env('CUSTOM_GITLAB_TOKEN') == 'token-value'
    monkeypatch.delenv('CUSTOM_GITLAB_TOKEN')
    with pytest.raises(GitLabAuthenticationError, match='CUSTOM_GITLAB_TOKEN'):
        token_from_env('CUSTOM_GITLAB_TOKEN')


def test_redirect_handler_rejects_cross_origin() -> None:
    handler = _SameOriginRedirectHandler('https://gitlab.example/api/v4')
    request = Request(
        'https://gitlab.example/api/v4/user',
        headers={'PRIVATE-TOKEN': 'secret-token'},
    )
    with pytest.raises(HTTPError, match='cross-origin'):
        handler.redirect_request(
            request,
            BytesIO(),
            302,
            'Found',
            Message(),
            'https://attacker.example/steal',
        )
