"""Host-selected OAuth2 provider profile (not agent-controlled parameters)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..errors import SecretsError
from ..host.files import read_owned
from ..primitives import codec, grammar
from .garrett.oauth_contract import _scopes


def _https_endpoint(value: Any) -> tuple[str, str]:
    if type(value) is not str or len(value) > 2048:
        raise SecretsError('invalid_policy')
    try:
        uri = urlsplit(value)
        if (uri.scheme != 'https' or not uri.hostname or
                uri.hostname != uri.hostname.lower() or
                uri.username or uri.password or uri.fragment or
                uri.port not in (None, 443) or
                not uri.path.startswith('/') or '\\' in value or
                '%' in uri.netloc or '#' in uri.path):
            raise ValueError('unsafe endpoint')
        grammar.hostname(uri.hostname)
        if uri.query or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError('query or controls')
    except (ValueError, SecretsError):
        raise SecretsError('invalid_policy') from None
    return uri.hostname, uri.path


@dataclass(frozen=True)
class OAuthProvider:
    name: str
    client_id: str
    authorization_url: str
    token_url: str
    resource_host: str
    callback_port: int
    scopes: tuple[str, ...]
    issuer_response: str = ''
    client_secret_file: str = ''
    refresh_rotation: bool = True
    fallback_ttl: int = 3600

    @classmethod
    def parse(cls, data: Any) -> 'OAuthProvider':
        fields = grammar.exact_keys(data, frozenset({
            'schema', 'name', 'client_id', 'authorization_url', 'token_url',
            'resource_host', 'callback_port', 'scopes',
        }), frozenset({
            'issuer_response', 'client_secret_file', 'refresh_rotation',
            'fallback_ttl',
        }), code='invalid_policy')
        if fields['schema'] != 1 or type(fields['schema']) is not int:
            raise SecretsError('invalid_policy')
        name = grammar.token(fields['name'], grammar.LOWER,
                             grammar.LOWER + grammar.DIGIT + '-_', 48,
                             code='invalid_policy')
        client_id = grammar.token(fields['client_id'], grammar.ALNUM,
                                  grammar.ALNUM + '-_.', 160,
                                  code='invalid_policy')
        _https_endpoint(fields['authorization_url'])
        _https_endpoint(fields['token_url'])
        host = grammar.hostname(fields['resource_host'])
        port = grammar.integer(fields['callback_port'], 1024, 65535,
                               code='invalid_policy')
        try:
            scopes = _scopes(fields['scopes'])
        except SecretsError:
            raise SecretsError('invalid_policy') from None
        if not scopes:
            raise SecretsError('invalid_policy')
        issuer = fields.get('issuer_response', '')
        if issuer:
            _https_endpoint(issuer)
        secret_file = fields.get('client_secret_file', '')
        if secret_file:
            if (type(secret_file) is not str or
                    not Path(secret_file).is_absolute() or
                    len(secret_file) > 2048):
                raise SecretsError('invalid_policy')
        rotate = fields.get('refresh_rotation', True)
        if type(rotate) is not bool or (not rotate and not secret_file):
            # Public OAuth clients must use refresh-token rotation or sender-
            # constrained refresh tokens. The latter is not supported here.
            raise SecretsError('invalid_policy')
        ttl = grammar.integer(fields.get('fallback_ttl', 3600), 1, 86400,
                              code='invalid_policy')
        return cls(name, client_id, fields['authorization_url'],
                   fields['token_url'], host, port, scopes, issuer,
                   secret_file, rotate, ttl)

    def canonical(self) -> bytes:
        return codec.dumps({
            'schema': 1, 'name': self.name, 'client_id': self.client_id,
            'authorization_url': self.authorization_url,
            'token_url': self.token_url, 'resource_host': self.resource_host,
            'callback_port': self.callback_port, 'scopes': list(self.scopes),
            'issuer_response': self.issuer_response,
            'client_secret_file': self.client_secret_file,
            'refresh_rotation': self.refresh_rotation,
            'fallback_ttl': self.fallback_ttl,
        })

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    @property
    def redirect_uri(self) -> str:
        return f'http://127.0.0.1:{self.callback_port}/oauth/callback'


def load_provider(path: Path, *, untrusted: tuple[Path, ...] = ()) -> OAuthProvider:
    return OAuthProvider.parse(codec.loads(read_owned(
        Path(path).expanduser().absolute(), private=False,
        untrusted=untrusted, what='OAuth provider configuration', limit=16384,
    ), code='invalid_policy'))


__all__ = ['OAuthProvider', 'load_provider']
