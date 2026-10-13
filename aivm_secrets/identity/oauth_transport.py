"""Host-only OAuth2 PKCE exchanges with a pinned HTTPS token endpoint.

No ambient proxy, redirects, logging, cookie jar or reusable bearer client.
Browser authorization happens at a loopback HTTP callback on the *host*.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import secrets
import socket
import ssl
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..errors import SecretsError
from ..host.files import read_owned
from ..primitives import codec
from .garrett.oauth_contract import (PendingAuthorization,
                                     accept_callback, assess_token_response,
                                     AccessGrant)
from .oauth_provider import OAuthProvider

MAX_RESPONSE = 16384
MAX_FORM = 8192


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def new_pending(provider: OAuthProvider, *, now: int | None = None,
                entropy: Callable[[int], bytes] = secrets.token_bytes
                ) -> PendingAuthorization:
    stamp = int(time.time()) if now is None else now
    return PendingAuthorization.create(_b64(entropy(32)), _b64(entropy(32)),
                                       provider.redirect_uri, now=stamp)


def authorization_url(provider: OAuthProvider, pending: PendingAuthorization) -> str:
    challenge = _b64(hashlib.sha256(pending.verifier.encode('ascii')).digest())
    query = urlencode({
        'response_type': 'code', 'client_id': provider.client_id,
        'redirect_uri': pending.redirect_uri, 'scope': ' '.join(provider.scopes),
        'state': pending.state, 'code_challenge_method': 'S256',
        'code_challenge': challenge,
    })
    return provider.authorization_url + ('&' if '?' in provider.authorization_url else '?') + query


def _form_response(body: bytes, content_type: str) -> dict:
    if not 1 <= len(body) <= MAX_RESPONSE:
        raise SecretsError('credential_source')
    if content_type.lower().split(';')[0].strip() == 'application/json':
        result = codec.loads(body, limit=MAX_RESPONSE, code='credential_source')
    elif content_type.lower().split(';')[0].strip() == 'application/x-www-form-urlencoded':
        try:
            fields = parse_qsl(body.decode('ascii'), keep_blank_values=True,
                               strict_parsing=True, max_num_fields=32)
            result = dict(fields)
            if len(result) != len(fields):
                raise ValueError('duplicate')
            if 'expires_in' in result:
                result['expires_in'] = int(result['expires_in'])
        except (ValueError, UnicodeError):
            raise SecretsError('credential_source') from None
    else:
        raise SecretsError('credential_source')
    if type(result) is not dict or 'error' in result:
        raise SecretsError('credential_source')
    return result


class PinnedOAuthHTTP:
    """One pinned HTTPS origin, no redirect or user-supplied target path."""

    def __init__(self, *, ca_file: str | None = None):
        self.ca_file = ca_file

    def post(self, provider: OAuthProvider, fields: dict[str, str],
             *, untrusted: tuple = ()) -> dict:
        from .oauth_provider import _https_endpoint
        host, target = _https_endpoint(provider.token_url)
        # Fail closed if manifest declared data cannot be represented as
        # an ordinary bounded application/x-www-form-urlencoded request.
        data = urlencode(fields).encode('ascii')
        if len(data) > MAX_FORM:
            raise SecretsError('credential_source')
        # Do not call create_default_context(): it reads SSLKEYLOGFILE and may
        # create that file *before* keylog_filename can be disabled. Construct
        # a TLS client context explicitly and load only the intended roots.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if self.ca_file is None:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            context.load_verify_locations(cafile=self.ca_file)
        context.keylog_filename = None
        conn = http.client.HTTPSConnection(host, 443, timeout=10, context=context)
        try:
            conn.request('POST', target, data, {
                'Host': host, 'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cache-Control': 'no-store',
            })
            resp = conn.getresponse()
            # Redirects are not followed, including any cross-origin Location.
            if resp.status != 200:
                raise SecretsError('credential_source')
            if resp.getheader('Content-Encoding', 'identity') != 'identity':
                raise SecretsError('credential_source')
            data = resp.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise SecretsError('credential_source')
            return _form_response(data, resp.getheader('Content-Type', ''))
        except (OSError, ssl.SSLError, http.client.HTTPException):
            raise SecretsError('credential_source') from None
        finally:
            conn.close()


def _secret(provider: OAuthProvider, untrusted: tuple) -> str:
    if not provider.client_secret_file:
        return ''
    try:
        secret = read_owned(provider.client_secret_file, private=True,
                            untrusted=untrusted, limit=4096,
                            what='OAuth client secret').decode('ascii').strip()
    except UnicodeError:
        raise SecretsError('credential_source') from None
    if not secret or '\n' in secret or '\r' in secret:
        raise SecretsError('credential_source')
    return secret


def exchange_code(provider: OAuthProvider, pending: PendingAuthorization,
                  callback: dict[str, str], *, now: int,
                  transport: Any, untrusted: tuple = ()) -> AccessGrant:
    code = accept_callback(pending, callback, now=now,
                           expected_issuer=provider.issuer_response)
    form = {'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': pending.redirect_uri, 'client_id': provider.client_id,
            'code_verifier': pending.verifier}
    secret = _secret(provider, untrusted)
    if secret:
        form['client_secret'] = secret
    result = transport.post(provider, form, untrusted=untrusted)
    return assess_token_response(result, now=now,
                                 allowed_scopes=provider.scopes,
                                 fallback_ttl=provider.fallback_ttl)


def refresh_token(provider: OAuthProvider, previous: AccessGrant,
                  *, now: int, transport: Any, untrusted: tuple = ()) -> AccessGrant:
    if previous.refresh_token is None:
        raise SecretsError('expired')
    form = {'grant_type': 'refresh_token', 'refresh_token': previous.refresh_token,
            'client_id': provider.client_id}
    secret = _secret(provider, untrusted)
    if secret:
        form['client_secret'] = secret
    result = transport.post(provider, form, untrusted=untrusted)
    return assess_token_response(result, now=now,
                                 allowed_scopes=provider.scopes,
                                 previous=previous, fallback_ttl=provider.fallback_ttl,
                                 require_rotation=provider.refresh_rotation)


class HostCallback:
    """One-shot host loopback callback. Never serves credential bytes."""

    def __init__(self, provider: OAuthProvider, pending: PendingAuthorization):
        self.provider = provider
        self.pending = pending
        self.parameters: dict[str, str] | None = None
        outer = self

        class Server(HTTPServer):
            allow_reuse_address = False

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Never log auth code or state from a browser URL.

            def do_GET(self):
                # Only one callback may be consumed. Never accept a relative
                # redirect, duplicate parameter, fragment, or hostile Host.
                status = 400
                try:
                    if self.headers.get('Host') != f'127.0.0.1:{provider.callback_port}':
                        raise ValueError('host')
                    target = urlsplit(self.path)
                    if target.path != '/oauth/callback' or target.fragment:
                        raise ValueError('path')
                    pairs = parse_qsl(target.query, keep_blank_values=True,
                                      strict_parsing=True, max_num_fields=4)
                    fields = dict(pairs)
                    if len(fields) != len(pairs) or outer.parameters is not None:
                        raise ValueError('duplicate or replay')
                    accept_callback(pending, fields, now=int(time.time()),
                                    expected_issuer=provider.issuer_response)
                    outer.parameters = fields
                    status = 200
                except (ValueError, SecretsError, UnicodeError):
                    pass
                content = (b'Authorization received. You may close this tab.'
                           if status == 200 else b'Authorization rejected.')
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        self._httpd = Server(('127.0.0.1', provider.callback_port), Handler)
        self._httpd.timeout = 0.5

    def __enter__(self):
        return self

    def wait(self, *, timeout: float = 180) -> dict[str, str]:
        deadline = min(time.monotonic() + timeout,
                       time.monotonic() + max(0, self.pending.expires_at - int(time.time())))
        while time.monotonic() < deadline:
            self._httpd.handle_request()
            if self.parameters is not None:
                return self.parameters
        raise SecretsError('expired')

    def __exit__(self, exc_type, exc, tb):
        self._httpd.server_close()


__all__ = ['HostCallback', 'PinnedOAuthHTTP', 'new_pending',
           'authorization_url', 'exchange_code', 'refresh_token']
