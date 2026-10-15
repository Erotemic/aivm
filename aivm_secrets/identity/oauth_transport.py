"""Host-only OAuth2 PKCE exchanges with a pinned HTTPS token endpoint.

No ambient proxy, redirects, logging, cookie jar, trust-store environment or
reusable bearer client. Browser authorization happens at a loopback HTTP
callback on the *host*.

A failed token request is ``credential_source`` with a fixed reason that says
what is known about the request it made, as decided by the pure
:func:`~.garrett.oauth_contract.classify_refresh_failure`:

``refresh_not_sent``   the connection or TLS handshake failed; nothing was sent
``refresh_rejected``   the server answered 400 ``invalid_grant``
``refresh_in_doubt``   anything else: the token may already have been rotated

An authorization-code exchange reports the same three outcomes as
``exchange_not_sent`` / ``exchange_rejected`` / ``exchange_in_doubt``; a 200
reply the contract refuses is ``*_in_doubt`` too, since the provider answered
and so received the request. Whether bytes were sent is judged
conservatively: once the handshake has completed, every failure counts as
sent. A refresh whose grant is already at the last generation is refused with
``exhausted`` (``refresh_exhausted``) before anything is sent, because no
reply to it could be accepted.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import os
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..errors import SecretsError
from ..host.files import Roots, read_owned
from ..primitives import codec, grammar
from .garrett.oauth_contract import (
    AUTHORIZATION_DENIED,
    MAX_GENERATION,
    AccessGrant,
    PendingAuthorization,
    accept_callback,
    assess_token_response,
    callback_outcome,
    classify_refresh_failure,
)
from .oauth_provider import OAuthProvider

MAX_RESPONSE = 16384
MAX_FORM = 8192
MAX_CA_BYTES = 1024 * 1024
MAX_ERROR_TOKEN = 64
TOKEN_TIMEOUT = 10
# Every read or write on a callback connection, and the whole of one request.
CALLBACK_SECONDS = 5

REFRESH_NOT_SENT = 'refresh_not_sent'
REFRESH_REJECTED = 'refresh_rejected'
REFRESH_IN_DOUBT = 'refresh_in_doubt'
REFRESH_EXHAUSTED = 'refresh_exhausted'
EXCHANGE_IN_DOUBT = 'exchange_in_doubt'
CALLBACK_PORT_UNAVAILABLE = 'callback_port_unavailable'
_GRANT_REASON = {'refresh_token': 'refresh', 'authorization_code': 'exchange'}
_OUTCOME_REASON = {'not_sent': 'not_sent', 'rejected_grant': 'rejected',
                   'in_doubt': 'in_doubt'}


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def new_pending(provider: OAuthProvider, *, now: int | None = None,
                ttl: int = 180,
                entropy: Callable[[int], bytes] = secrets.token_bytes
                ) -> PendingAuthorization:
    """A fresh state and PKCE verifier valid for ``ttl`` (1..600) seconds."""
    stamp = int(time.time()) if now is None else now
    return PendingAuthorization.create(_b64(entropy(32)), _b64(entropy(32)),
                                       provider.redirect_uri, now=stamp, ttl=ttl)


def authorization_url(provider: OAuthProvider, pending: PendingAuthorization) -> str:
    challenge = _b64(hashlib.sha256(pending.verifier.encode('ascii')).digest())
    query = urlencode({
        'response_type': 'code', 'client_id': provider.client_id,
        'redirect_uri': pending.redirect_uri, 'scope': ' '.join(provider.scopes),
        'state': pending.state, 'code_challenge_method': 'S256',
        'code_challenge': challenge,
    })
    return provider.authorization_url + ('&' if '?' in provider.authorization_url else '?') + query


def failure_reason(grant_type: str, outcome: str) -> str:
    """The fixed reason for a failed token request of ``grant_type``."""
    return _GRANT_REASON.get(grant_type, 'token') + '_' + _OUTCOME_REASON[outcome]


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


def _error_token(response: Any) -> str:
    """The RFC 6749 5.2 ``error`` code of a 400 reply, or ``''``.

    Only this one bounded token is read, to tell a definite ``invalid_grant``
    from everything else. ``error_description`` and ``error_uri`` are
    provider text and are never used. Anything unusual reads as ``''``, which
    classifies as in doubt.
    """
    try:
        if response.getheader('Content-Encoding', 'identity') != 'identity':
            return ''
        kind = response.getheader('Content-Type', '').lower().split(';')[0].strip()
        if kind != 'application/json':
            return ''
        body = response.read(MAX_RESPONSE + 1)
        if not 1 <= len(body) <= MAX_RESPONSE:
            return ''
        value = codec.loads(body, limit=MAX_RESPONSE, code='credential_source')
    except (OSError, ValueError, http.client.HTTPException, SecretsError):
        return ''
    error = value.get('error') if type(value) is dict else None
    if (type(error) is not str or not 1 <= len(error) <= MAX_ERROR_TOKEN or
            not grammar.within(error, grammar.LOWER + grammar.DIGIT + '_')):
        return ''
    return error


def _system_anchors(context: ssl.SSLContext) -> None:
    """Trust the roots compiled into OpenSSL, whatever the environment says.

    ``load_default_certs`` lets ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` replace
    the trust store, and this client runs in the operator's own shell, not
    in the scrubbed environment AIVM gives the broker. The locations below
    were fixed when OpenSSL was built; no variable can move them.
    """
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if os.path.isfile(paths.openssl_cafile) else None
    capath = paths.openssl_capath if os.path.isdir(paths.openssl_capath) else None
    if cafile is None and capath is None:
        raise SecretsError('credential_source',
                           detail='OpenSSL has no compiled-in trust store')
    context.load_verify_locations(cafile=cafile, capath=capath)


def _tls_context(ca_file: str | None, untrusted: Roots) -> ssl.SSLContext:
    """Verified TLS 1.2+ to system roots, or to one operator-pinned anchor.

    The same construction as the broker's executor (``host/egress.py``): no
    ``create_default_context``, which reads SSLKEYLOGFILE and may create that
    file before key logging can be disabled; a pinned anchor is read as a
    trusted host file and loaded as data.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_file is None:
        _system_anchors(context)
    else:
        try:
            anchors = read_owned(Path(ca_file), private=False,
                                 limit=MAX_CA_BYTES, untrusted=untrusted,
                                 what='OAuth trust anchor').decode('ascii')
            context.load_verify_locations(cadata=anchors)
        except (UnicodeError, ssl.SSLError, ValueError):
            raise SecretsError('unsafe_file', detail=(
                f'{ca_file}: not a PEM certificate bundle')) from None
    context.keylog_filename = None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class PinnedOAuthHTTP:
    """One pinned HTTPS origin, no redirect or user-supplied target path.

    The TLS context is built once, at construction, as the broker's executor
    does: an unsafe or unreadable trust anchor stops the caller before any
    request is made, and so before the vault marks a refresh as in flight.
    """

    def __init__(self, *, ca_file: str | None = None,
                 untrusted: Roots = ()):
        self.ca_file = ca_file
        self._context = _tls_context(ca_file, tuple(Path(p) for p in untrusted))

    def post(self, provider: OAuthProvider, fields: dict[str, str],
             *, untrusted: tuple = ()) -> dict:
        from .oauth_provider import _https_endpoint
        sent = False
        status = 0
        oauth_error = ''
        conn = None
        resp = None
        try:
            host, target = _https_endpoint(provider.token_url)
            # Fail closed if manifest declared data cannot be represented as
            # an ordinary bounded application/x-www-form-urlencoded request.
            data = urlencode(fields).encode('ascii')
            if len(data) > MAX_FORM:
                raise SecretsError('credential_source')
            conn = http.client.HTTPSConnection(host, 443, timeout=TOKEN_TIMEOUT,
                                               context=self._context)
            # Connect and handshake on their own: until both have succeeded
            # no byte of the request exists outside this process. From here
            # on any failure, even one inside request(), counts as sent.
            conn.connect()
            sent = True
            conn.request('POST', target, data, {
                'Host': host, 'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cache-Control': 'no-store',
            })
            resp = conn.getresponse()
            status = resp.status if 100 <= resp.status <= 599 else 0
            if resp.status == 400:
                oauth_error = _error_token(resp)
            # Redirects are not followed, including any cross-origin Location.
            if resp.status != 200:
                raise SecretsError('credential_source')
            if resp.getheader('Content-Encoding', 'identity') != 'identity':
                raise SecretsError('credential_source')
            body = resp.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise SecretsError('credential_source')
            return _form_response(body, resp.getheader('Content-Type', ''))
        except Exception:
            outcome = classify_refresh_failure(sent, status, oauth_error)
            raise SecretsError('credential_source', status=status, detail=(
                failure_reason(fields.get('grant_type', ''), outcome))) from None
        finally:
            # A ``Connection: close`` reply owns the socket, not ``conn``.
            if resp is not None:
                resp.close()
            if conn is not None:
                conn.close()


def _secret(provider: OAuthProvider, untrusted: tuple) -> str:
    if not provider.client_secret_file:
        return ''
    try:
        secret = read_owned(Path(provider.client_secret_file), private=True,
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
    """Redeem the callback's code; an unusable 200 reply is ``exchange_in_doubt``.

    The provider answered, so it may well have issued a grant -- broader
    scopes than the profile allows, say -- that this host will not store.
    The reason tells the caller so; the reply's tokens are discarded.
    """
    code = accept_callback(pending, callback, now=now,
                           expected_issuer=provider.issuer_response)
    form = {'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': pending.redirect_uri, 'client_id': provider.client_id,
            'code_verifier': pending.verifier}
    secret = _secret(provider, untrusted)
    if secret:
        form['client_secret'] = secret
    result = transport.post(provider, form, untrusted=untrusted)
    try:
        return assess_token_response(result, now=now,
                                     allowed_scopes=list(provider.scopes),
                                     fallback_ttl=provider.fallback_ttl)
    except SecretsError:
        raise SecretsError('credential_source',
                           detail=EXCHANGE_IN_DOUBT) from None


def refresh_form(provider: OAuthProvider, previous: AccessGrant,
                 *, untrusted: tuple = ()) -> dict[str, str]:
    """The refresh request for ``previous``; reads the client secret.

    Everything that can fail without contacting the provider fails here, so
    a caller can make its in-flight marker durable between this and the
    POST and know that a failure before it sent nothing. That includes a
    grant at the last generation: the contract could accept no successor,
    so presenting its rotating refresh token would only spend it.
    """
    if type(previous) is not AccessGrant:
        raise SecretsError('credential_source')
    if previous.refresh_token is None:
        raise SecretsError('expired')
    if previous.generation >= MAX_GENERATION:
        raise SecretsError('exhausted', detail=REFRESH_EXHAUSTED)
    form = {'grant_type': 'refresh_token', 'refresh_token': previous.refresh_token,
            'client_id': provider.client_id}
    secret = _secret(provider, untrusted)
    if secret:
        form['client_secret'] = secret
    return form


def assess_refresh(provider: OAuthProvider, previous: AccessGrant,
                   response: Any, *, now: int) -> AccessGrant:
    """Validate a refresh reply; an unusable one leaves the token in doubt.

    The server answered, so it received the refresh token and may have
    rotated it even though its reply cannot be used.
    """
    try:
        return assess_token_response(response, now=now,
                                     allowed_scopes=list(provider.scopes),
                                     previous=previous,
                                     fallback_ttl=provider.fallback_ttl,
                                     require_rotation=provider.refresh_rotation)
    except SecretsError:
        raise SecretsError('credential_source', detail=REFRESH_IN_DOUBT) from None


def refresh_token(provider: OAuthProvider, previous: AccessGrant,
                  *, now: int, transport: Any, untrusted: tuple = ()) -> AccessGrant:
    form = refresh_form(provider, previous, untrusted=untrusted)
    result = transport.post(provider, form, untrusted=untrusted)
    return assess_refresh(provider, previous, result, now=now)


class HostCallback:
    """One-shot host loopback callback. Never serves credential bytes.

    Any local process can connect to the fixed port, so a connection cannot
    hold the login open: each read and write has a :data:`CALLBACK_SECONDS`
    timeout, and the connection is cut at an absolute deadline of
    :data:`CALLBACK_SECONDS` that never reaches past the deadline of the
    :meth:`wait` in progress. A provider error response bound to this
    authorization ends the wait at once with ``authorization_denied``.
    """

    def __init__(self, provider: OAuthProvider, pending: PendingAuthorization):
        self.provider = provider
        self.pending = pending
        self.parameters: dict[str, str] | None = None
        self.denied = False
        self._deadline = time.monotonic() + max(
            0, pending.expires_at - int(time.time()))
        outer = self

        class Server(HTTPServer):
            allow_reuse_address = False

            def handle_error(self, request: Any, client_address: Any) -> None:
                pass  # Never print a traceback; it may quote the request.

        class Handler(BaseHTTPRequestHandler):
            timeout = CALLBACK_SECONDS

            def setup(self) -> None:
                super().setup()
                remaining = min(CALLBACK_SECONDS,
                                outer._deadline - time.monotonic())
                self._watchdog = threading.Timer(max(0.0, remaining), self._cut)
                self._watchdog.daemon = True
                self._watchdog.start()

            def _cut(self) -> None:
                # Unblocks whatever read or write the handler is waiting in.
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            def finish(self) -> None:
                self._watchdog.cancel()
                try:
                    super().finish()
                except OSError:
                    pass

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Never log auth code or state from a browser URL.

            def do_GET(self) -> None:
                # Only one callback may be consumed. Never accept a relative
                # redirect, duplicate parameter, fragment, or hostile Host.
                status = 400
                content = b'Authorization rejected.'
                try:
                    if self.headers.get('Host') != f'127.0.0.1:{provider.callback_port}':
                        raise ValueError('host')
                    target = urlsplit(self.path)
                    if target.path != '/oauth/callback' or target.fragment:
                        raise ValueError('path')
                    pairs = parse_qsl(target.query, keep_blank_values=True,
                                      strict_parsing=True, max_num_fields=5)
                    fields = dict(pairs)
                    if (len(fields) != len(pairs) or outer.parameters is not None
                            or outer.denied):
                        raise ValueError('duplicate or replay')
                    outcome = callback_outcome(
                        pending, fields, now=int(time.time()),
                        expected_issuer=provider.issuer_response)
                    status = 200
                    if outcome == 'denied':
                        # The provider's description is never shown or kept.
                        outer.denied = True
                        content = b'Authorization was declined. Return to the terminal.'
                    else:
                        outer.parameters = fields
                        content = b'Authorization received. You may close this tab.'
                except (ValueError, SecretsError, UnicodeError):
                    pass
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        try:
            self._httpd = Server(('127.0.0.1', provider.callback_port), Handler)
        except OSError:
            raise SecretsError('credential_source',
                               detail=CALLBACK_PORT_UNAVAILABLE) from None
        self._httpd.timeout = 0.5

    def __enter__(self) -> 'HostCallback':
        return self

    def wait(self, *, timeout: float = 180) -> dict[str, str]:
        start = time.monotonic()
        self._deadline = min(start + timeout, start + max(
            0, self.pending.expires_at - int(time.time())))
        while True:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise SecretsError('expired')
            self._httpd.timeout = min(0.5, remaining)
            self._httpd.handle_request()
            if self.denied:
                raise SecretsError('credential_source',
                                   detail=AUTHORIZATION_DENIED)
            if self.parameters is not None:
                return self.parameters

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._httpd.server_close()


__all__ = ['HostCallback', 'PinnedOAuthHTTP', 'new_pending',
           'authorization_url', 'exchange_code', 'refresh_token',
           'refresh_form', 'assess_refresh', 'failure_reason',
           'REFRESH_NOT_SENT', 'REFRESH_REJECTED', 'REFRESH_IN_DOUBT',
           'REFRESH_EXHAUSTED', 'EXCHANGE_IN_DOUBT',
           'CALLBACK_PORT_UNAVAILABLE']
