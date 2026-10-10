"""The one trusted egress path: where a credential leaves the host.

An executor is constructed for exactly one :class:`Egress` and accepts only
an :class:`AuthorizedEffect` from the kernel. It can therefore reach one TLS
identity, with one authentication scheme, on a request the kernel computed.
There is no URL parameter, no redirect following, no retry, no proxy
environment and no fallback origin (ROUTE-01, COMP-01).

Failures are reported as fixed codes that tell the caller what is known
about a write:

``unreachable``        no connection was established; nothing was sent
``upstream_rejected``  the service answered 4xx; it did not apply the request
``outcome_unknown``    bytes were sent and no definite answer came back
``upstream_error`` / ``upstream_response``  a read failed or was unusable
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import threading
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..kernel import codec
from ..kernel.machine import AuthorizedEffect
from ..kernel.model import Egress, check_effect
from ..kernel.wire import MAX_RESPONSE
from .files import read_owned

USER_AGENT = 'aivm-secrets/1'
CONNECT_TIMEOUT = 10.0
IO_TIMEOUT = 15.0
# A hard bound on one exchange. A peer that trickles one byte per socket
# timeout cannot hold a request, or the session lock behind it, open.
TOTAL_DEADLINE = 45.0
MAX_CA_BYTES = 1024 * 1024


def tls_context(egress: Egress) -> ssl.SSLContext:
    """Verified TLS 1.2+ to system roots, or to one operator-pinned anchor."""
    if egress.ca_file:
        try:
            anchors = read_owned(
                Path(egress.ca_file), private=False, limit=MAX_CA_BYTES
            ).decode('ascii')
            context = ssl.create_default_context(cadata=anchors)
        except (UnicodeError, ssl.SSLError, ValueError):
            raise SecretsError(
                'unsafe_file',
                detail=f'{egress.ca_file}: not a PEM certificate bundle',
            ) from None
    else:
        context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class _Connection(http.client.HTTPSConnection):
    """Connect to the pinned address; authenticate the policy's hostname.

    ``abort`` must be able to end the exchange from another thread at any
    point -- mid-handshake, mid-headers or mid-body. Wrapping a socket in
    TLS *detaches* the original object, so the connection keeps its own
    duplicate descriptor of the same kernel socket and shuts that down:
    whichever call is blocked on the connection returns at once.
    """

    def __init__(self, egress: Egress, context: ssl.SSLContext):
        super().__init__(
            egress.host, egress.port, timeout=IO_TIMEOUT, context=context
        )
        self._tls = context
        self._address = egress.address or egress.host
        self._killer: socket.socket | None = None
        self.aborted = False

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._address, self.port), CONNECT_TIMEOUT
        )
        try:
            self._killer = socket.socket(fileno=os.dup(raw.fileno()))
            raw.settimeout(IO_TIMEOUT)
            self.sock = self._tls.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise

    def abort(self) -> None:
        self.aborted = True
        killer = self._killer
        if killer is not None:
            try:
                killer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        super().close()
        killer, self._killer = self._killer, None
        if killer is not None:
            killer.close()


class HTTPSExecutor:
    def __init__(self, egress: Egress):
        self.egress = egress
        # Built once, so a trust anchor that is unsafe or unreadable stops
        # the session at start rather than at the first request.
        self._context = tls_context(egress)

    def _headers(self, authorized: AuthorizedEffect, credential: str) -> dict:
        effect = authorized.effect
        headers = {
            'Accept': effect.accept,
            'Accept-Encoding': 'identity',
            'User-Agent': USER_AGENT,
        }
        headers.update(self.egress.headers)
        if self.egress.authentication == 'bearer':
            headers['Authorization'] = 'Bearer ' + credential
        else:
            headers['X-API-Key'] = credential
        if effect.body is not None:
            headers['Content-Type'] = 'application/json'
        return headers

    def execute(self, authorized: AuthorizedEffect, credential: str) -> Any:
        if type(authorized) is not AuthorizedEffect:
            raise SecretsError('denied')
        effect = check_effect(authorized.effect)
        if effect.is_write and not authorized.final:
            raise SecretsError('denied')
        body = None
        if effect.body is not None:
            body = codec.dumps(dict(effect.body))
        headers = self._headers(authorized, credential)
        connection = _Connection(self.egress, self._context)
        watchdog = threading.Timer(TOTAL_DEADLINE, connection.abort)
        watchdog.daemon = True
        sent = False
        response = None
        try:
            watchdog.start()
            try:
                connection.connect()
            except Exception:
                raise SecretsError('unreachable') from None
            sent = True
            connection.request(
                effect.method, effect.target, body=body, headers=headers
            )
            response = connection.getresponse()
            status = response.status
            if 400 <= status < 500:
                # The service answered and declined. Its body is provider
                # text and is never read.
                raise SecretsError('upstream_rejected', status=status)
            if not 200 <= status < 300:
                raise SecretsError('upstream_error', status=status)
            if response.getheader('Content-Encoding', 'identity') != 'identity':
                raise SecretsError('upstream_response')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise SecretsError('upstream_response')
            if connection.aborted or response.length:
                # Cut off by the deadline, or shorter than its own declared
                # length: a transport failure, not an answer to interpret.
                raise SecretsError('upstream_error')
            if effect.response == 'text':
                try:
                    return data.decode('utf-8')
                except UnicodeError:
                    raise SecretsError('upstream_response') from None
            return codec.loads(
                data, limit=MAX_RESPONSE, code='upstream_response'
            )
        except SecretsError as ex:
            if ex.code in ('unreachable', 'upstream_rejected'):
                raise
            if effect.is_write and sent:
                raise SecretsError(
                    'outcome_unknown', status=ex.status
                ) from None
            raise
        except Exception:
            code = 'outcome_unknown' if effect.is_write else 'upstream_error'
            raise SecretsError(code) from None
        finally:
            watchdog.cancel()
            if response is not None:
                response.close()
            connection.close()
