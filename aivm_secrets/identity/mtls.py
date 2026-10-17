"""Per-connection mTLS bridge for P4a certificate-bound capabilities.

This module serves one already-accepted connection; it owns no listener.
``identity/service.py`` is the listener, started explicitly by the host-only
``python -I -m aivm_secrets identity bridge`` command, which ``aivm ssh
--secrets_identity_root`` launches for a bound session. Nothing starts it
implicitly, and it never opens a TCP port. The existing Broker remains the
*only* interpreter authorized to use provider credentials.

CRITICAL: do not turn this into an unverified HTTP forwarding proxy. A bridge
request can only be a signed, certificate-bound wrapper around one of the
existing broker protocol verbs; delegated capabilities are intentionally
forbidden until the response is itself identity-bound.
"""

from __future__ import annotations

import socket
import ssl
import time
from pathlib import Path
from typing import Any, Callable

from ..errors import SecretsError
from ..transport.framing import FRAME_TIMEOUT, read_frame
from ..primitives import codec, grammar, wire
from .token import IdentityTokenVerifier, MAX_JWT_BYTES
from .garrett.claims import IdentityExpectation

# Each of the bridge's own legs: the handshake, the request frame and the
# answer. ``RELAYED_REPLY_DEADLINE`` counts on this being ``FRAME_TIMEOUT``.
FRAME_DEADLINE_SECONDS = FRAME_TIMEOUT


def server_context(*, certificate: Path, private_key: Path,
                   client_ca: Path) -> ssl.SSLContext:
    """Require real client certificate chain validation, not a spoofed header.

    Trusted callers MUST validate configuration-path ownership and exclusion
    from guest shares before passing files; ``IdentityAuthority.tls_paths``
    does so for the files the identity CLI and the AIVM launcher pass here.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.keylog_filename = None
    # Session tickets/resumption are unnecessary for one-frame identity calls;
    # require a fresh certificate-authenticated handshake each connection.
    if hasattr(ctx, 'num_tickets'):
        ctx.num_tickets = 0
    ctx.load_verify_locations(cafile=str(client_ca))
    ctx.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    return ctx


def _keylog(context: ssl.SSLContext) -> str | None:
    # Typeshed calls this ``str``; at runtime an unset key log is None.
    return context.keylog_filename


class IdentityTLSBridge:
    """One P4a authenticated channel feeding exactly one existing broker."""

    def __init__(self, *, context: ssl.SSLContext,
                 verifier: IdentityTokenVerifier, broker: Any,
                 wall_clock: Callable[[], float] = time.time,
                 expected_for_peer: Callable[[bytes, int], IdentityExpectation] | None = None,
                 subject: str | None = None):
        # A subject pin is judged against the *registry's* answer for the
        # peer, so it is meaningless without one.
        if subject is not None and (type(subject) is not str or not subject or
                                    expected_for_peer is None):
            raise SecretsError('invalid_policy')
        if (not isinstance(context, ssl.SSLContext) or
                context.protocol != ssl.PROTOCOL_TLS_SERVER or
                context.verify_mode != ssl.CERT_REQUIRED or
                context.minimum_version < ssl.TLSVersion.TLSv1_3):
            raise SecretsError('invalid_policy')
        if _keylog(context) is not None:
            raise SecretsError('invalid_policy')
        self._context = context
        self._verifier = verifier
        self._broker = broker
        self._clock = wall_clock
        self._expected_for_peer = expected_for_peer
        self._subject = subject

    def serve_accepted(self, accepted: socket.socket) -> None:
        """Perform a verified TLS handshake and process a single framed call.

        Listener binding, concurrency, host-path validation and lifetime are
        ``UnixIdentityService``'s; process isolation is the launcher's
        (``python -I``). This method may run on several threads at once: it
        keeps no state between calls, and every per-request read it makes
        through the verifier and ``expected_for_peer`` is side-effect free.

        Only a failed handshake sends the caller a TLS alert. Once the
        handshake has succeeded the bridge answers or hangs up, and never
        sends one: a client takes an alert before any reply byte to mean that
        its certificate was refused and nothing was read
        (``identity/client.py``).
        """
        accepted.settimeout(FRAME_DEADLINE_SECONDS)
        with self._context.wrap_socket(accepted, server_side=True) as channel:
            channel.settimeout(FRAME_DEADLINE_SECONDS)
            cert_der = channel.getpeercert(binary_form=True)
            if type(cert_der) is not bytes or not cert_der:
                # An authenticated peer cert must be present after handshake.
                return
            try:
                raw = read_frame(channel, limit=codec.MAX_FRAME,
                                 timeout=FRAME_DEADLINE_SECONDS)
                request = codec.loads(raw)
                request = self._unwrap(request, cert_der)
                # No shortcut to the executor; the existing broker still
                # parses, authenticates aivs1 and checks every grant/effect.
                answer = self._broker.handle(codec.dumps(request))
                if type(answer) is not dict:
                    raise SecretsError('internal_error')
            except SecretsError as ex:
                answer = wire.failure(ex)
            except Exception:
                answer = wire.failure(SecretsError('internal_error'))
            try:
                channel.sendall(codec.dumps(answer) + b'\n')
            except (OSError, ssl.SSLError):
                return

    def _unwrap(self, incoming: Any, certificate_der: bytes) -> dict[str, Any]:
        # The only forwarded operations are those whose reply cannot include
        # a raw child `aivs1` capability. Delegate requires a distinct P4b
        # wrapped-child protocol, not an unbound response.
        if type(incoming) is not dict:
            raise SecretsError('invalid_request')
        verbs = [verb for verb in ('request', 'describe', 'renounce', 'delegate')
                 if verb in incoming]
        if len(verbs) != 1 or verbs[0] == 'delegate':
            raise SecretsError('denied')
        verb = verbs[0]
        fields = grammar.exact_keys(incoming,
                                    frozenset({'version', 'capability', verb}))
        grammar.integer(fields['version'], 1, 1)
        outer = fields['capability']
        if type(outer) is not str or len(outer) > MAX_JWT_BYTES:
            raise SecretsError('invalid_request')
        now = int(self._clock())
        # When backed by the trusted host enrollment ledger, resolve the
        # active epoch and certificate pin *fresh* on every request. A sealed
        # token from a revoked identity must fail before broker dispatch.
        expected = (None if self._expected_for_peer is None else
                    self._expected_for_peer(certificate_der, now))
        # A bridge pinned to one subject serves that subject only, whoever
        # else the same CA has enrolled; refused before any token is opened.
        if self._subject is not None and (
                expected is None or expected.subject != self._subject):
            raise SecretsError('wrong_binding')
        inner = self._verifier.open(
            outer, authenticated_peer_der=certificate_der,
            now=now, expected=expected,
        ).broker_capability
        forwarded = dict(fields)
        forwarded['capability'] = inner
        # The same frame parser used by the ordinary Unix socket guards
        # all protocol shapes, including describe/renounce payloads.
        wire.parse_frame(forwarded)
        return forwarded
