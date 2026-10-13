"""Minimal TLS 1.3 Unix client for a deliberately enabled bound identity.

This is only transport plumbing. Every request is reauthorized by the trusted
broker. No raw HTTP forwarding, OAuth or fallback to an unbound socket exists.
"""

from __future__ import annotations

import socket
import ssl
import time
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..host.files import read_owned
from ..transport.framing import (
    CONNECT_TIMEOUT, FRAME_TIMEOUT, RELAYED_REPLY_DEADLINE,
)
from ..primitives import codec, wire

# How OpenSSL names a TLS alert *received from the peer*. A fault this side
# detects (a bad record, an unexpected EOF) is named otherwise.
_PEER_ALERT = ('SSLV3_ALERT_', 'TLSV1_ALERT_', 'TLSV13_ALERT_')


def _refused_handshake(error: ssl.SSLError) -> bool:
    """Whether the bridge refused this client's certificate.

    In TLS 1.3 the client's side of the handshake completes before the server
    has judged the client certificate, so a refusal (an unknown CA, an
    expired or wrong certificate) arrives as an alert on the first read,
    after the frame was sent. Only the bridge's handshake sends an alert
    (``identity/mtls.py``), and it reads nothing before its handshake
    succeeds, so such an alert means nothing was dispatched.
    """
    if isinstance(error, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return False  # A hang-up, not a verdict.
    reason = error.reason
    return type(reason) is str and reason.startswith(_PEER_ALERT)


def _read_reply(channel: ssl.SSLSocket, deadline: float) -> bytes:
    """One reply line, or the code that says what is known of the request."""
    end = time.monotonic() + deadline
    data = bytearray()
    while b'\n' not in data:
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise SecretsError('outcome_unknown')
        try:
            channel.settimeout(remaining)
            chunk = channel.recv(min(16384, wire.MAX_REPLY + 1 - len(data)))
        except ssl.SSLError as ex:
            if not data and _refused_handshake(ex):
                raise SecretsError('unreachable') from None
            raise SecretsError('outcome_unknown') from None
        except OSError:
            raise SecretsError('outcome_unknown') from None
        if not chunk or len(data) + len(chunk) > wire.MAX_REPLY:
            raise SecretsError('outcome_unknown')
        data.extend(chunk)
    line, trailing = bytes(data).split(b'\n', 1)
    if trailing:
        raise SecretsError('outcome_unknown')
    return line


def bound_call(*, socket_path: Path, ca: Path, certificate: Path,
               private_key: Path, jwt_file: Path,
               request: dict[str, Any],
               reply_deadline: float = RELAYED_REPLY_DEADLINE) -> dict[str, Any]:
    """One framed call; caller supplies no server identity or TLS override.

    Before the frame is sent, a failure is ``unreachable``: nothing left this
    process. So is the bridge refusing this client's certificate, which in
    TLS 1.3 is only seen on the first read: it refuses before reading
    anything. Otherwise, once the frame is sent the bridge and broker may be
    acting on it, so a timeout, EOF, reset or unusable reply is
    ``outcome_unknown`` -- the same answer the bridge gives when its own wait
    for the broker runs out, and never a claim that the request was
    malformed. ``reply_deadline`` exceeds the bridge's wait for the broker;
    it is a parameter only for tests.
    """
    key = Path(private_key).expanduser().absolute()
    token = Path(jwt_file).expanduser().absolute()
    read_owned(key, private=True, what='client identity key')
    jwt = read_owned(token, private=True, limit=65536,
                     what='bound client token').decode('ascii')
    # This client does not trust a JWT claim about the peer. TLS must verify
    # the configured CA and the localhost SAN, even over a forwarded socket.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_COMPRESSION
    context.keylog_filename = None
    context.load_verify_locations(cafile=str(Path(ca).expanduser()))
    context.load_cert_chain(str(Path(certificate).expanduser()), str(key))
    outgoing = {'version': 1, 'capability': jwt, 'request': request}
    wire.parse_frame(outgoing)
    data = codec.dumps(outgoing) + b'\n'
    try:
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError:
        raise SecretsError('unreachable') from None
    with raw:
        try:
            raw.settimeout(CONNECT_TIMEOUT)
            raw.connect(str(Path(socket_path).expanduser()))
            secure = context.wrap_socket(raw, server_hostname='localhost')
        except (OSError, ssl.SSLError, UnicodeError):
            raise SecretsError('unreachable') from None
        with secure:
            try:
                secure.settimeout(FRAME_TIMEOUT)
                secure.sendall(data)
            except (OSError, ssl.SSLError):
                raise SecretsError('unreachable') from None
            line = _read_reply(secure, reply_deadline)
    try:
        reply = codec.loads(line, limit=wire.MAX_REPLY)
    except Exception:
        raise SecretsError('outcome_unknown') from None
    if type(reply) is not dict:
        raise SecretsError('outcome_unknown')
    return reply
