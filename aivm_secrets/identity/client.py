"""Minimal TLS 1.3 Unix client for a deliberately enabled bound identity.

This is only transport plumbing. Every request is reauthorized by the trusted
broker. No raw HTTP forwarding, OAuth or fallback to an unbound socket exists.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..host.files import read_owned
from ..transport.framing import read_frame
from ..primitives import codec, wire


def bound_call(*, socket_path: Path, ca: Path, certificate: Path,
               private_key: Path, jwt_file: Path,
               request: dict[str, Any]) -> dict[str, Any]:
    """One framed call; caller supplies no server identity or TLS override."""
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
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(5.0)
            raw.connect(str(Path(socket_path).expanduser()))
            with context.wrap_socket(raw, server_hostname='localhost') as secure:
                secure.settimeout(5.0)
                secure.sendall(codec.dumps(outgoing) + b'\n')
                reply = codec.loads(read_frame(
                    secure, limit=codec.MAX_FRAME, timeout=5.0))
                if type(reply) is not dict:
                    raise SecretsError('invalid_request')
                return reply
    except (OSError, ssl.SSLError, UnicodeError):
        raise SecretsError('unreachable') from None
