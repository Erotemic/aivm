"""Where live sessions are found, and the host side of the control channel.

Each running broker owns one directory under a per-user runtime root::

    $XDG_RUNTIME_DIR/aivm-secrets/<channel>/
        broker.sock     forwarded to the guest
        control.sock    host operator only
        capability      sealed capability (ciphertext)

A session is *live* exactly when its control socket answers. The directory
listing is only an index: a stale entry confers nothing, because the key that
gave its capability meaning died with the process.
"""

from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..kernel import codec, grammar
from .files import private_directory
from .server import CONTROL_SOCKET, GUEST_SOCKET, read_frame

CAPABILITY_FILE = 'capability'
CONTROL_TIMEOUT = 5.0


def runtime_root(untrusted: tuple[Path, ...] = ()) -> Path:
    """A host-only runtime root, outside all guest-writable directories.

    The caller's environment selects a candidate, not an exemption from the
    trust boundary. File/path validation is the same as for policy and audit.
    """
    base = os.environ.get('XDG_RUNTIME_DIR', '')
    if base and os.path.isabs(base):
        root = Path(base) / 'aivm-secrets'
    else:
        root = Path(tempfile.gettempdir()) / f'aivm-secrets-{os.getuid()}'
    return private_directory(root, untrusted=untrusted)


def session_directory(
    channel: str, untrusted: tuple[Path, ...] = ()
) -> Path:
    grammar.hex_string(channel, 32, code='internal_error')
    return private_directory(runtime_root(untrusted) / channel, untrusted)


def remove_session_directory(directory: Path) -> None:
    """Remove only what a session creates; never follow anything."""
    for name in (CAPABILITY_FILE, GUEST_SOCKET, CONTROL_SOCKET):
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            return
    try:
        directory.rmdir()
    except OSError:
        pass


def control_call(directory: Path, command: dict[str, Any]) -> dict[str, Any]:
    """Send one command to a session's control socket and return its reply."""
    path = directory / CONTROL_SOCKET
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONTROL_TIMEOUT)
            sock.connect(str(path))
            sock.sendall(codec.dumps(command) + b'\n')
            reply = codec.loads(
                read_frame(sock, limit=1024 * 1024, timeout=CONTROL_TIMEOUT),
                limit=1024 * 1024,
            )
    except (OSError, SecretsError):
        raise SecretsError('no_session', detail=f'{directory.name}') from None
    if type(reply) is not dict:
        raise SecretsError('no_session', detail=f'{directory.name}')
    return reply


def _directories() -> list[Path]:
    root = runtime_root()
    result = []
    for entry in sorted(root.iterdir()):
        try:
            grammar.hex_string(entry.name, 32)
        except SecretsError:
            continue
        if entry.is_dir() and not entry.is_symlink():
            result.append(entry)
    return result


def list_sessions(*, prune: bool = False) -> list[dict[str, Any]]:
    """Describe every live session of the calling user.

    With ``prune``, directories whose broker no longer answers are removed.
    """
    sessions = []
    for directory in _directories():
        try:
            reply = control_call(directory, {'command': 'status'})
        except SecretsError:
            if prune:
                remove_session_directory(directory)
            continue
        if reply.get('ok') is True and type(reply.get('session')) is dict:
            sessions.append(dict(reply['session'], directory=str(directory)))
    return sessions


def find_sessions(
    selector: str = '',
    *,
    access_identity: str = '',
    vm: str = '',
) -> list[dict[str, Any]]:
    """Live sessions matching a channel prefix and/or an AIVM binding."""
    matches = []
    for item in list_sessions():
        if selector and not str(item['channel']).startswith(selector):
            continue
        if access_identity and item['access_identity'] != access_identity:
            continue
        if vm and item['vm'] != vm:
            continue
        matches.append(item)
    return matches
