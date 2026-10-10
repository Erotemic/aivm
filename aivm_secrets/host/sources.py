"""Host-only credential acquisition. A guest can never select a source.

A source is operator configuration: a private file, or a literal ``argv``
run without a shell. Acquiring a credential is independent of the service it
is for and of whatever CLI the guest happens to run (RESOLVER-01).

``untrusted`` names directories the guest can write -- for AIVM, the shared
workspace. A credential file, a resolver executable or a literal path
argument found inside one is refused before anything is read or run.
"""

from __future__ import annotations

import os
import select
import shutil
import subprocess
import time
from pathlib import Path
from typing import IO, Any

from ..errors import SecretsError
from ..kernel import grammar
from ..kernel.source import parse_source
from .files import outside, read_owned, verify_program

MAX_OUTPUT = 4097
RESOLVER_TIMEOUT = 15.0
Roots = tuple[Path, ...]


def _credential(data: bytes) -> str:
    try:
        return grammar.credential(data.decode('ascii').rstrip('\n'))
    except UnicodeError:
        raise SecretsError('credential_source') from None


def credential_from_file(path: Path, *, untrusted: Roots = ()) -> str:
    outside(path, untrusted, what='credential file')
    return _credential(read_owned(Path(path), private=True, limit=MAX_OUTPUT))


def credential_from_stream(stream: IO[bytes]) -> str:
    """Read one credential from an already open host stream (stdin)."""
    return _credential(stream.read(MAX_OUTPUT + 1))


def _program(name: str, untrusted: Roots) -> Path:
    found = shutil.which(name)
    if found is None:
        raise SecretsError(
            'credential_source', detail=f'resolver {name!r} not found'
        )
    return verify_program(Path(found), untrusted)


def credential_from_command(
    argv: list[str],
    inherit_env: list[str] | tuple[str, ...] = (),
    *,
    untrusted: Roots = (),
) -> str:
    """Run a trusted host resolver: no shell, bounded output, total deadline.

    The child sees ``HOME`` and ``PATH`` plus the named variables only, a
    closed stdin and a discarded stderr. Its executable is located once,
    verified along its whole path, and then executed by that absolute name.
    """
    program = _program(argv[0], untrusted)
    for argument in argv[1:]:
        if argument.startswith(('/', './', '../', '~/')):
            base = Path.home() if not argument.startswith('/') else Path('/')
            outside(base / argument, untrusted, what='resolver argument')
    env = {
        key: os.environ[key] for key in ('HOME', 'PATH') if key in os.environ
    }
    for key in inherit_env:
        if key in os.environ:
            env[key] = os.environ[key]
    failure = SecretsError(
        'credential_source', detail=f'resolver {argv[0]!r} failed'
    )
    process = None
    try:
        process = subprocess.Popen(
            [str(program), *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            close_fds=True,
            cwd=os.path.expanduser('~'),
        )
        assert process.stdout is not None
        deadline = time.monotonic() + RESOLVER_TIMEOUT
        output = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise failure
            if not select.select([process.stdout], [], [], remaining)[0]:
                raise failure
            chunk = os.read(
                process.stdout.fileno(), MAX_OUTPUT + 1 - len(output)
            )
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                raise failure
        remaining = max(0.01, deadline - time.monotonic())
        if process.wait(timeout=remaining) != 0:
            raise failure
        return _credential(bytes(output))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise failure from None
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.poll() is None:
                process.kill()
            process.wait()


def resolve_source(value: Any, *, untrusted: Roots = ()) -> str:
    source = parse_source(value)
    if source['kind'] == 'file':
        return credential_from_file(Path(source['path']), untrusted=untrusted)
    return credential_from_command(
        source['argv'], source['inherit_env'], untrusted=untrusted
    )
