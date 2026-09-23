#!/usr/bin/env python3
"""Standalone guest-side helper for VS Code Remote Tunnel sessions.

The source of this module is installed verbatim into managed guests so the
normal AIVM command log can invoke a small, inspectable helper rather than
shipping an anonymous shell program over SSH on every tunnel launch.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

TUNNEL_HELPER_PATH = '/usr/local/libexec/aivm/code-tunnel'
DEFAULT_TMUX_SESSION = 'aivm-tunnel'
_REQUIRED_COMMANDS = ('tmux', 'code')



def missing_commands() -> tuple[str, ...]:
    """Return tunnel prerequisites that are absent from ``PATH``."""
    return tuple(name for name in _REQUIRED_COMMANDS if shutil.which(name) is None)


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(part) for part in argv],
        text=True,
        capture_output=True,
        check=False,
    )


def _check() -> int:
    print(json.dumps({'missing': list(missing_commands())}, sort_keys=True))
    return 0


def _start(*, guest_path: str, tunnel_name: str, session: str) -> int:
    missing = missing_commands()
    if missing:
        print(
            'missing VS Code tunnel prerequisite(s): ' + ', '.join(missing),
            file=sys.stderr,
        )
        return 2

    path = Path(guest_path)
    if not path.is_dir():
        print(f'guest tunnel working directory does not exist: {path}', file=sys.stderr)
        return 2

    existing = _run(['tmux', 'has-session', '-t', session])
    if existing.returncode == 0:
        print(f'{session} session already running')
        return 0
    if existing.returncode != 1:
        detail = (existing.stderr or existing.stdout or '').strip()
        print(
            f'could not inspect tmux session {session!r}: {detail}',
            file=sys.stderr,
        )
        return existing.returncode or 1

    tunnel_command = shlex.join(
        [
            'code',
            'tunnel',
            '--name',
            tunnel_name,
            '--accept-server-license-terms',
        ]
    )
    started = _run(
        [
            'tmux',
            'new-session',
            '-d',
            '-s',
            session,
            '-c',
            str(path),
            tunnel_command,
        ]
    )
    if started.returncode != 0:
        detail = (started.stderr or started.stdout or '').strip()
        print(
            f'could not start tmux session {session!r}: {detail}',
            file=sys.stderr,
        )
        return started.returncode or 1

    print(f'Started {session} session running: {tunnel_command}')
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('check')

    start = subparsers.add_parser('start')
    start.add_argument('--guest-path', required=True)
    start.add_argument('--name', required=True)
    start.add_argument('--session', default=DEFAULT_TMUX_SESSION)

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == 'check':
        return _check()
    if args.command == 'start':
        return _start(
            guest_path=args.guest_path,
            tunnel_name=args.name,
            session=args.session,
        )
    raise AssertionError(f'unhandled command: {args.command!r}')


if __name__ == '__main__':
    raise SystemExit(main())
