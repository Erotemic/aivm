#!/usr/bin/env python3
"""Guest client for an AIVM secret-use session (standard library only).

This file is copied into the guest as-is and is NOT a security boundary:
every check that matters is made by the host broker, and a guest may replace
or bypass this client without gaining anything. It only translates command
lines into protocol version 1 frames.

  invoke OPERATION [--arguments JSON]   call a named, policy-allowed operation
  operations                            show what this capability permits
  delegate --scope JSON --output FILE   mint a smaller capability for a helper
  renounce                              give up this capability
  pr ...                                gh-shaped sugar for the GitHub PR service

Exit status: 0 success, 2 client or transport failure, 3 refused by the
broker, 4 a host operator must approve this exact write first.

There is no fallback to a host tool, an unrestricted API, a shell or a URL.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from typing import Any

MAX_FRAME = 65536
MAX_REPLY = 2 * 1024 * 1024 + 65536
MAX_INPUT = 16384
PR_COMMANDS = (
    'view',
    'diff',
    'comments',
    'reviews',
    'review-comments',
    'checks',
    'comment',
    'edit',
)
PAGED = ('comments', 'reviews', 'review-comments', 'checks')


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='aivm-secrets',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    p.add_argument(
        '--socket', default=os.environ.get('AIVM_SECRETS_SOCKET', '')
    )
    p.add_argument(
        '--capability-file',
        default=os.environ.get('AIVM_SECRETS_CAPABILITY_FILE', ''),
    )
    groups = p.add_subparsers(dest='group', required=True)

    invoke = groups.add_parser(
        'invoke',
        allow_abbrev=False,
        help='Invoke a named, policy-allowed service operation',
    )
    invoke.add_argument('operation')
    source = invoke.add_mutually_exclusive_group()
    source.add_argument('--arguments', help='JSON object of typed arguments')
    source.add_argument(
        '--arguments-file',
        help='JSON argument object from a file, or - for stdin',
    )
    invoke.add_argument(
        '--result-only',
        action='store_true',
        help='Print only the result (text results are printed raw)',
    )

    groups.add_parser(
        'operations',
        allow_abbrev=False,
        help='Show the operations, limits and expiry of this capability',
    )

    delegate = groups.add_parser(
        'delegate',
        allow_abbrev=False,
        help='Mint a strictly smaller capability, e.g. for a sub-agent',
    )
    scope = delegate.add_mutually_exclusive_group(required=True)
    scope.add_argument('--scope', help='JSON narrowing: operations and limits')
    scope.add_argument(
        '--scope-file', help='Narrowing from a file, or - for stdin'
    )
    delegate.add_argument(
        '--output',
        required=True,
        help='New file to receive the child capability',
    )

    groups.add_parser(
        'renounce', allow_abbrev=False, help='Give up this capability for good'
    )

    pr = groups.add_parser('pr', allow_abbrev=False)
    operations = pr.add_subparsers(dest='operation', required=True)
    for name in PR_COMMANDS:
        op = operations.add_parser(name, allow_abbrev=False)
        op.add_argument('number', type=int)
        op.add_argument('--repo', '-R', required=True)
        if name in PAGED:
            op.add_argument('--page', type=int, default=1)
        if name in ('comment', 'edit'):
            body = op.add_mutually_exclusive_group(required=name == 'comment')
            body.add_argument('--body')
            body.add_argument('--body-file', help='UTF-8 file, or - for stdin.')
        if name == 'edit':
            op.add_argument('--title')
    return p


def read_bounded(path: str) -> str:
    if path == '-':
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    else:
        with open(path, 'rb') as stream:
            raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError('input too large')
    return raw.decode('utf-8')


def json_object(inline: str | None, path: str | None) -> dict[str, Any]:
    text = inline if path is None else read_bounded(path)
    value = json.loads(text) if text is not None else {}
    if type(value) is not dict:
        raise ValueError('expected a JSON object')
    return value


def frame_from_args(args: argparse.Namespace) -> tuple[str, Any]:
    """Translate a command line into one ``(verb, payload)`` pair."""
    if args.group == 'invoke':
        arguments = json_object(args.arguments, args.arguments_file)
        return 'request', {'operation': args.operation, 'arguments': arguments}
    if args.group == 'operations':
        return 'describe', True
    if args.group == 'renounce':
        return 'renounce', True
    if args.group == 'delegate':
        return 'delegate', json_object(args.scope, args.scope_file)
    request: dict[str, Any] = {
        'operation': 'pr.' + args.operation,
        'repository': args.repo,
        'pr': args.number,
    }
    if hasattr(args, 'page'):
        request['page'] = args.page
    if getattr(args, 'body', None) is not None:
        request['body'] = args.body
    if getattr(args, 'body_file', None) is not None:
        request['body'] = read_bounded(args.body_file)
    if getattr(args, 'title', None) is not None:
        request['title'] = args.title
    return 'request', request


def request_from_args(args: argparse.Namespace) -> Any:
    return frame_from_args(args)[1]


def exchange(
    socket_path: str, capability: str, payload: Any, verb: str = 'request'
) -> dict[str, Any]:
    """Send one frame and read one reply. One connection per request."""
    wire = json.dumps(
        {'version': 1, 'capability': capability, verb: payload},
        allow_nan=False,
    ).encode('utf-8')
    if len(wire) + 1 > MAX_FRAME:
        raise ValueError('request too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(socket_path)
        sock.sendall(wire + b'\n')
        deadline = time.monotonic() + 60
        data = bytearray()
        while b'\n' not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('response deadline')
            sock.settimeout(remaining)
            chunk = sock.recv(min(16384, MAX_REPLY + 1 - len(data)))
            if not chunk or len(data) + len(chunk) > MAX_REPLY:
                raise ValueError('invalid response')
            data.extend(chunk)
    reply = json.loads(bytes(data).decode('utf-8'))
    if type(reply) is not dict:
        raise ValueError('invalid response')
    return reply


def _safe_code(value: Any) -> str:
    # Host-generated codes only; never echo arbitrary error text.
    if not isinstance(value, str) or not value.replace('_', '').isalnum():
        return 'request_failed'
    return value[:64]


def report_failure(reply: dict[str, Any]) -> int:
    error = reply.get('error')
    error = error if isinstance(error, dict) else {}
    code = _safe_code(error.get('code'))
    status = error.get('status')
    suffix = f' (HTTP {status})' if type(status) is int else ''
    print(f'aivm-secrets: {code}{suffix}', file=sys.stderr)
    if code == 'approval_required':
        approval = reply.get('approval')
        digest = approval.get('digest') if isinstance(approval, dict) else ''
        if isinstance(digest, str) and digest.isalnum():
            print(
                'aivm-secrets: nothing was sent. Ask the host operator to '
                f'review and run:  aivm-secrets approve {digest[:16]}\n'
                'aivm-secrets: then repeat this exact command.',
                file=sys.stderr,
            )
        return 4
    return 3


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.socket or not args.capability_file:
        print(
            'Use an AIVM secret session, or specify --socket and '
            '--capability-file.',
            file=sys.stderr,
        )
        return 2
    try:
        with open(args.capability_file, 'r', encoding='ascii') as stream:
            capability = stream.read(32769).strip()
        if len(capability) > 32768:
            raise ValueError('capability too large')
        verb, payload = frame_from_args(args)
        if args.group == 'delegate':
            # Fail before spending anything if the output cannot be created.
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            output = os.open(args.output, flags, 0o600)
        reply = exchange(args.socket, capability, payload, verb)
        if reply.get('ok') is not True:
            if args.group == 'delegate':
                os.close(output)
                os.unlink(args.output)
            return report_failure(reply)
        if args.group == 'delegate':
            with os.fdopen(output, 'w', encoding='ascii') as stream:
                stream.write(reply.pop('capability'))
        result = reply.get('result')
        raw = (args.group == 'pr' and args.operation == 'diff') or getattr(
            args, 'result_only', False
        )
        if raw and isinstance(result, str):
            sys.stdout.write(result)
        elif raw:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        else:
            print(json.dumps(reply, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print(
            'aivm-secrets: client or transport failure; do not automatically '
            'retry writes.',
            file=sys.stderr,
        )
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
