#!/usr/bin/env python3
"""Restricted gh-shaped client. Stdlib only; NOT the stock GitHub CLI.

No fallback to gh, gh api, shell execution, or raw URLs is implemented.
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


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--socket', default=os.environ.get('AIVM_SECRETS_SOCKET', ''))
    p.add_argument('--capability-file', default=os.environ.get('AIVM_SECRETS_CAPABILITY_FILE', ''))
    groups = p.add_subparsers(dest='group', required=True)
    pr = groups.add_parser('pr', allow_abbrev=False)
    operations = pr.add_subparsers(dest='operation', required=True)
    for name in ('view', 'diff', 'comments', 'reviews', 'review-comments', 'checks', 'comment', 'edit'):
        op = operations.add_parser(name, allow_abbrev=False)
        op.add_argument('number', type=int)
        op.add_argument('--repo', '-R', required=True)
        if name in ('comments', 'reviews', 'review-comments', 'checks'):
            op.add_argument('--page', type=int, default=1)
        if name in ('comment', 'edit'):
            body = op.add_mutually_exclusive_group(required=name == 'comment')
            body.add_argument('--body')
            body.add_argument('--body-file', help='UTF-8 file, or - for stdin.')
        if name == 'edit':
            op.add_argument('--title')
    return p


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    request = {'operation': 'pr.' + args.operation, 'repository': args.repo, 'pr': args.number}
    if hasattr(args, 'page'):
        request['page'] = args.page
    if getattr(args, 'body', None) is not None:
        request['body'] = args.body
    if getattr(args, 'body_file', None) is not None:
        if args.body_file == '-':
            body = sys.stdin.buffer.read(16385)
        else:
            with open(args.body_file, 'rb') as stream:
                body = stream.read(16385)
        if len(body) > 16384:
            raise ValueError('body too large')
        request['body'] = body.decode('utf-8')
    if getattr(args, 'title', None) is not None:
        request['title'] = args.title
    return request


def exchange(socket_path: str, capability: str, request: dict[str, Any]) -> dict[str, Any]:
    wire = json.dumps({'version': 1, 'capability': capability, 'request': request},
                      allow_nan=False).encode('utf-8') + b'\n'
    if len(wire) > MAX_FRAME:
        raise ValueError('request too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(socket_path)
        sock.sendall(wire)
        deadline = time.monotonic() + 45
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
    return json.loads(bytes(data).decode('utf-8'))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.socket or not args.capability_file:
        print('Use an AIVM secret session, or specify --socket and --capability-file.', file=sys.stderr)
        return 2
    try:
        with open(args.capability_file, 'r', encoding='ascii') as stream:
            capability = stream.read(32769).strip()
        if len(capability) > 32768:
            raise ValueError('capability too large')
        result = exchange(args.socket, capability, request_from_args(args))
        if result.get('ok') is not True:
            # Host-generated codes only; do not echo arbitrary error text.
            code = result.get('error', {}).get('code', 'request_failed')
            if not isinstance(code, str) or not code.replace('_', '').isalnum():
                code = 'request_failed'
            print('aivm-secrets: ' + code[:64], file=sys.stderr)
            return 3
        if args.operation == 'diff':
            sys.stdout.write(result['result'])
        else:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('aivm-secrets: client or transport failure; do not automatically retry writes.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
