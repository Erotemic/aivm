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
  as NAME WORDS...                      speak another tool's command line

A session's policy may give this client other names. Installed under one of
them (a ``gh`` symlink, say) -- or run as ``aivm-secrets as gh ...`` -- it
translates that tool's command line into an ordinary request, using a
command table the broker sends. The table is data from the operator's
policy; nothing about any particular tool is built into this file, and a
command the table does not list is an error, never a fallback.

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
WORD = 'abcdefghijklmnopqrstuvwxyz0123456789-'


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

    alias = groups.add_parser(
        'as',
        allow_abbrev=False,
        help="Run a command line of another tool this session's policy maps",
    )
    alias.add_argument('alias')
    alias.add_argument('words', nargs=argparse.REMAINDER)
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
    raise ValueError('not a frame-producing command')


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


class Usage(Exception):
    """The command line does not fit the session's command table."""


def _word(value: Any) -> str:
    """A table word that is safe to print: this is data from a peer."""
    if isinstance(value, str) and value and all(c in WORD for c in value):
        return value[:32]
    return '?'


def _matching(rows: Any, words: list[str]) -> tuple[dict[str, Any], list[str]]:
    """The table row whose command words are the longest prefix of ``words``."""
    best: dict[str, Any] | None = None
    for row in rows if isinstance(rows, list) else []:
        command = row.get('command') if isinstance(row, dict) else None
        if not isinstance(command, list) or not command:
            continue
        if words[: len(command)] == command and (
            best is None or len(command) > len(best['command'])
        ):
            best = row
    if best is None:
        known = sorted(
            ' '.join(_word(w) for w in row['command'])
            for row in rows
            if isinstance(row, dict) and isinstance(row.get('command'), list)
        )
        raise Usage('available here: ' + ('; '.join(known) or '(nothing)'))
    return best, words[len(best['command']) :]


def _typed(operation: dict[str, Any], name: str, text: str) -> Any:
    """Give a command-line string the type the operation declares for it."""
    spec = operation.get('parameters', {}).get(name)
    numeric = isinstance(spec, dict) or (
        isinstance(spec, list) and spec and type(spec[0]) is int
    )
    if not numeric:
        return text
    try:
        return int(text, 10)
    except ValueError:
        raise Usage(f'{_word(name)} must be a number') from None


def request_from_alias(
    rows: Any, operations: Any, words: list[str]
) -> tuple[dict[str, Any], str]:
    """Translate ``words`` into a request, using only the supplied table.

    Returns the request and the row's output mode. Raises :class:`Usage` for
    anything the table does not describe.
    """
    row, rest = _matching(rows, words)
    options = row.get('options', {})
    positional = list(row.get('positional', []))
    operation = {}
    for item in operations if isinstance(operations, list) else []:
        if isinstance(item, dict) and item.get('name') == row.get('operation'):
            operation = item
    arguments: dict[str, Any] = {}
    values: list[str] = []
    index = 0
    literal = False
    while index < len(rest):
        token = rest[index]
        index += 1
        if literal or not token.startswith('-') or token == '-':
            values.append(token)
            continue
        if token == '--':
            literal = True
            continue
        flag, joined, attached = token.partition('=')
        if not isinstance(options, dict) or flag not in options:
            raise Usage('unsupported option here')
        if joined:
            text = attached
        elif index < len(rest):
            text = rest[index]
            index += 1
        else:
            raise Usage('an option is missing its value')
        destination = str(options[flag])
        from_file = destination.startswith('@')
        destination = destination.lstrip('@')
        if destination in arguments:
            raise Usage('an argument was given twice')
        if from_file:
            try:
                text = read_bounded(text)
            except (OSError, ValueError):
                raise Usage('cannot read the file given to an option') from None
        arguments[destination] = _typed(operation, destination, text)
    if len(values) != len(positional):
        raise Usage('wrong number of arguments')
    for name, text in zip(positional, values):
        if name in arguments:
            raise Usage('an argument was given twice')
        arguments[name] = _typed(operation, str(name), text)
    request = {'operation': row.get('operation'), 'arguments': arguments}
    return request, str(row.get('output', 'reply'))


def print_result(reply: dict[str, Any], *, raw: bool) -> None:
    result = reply.get('result')
    if raw and isinstance(result, str):
        sys.stdout.write(result)
    elif raw:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(json.dumps(reply, indent=2, ensure_ascii=True))


def run_alias(
    alias: str, words: list[str], socket_path: str, capability: str
) -> int:
    """Answer to another tool's name, for the commands the policy maps."""
    described = exchange(socket_path, capability, True, 'describe')
    if described.get('ok') is not True:
        return report_failure(described)
    tables = described.get('cli')
    rows = tables.get(alias) if isinstance(tables, dict) else None
    shown = _word(alias)
    if rows is None:
        print(
            f'aivm-secrets: this session has no {shown} commands; '
            'see `aivm-secrets operations`.',
            file=sys.stderr,
        )
        return 2
    grant = described.get('grant')
    operations = grant.get('operations') if isinstance(grant, dict) else []
    try:
        request, output = request_from_alias(rows, operations, words)
    except Usage as problem:
        print(
            f'{shown}: this is the aivm-secrets client, not the real {shown}; '
            f'only commands the session policy lists work. {problem}',
            file=sys.stderr,
        )
        return 2
    reply = exchange(socket_path, capability, request)
    if reply.get('ok') is not True:
        return report_failure(reply)
    print_result(reply, raw=output == 'result')
    return 0


def read_capability(path: str) -> str:
    with open(path, 'r', encoding='ascii') as stream:
        capability = stream.read(32769).strip()
    if len(capability) > 32768:
        raise ValueError('capability too large')
    return capability


def invoked_alias() -> str:
    """The other name this file was run under, if any (a symlink to it)."""
    name = os.path.basename(sys.argv[0])
    real = os.path.basename(os.path.realpath(sys.argv[0]))
    return name if name != real else ''


TRANSPORT_FAILURE = (
    'aivm-secrets: client or transport failure; do not automatically '
    'retry writes.'
)


def main(argv: list[str] | None = None, alias: str = '') -> int:
    if argv is None:
        argv = sys.argv[1:]
        alias = alias or invoked_alias()
    if alias:
        # The whole command line belongs to the other tool; the session is
        # found through the environment only.
        socket_path = os.environ.get('AIVM_SECRETS_SOCKET', '')
        capability_file = os.environ.get('AIVM_SECRETS_CAPABILITY_FILE', '')
        if not socket_path or not capability_file:
            print(f'{_word(alias)}: no AIVM secret session.', file=sys.stderr)
            return 2
        try:
            return run_alias(
                alias, list(argv), socket_path, read_capability(capability_file)
            )
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            print(TRANSPORT_FAILURE, file=sys.stderr)
            return 2
    args = parser().parse_args(argv)
    if not args.socket or not args.capability_file:
        print(
            'Use an AIVM secret session, or specify --socket and '
            '--capability-file.',
            file=sys.stderr,
        )
        return 2
    try:
        capability = read_capability(args.capability_file)
        if args.group == 'as':
            return run_alias(args.alias, args.words, args.socket, capability)
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
        print_result(reply, raw=getattr(args, 'result_only', False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print(TRANSPORT_FAILURE, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
