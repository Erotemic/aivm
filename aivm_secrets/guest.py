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
import ssl
import configparser
from pathlib import Path
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
        # The guest client is not a trust boundary, but must never fall back
        # to the unbound wire when this explicitly provisioned mode is chosen.
        if os.environ.get('AIVM_SECRETS_IDENTITY_MODE', '') == 'mtls-v1':
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.keylog_filename = None
            ctx.load_verify_locations(cafile=os.environ['AIVM_SECRETS_IDENTITY_CA'])
            ctx.load_cert_chain(
                certfile=os.environ['AIVM_SECRETS_IDENTITY_CERT'],
                keyfile=os.environ['AIVM_SECRETS_IDENTITY_KEY'],
            )
            connection = ctx.wrap_socket(sock, server_hostname='localhost')
        elif os.environ.get('AIVM_SECRETS_IDENTITY_MODE', ''):
            raise ValueError('invalid identity mode (no plaintext fallback)')
        else:
            connection = sock
        with connection:
            connection.settimeout(5.0)
            connection.sendall(wire + b'\n')
            deadline = time.monotonic() + 60
            data = bytearray()
            while b'\n' not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('response deadline')
                connection.settimeout(remaining)
                chunk = connection.recv(min(16384, MAX_REPLY + 1 - len(data)))
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


def _repository_from_url(value: str, host: str) -> str:
    """Interpret recognized remote formats without network access or tools."""
    text = value.strip()
    repo = ''
    for prefix in (
        f'git@{host}:', f'ssh://git@{host}/', f'https://{host}/',
    ):
        if text.startswith(prefix):
            repo = text[len(prefix):]
            break
    if repo.endswith('.git'):
        repo = repo[:-4]
    parts = repo.split('/')
    allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-'
    if (len(parts) != 2 or not all(parts) or
            not all(len(part) <= 100 and all(ch in allowed for ch in part)
                    for part in parts) or any(part in ('.', '..') for part in parts)):
        raise Usage('cannot infer a valid repository; supply --repo')
    return repo


def _git_config() -> configparser.RawConfigParser | None:
    """Read local git config as inert data, including linked worktree gitdirs.

    Never invoke ``git`` or its credential helpers; the guest client must
    remain a single, stdlib-only script that only opens its Unix socket.
    """
    directory = Path.cwd()
    for folder in (directory, *directory.parents):
        dotgit = folder / '.git'
        if not dotgit.exists():
            continue
        if dotgit.is_dir():
            config = dotgit / 'config'
        else:
            try:
                pointer = dotgit.read_text(encoding='utf-8')[:4096]
                if not pointer.startswith('gitdir: '):
                    return None
                gitdir = Path(pointer[8:].strip())
                if not gitdir.is_absolute():
                    gitdir = folder / gitdir
                # Worktree gitdir has a commondir pointer to the real config.
                shared = gitdir / 'commondir'
                if shared.is_file():
                    common = Path(shared.read_text(encoding='utf-8')[:4096].strip())
                    config = (gitdir / common / 'config') if not common.is_absolute() else common / 'config'
                else:
                    config = gitdir / 'config'
            except (OSError, UnicodeError):
                return None
        try:
            if config.stat().st_size > 65536:
                return None
            reader = configparser.RawConfigParser(interpolation=None)
            with config.open(encoding='utf-8') as stream:
                reader.read_file(stream)
            return reader
        except (OSError, UnicodeError, configparser.Error):
            return None
    return None


def _infer_repository(row: dict[str, Any]) -> tuple[str, str] | None:
    """Resolve an untrusted guest-side default; host scope still decides."""
    spec = row.get('repository_default')
    if not isinstance(spec, dict) or not spec:
        return None
    parameter = spec['parameter']
    env_name = spec['environment']
    host = spec['host']
    remote = spec['remote']
    candidate = os.environ.get(env_name)
    if candidate:
        candidate = _repository_from_url(f'git@{host}:{candidate}', host)
        return parameter, candidate
    config = _git_config()
    if config is not None:
        for name in (remote, 'origin'):
            section = f'remote "{name}"'
            if config.has_option(section, 'url'):
                candidate = _repository_from_url(config.get(section, 'url'), host)
                return parameter, candidate
    raise Usage('cannot infer a repository; supply --repo or set ' + env_name)


def _projection(data: Any, path: list[str]) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _render_json_result(reply: dict[str, Any], row: dict[str, Any],
                        names: list[str]) -> None:
    """A bounded local projection; the broker already authorized the read."""
    fields = row['json_fields']
    data = _projection(reply.get('result'), row.get('json_at', []))
    if ('reviews' in names and row.get('incomplete_when') and
            _projection(data, row['incomplete_when']) is True):
        raise Usage('more review pages exist; this client cannot return a complete review list')
    if row.get('json_complete') and reply.get('pagination', {}).get('possibly_more'):
        raise Usage('more result pages exist; use a paged read')
    rules = row.get('json_rules', {})
    def field(item: Any, name: str) -> Any:
        value = _projection(item, fields[name])
        rule = rules.get(name) if isinstance(rules, dict) else None
        if isinstance(rule, dict):
            if value is None:
                value = _projection(item, rule.get('fallback', []))
            if isinstance(value, str):
                value = rule.get('map', {}).get(value, value)
        return value
    if row.get('json_list'):
        if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
            raise ValueError('unexpected list result')
        result = [
            {name: field(item, name) for name in names}
            for item in data
        ]
    else:
        if not isinstance(data, dict):
            raise ValueError('unexpected object result')
        result = {name: field(data, name) for name in names}
    print(json.dumps(result, ensure_ascii=True))


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
    json_selection: list[str] | None = None
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
        if flag == '--json' and isinstance(row.get('json_fields'), dict):
            if json_selection is not None:
                raise Usage('an argument was given twice')
            if joined:
                field_text = attached
            elif index < len(rest):
                field_text = rest[index]
                index += 1
            else:
                raise Usage('an option is missing its value')
            json_selection = field_text.split(',')
            permitted = row['json_fields']
            alternate = row.get('json_alternative')
            alternative = (
                alternate.get('json_fields', {})
                if isinstance(alternate, dict) else {}
            )
            if (not json_selection or len(json_selection) > 32 or
                    len(set(json_selection)) != len(json_selection) or
                    (not set(json_selection) <= set(permitted) and
                     not set(json_selection) <= set(alternative))):
                raise Usage('unsupported JSON field here')
            continue
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
    if 'repository_default' in row:
        inferred_param = row['repository_default']['parameter']
        if inferred_param not in arguments:
            inferred = _infer_repository(row)
            if inferred is not None:
                arguments[inferred[0]] = inferred[1]
    request = {'operation': row.get('operation'), 'arguments': arguments}
    if json_selection is not None:
        if not set(json_selection) <= set(row['json_fields']):
            request['operation'] = row['json_alternative']['operation']
            return request, 'jsonalt:' + ','.join(json_selection)
        return request, 'json:' + ','.join(json_selection)
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
    if output.startswith(('json:', 'jsonalt:')):
        row, _ = _matching(rows, words)
        try:
            if output.startswith('jsonalt:'):
                _render_json_result(reply, row['json_alternative'],
                                    output[len('jsonalt:'):].split(','))
            else:
                _render_json_result(reply, row, output[5:].split(','))
        except Usage as problem:
            print(f'{shown}: {problem}', file=sys.stderr)
            return 2
    else:
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
