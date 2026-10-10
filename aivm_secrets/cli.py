"""Host operator CLI for the secret-use broker.

  policy-check POLICY       validate a policy and print its canonical form
  serve --policy POLICY     hold one session in the foreground
  sessions                  list this user's live sessions
  pending                   show writes waiting for approval, exactly as sent
  approve DIGEST            approve one exact write, once
  deny DIGEST               discard a pending write
  revoke [SESSION]          end a session's authority now
  audit-verify FILE...      check an audit file's hash chain

``invoke``, ``operations``, ``delegate``, ``renounce`` and ``pr`` are the
guest client's verbs and are passed straight through to it.

AIVM's ``aivm ssh --secrets_policy`` runs ``serve`` as a child process, so
the provider credential never enters the AIVM process.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import guest
from .errors import SecretsError

GUEST_VERBS = ('invoke', 'operations', 'delegate', 'renounce', 'pr')
ANNOUNCE_VERSION = 1


def load_policy(path: Path, untrusted: tuple[Path, ...] = ()) -> Any:
    """Read and parse a host-owned policy file into a service spec."""
    from .host.files import outside, read_owned
    from .kernel import codec
    from .kernel.service import parse_policy

    path = Path(path).expanduser()
    outside(path, untrusted, what='policy')
    data = read_owned(path, private=False)
    return parse_policy(codec.loads(data, code='invalid_policy'))


def default_audit_directory() -> Path:
    base = os.environ.get('XDG_STATE_HOME', '')
    root = (
        Path(base)
        if base and os.path.isabs(base)
        else Path.home() / '.local/state'
    )
    return root / 'aivm-secrets' / 'audit'


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='aivm-secrets',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    subs = p.add_subparsers(dest='command', required=True)

    check = subs.add_parser('policy-check', allow_abbrev=False)
    check.add_argument('policy', type=Path)

    serve = subs.add_parser('serve', allow_abbrev=False)
    serve.add_argument('--policy', type=Path, required=True)
    serve.add_argument(
        '--writes',
        choices=['deny', 'approve', 'allow'],
        default='deny',
        help=(
            'deny: reads only (default). approve: each exact write needs a '
            'host `aivm-secrets approve`. allow: policy-listed writes proceed.'
        ),
    )
    token = serve.add_mutually_exclusive_group()
    token.add_argument(
        '--token-file',
        type=Path,
        help='Private host file to use instead of the policy credential source.',
    )
    token.add_argument(
        '--token-stdin',
        action='store_true',
        help='Read the credential from stdin instead of the policy source.',
    )
    serve.add_argument('--access-identity', default='')
    serve.add_argument('--vm', default='')
    serve.add_argument(
        '--audit-dir',
        type=Path,
        help='Private directory for this session audit file.',
    )
    serve.add_argument(
        '--untrusted-root',
        type=Path,
        action='append',
        default=[],
        help=(
            'A guest-writable directory. The broker refuses to start if its '
            'own code, the policy, a credential or a resolver lies inside.'
        ),
    )
    serve.add_argument('--announce', choices=['text', 'json'], default='text')
    serve.add_argument(
        '--exit-on-stdin-eof',
        action='store_true',
        help='Bind the session to its parent: revoke and exit when stdin closes.',
    )

    sessions = subs.add_parser('sessions', allow_abbrev=False)
    sessions.add_argument('--json', action='store_true')
    sessions.add_argument(
        '--prune',
        action='store_true',
        help='Remove directories of dead sessions.',
    )

    pending = subs.add_parser('pending', allow_abbrev=False)
    pending.add_argument('session', nargs='?', default='')
    pending.add_argument('--json', action='store_true')

    for name in ('approve', 'deny'):
        decide = subs.add_parser(name, allow_abbrev=False)
        decide.add_argument('digest')
        decide.add_argument('--session', default='')
        if name == 'approve':
            decide.add_argument('--ttl', type=int, default=300)
            decide.add_argument(
                '--yes',
                '-y',
                action='store_true',
                help='Do not ask to confirm.',
            )

    revoke = subs.add_parser('revoke', allow_abbrev=False)
    revoke.add_argument('session', nargs='?', default='')
    revoke.add_argument('--all', action='store_true')
    revoke.add_argument('--access-identity', default='')
    revoke.add_argument('--vm', default='')
    revoke.add_argument('--grant', default='')

    verify = subs.add_parser('audit-verify', allow_abbrev=False)
    verify.add_argument('files', type=Path, nargs='+')
    return p


def _say(text: str, *, stream: Any = None) -> None:
    """Write one line, tolerating a reader that has gone away.

    A broker whose parent was killed still has cleanup to finish. If the
    pipe is broken, point the descriptor at ``/dev/null`` so that neither
    this write nor the interpreter's flush at exit can raise.
    """
    stream = sys.stdout if stream is None else stream
    try:
        print(text, file=stream, flush=True)
    except (OSError, ValueError):
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())
        except (OSError, ValueError):
            pass


def _announce(mode: str, payload: dict[str, Any]) -> None:
    if mode == 'json':
        _say(json.dumps(payload, sort_keys=True))


def _serve(args: argparse.Namespace) -> int:
    from .host.broker import Broker
    from .host.files import outside, private_directory, write_new
    from .host.hardening import harden_process
    from .host.server import LocalServer
    from .host.session import (
        CAPABILITY_FILE,
        remove_session_directory,
        session_directory,
    )
    from .host.sources import (
        credential_from_file,
        credential_from_stream,
        resolve_source,
    )
    from .kernel.model import Binding

    if args.token_stdin and args.exit_on_stdin_eof:
        raise SecretsError(
            'credential_source',
            detail='stdin cannot carry both a token and EOF',
        )
    harden_process()
    untrusted = tuple(args.untrusted_root)
    # A broker loaded from a tree the guest can write is not a boundary, and
    # neither is one whose interpreter and libraries live there (a project
    # virtualenv inside the shared folder, say).
    outside(Path(__file__).resolve().parent, untrusted, what='broker code')
    outside(Path(sys.prefix), untrusted, what='broker python environment')
    spec = load_policy(args.policy, untrusted)
    if args.token_file is not None:
        credential = credential_from_file(
            args.token_file.expanduser(), untrusted=untrusted
        )
    elif args.token_stdin:
        credential = credential_from_stream(sys.stdin.buffer)
    else:
        credential = resolve_source(spec.credential_source, untrusted=untrusted)
    channel = secrets.token_hex(16)
    binding = Binding(
        os.getuid(),
        args.access_identity or f'local-uid-{os.getuid()}',
        args.vm or 'local',
        channel,
    )
    audit_dir = private_directory(
        (args.audit_dir or default_audit_directory()).expanduser()
    )
    directory = session_directory(channel)
    broker = None
    announced = False
    stop = threading.Event()
    try:
        broker = Broker(
            spec,
            binding,
            credential,
            audit_dir / f'{channel}.jsonl',
            writes=args.writes,
        )
        del credential
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, lambda *_: stop.set())
        with LocalServer(broker, directory) as server:
            capability_file = directory / CAPABILITY_FILE
            write_new(capability_file, broker.capability.encode('ascii'))
            status = broker.status()
            _announce(
                args.announce,
                {
                    'aivm_secrets': ANNOUNCE_VERSION,
                    'channel': channel,
                    'socket': str(server.socket_path),
                    'control': str(server.control_path),
                    'capability_file': str(capability_file),
                    'client': str(Path(guest.__file__).resolve()),
                    'audit': status['audit'],
                    'service': status['service'],
                    'operations': status['operations'],
                    'client_aliases': list(spec.client_aliases),
                    'writes': status['writes'],
                    'expires_at': status['expires_at'],
                    'lifetime_seconds': spec.lifetime_seconds,
                },
            )
            announced = True
            if args.announce == 'text':
                print(
                    f'Serving {status["service"]} (writes: {args.writes}); '
                    f'expires after {spec.lifetime_seconds}s.\n'
                    f'Session: {channel}\n'
                    f'  export AIVM_SECRETS_SOCKET={server.socket_path}\n'
                    f'  export AIVM_SECRETS_CAPABILITY_FILE={capability_file}\n'
                    f'Audit: {status["audit"]}\n'
                    'Ctrl-C revokes this session.',
                    flush=True,
                )
            if args.exit_on_stdin_eof:
                # The parent owns the lifetime. Stay up past expiry so the
                # guest is told ``expired`` rather than losing its socket.
                threading.Thread(
                    target=_wait_for_eof, args=(stop,), daemon=True
                ).start()
                stop.wait()
            else:
                stop.wait(spec.lifetime_seconds)
        return 0
    finally:
        # Order matters: end authority and remove the runtime files first.
        # The parent may already be dead, and nothing below may depend on
        # being able to tell it anything.
        head = ''
        if broker is not None:
            try:
                broker.close()
                head = broker.status()['audit_head']
            except SecretsError:
                _say('aivm-secrets: audit close failed.', stream=sys.stderr)
        remove_session_directory(directory)
        if head and announced:
            # The digest an operator can keep to detect later truncation.
            if args.announce == 'text':
                _say(f'Session closed. Audit head: {head}')
            else:
                _announce(
                    'json',
                    {
                        'aivm_secrets': ANNOUNCE_VERSION,
                        'closed': True,
                        'audit_head': head,
                    },
                )


def _wait_for_eof(stop: threading.Event) -> None:
    """Set ``stop`` when the parent closes (or dies holding) our stdin.

    Reads the raw descriptor on purpose. A daemon thread blocked inside the
    buffered ``sys.stdin`` object holds its lock, and the interpreter aborts
    at shutdown if it cannot take that lock back.
    """
    try:
        descriptor = sys.stdin.fileno()
        while os.read(descriptor, 4096):
            pass
    except (OSError, ValueError):
        pass
    stop.set()


def _selected(args: argparse.Namespace, **binding: str) -> list[dict[str, Any]]:
    from .host.session import find_sessions

    found = find_sessions(getattr(args, 'session', ''), **binding)
    if not found:
        raise SecretsError('no_session')
    return found


def _control(
    session: dict[str, Any], command: dict[str, Any]
) -> dict[str, Any]:
    from .host.session import control_call

    return control_call(Path(session['directory']), command)


def _require_ok(reply: dict[str, Any]) -> dict[str, Any]:
    if reply.get('ok') is not True:
        error = reply.get('error')
        code = error.get('code') if isinstance(error, dict) else ''
        raise SecretsError(code if isinstance(code, str) else 'internal_error')
    return reply


def _sessions(args: argparse.Namespace) -> int:
    from .host.session import list_sessions

    found = list_sessions(prune=args.prune)
    if args.json:
        print(json.dumps(found, indent=2, sort_keys=True))
        return 0
    if not found:
        print('No live secret sessions.')
        return 0
    now = int(time.time())
    for item in found:
        state = 'active' if item['active'] else 'revoked'
        remaining = max(0, item['expires_at'] - now)
        print(
            f'{item["channel"][:12]}  {item["service"]}  vm={item["vm"]}  '
            f'identity={item["access_identity"]}  writes={item["writes"]}  '
            f'{state}  used={item["used"]}/{item["max_requests"]}  '
            f'expires_in={remaining}s  pending={item["pending"]}'
        )
    return 0


def _pending_items(args: argparse.Namespace) -> list[dict[str, Any]]:
    result = []
    for session in _selected(args):
        reply = _require_ok(_control(session, {'command': 'pending'}))
        for item in reply['pending']:
            result.append(dict(item, session=session['channel'], _at=session))
    return result


def _show_pending(item: dict[str, Any]) -> None:
    age = max(0, int(time.time()) - int(item['requested_at']))
    print(
        f'{item["digest"][:16]}  session={item["session"][:12]}  '
        f'{item["operation"]}  requested {age}s ago'
    )
    print(
        json.dumps(
            item['arguments'], indent=2, ensure_ascii=True, sort_keys=True
        )
    )


def _pending(args: argparse.Namespace) -> int:
    items = _pending_items(args)
    if args.json:
        public = [
            {k: v for k, v in item.items() if k != '_at'} for item in items
        ]
        print(json.dumps(public, indent=2, sort_keys=True))
        return 0
    if not items:
        print('No writes are waiting for approval.')
    for item in items:
        _show_pending(item)
    return 0


def _decide(args: argparse.Namespace) -> int:
    matches = [
        item
        for item in _pending_items(args)
        if item['digest'].startswith(args.digest)
    ]
    if len(args.digest) < 8 or len(matches) != 1:
        raise SecretsError(
            'no_session',
            detail='the digest must match exactly one pending write',
        )
    item = matches[0]
    command: dict[str, Any] = {
        'command': args.command,
        'digest': item['digest'],
    }
    if args.command == 'approve':
        # The operator approves bytes, not a description: show them.
        _show_pending(item)
        if not args.yes:
            if not sys.stdin.isatty():
                raise SecretsError(
                    'invalid_request',
                    detail='pass --yes to approve without a terminal',
                )
            answer = input('Send exactly this write, once? [y/N] ')
            if answer.strip().lower() not in ('y', 'yes'):
                print('Not approved.')
                return 1
        command['ttl'] = args.ttl
    _require_ok(_control(item['_at'], command))
    done = 'Approved' if args.command == 'approve' else 'Discarded'
    print(f'{done} {item["digest"][:16]} ({item["operation"]}).')
    return 0


def _revoke(args: argparse.Namespace) -> int:
    binding = {'access_identity': args.access_identity, 'vm': args.vm}
    if not (args.session or args.all or args.access_identity or args.vm):
        raise SecretsError(
            'invalid_request',
            detail='name a session, an identity/VM, or pass --all',
        )
    for session in _selected(args, **binding):
        _require_ok(
            _control(session, {'command': 'revoke', 'grant': args.grant})
        )
        print(f'Revoked {session["channel"][:12]} ({session["service"]}).')
    return 0


def _audit_verify(args: argparse.Namespace) -> int:
    from .host.audit import verify

    for path in args.files:
        count, head = verify(path)
        print(f'{path}: {count} records, chain intact, head {head}')
    return 0


def _is_guest_invocation(argv: list[str]) -> bool:
    """True when the first word after the client's own options is its verb."""
    index = 0
    while index < len(argv):
        word = argv[index]
        if word in ('--socket', '--capability-file'):
            index += 2
        elif word.startswith(('--socket=', '--capability-file=')):
            index += 1
        else:
            return word in GUEST_VERBS
    return False


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == 'gh':
        return guest.main(argv[1:])
    if _is_guest_invocation(argv):
        return guest.main(argv)
    args = _parser().parse_args(argv)
    announce = getattr(args, 'announce', 'text')
    try:
        if args.command == 'policy-check':
            from .kernel import codec

            spec = load_policy(args.policy)
            report = {'policy': spec.to_dict(), 'digest': spec.digest}
            print(codec.dumps(report).decode('ascii'))
            return 0
        handler = {
            'serve': _serve,
            'sessions': _sessions,
            'pending': _pending,
            'approve': _decide,
            'deny': _decide,
            'revoke': _revoke,
            'audit-verify': _audit_verify,
        }[args.command]
        return handler(args)
    except KeyboardInterrupt:
        return 0
    except SecretsError as ex:
        _announce(
            announce,
            {
                'aivm_secrets': ANNOUNCE_VERSION,
                'error': {
                    'code': ex.code,
                    'message': str(ex),
                    'detail': ex.detail,
                },
            },
        )
        _say('aivm-secrets: ' + ex.for_operator(), stream=sys.stderr)
        return 1
    except OSError:
        _say('aivm-secrets: Host runtime setup failed.', stream=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
