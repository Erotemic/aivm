"""Standalone host CLI; AIVM's SSH adapter uses the same broker library."""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import threading
from pathlib import Path

from . import guest
from .broker import Broker
from .core import Binding, Policy
from .envelope import validate_credential
from .errors import SecretsError
from .files import private_directory, read_owned, write_new
from .server import LocalServer
from .sources import credential_from_file, credential_from_gh
from .wire import dumps, loads


def boolean(value: str) -> bool:
    if value.lower() not in {'true', 'false'}:
        raise argparse.ArgumentTypeError('use true or false')
    return value.lower() == 'true'


def load_policy(path: Path) -> Policy:
    try:
        return Policy.parse(loads(read_owned(path, private=False)))
    except SecretsError as ex:
        if ex.code == 'invalid_request':
            raise SecretsError('invalid_policy') from None
        raise


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'gh':
        return guest.main(argv[1:])
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subs = p.add_subparsers(dest='command', required=True)
    check = subs.add_parser('policy-check', allow_abbrev=False)
    check.add_argument('policy', type=Path)
    serve = subs.add_parser('serve', allow_abbrev=False)
    serve.add_argument('--policy', type=Path, required=True)
    serve.add_argument('--runtime-dir', type=Path, required=True,
                       help='New, short, host-only directory. Existing paths are refused.')
    serve.add_argument('--credential-source', choices=['gh', 'file', 'stdin'], required=True)
    serve.add_argument('--token-file', type=Path)
    serve.add_argument('--allow-writes', type=boolean, default=False)
    args = p.parse_args(argv)
    broker = None
    try:
        policy = load_policy(args.policy)
        if args.command == 'policy-check':
            print(dumps({'policy': policy.to_dict(), 'digest': policy.digest}).decode('ascii'))
            return 0
        if args.credential_source == 'file' and args.token_file is None:
            p.error('--credential-source=file requires --token-file')
        if args.credential_source != 'file' and args.token_file is not None:
            p.error('--token-file requires --credential-source=file')
        # Existing directories are never reused with new authority.
        args.runtime_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        private_directory(args.runtime_dir)
        if args.credential_source == 'gh':
            credential = credential_from_gh()
        elif args.credential_source == 'file':
            credential = credential_from_file(args.token_file)
        else:
            credential = validate_credential(sys.stdin.read(4098).rstrip('\n'))
        binding = Binding(os.getuid(), f'local-uid-{os.getuid()}', 'local', secrets.token_hex(16))
        broker = Broker(policy, binding, credential, args.runtime_dir / 'audit.jsonl',
                        allow_writes=args.allow_writes)
        del credential
        with LocalServer(broker, args.runtime_dir / 'broker.sock'):
            write_new(args.runtime_dir / 'capability', broker.capability.encode('ascii'))
            print(f'Serving {policy.repository}; expires after {policy.lifetime_seconds}s.', flush=True)
            print(f'Runtime: {args.runtime_dir}; Ctrl-C revokes this session.', flush=True)
            threading.Event().wait(policy.lifetime_seconds)
        return 0
    except KeyboardInterrupt:
        return 0
    except (SecretsError, OSError) as ex:
        message = str(ex) if isinstance(ex, SecretsError) else 'Host runtime setup failed.'
        print('aivm-secrets: ' + message, file=sys.stderr)
        return 1
    finally:
        if broker is not None:
            try:
                broker.close()
            except SecretsError:
                print('aivm-secrets: audit close failed.', file=sys.stderr)


if __name__ == '__main__':
    raise SystemExit(main())
