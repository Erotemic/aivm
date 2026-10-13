"""Explicit host operator commands for P4a offline enrollment and mTLS.

No default background service. No VM is modified. No external service credential or
provider API is needed for these commands. Only the `request` subcommand is
suitable for execution inside the untrusted guest; all other operations are
host principal-controlled.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from ..errors import SecretsError
from ..host.files import private_directory, read_owned
from ..primitives import codec
from .enrollment import IdentityAuthority
from .certificates import MAX_CSR_BYTES, create_csr, inspect_csr
from .service import UnixIdentityService

DEFAULT_ROOT = Path('~/.config/aivm/secrets/identity')


def add_parser(subs):
    p = subs.add_parser('identity', allow_abbrev=False,
                        help='Opt-in host CA, enrollment and mTLS bridge (P4a)')
    actions = p.add_subparsers(dest='identity_action', required=True)

    def common(name, *, authority=True):
        target = actions.add_parser(name, allow_abbrev=False)
        if authority:
            target.add_argument('--root', type=Path, default=DEFAULT_ROOT)
            target.add_argument('--untrusted-root', type=Path, action='append', default=[])
        return target

    init = common('init')
    init.add_argument('--issuer', default='aivm.local')
    init.add_argument('--audience', default='aivm-secrets.identity')

    request = common('request', authority=False)
    request.add_argument('--key', type=Path, required=True)
    request.add_argument('--csr', type=Path, required=True)

    inspect = common('inspect-csr', authority=False)
    inspect.add_argument('--csr', type=Path, required=True)

    enroll = common('enroll')
    enroll.add_argument('--subject', required=True)
    enroll.add_argument('--csr', type=Path, required=True)
    enroll.add_argument('--approve-key-fingerprint', required=True)
    enroll.add_argument('--replace', action='store_true')
    # Optional compare-and-swap for --replace: both or neither. Without them a
    # replacement is unconditional (the operator's emergency path).
    enroll.add_argument('--expected-epoch', type=int)
    enroll.add_argument('--expected-certificate-sha256')

    status = common('status')

    public = common('public-client')
    public.add_argument('--subject', required=True)

    revoke = common('revoke')
    revoke.add_argument('--subject', required=True)
    guarded_revoke = common('revoke-if-current')
    guarded_revoke.add_argument('--subject', required=True)
    guarded_revoke.add_argument('--expected-epoch', type=int, required=True)
    guarded_revoke.add_argument('--expected-certificate-sha256', required=True)

    renew_client = common('renew-client')
    renew_client.add_argument('--subject', required=True)
    renew_client.add_argument('--csr', type=Path, required=True)
    renew_client.add_argument('--approve-key-fingerprint', required=True)
    renew_client.add_argument('--expected-epoch', required=True, type=int)
    renew_client.add_argument('--expected-certificate-sha256', required=True)

    rekey = common('rotate-client-key')
    rekey.add_argument('--subject', required=True)
    rekey.add_argument('--csr', type=Path, required=True)
    rekey.add_argument('--approve-key-fingerprint', required=True)
    rekey.add_argument('--expected-epoch', required=True, type=int)
    rekey.add_argument('--expected-certificate-sha256', required=True)

    common('renew-server')
    rotate_ca = common('rotate-ca')
    # Required CAS: the SHA-256 of the active CA certificate (identity status
    # prints it as ca_sha256). A stale or repeated run is refused.
    rotate_ca.add_argument('--expected-ca-sha256', required=True)

    forget = common('forget')
    forget.add_argument('--subject', required=True)
    common('prune')

    rotate = common('rotate-issuer')
    retire = common('retire-issuer')
    retire.add_argument('--key-id', required=True)

    issue = common('issue')
    issue.add_argument('--subject', required=True)
    issue.add_argument('--capability-file', type=Path, required=True)
    issue.add_argument('--output', type=Path, required=True)
    issue.add_argument('--lifetime', type=int, default=900)

    call = common('call', authority=False)
    call.add_argument('--socket', type=Path, required=True)
    call.add_argument('--ca', type=Path, required=True)
    call.add_argument('--certificate', type=Path, required=True)
    call.add_argument('--key', type=Path, required=True)
    call.add_argument('--jwt-file', type=Path, required=True)
    call.add_argument('--request', required=True,
                      help='JSON operation object, not HTTP or GraphQL text')

    # Separate host-only OAuth credential acquisition, without an AIVM VM or
    # trusted Garrett identity authority. Provider manifests and vault contents
    # stay on the host; the ordinary authorized broker consumes access tokens.
    for name in ('oauth-init', 'oauth-login', 'oauth-status',
                 'oauth-revoke', 'oauth-refresh'):
        oauth = common(name, authority=False)
        oauth.add_argument('--vault', type=Path, required=True)
        oauth.add_argument('--untrusted-root', type=Path, action='append', default=[])
        if name != 'oauth-init':
            oauth.add_argument('--provider-config', type=Path, required=True)
            oauth.add_argument('--subject', required=True)
        if name == 'oauth-login':
            oauth.add_argument('--replace', action='store_true')
            oauth.add_argument('--timeout', type=int, default=180)

    bridge = common('bridge')
    bridge.add_argument('--broker-socket', type=Path, required=True)
    bridge.add_argument('--listen', type=Path, required=True)
    bridge.add_argument('--max-connections', type=int, default=64)
    bridge.add_argument('--idle-seconds', type=int, default=900)
    bridge.add_argument('--exit-on-stdin-eof', action='store_true',
                        help='Keep the bridge alive only while its parent holds stdin')


def _csr_data(path: Path) -> bytes:
    # CSRs are guest-supplied and intentionally untrusted. Open without
    # following the final symlink and bound the read before parsing ASN.1.
    path = Path(path).expanduser().absolute()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CSR_BYTES:
                raise SecretsError('invalid_capability')
            data = handle.read(MAX_CSR_BYTES + 1)
            if len(data) > MAX_CSR_BYTES:
                raise SecretsError('invalid_capability')
            return data
    except OSError:
        raise SecretsError('invalid_capability') from None


def run(args: argparse.Namespace) -> int:
    if args.identity_action == 'request':
        key = args.key.expanduser().absolute()
        csr = args.csr.expanduser().absolute()
        private_directory(key.parent)
        print(codec.dumps({'key_fingerprint': create_csr(
            private_key=key, request_file=csr),
            'csr': str(csr), 'key': str(key),
            'security': 'exportable software key; no VM attestation',
        }).decode('ascii'))
        return 0
    if args.identity_action == 'inspect-csr':
        print(codec.dumps({'key_fingerprint': inspect_csr(_csr_data(args.csr))}).decode())
        return 0
    if args.identity_action == 'call':
        from .client import bound_call
        request = codec.loads(args.request, limit=8192)
        if type(request) is not dict:
            raise SecretsError('invalid_request')
        result = bound_call(
            socket_path=args.socket, ca=args.ca, certificate=args.certificate,
            private_key=args.key, jwt_file=args.jwt_file, request=request,
        )
        print(codec.dumps(result).decode('ascii'))
        return 0 if result.get('ok') is True else 1

    # The OAuth layer is independently usable; no enrollment CA, VM or
    # provider credential is initialized by merely importing this CLI.
    if args.identity_action.startswith('oauth-'):
        if not sys.flags.isolated:
            raise SecretsError('unsafe_file', detail='OAuth host commands require python -I')
        from ..host.hardening import harden_process, verify_runtime
        from .oauth_provider import load_provider
        from .oauth_vault import OAuthVault
        from .oauth_transport import (HostCallback, PinnedOAuthHTTP,
                                      new_pending, authorization_url,
                                      exchange_code)
        import time
        roots = tuple(args.untrusted_root)
        harden_process()
        verify_runtime(roots)
        if args.identity_action == 'oauth-init':
            OAuthVault.initialize(args.vault, untrusted=roots)
            print(codec.dumps({'initialized': True}).decode())
            return 0
        provider = load_provider(args.provider_config, untrusted=roots)
        vault = OAuthVault(args.vault, untrusted=roots)
        if args.identity_action == 'oauth-status':
            answer = vault.status(provider, args.subject)
        elif args.identity_action == 'oauth-revoke':
            answer = vault.revoke(provider, args.subject)
        elif args.identity_action == 'oauth-refresh':
            # Explicit refresh; the return token stays in this host process.
            vault.credential_for_session(provider, args.subject,
                                         resource_host=provider.resource_host,
                                         force_refresh=True)
            answer = vault.status(provider, args.subject)
        elif args.identity_action == 'oauth-login':
            if not 1 <= args.timeout <= 600:
                raise SecretsError('invalid_policy')
            pending = new_pending(provider)
            with HostCallback(provider, pending) as callback:
                print('Open this URL in a trusted host browser:', flush=True)
                print(authorization_url(provider, pending), flush=True)
                params = callback.wait(timeout=args.timeout)
            grant = exchange_code(provider, pending, params,
                                  now=int(time.time()), transport=PinnedOAuthHTTP(),
                                  untrusted=roots)
            answer = vault.enroll(provider, args.subject, grant,
                                  replace=args.replace)
        else:
            raise SecretsError('invalid_request')
        print(codec.dumps(answer).decode('ascii'))
        return 0

    # Identity host operations handle CA/signing keys and broker capabilities.
    # Isolated Python must ignore PYTHONPATH, user-site hooks and CWD BEFORE
    # this module is imported. Unlike broker spawn, this is a manual command.
    if not sys.flags.isolated:
        raise SecretsError('unsafe_file', detail=(
            'host identity commands require python -I -m aivm_secrets '
            'identity ... from a trusted installation'))
    from ..host.hardening import harden_process, verify_runtime
    untrusted = tuple(args.untrusted_root)
    harden_process()
    verify_runtime(untrusted)
    if args.identity_action == 'init':
        authority = IdentityAuthority.initialize(
            args.root, issuer=args.issuer, audience=args.audience,
            untrusted=untrusted,
        )
        print(codec.dumps(authority.status()).decode())
        return 0

    authority = IdentityAuthority(args.root, untrusted=untrusted)
    if args.identity_action == 'enroll':
        result = authority.enroll(
            subject=args.subject, csr=_csr_data(args.csr),
            approve_fingerprint=args.approve_key_fingerprint,
            replace=args.replace, expected_epoch=args.expected_epoch,
            expected_thumbprint=args.expected_certificate_sha256,
        )
    elif args.identity_action == 'revoke':
        result = authority.revoke(args.subject)
    elif args.identity_action == 'revoke-if-current':
        result = authority.revoke_if_current(
            subject=args.subject, expected_epoch=args.expected_epoch,
            expected_thumbprint=args.expected_certificate_sha256,
        )
    elif args.identity_action == 'renew-client':
        result = authority.renew_client(
            subject=args.subject, csr=_csr_data(args.csr),
            approve_fingerprint=args.approve_key_fingerprint,
            expected_epoch=args.expected_epoch,
            expected_thumbprint=args.expected_certificate_sha256,
        )
    elif args.identity_action == 'rotate-client-key':
        result = authority.rotate_client_key(
            subject=args.subject, csr=_csr_data(args.csr),
            approve_fingerprint=args.approve_key_fingerprint,
            expected_epoch=args.expected_epoch,
            expected_thumbprint=args.expected_certificate_sha256,
        )
    elif args.identity_action == 'renew-server':
        result = authority.renew_server()
    elif args.identity_action == 'rotate-ca':
        result = authority.rotate_ca(expected_ca_sha256=args.expected_ca_sha256)
    elif args.identity_action == 'forget':
        result = authority.forget(args.subject)
    elif args.identity_action == 'prune':
        result = authority.prune()
    elif args.identity_action == 'status':
        result = authority.status()
    elif args.identity_action == 'rotate-issuer':
        result = authority.rotate_issuer()
    elif args.identity_action == 'retire-issuer':
        result = authority.retire_issuer(args.key_id)
    elif args.identity_action == 'public-client':
        result = authority.public_client(args.subject)
    elif args.identity_action == 'issue':
        inner = read_owned(args.capability_file.expanduser().absolute(),
                           private=True, untrusted=untrusted,
                           what='local broker capability').decode('ascii')
        result = authority.issue(
            subject=args.subject, broker_capability=inner.strip(),
            output=args.output, lifetime=args.lifetime,
        )
    elif args.identity_action == 'bridge':
        with UnixIdentityService(
            authority=authority, broker_socket=args.broker_socket,
            listen=args.listen, max_connections=args.max_connections,
            idle_seconds=args.idle_seconds,
        ) as bridge:
            print(codec.dumps({'listening': str(bridge.listen),
                               'max_connections': bridge.max_connections,
                               'idle_seconds': bridge.idle_seconds}).decode(),
                  flush=True)
            if args.exit_on_stdin_eof:
                import select
                def lease_closed() -> bool:
                    # No requests are received over stdin. EOF only releases
                    # the foreground session's liveness lease.
                    if not select.select([sys.stdin.buffer], [], [], 0)[0]:
                        return False
                    return not sys.stdin.buffer.read(1)
                bridge.serve(should_stop=lease_closed)
            else:
                bridge.serve()
        return 0
    else:
        raise SecretsError('invalid_request')
    print(codec.dumps(result).decode('ascii'))
    return 0
