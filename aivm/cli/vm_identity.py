"""Explicit managed-VM enrollment into the certificate-bound secret service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import kwconf
from loguru import logger as log

from ..errors import AIVMError
from ..services import load_vm_context_with_path
from ..vm.connectivity import get_ip_cached, wait_for_ip
from ._common import _BaseCommand


def _run_identity(args: Any, *, renew: bool, rotate_key: bool = False) -> int:
    """Run one explicit identity operation and report it for an operator.

    Every expected refusal of the identity path -- an old forced helper, an
    unpinned host key, a renewal CAS conflict, a changed domain UUID -- is a
    ``SecretsError`` whose actionable part is only in ``for_operator()``, so
    it is reported as an error line and exit status 1, never a traceback.
    A ``CommandControlError`` (the user declined a prompt) is deliberately
    not caught: it is the user's decision, reported as such by the CLI.
    """
    if not args.identity_root:
        raise AIVMError('--identity_root is required; identity is opt-in')
    # The ordinary AIVM command tree must import without aivm_secrets present.
    # Load the experimental adapter only for an explicitly requested action.
    try:
        from aivm_secrets.errors import SecretsError
        from ..secrets_identity_transport import enroll_managed_vm
    except ModuleNotFoundError as ex:
        if ex.name and ex.name.split('.')[0] in {'aivm_secrets', 'cryptography'}:
            log.error('Identity enrollment requires optional AIVM secrets support '                       '(install aivm[secrets] on this branch).')
            return 1
        raise
    context, store = load_vm_context_with_path(
        args.config, vm_opt=args.vm,
        hydrate_runtime_defaults=False, persist_runtime_defaults=False,
    )
    # Do not create, boot, replace or adopt a VM to renew its identity.
    ip = get_ip_cached(context.effective_cfg) or wait_for_ip(
        context.effective_cfg, timeout_s=45, dry_run=False)
    try:
        result = enroll_managed_vm(
            context=context, store=store, ip=ip,
            authority_root=Path(args.identity_root),
            replace=(args.replace if not renew else False), renew=renew,
            rotate_key=rotate_key,
        )
    except SecretsError as ex:
        log.error('Identity operation failed: {}', ex.for_operator())
        return 1
    print('Rotated' if rotate_key else ('Renewed' if renew else 'Enrolled'),
          'certificate-bound identity for ' + result['vm'])
    print('Managed domain UUID: ' + result['domain_uuid'])
    print('Subject: ' + result['subject'])
    print('Certificate SHA-256: ' + result['certificate_sha256'])
    print('Enrollment epoch: ' + str(result['epoch']))
    return 0


class VMIdentityEnrollCLI(_BaseCommand):
    """Enroll this host principal's managed VM through its forced SSH helper."""

    vm: str = kwconf.Value('', help='Existing managed VM name.')
    identity_root: str = kwconf.Value(
        '', help='Existing protected P4a host authority directory (required).')
    replace: bool = kwconf.Flag(
        False, help='Explicitly rotate an enrolled client certificate and epoch.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        return _run_identity(cls.cli(argv=argv, data=kwargs), renew=False)


class VMIdentityRenewCLI(_BaseCommand):
    """Explicitly renew an existing managed VM certificate and epoch.

    Requires the same pinned forced-bootstrap SSH proof as initial enrollment.
    It reuses the guest's *active* software key -- the guest re-signs its CSR
    with that key first, so a renewal after identity_rotate_key certifies the
    rotated key, never the retired one; it does not rotate guest keys.
    """

    vm: str = kwconf.Value('', help='Existing managed VM name.')
    identity_root: str = kwconf.Value(
        '', help='Existing protected identity authority directory (required).')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        return _run_identity(cls.cli(argv=argv, data=kwargs), renew=True)


class VMIdentityRotateKeyCLI(_BaseCommand):
    """Generate a fresh guest-owned key through the forced bootstrap channel.

    Requires an active enrollment and a separate host-confirmed epoch CAS.
    Failed installation revokes the new enrollment, never enabling fallback.
    """

    vm: str = kwconf.Value('', help='Existing managed VM name.')
    identity_root: str = kwconf.Value(
        '', help='Existing protected identity authority directory (required).')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        return _run_identity(cls.cli(argv=argv, data=kwargs),
                             renew=True, rotate_key=True)
