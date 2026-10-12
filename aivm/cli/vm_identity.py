"""Explicit managed-VM enrollment into the certificate-bound secret service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import kwconf

from ..errors import AIVMError
from ..services import load_vm_context_with_path
from ..vm.connectivity import get_ip_cached, wait_for_ip
from ..secrets_identity_transport import enroll_managed_vm
from ._common import _BaseCommand


class VMIdentityEnrollCLI(_BaseCommand):
    """Enroll this host principal's managed VM through its forced SSH helper."""

    vm: str = kwconf.Value('', help='Existing managed VM name.')
    identity_root: str = kwconf.Value(
        '', help='Existing protected P4a host authority directory (required).')
    replace: bool = kwconf.Flag(
        False, help='Explicitly rotate an enrolled client certificate and epoch.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.identity_root:
            raise AIVMError('--identity_root is required; identity is opt-in')
        context, store = load_vm_context_with_path(
            args.config, vm_opt=args.vm,
            hydrate_runtime_defaults=False, persist_runtime_defaults=False,
        )
        # Refuse to create, recreate, boot or adopt a VM. Enrollment only
        # operates against an already reachable authoritative guest.
        ip = get_ip_cached(context.effective_cfg) or wait_for_ip(
            context.effective_cfg, timeout_s=45, dry_run=False)
        result = enroll_managed_vm(
            context=context, store=store, ip=ip,
            authority_root=Path(args.identity_root), replace=args.replace,
        )
        print('Enrolled certificate-bound identity for ' + result['vm'])
        print('Managed domain UUID: ' + result['domain_uuid'])
        print('Subject: ' + result['subject'])
        print('Certificate SHA-256: ' + result['certificate_sha256'])
        print('Enrollment epoch: ' + str(result['epoch']))
        return 0
