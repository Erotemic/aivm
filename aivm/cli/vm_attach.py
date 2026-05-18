"""VM attachment CLI command implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import scriptconfig as scfg

from ..ops.vm_attach import (
    VMAttachRequest,
    VMDetachRequest,
    VMInstallPersistentHostReplayServiceRequest,
    VMPersistentHostReplayRequest,
    run_install_persistent_host_replay_service,
    run_persistent_host_replay,
    run_vm_attach,
    run_vm_detach,
)
from ._common import _BaseCommand, log


class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    host_src: Any = scfg.Value(
        '.', position=1, help='Host directory to attach.'
    )
    guest_dst: Any = scfg.Value('', help='Guest mount path override.')
    mode: Any = scfg.Value(
        '',
        help='Attachment mode: shared, shared-root, persistent, or git (default: saved mode (TODO: programatic documentation of default); mode changes require detach+reattach).',
    )
    access: Any = scfg.Value(
        '',
        help='Attachment access: rw or ro (default: saved access or rw). ro is supported for shared, shared-root, and persistent modes.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMAttachCLI.main host_src={} vm={} guest_dst={} mode={} access={} dry_run={} yes={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            args.mode,
            args.access,
            bool(args.dry_run),
            bool(args.yes),
        )
        return run_vm_attach(
            VMAttachRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src),
                guest_dst=args.guest_dst,
                mode=args.mode,
                access=args.access,
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        )


class VMDetachCLI(_BaseCommand):
    """Detach/unregister a host directory from a managed VM."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    host_src: Any = scfg.Value(
        '.', position=1, help='Host directory to detach.'
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_vm_detach(
            VMDetachRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src),
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        )


class VMPersistentHostReplayCLI(_BaseCommand):
    """Replay host-side persistent bind mounts from the saved manifest."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_persistent_host_replay(
            VMPersistentHostReplayRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                dry_run=bool(args.dry_run),
            )
        )


class VMInstallPersistentHostReplayServiceCLI(_BaseCommand):
    """Install and enable a host systemd service for persistent bind replay."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_install_persistent_host_replay_service(
            VMInstallPersistentHostReplayServiceRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                dry_run=bool(args.dry_run),
            )
        )
