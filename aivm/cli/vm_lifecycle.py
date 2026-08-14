"""VM lifecycle CLI command implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import kwconf
from loguru import logger as log

from ..attachments.persistent import (
    _reconcile_persistent_host_binds,
    _sync_persistent_attachment_manifest_on_host,
)
from ..attachments.session import (
    _maybe_warn_hardware_drift,
    _resolve_ip_for_ssh_ops,
)
from ..commands import CommandManager
from ..firewall import ensure_firewall_ready
from ..operational_scope import announce_vm_machine_impact
from ..scoped_store import resolve_store_scope
from ..services import (
    cfg_path,
    load_cfg,
    load_cfg_with_path,
    maybe_install_missing_host_deps,
    record_vm,
    resolve_cfg_for_code,
)
from ..vm import (
    create_or_start_vm,
    provision,
    restart_vm,
    shutdown_vm,
    vm_status,
)
from ..vm.create_ops import create_vm_from_defaults
from ..vm.deletion import complete_missing_vm_deletion, delete_managed_vm
from ..vm.guest_tools import (
    GUEST_TOOL_REGISTRY,
    UnknownGuestToolError,
)
from ..vm.rename import rename_managed_vm, validate_vm_name
from ._common import _BaseCommand


class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate: bool = kwconf.Flag(
        False, help='Destroy and recreate if it exists.'
    )
    ensure_firewall: bool = kwconf.Flag(
        True,
        help='Verify (and repair) firewall rules when firewall.enabled=true.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config)
        announce_vm_machine_impact(
            cfg_path, cfg.vm.name, action='start or reconcile'
        )
        maybe_install_missing_host_deps(yes=args.yes, dry_run=args.dry_run)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Create/start VM {cfg.vm.name}',
            why='Ensure the managed VM exists and is running with the configured resources.',
            role='modify',
        ):
            create_or_start_vm(
                cfg,
                dry_run=args.dry_run,
                recreate=args.recreate,
                config_store_path=cfg_path,
                ensure_firewall=args.ensure_firewall,
            )
        if not args.dry_run and not args.recreate:
            _maybe_warn_hardware_drift(cfg)
        if not args.dry_run:
            _sync_persistent_attachment_manifest_on_host(
                cfg,
                cfg_path,
                dry_run=False,
            )
            _reconcile_persistent_host_binds(
                cfg,
                cfg_path,
                dry_run=False,
                vm_running=True,
            )
            record_vm(cfg, cfg_path)
        return 0


class VMDownCLI(_BaseCommand):
    """Gracefully shut down the VM."""

    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config)
        announce_vm_machine_impact(cfg_path, cfg.vm.name, action='shut down')
        mgr = CommandManager.current()
        with mgr.intent(
            f'Shut down VM {cfg.vm.name}',
            why='Gracefully stop the VM by sending an ACPI shutdown signal to the guest OS.',
            role='modify',
        ):
            shutdown_vm(cfg, dry_run=args.dry_run)
        return 0


class VMRestartCLI(_BaseCommand):
    """Gracefully restart the VM (shutdown then start)."""

    ensure_firewall: bool = kwconf.Flag(
        True,
        help='Verify (and repair) firewall rules when firewall.enabled=true.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config)
        announce_vm_machine_impact(cfg_path, cfg.vm.name, action='restart')
        if args.ensure_firewall:
            ensure_firewall_ready(cfg, dry_run=args.dry_run)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Restart VM {cfg.vm.name}',
            why='Gracefully stop and then start the VM to apply changes or recover from transient issues.',
            role='modify',
        ):
            restart_vm(cfg, dry_run=args.dry_run)
        return 0


class VMCreateCLI(_BaseCommand):
    """Create a managed VM from config-store defaults and start it."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    set_default: bool = kwconf.Flag(
        False,
        help='Set the created VM as the active default VM.',
    )
    force: bool = kwconf.Flag(
        False,
        short_alias=['f'],
        help='Overwrite existing VM entry and recreate VM definition if present.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMCreateCLI.main vm={} set_default={} force={} dry_run={} yes={}',
            args.vm,
            args.set_default,
            args.force,
            args.dry_run,
            args.yes,
        )
        store_fpath = cfg_path(args.config)
        return create_vm_from_defaults(
            store_fpath,
            vm_override=args.vm if args.vm else None,
            set_default=args.set_default,
            force=args.force,
            dry_run=args.dry_run,
            yes=args.yes,
        )


class VMStatusCLI(_BaseCommand):
    """Show VM lifecycle status and cached IP information."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg = load_cfg(args.config)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Inspect VM {cfg.vm.name}',
            why='Read the live libvirt state and cached IP for this managed VM.',
            role='read',
        ):
            print(vm_status(cfg))
        return 0


class VMDeleteCLI(_BaseCommand):
    """Durably delete a managed VM and every AIVM-owned host artifact."""

    vm: str = kwconf.Value(
        '',
        position=1,
        help='Optional VM name override (positional).',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        requested_vm = str(args.vm or '').strip()
        if requested_vm and not args.dry_run:
            requested_path = resolve_store_scope(args.config).store_path
            requested_scope = resolve_store_scope(str(requested_path))
            completed = complete_missing_vm_deletion(
                requested_scope, requested_path, requested_vm
            )
            if completed is not None:
                print(
                    f'Completed deletion journal recovery for {requested_vm}; '
                    'the VM was already absent from the machine store.'
                )
                return 0
        cfg, cfg_path = load_cfg_with_path(args.config, vm_opt=args.vm)
        scope = resolve_store_scope(str(cfg_path))
        announce_vm_machine_impact(cfg_path, cfg.vm.name, action='delete')
        mgr = CommandManager.current()
        with mgr.approved_action(
            purpose=(
                f'Create or resume the deletion journal for VM {cfg.vm.name}, '
                'remove attachment exposure and host artifacts, delete the '
                'domain with verified storage cleanup, and finalize the store.'
            )
        ):
            delete_managed_vm(
                scope,
                cfg,
                cfg_path,
                dry_run=args.dry_run,
            )
        return 0


class VMProvisionCLI(_BaseCommand):
    """Provision the VM with configured or one-shot optional guest tools.

    Positional tool names enable registry-defined tools for this invocation in
    addition to persistent ``[tools]`` configuration. Version or channel pins
    remain config values; the registry supplies each one-shot default.
    """

    tools: list[str] = kwconf.Value(
        [],
        position=1,
        nargs='*',
        help=(
            'Names of additional tools to install for this run. Known tools: '
            + ', '.join(GUEST_TOOL_REGISTRY.names())
            + '.'
        ),
    )
    vm: str = kwconf.Value(
        '',
        help='Optional VM name override.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.config is not None or cfg_path(None).exists():
            cfg = load_cfg(args.config)
        else:
            cfg, _ = resolve_cfg_for_code(
                config_opt=None,
                vm_opt=args.vm,
                host_src=Path.cwd(),
            )
        requested = list(args.tools or [])
        try:
            GUEST_TOOL_REGISTRY.apply_enable_overrides(cfg.tools, requested)
        except UnknownGuestToolError as ex:
            log.error(str(ex))
            return 2
        if not args.dry_run:
            _resolve_ip_for_ssh_ops(
                cfg,
                yes=args.yes,
                purpose='Query VM networking state before SSH provisioning.',
            )
        provision(cfg, dry_run=args.dry_run)
        return 0


class VMListCLI(_BaseCommand):
    """List managed VM records (VM-focused view)."""

    section: Literal['all', 'vms', 'networks', 'folders'] = kwconf.Value(
        'vms',
        help='One of: all, vms, networks, folders (default: vms).',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        from .main import ListCLI

        return ListCLI.main(
            argv=False, section=args.section, config=args.config
        )


class VMRenameCLI(_BaseCommand):
    """Rename a managed VM and every AIVM-owned artifact naming it."""

    to: str = kwconf.Value(
        '',
        position=1,
        help='New VM name (positional).',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config, vm_opt=args.vm)
        scope = resolve_store_scope(str(cfg_path))
        new_name = validate_vm_name(str(args.to or ''))
        announce_vm_machine_impact(cfg_path, cfg.vm.name, action='rename')
        mgr = CommandManager.current()
        with mgr.approved_action(
            purpose=(
                f'Rename VM {cfg.vm.name} to {new_name}: move its storage '
                'tree, machine state, and bootstrap identity, rename the '
                'libvirt domain and repoint its storage paths, then rewrite '
                'every store record naming it.'
            )
        ):
            rename_managed_vm(
                scope,
                cfg,
                cfg_path,
                new_name,
                dry_run=args.dry_run,
            )
        return 0
