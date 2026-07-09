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
from ..config_store import (
    find_network,
    load_store,
    network_users,
    remove_vm,
    save_store,
)
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
    destroy_vm,
    provision,
    restart_vm,
    shutdown_vm,
    vm_status,
)
from ..vm.create_ops import create_vm_from_defaults
from ._common import _BaseCommand


class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate: bool = kwconf.Flag(
        False, help='Destroy and recreate if it exists.'
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config)
        maybe_install_missing_host_deps(
            yes=bool(args.yes), dry_run=bool(args.dry_run)
        )
        mgr = CommandManager.current()
        with mgr.intent(
            f'Create/start VM {cfg.vm.name}',
            why='Ensure the managed VM exists and is running with the configured resources.',
            role='modify',
        ):
            create_or_start_vm(
                cfg, dry_run=args.dry_run, recreate=args.recreate
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
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config)
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

    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config)
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
        help='Overwrite existing VM entry and recreate VM definition if present.',
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMCreateCLI.main vm={} set_default={} force={} dry_run={} yes={}',
            args.vm,
            bool(args.set_default),
            bool(args.force),
            bool(args.dry_run),
            bool(args.yes),
        )
        store_fpath = cfg_path(args.config)
        return create_vm_from_defaults(
            store_fpath,
            vm_override=args.vm if args.vm else None,
            set_default=bool(args.set_default),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
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
    """Delete the managed VM domain (shared host directories are not deleted)."""

    vm: str = kwconf.Value(
        '',
        position=1,
        help='Optional VM name override (positional).',
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = load_cfg_with_path(args.config, vm_opt=args.vm)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Delete VM {cfg.vm.name}',
            why=(
                'Remove the managed VM domain while leaving host project directories intact.'
            ),
            role='modify',
        ):
            destroy_vm(cfg, dry_run=args.dry_run)
        if not args.dry_run:
            reg = load_store(cfg_path)
            remove_vm(reg, cfg.vm.name, remove_attachments=True)
            save_store(
                reg,
                cfg_path,
                reason=(
                    f'Remove VM record for {cfg.vm.name} after deleting the '
                    'managed libvirt domain.'
                ),
            )
            net_name = (cfg.network.name or '').strip()
            if net_name:
                net = find_network(reg, net_name)
                if net is not None and not network_users(reg, net_name):
                    log.warning(
                        "Network '{}' now has no VM users and remains defined. "
                        'Destroy it explicitly if no longer needed: aivm host net destroy {}',
                        net_name,
                        net_name,
                    )
        return 0


_TOOL_OVERRIDE_DEFAULTS: dict[str, str] = {
    'uv': 'latest',
    'rust': 'stable',
    'code': 'latest',
}


class VMProvisionCLI(_BaseCommand):
    """Provision the VM with optional developer packages.

    Positional ``tools`` arguments are tool names to enable for this
    invocation in addition to whatever is already enabled in
    ``[tools]`` config. Known tools: ``uv``, ``rust``, ``code``. Each
    enables the tool at its sensible default (``latest`` for ``uv`` and
    ``code``, ``stable`` for ``rust``). To pin a version, set the value
    in config.toml instead.
    """

    tools: list[str] = kwconf.Value(
        [],
        position=1,
        nargs='*',
        help=(
            'Names of additional tools to install for this run (e.g. '
            '`aivm vm provision code`). Known tools: uv, rust, code.'
        ),
    )
    vm: str = kwconf.Value(
        '',
        help='Optional VM name override.',
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
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
        unknown = [t for t in requested if t not in _TOOL_OVERRIDE_DEFAULTS]
        if unknown:
            known = ', '.join(sorted(_TOOL_OVERRIDE_DEFAULTS))
            log.error(
                'Unknown tool name(s): {}. Known tools: {}.',
                ', '.join(unknown),
                known,
            )
            return 2
        for name in requested:
            setattr(cfg.tools, name, _TOOL_OVERRIDE_DEFAULTS[name])
        if not args.dry_run:
            _resolve_ip_for_ssh_ops(
                cfg,
                yes=bool(args.yes),
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
