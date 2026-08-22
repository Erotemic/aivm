"""CLI wrappers around managed libvirt network lifecycle operations."""

from __future__ import annotations

from typing import Any

import kwconf

from aivm.config_store import Store

from ..commands import CommandManager
from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from ..config_store import (
    load_store,
    network_users,
    remove_network,
    require_network,
)
from ..errors import AIVMError
from ..machine_store import current_machine_group_gid, machine_resource_locks
from ..net import destroy_network, ensure_network, network_status
from ..operational_scope import announce_network_machine_impact
from ..scoped_store import (
    load_scope_profile,
    load_scope_store,
    resolve_store_scope,
    save_scope_store,
)
from ..services import cfg_path
from ._common import _BaseCommand


class NetCreateCLI(_BaseCommand):
    """Create or recreate the configured libvirt network."""

    network: str = kwconf.Value(
        '',
        position=1,
        help='Optional managed network name (positional).',
    )
    recreate: bool = kwconf.Flag(
        False, help='Destroy and recreate if it exists.'
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        store_fpath = cfg_path(args.config)
        cfg = _resolve_network_cfg(args.config, network_opt=args.network)
        announce_network_machine_impact(
            store_fpath, cfg.network.name, action='create or recreate'
        )
        mgr = CommandManager.current()
        with mgr.intent(
            f'Create/update network {cfg.network.name}',
            why='Prepare the managed libvirt network used by aivm VMs.',
            role='modify',
        ):
            ensure_network(cfg, recreate=args.recreate, dry_run=args.dry_run)
        return 0


class NetStatusCLI(_BaseCommand):
    """Print detailed status of the configured libvirt network."""

    network: str = kwconf.Value(
        '',
        position=1,
        help='Optional managed network name (positional).',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _resolve_network_cfg(args.config, network_opt=args.network)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Inspect network {cfg.network.name}',
            why='Read the live libvirt network state for the managed bridge.',
            role='read',
        ):
            print(network_status(cfg))
        return 0


class NetDestroyCLI(_BaseCommand):
    """Destroy and undefine the configured libvirt network."""

    network: str = kwconf.Value(
        '',
        position=1,
        help='Optional managed network name (positional).',
    )
    force: bool = kwconf.Flag(
        False,
        short_alias=['f'],
        help='Allow destroying network even if referenced by managed VMs.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        scope = resolve_store_scope(args.config)
        initial = load_scope_store(scope)
        initial_cfg = _resolve_network_cfg(
            args.config, network_opt=args.network, reg=initial
        )
        network_name = initial_cfg.network.name
        announce_network_machine_impact(
            scope.store_path, network_name, action='destroy'
        )

        def execute() -> None:
            # Reload beneath the authoritative lock.  The initial read above is
            # only for selecting which network lock to acquire.
            reg = load_scope_store(scope)
            cfg = _resolve_network_cfg(
                args.config, network_opt=network_name, reg=reg
            )
            users = network_users(reg, network_name)
            if users and not args.force and not args.dry_run:
                names = ', '.join(users)
                raise AIVMError(
                    f"Network '{network_name}' is referenced by managed VMs: "
                    f'{names}. Detach or destroy those VMs first, or use --force.'
                )
            destroy_network(cfg, dry_run=args.dry_run)
            if args.dry_run:
                return
            remove_network(reg, network_name)
            save_scope_store(
                scope,
                reg,
                reason=(
                    f'Remove network {network_name} after verified libvirt teardown.'
                ),
            )

        mgr = CommandManager.current()
        with mgr.intent(
            f'Destroy network {network_name}',
            why='Remove the managed libvirt network when it is no longer needed.',
            role='modify',
        ):
            if scope.is_machine and not args.dry_run:
                assert scope.machine_layout is not None
                with machine_resource_locks(
                    scope.machine_layout,
                    group_gid=current_machine_group_gid(scope.machine_layout),
                    include_store=True,
                    networks=(network_name,),
                ):
                    execute()
            else:
                execute()
        return 0


class NetModalCLI(kwconf.ModalCLI):
    """Network subcommands."""

    create = NetCreateCLI
    status = NetStatusCLI
    destroy = NetDestroyCLI


def _resolve_network_cfg(
    config_opt: str | None,
    *,
    network_opt: str = '',
    reg: Store | None = None,
) -> AgentVMConfig:
    scope = resolve_store_scope(config_opt)
    reg = reg if reg is not None else load_store(scope.store_path)
    net_name = str(network_opt or '').strip()
    if not net_name:
        active_vm = (
            load_scope_profile(scope).active_vm
            if scope.is_machine
            else reg.active_vm
        )
        if active_vm:
            vm = next((v for v in reg.vms if v.name == active_vm), None)
            if vm is not None:
                net_name = vm.network_name
        if not net_name and len(reg.networks) == 1:
            net_name = reg.networks[0].name
        if not net_name and len(reg.vms) == 1:
            net_name = reg.vms[0].network_name
    if not net_name:
        raise AIVMError(
            'Unable to resolve a managed network. Pass a network name explicitly.'
        )
    net = require_network(reg, net_name)
    cfg = AgentVMConfig()
    cfg.network = NetworkConfig(**net.network.__dict__)
    cfg.firewall = FirewallConfig(**net.firewall.__dict__)
    cfg.network.name = net.name
    return cfg
