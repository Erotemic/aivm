"""CLI wrappers around managed libvirt network lifecycle operations."""

from __future__ import annotations

from typing import Any

import kwconf

from aivm.config_store import Store

from ..commands import CommandManager
from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from ..config_store import (
    find_network,
    load_store,
    network_users,
    remove_network,
    save_store,
)
from ..errors import AIVMError, SessionRuntimeError
from ..net import destroy_network, ensure_network, network_status
from ..runtime import normalize_runtime_mode
from ..services import cfg_path
from ._common import _BaseCommand


def _require_managed_networks_applicable(reg: Store) -> None:
    """Reject managed-network creation in a session-only config store.

    Managed libvirt networks are a system-runtime concept: session VMs use
    passt user-mode networking and never reference a bridge. When the
    store's defaults are session and no system-runtime VM exists, creating
    a network is a configuration mistake worth a hard error. Status and
    destroy stay available so leftover system networks remain inspectable
    and removable.
    """
    defaults_mode = 'system'
    if reg.defaults is not None:
        defaults_mode = normalize_runtime_mode(reg.defaults.runtime.mode)
    has_system_vm = any(
        normalize_runtime_mode(v.cfg.runtime.mode) == 'system'
        for v in reg.vms
    )
    if defaults_mode == 'session' and not has_system_vm:
        raise SessionRuntimeError(
            'Managed libvirt networks are not used by session-runtime VMs '
            '(passt user-mode networking replaces them).\n'
            'This config store defaults to runtime.mode=session and has no '
            "system-runtime VMs. Set runtime.mode = 'system' in defaults "
            'first if you really need a managed network.'
        )


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
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        _require_managed_networks_applicable(load_store(cfg_path(args.config)))
        cfg = _resolve_network_cfg(args.config, network_opt=args.network)
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
        help='Allow destroying network even if referenced by managed VMs.',
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        store_fpath = cfg_path(args.config)
        reg = load_store(store_fpath)
        cfg = _resolve_network_cfg(
            args.config, network_opt=args.network, reg=reg
        )
        users = network_users(reg, cfg.network.name)
        if users and not args.force and not args.dry_run:
            names = ', '.join(users)
            raise AIVMError(
                f"Network '{cfg.network.name}' is referenced by managed VMs: {names}. "
                'Detach or destroy those VMs first, or use --force.'
            )
        mgr = CommandManager.current()
        with mgr.intent(
            f'Destroy network {cfg.network.name}',
            why='Remove the managed libvirt network when it is no longer needed.',
            role='modify',
        ):
            destroy_network(cfg, dry_run=args.dry_run)
        if not args.dry_run:
            remove_network(reg, cfg.network.name)
            save_store(reg, cfg_path(args.config))
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
    reg = reg if reg is not None else load_store(cfg_path(config_opt))
    net_name = str(network_opt or '').strip()
    if not net_name:
        if reg.active_vm:
            vm = next((v for v in reg.vms if v.name == reg.active_vm), None)
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
    net = find_network(reg, net_name)
    if net is None:
        raise AIVMError(
            f'Managed network not found in config store: {net_name}'
        )
    cfg = AgentVMConfig()
    cfg.network = NetworkConfig(**net.network.__dict__)
    cfg.firewall = FirewallConfig(**net.firewall.__dict__)
    cfg.network.name = net.name
    return cfg
