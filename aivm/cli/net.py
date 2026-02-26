from __future__ import annotations

from ._common import *  # noqa: F401,F403

class NetCreateCLI(_BaseCommand):
    """Create or recreate the configured libvirt network."""

    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose=f"Create/update libvirt network '{cfg.network.name}'.",
        )
        ensure_network(cfg, recreate=args.recreate, dry_run=args.dry_run)
        return 0

class NetStatusCLI(_BaseCommand):
    """Print detailed status of the configured libvirt network."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Inspect libvirt network status via virsh."
        )
        print(network_status(cfg))
        return 0

class NetDestroyCLI(_BaseCommand):
    """Destroy and undefine the configured libvirt network."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Destroy/undefine libvirt network."
        )
        destroy_network(cfg, dry_run=args.dry_run)
        return 0

class NetModalCLI(scfg.ModalCLI):
    """Network subcommands."""

    create = NetCreateCLI
    status = NetStatusCLI
    destroy = NetDestroyCLI
