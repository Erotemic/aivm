from __future__ import annotations

import sys

import scriptconfig as scfg

from . import _common
from ._common import *  # noqa: F401,F403
from .config import ConfigModalCLI
from .help import HelpModalCLI
from .host import HostModalCLI
from .vm import AttachCLI, CodeCLI, SSHCLI, VMModalCLI


class ApplyCLI(_BaseCommand):
    """Run the full setup workflow from network to provisioning."""

    interactive = scfg.Value(
        False, isflag=True, help="Print plan and SSH config at the end."
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        if args.interactive:
            from .help import PlanCLI

            PlanCLI.main(argv=False, config=args.config, verbose=args.verbose)
            print()
        log.debug("Ensuring network is set up")
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose=f"Create/update libvirt network '{cfg.network.name}'.",
        )
        ensure_network(cfg, recreate=False, dry_run=args.dry_run)
        if cfg.firewall.enabled:
            log.debug("Applying firewall rules")
            _confirm_sudo_block(
                yes=bool(args.yes), purpose="Apply nftables firewall rules."
            )
            apply_firewall(cfg, dry_run=args.dry_run)
        log.debug("Fetching Ubuntu image")
        _confirm_sudo_block(yes=bool(args.yes), purpose="Download/cache VM base image.")
        fetch_image(cfg, dry_run=args.dry_run)
        log.debug("Creating or starting VM")
        _confirm_sudo_block(
            yes=bool(args.yes), purpose=f"Create/start VM '{cfg.vm.name}'."
        )
        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=False)
        if not args.dry_run:
            _record_vm(cfg, cfg_path)
        log.debug("Waiting for VM IP address")
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Query VM networking state via virsh."
        )
        wait_for_ip(cfg, timeout_s=360, dry_run=args.dry_run)
        if cfg.provision.enabled:
            log.debug("Provisioning VM with tools")
            provision(cfg, dry_run=args.dry_run)
        if args.interactive:
            print("\nSSH config for VS Code:")
            print(mk_ssh_config(cfg))
        return 0


class ListCLI(_BaseCommand):
    """List managed VMs, managed networks, and attached host folders."""

    section = scfg.Value(
        "all",
        help="One of: all, vms, networks, folders.",
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        want = str(args.section or "all").strip().lower()
        allowed = {"all", "vms", "networks", "folders"}
        if want not in allowed:
            raise RuntimeError(
                f"--section must be one of: {', '.join(sorted(allowed))}"
            )

        reg_path = registry_path()
        reg = load_registry(reg_path)

        if want in {"all", "vms"}:
            print("Managed VMs")
            if not reg.vms:
                print("  (none)")
            else:
                for vm in sorted(reg.vms, key=lambda x: x.name):
                    cfg_ok = Path(vm.config_path).expanduser().exists()
                    cfg_state = "ok" if cfg_ok else "missing"
                    print(
                        f"  - {vm.name} | network={vm.network_name} "
                        f"| strict_firewall={'yes' if vm.strict_firewall else 'no'} "
                        f"| config={vm.config_path} ({cfg_state})"
                    )

        if want in {"all", "networks"}:
            if want == "all":
                print("")
            print("Managed Networks")
            by_name: dict[str, bool] = {}
            for vm in reg.vms:
                strict = bool(vm.strict_firewall)
                if vm.network_name not in by_name:
                    by_name[vm.network_name] = strict
                else:
                    by_name[vm.network_name] = by_name[vm.network_name] or strict
            if not by_name:
                print("  (none)")
            else:
                for name in sorted(by_name):
                    print(
                        f"  - {name} | strict_firewall={'yes' if by_name[name] else 'no'}"
                    )

        if want in {"all", "folders"}:
            if want == "all":
                print("")
            print("Attached Folders")
            if not reg.attachments:
                print("  (none)")
            else:
                for att in sorted(
                    reg.attachments, key=lambda x: (x.vm_name, x.host_path)
                ):
                    print(
                        f"  - {att.host_path} | vm={att.vm_name} "
                        f"| mode={att.mode} | guest_dst={att.guest_dst or '(default)'}"
                    )
        print("")
        print(f"Registry: {reg_path}")
        return 0


class StatusCLI(_BaseCommand):
    """Report setup progress across host, network, VM, SSH, and provisioning."""

    sudo = scfg.Value(
        False,
        isflag=True,
        help="Run privileged status checks (virsh/nft/image) with sudo.",
    )
    vm = scfg.Value(
        "",
        help="Optional VM name override (mainly when no local config file is present).",
    )
    detail = scfg.Value(
        False,
        isflag=True,
        help="Include raw diagnostics (virsh/nft/ssh probe outputs).",
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg = None
        path = None
        try:
            if args.config is not None or _cfg_path(None).exists():
                cfg, path = _load_cfg_with_path(args.config)
            else:
                cfg, path = _resolve_cfg_for_code(
                    config_opt=None,
                    vm_opt=args.vm,
                    host_src=Path.cwd(),
                )
        except Exception:
            cfg = None
            path = None
        if cfg is None or path is None:
            print(_render_global_status())
            return 0
        if args.sudo:
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose=f"Inspect host/libvirt/firewall/VM state for status of '{cfg.vm.name}'.",
            )
        print(_render_status(cfg, path, detail=args.detail, use_sudo=bool(args.sudo)))
        return 0


class AgentVMModalCLI(scfg.ModalCLI):
    """Local libvirt/KVM sandbox VM manager for coding agents."""

    config = ConfigModalCLI
    help = HelpModalCLI
    host = HostModalCLI
    code = CodeCLI
    ssh = SSHCLI
    attach = AttachCLI
    vm = VMModalCLI
    apply = ApplyCLI
    list = ListCLI
    status = StatusCLI


def main(argv: list[str] | None = None) -> None:
    verbosity = 1
    config_value = None
    if argv is None:
        argv = sys.argv[1:]
    argv = _common._normalize_argv(argv)
    if "--config" in argv:
        try:
            config_value = argv[argv.index("--config") + 1]
        except IndexError:
            pass
    elif "-c" in argv:
        try:
            config_value = argv[argv.index("-c") + 1]
        except IndexError:
            pass
    try:
        if config_value is not None:
            verbosity = _common._load_cfg(config_value).verbosity
        elif _common._cfg_path(None).exists():
            verbosity = _common._load_cfg(None).verbosity
    except Exception:
        verbosity = 1

    explicit_verbose = _common._count_verbose(argv)
    _common._setup_logging(explicit_verbose, verbosity)

    try:
        rc = AgentVMModalCLI.main(argv=argv, _noexit=True)
    except Exception as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        _common.log.error("Unhandled aivm error: {}", ex)
        sys.exit(2)

    if any(flag in argv for flag in ("-h", "--help")):
        sys.exit(0)
    if isinstance(rc, int):
        sys.exit(rc)
    sys.exit(0)
