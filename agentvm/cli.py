from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import scriptconfig as scfg
from loguru import logger

from .config import AgentVMConfig, load, save
from .detect import auto_defaults
from .firewall import apply_firewall, firewall_status, remove_firewall
from .host import check_commands, host_is_debian_like, install_deps_debian
from .net import destroy_network, ensure_network, network_status
from .vm import (
    create_or_start_vm,
    destroy_vm,
    fetch_image,
    provision,
    ssh_config as mk_ssh_config,
    vm_status,
    wait_for_ip,
)

log = logger


class _BaseCommand(scfg.DataConfig):
    config = scfg.Value(None, help="Path to config TOML (default: .agentvm.toml).")
    verbose = scfg.Value(0, short_alias=["v"], isflag='counter', help="Increase verbosity (-v, -vv).")


def _setup_logging(args_verbose: int, cfg_verbosity: int) -> None:
    logger.remove()
    effective_verbosity = args_verbose if args_verbose > 0 else cfg_verbosity
    level = "WARNING"
    if effective_verbosity == 1:
        level = "INFO"
    elif effective_verbosity >= 2:
        level = "DEBUG"
    logger.add(
        sys.stderr,
        level=level,
        colorize=False,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    )
    log.debug("Logging configured at {} (effective_verbosity={})", level, effective_verbosity)


def _cfg_path(p: str | None) -> Path:
    return Path(p or ".agentvm.toml").resolve()


def _load_cfg(config_path: str | None) -> AgentVMConfig:
    path = _cfg_path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found: {path}. Run: agentvm init --config {path}"
        )
    return load(path).expanded_paths()



class InitCLI(_BaseCommand):
    __command__ = "init"
    force = scfg.Value(False, isflag=True, help="Overwrite existing config.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        path = _cfg_path(args.config)
        cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
        if path.exists() and not args.force:
            print(f"Refusing to overwrite existing config: {path}", file=sys.stderr)
            print("Use --force to overwrite.", file=sys.stderr)
            return 2
        save(path, cfg)
        print(f"Wrote config: {path}")
        return 0


class PlanCLI(_BaseCommand):
    __command__ = "plan"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        path = _cfg_path(args.config)
        steps = textwrap.dedent(f"""
        Config: {path}

        Suggested flow:

          agentvm doctor --config {path}
          agentvm net create --config {path}
          # Optional but recommended for isolation:
          agentvm fw apply --config {path}
          agentvm image fetch --config {path}
          agentvm vm up --config {path}
          agentvm vm wait-ip --config {path}
          agentvm vm ssh-config --config {path}   # use with VS Code Remote-SSH
          # Optional: install docker + dev tools inside the VM
          agentvm vm provision --config {path}
        """).strip()
        print(steps)
        return 0


class DoctorCLI(_BaseCommand):
    __command__ = "doctor"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        cls.cli(cmdline=cmdline, data=kwargs)
        missing, missing_opt = check_commands()
        if missing:
            print("Missing required commands:", ", ".join(missing))
            print("On Debian/Ubuntu you can run: agentvm host-install-deps")
            return 2
        if missing_opt:
            print("Missing optional commands:", ", ".join(missing_opt))
        print("OK: required host commands present.")
        return 0


class HostInstallDepsCLI(_BaseCommand):
    __command__ = "host-install-deps"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        cls.cli(cmdline=cmdline, data=kwargs)
        if not host_is_debian_like():
            print("Host not detected as Debian/Ubuntu. Install dependencies manually.", file=sys.stderr)
            return 2
        install_deps_debian(assume_yes=True)
        print("Installed host dependencies (best effort).")
        return 0


class NetCreateCLI(_BaseCommand):
    __command__ = "net-create"
    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        cfg = _load_cfg(args.config)
        ensure_network(cfg, recreate=args.recreate, dry_run=args.dry_run)
        return 0


class NetStatusCLI(_BaseCommand):
    __command__ = "net-status"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        print(network_status(_load_cfg(args.config)))
        return 0


class NetDestroyCLI(_BaseCommand):
    __command__ = "net-destroy"
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        destroy_network(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class FirewallApplyCLI(_BaseCommand):
    __command__ = "fw-apply"
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        apply_firewall(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class FirewallStatusCLI(_BaseCommand):
    __command__ = "fw-status"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        print(firewall_status(_load_cfg(args.config)))
        return 0


class FirewallRemoveCLI(_BaseCommand):
    __command__ = "fw-remove"
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        remove_firewall(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class ImageFetchCLI(_BaseCommand):
    __command__ = "image-fetch"
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        print(str(fetch_image(_load_cfg(args.config), dry_run=args.dry_run)))
        return 0


class VMUpCLI(_BaseCommand):
    __command__ = "vm-up"
    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        create_or_start_vm(_load_cfg(args.config), dry_run=args.dry_run, recreate=args.recreate)
        return 0


class VMWaitIPCLI(_BaseCommand):
    __command__ = "vm-wait-ip"
    timeout = scfg.Value(360, type=int, help="Timeout seconds.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        print(wait_for_ip(_load_cfg(args.config), timeout_s=args.timeout, dry_run=args.dry_run))
        return 0


class VMStatusCLI(_BaseCommand):
    __command__ = "vm-status"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        print(vm_status(_load_cfg(args.config)))
        return 0


class VMDestroyCLI(_BaseCommand):
    __command__ = "vm-destroy"
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        destroy_vm(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class VMSshConfigCLI(_BaseCommand):
    __command__ = "vm-ssh-config"

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        print(mk_ssh_config(_load_cfg(args.config)))
        return 0


class VMProvisionCLI(_BaseCommand):
    __command__ = "vm-provision"
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        provision(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class ApplyCLI(_BaseCommand):
    __command__ = "apply"
    interactive = scfg.Value(False, isflag=True, help="Print plan and SSH config at the end.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, cmdline=1, **kwargs):
        args = cls.cli(cmdline=cmdline, data=kwargs)
        cfg = _load_cfg(args.config)
        if args.interactive:
            PlanCLI.main(cmdline=0, config=args.config, verbose=args.verbose)
            print()
        log.debug("Ensuring network is set up")
        ensure_network(cfg, recreate=False, dry_run=args.dry_run)
        if cfg.firewall.enabled:
            log.debug("Applying firewall rules")
            apply_firewall(cfg, dry_run=args.dry_run)
        log.debug("Fetching Ubuntu image")
        fetch_image(cfg, dry_run=args.dry_run)
        log.debug("Creating or starting VM")
        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=False)
        log.debug("Waiting for VM IP address")
        wait_for_ip(cfg, timeout_s=360, dry_run=args.dry_run)
        if cfg.provision.enabled:
            log.debug("Provisioning VM with tools")
            provision(cfg, dry_run=args.dry_run)
        if args.interactive:
            print("\nSSH config for VS Code:")
            print(mk_ssh_config(cfg))
        return 0


class AgentVMModalCLI(scfg.ModalCLI):
    """Local libvirt/KVM sandbox VM manager for coding agents."""


AgentVMModalCLI.register(InitCLI)
AgentVMModalCLI.register(PlanCLI)
AgentVMModalCLI.register(DoctorCLI)
AgentVMModalCLI.register(HostInstallDepsCLI)
AgentVMModalCLI.register(NetCreateCLI)
AgentVMModalCLI.register(NetStatusCLI)
AgentVMModalCLI.register(NetDestroyCLI)
AgentVMModalCLI.register(FirewallApplyCLI)
AgentVMModalCLI.register(FirewallStatusCLI)
AgentVMModalCLI.register(FirewallRemoveCLI)
AgentVMModalCLI.register(ImageFetchCLI)
AgentVMModalCLI.register(VMUpCLI)
AgentVMModalCLI.register(VMWaitIPCLI)
AgentVMModalCLI.register(VMStatusCLI)
AgentVMModalCLI.register(VMDestroyCLI)
AgentVMModalCLI.register(VMSshConfigCLI)
AgentVMModalCLI.register(VMProvisionCLI)
AgentVMModalCLI.register(ApplyCLI)


def _normalize_argv(argv: list[str]) -> list[str]:
    """Map legacy grouped subcommands to modal command names."""
    pair_map = {
        ("host", "install-deps"): "host-install-deps",
        ("net", "create"): "net-create",
        ("net", "status"): "net-status",
        ("net", "destroy"): "net-destroy",
        ("fw", "apply"): "fw-apply",
        ("fw", "status"): "fw-status",
        ("fw", "remove"): "fw-remove",
        ("image", "fetch"): "image-fetch",
        ("vm", "up"): "vm-up",
        ("vm", "wait-ip"): "vm-wait-ip",
        ("vm", "status"): "vm-status",
        ("vm", "destroy"): "vm-destroy",
        ("vm", "ssh-config"): "vm-ssh-config",
        ("vm", "provision"): "vm-provision",
    }
    if len(argv) >= 2:
        key = (argv[0], argv[1])
        if key in pair_map:
            return [pair_map[key], *argv[2:]]
    return argv


def _count_verbose(argv: list[str]) -> int:
    count = 0
    for item in argv:
        if item == "--verbose":
            count += 1
        elif item.startswith("-") and not item.startswith("--"):
            short = item[1:]
            if short and set(short) <= {"v"}:
                count += len(short)
    return count


def main(argv: list[str] | None = None) -> None:
    verbosity = 1
    config_value = None
    if argv is None:
        argv = sys.argv[1:]
    argv = _normalize_argv(argv)
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
            verbosity = _load_cfg(config_value).verbosity
        elif _cfg_path(None).exists():
            verbosity = _load_cfg(None).verbosity
    except Exception:
        verbosity = 1

    explicit_verbose = _count_verbose(argv)
    _setup_logging(explicit_verbose, verbosity)

    try:
        rc = AgentVMModalCLI.main(argv=argv, _noexit=True)
    except Exception as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        log.error("Unhandled agentvm error: {}", ex)
        sys.exit(2)

    if any(flag in argv for flag in ("-h", "--help")):
        sys.exit(0)
    if isinstance(rc, int):
        sys.exit(rc)
    sys.exit(0)
