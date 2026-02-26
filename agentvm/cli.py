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
from .util import run_cmd
from .vm import (
    create_or_start_vm,
    destroy_vm,
    fetch_image,
    get_ip_cached,
    provision,
    ssh_config as mk_ssh_config,
    vm_status,
    wait_for_ip,
)

log = logger


class _BaseCommand(scfg.DataConfig):
    """Base options shared by all commands."""

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


def _status_line(ok: bool | None, label: str, detail: str = "") -> str:
    icon = "[x]" if ok is True else ("[-]" if ok is None else "[ ]")
    suffix = f" - {detail}" if detail else ""
    return f"{icon} {label}{suffix}"


def _check_network(cfg: AgentVMConfig) -> tuple[bool, str]:
    info = run_cmd(
        ["virsh", "net-info", cfg.network.name], sudo=True, check=False, capture=True
    )
    if info.code != 0:
        return False, f"{cfg.network.name} not defined"
    active = "active: yes" in info.stdout.lower()
    autostart = "autostart: yes" in info.stdout.lower()
    if active:
        return True, f"{cfg.network.name} active (autostart={'yes' if autostart else 'no'})"
    return False, f"{cfg.network.name} defined but inactive"


def _check_firewall(cfg: AgentVMConfig) -> tuple[bool | None, str]:
    if not cfg.firewall.enabled:
        return None, "disabled in config"
    res = run_cmd(
        ["nft", "list", "table", "inet", cfg.firewall.table],
        sudo=True,
        check=False,
        capture=True,
    )
    if res.code == 0:
        return True, f"table inet {cfg.firewall.table} present"
    return False, f"table inet {cfg.firewall.table} missing"


def _sudo_file_exists(path: Path) -> bool:
    return (
        run_cmd(["test", "-f", str(path)], sudo=True, check=False, capture=True).code
        == 0
    )


def _check_vm_state(cfg: AgentVMConfig) -> tuple[bool, str]:
    dom = run_cmd(["virsh", "dominfo", cfg.vm.name], sudo=True, check=False, capture=True)
    if dom.code != 0:
        return False, f"{cfg.vm.name} not defined"
    state = run_cmd(
        ["virsh", "domstate", cfg.vm.name], sudo=True, check=False, capture=True
    ).stdout.strip()
    return ("running" in state.lower(), f"{cfg.vm.name} state={state}")


def _check_ssh_ready(cfg: AgentVMConfig, ip: str) -> tuple[bool, str]:
    ident = cfg.paths.ssh_identity_file
    if not ident:
        return False, "paths.ssh_identity_file is empty"
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=3",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-i",
        ident,
        f"{cfg.vm.user}@{ip}",
        "true",
    ]
    res = run_cmd(cmd, sudo=False, check=False, capture=True)
    return (res.code == 0, "ready" if res.code == 0 else "not ready")


def _check_provisioned(cfg: AgentVMConfig, ip: str) -> tuple[bool | None, str]:
    if not cfg.provision.enabled:
        return None, "disabled in config"
    ident = cfg.paths.ssh_identity_file
    if not ident:
        return False, "paths.ssh_identity_file is empty"
    needed = list(cfg.provision.packages)
    if cfg.provision.install_docker:
        needed.extend(["docker.io", "docker-compose-v2"])
    quoted = " ".join(f"'{p}'" for p in needed)
    remote = (
        "set -e; "
        f"for p in {quoted}; do "
        "dpkg-query -W -f='${Status}' \"$p\" 2>/dev/null | grep -q 'install ok installed' || exit 10; "
        "done"
    )
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=4",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-i",
        ident,
        f"{cfg.vm.user}@{ip}",
        remote,
    ]
    res = run_cmd(cmd, sudo=False, check=False, capture=True)
    if res.code == 0:
        return True, "configured packages appear present"
    return False, "one or more configured packages missing"


def _render_status(cfg: AgentVMConfig, path: Path) -> str:
    lines: list[str] = [f"Config: {path}", ""]
    done = 0
    total = 0

    missing, missing_opt = check_commands()
    host_ok = len(missing) == 0
    total += 1
    done += int(host_ok)
    host_detail = "all required commands found" if host_ok else f"missing: {', '.join(missing)}"
    if missing_opt:
        host_detail += f" (optional missing: {', '.join(missing_opt)})"
    lines.append(_status_line(host_ok, "Host dependencies", host_detail))

    net_ok, net_detail = _check_network(cfg)
    total += 1
    done += int(net_ok)
    lines.append(_status_line(net_ok, "Libvirt network", net_detail))

    fw_ok, fw_detail = _check_firewall(cfg)
    if fw_ok is not None:
        total += 1
        done += int(fw_ok)
    lines.append(_status_line(fw_ok, "Firewall", fw_detail))

    base_img = Path(cfg.paths.base_dir) / cfg.vm.name / "images" / cfg.image.cache_name
    img_ok = _sudo_file_exists(base_img)
    total += 1
    done += int(img_ok)
    lines.append(_status_line(img_ok, "Base image cache", str(base_img)))

    vm_ok, vm_detail = _check_vm_state(cfg)
    total += 1
    done += int(vm_ok)
    lines.append(_status_line(vm_ok, "VM state", vm_detail))

    ip = get_ip_cached(cfg)
    ip_ok = bool(ip)
    total += 1
    done += int(ip_ok)
    lines.append(_status_line(ip_ok, "Cached VM IP", ip or "no cached IP yet"))

    ssh_ok = False
    ssh_detail = "IP unknown"
    if ip:
        ssh_ok, ssh_detail = _check_ssh_ready(cfg, ip)
    total += 1
    done += int(ssh_ok)
    lines.append(_status_line(ssh_ok, "SSH readiness", ssh_detail))

    if ip and ssh_ok:
        prov_ok, prov_detail = _check_provisioned(cfg, ip)
    else:
        prov_ok, prov_detail = (
            (None, "waiting for SSH")
            if cfg.provision.enabled
            else (None, "disabled in config")
        )
    if prov_ok is not None:
        total += 1
        done += int(prov_ok)
    lines.append(_status_line(prov_ok, "Provisioning", prov_detail))

    lines.append("")
    lines.append(f"Progress: {done}/{total} checks complete")
    return "\n".join(lines)



class InitCLI(_BaseCommand):
    """Initialize a new config file with auto-detected defaults."""

    force = scfg.Value(False, isflag=True, help="Overwrite existing config.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
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
    """Show the recommended end-to-end setup command sequence."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        steps = textwrap.dedent(f"""
        Config: {path}

        Suggested flow:

          agentvm doctor --config {path}
          agentvm status --config {path}
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
    """Check host prerequisites and list missing required tools."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        cls.cli(argv=argv, data=kwargs)
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
    """Install required host dependencies on Debian/Ubuntu."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        cls.cli(argv=argv, data=kwargs)
        if not host_is_debian_like():
            print("Host not detected as Debian/Ubuntu. Install dependencies manually.", file=sys.stderr)
            return 2
        install_deps_debian(assume_yes=True)
        print("Installed host dependencies (best effort).")
        return 0


class NetCreateCLI(_BaseCommand):
    """Create or recreate the configured libvirt network."""

    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        ensure_network(cfg, recreate=args.recreate, dry_run=args.dry_run)
        return 0


class NetStatusCLI(_BaseCommand):
    """Print detailed status of the configured libvirt network."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(network_status(_load_cfg(args.config)))
        return 0


class NetDestroyCLI(_BaseCommand):
    """Destroy and undefine the configured libvirt network."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        destroy_network(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class FirewallApplyCLI(_BaseCommand):
    """Apply nftables isolation rules for the VM network."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        apply_firewall(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class FirewallStatusCLI(_BaseCommand):
    """Print current nftables status for the configured firewall table."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(firewall_status(_load_cfg(args.config)))
        return 0


class FirewallRemoveCLI(_BaseCommand):
    """Remove nftables rules managed by agentvm."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        remove_firewall(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class ImageFetchCLI(_BaseCommand):
    """Download/cache the configured Ubuntu base image."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(str(fetch_image(_load_cfg(args.config), dry_run=args.dry_run)))
        return 0


class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        create_or_start_vm(_load_cfg(args.config), dry_run=args.dry_run, recreate=args.recreate)
        return 0


class VMWaitIPCLI(_BaseCommand):
    """Wait for and print the VM IPv4 address."""

    timeout = scfg.Value(360, type=int, help="Timeout seconds.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(wait_for_ip(_load_cfg(args.config), timeout_s=args.timeout, dry_run=args.dry_run))
        return 0


class VMStatusCLI(_BaseCommand):
    """Show VM lifecycle status and cached IP information."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(vm_status(_load_cfg(args.config)))
        return 0


class VMDestroyCLI(_BaseCommand):
    """Destroy and undefine the VM and associated storage."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        destroy_vm(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class VMSshConfigCLI(_BaseCommand):
    """Print an SSH config stanza for easy VM access."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(mk_ssh_config(_load_cfg(args.config)))
        return 0


class VMProvisionCLI(_BaseCommand):
    """Provision the VM with optional developer packages."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        provision(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class ApplyCLI(_BaseCommand):
    """Run the full setup workflow from network to provisioning."""

    interactive = scfg.Value(False, isflag=True, help="Print plan and SSH config at the end.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        if args.interactive:
            PlanCLI.main(argv=False, config=args.config, verbose=args.verbose)
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


class StatusCLI(_BaseCommand):
    """Report setup progress across host, network, VM, SSH, and provisioning."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        cfg = _load_cfg(args.config)
        print(_render_status(cfg, path))
        return 0


class NetModalCLI(scfg.ModalCLI):
    """Network subcommands."""

    create = NetCreateCLI
    status = NetStatusCLI
    destroy = NetDestroyCLI


class FirewallModalCLI(scfg.ModalCLI):
    """Firewall subcommands."""

    apply = FirewallApplyCLI
    status = FirewallStatusCLI
    remove = FirewallRemoveCLI


class VMModalCLI(scfg.ModalCLI):
    """VM lifecycle subcommands."""

    up = VMUpCLI
    wait_ip = VMWaitIPCLI
    status = VMStatusCLI
    destroy = VMDestroyCLI
    ssh_config = VMSshConfigCLI
    provision = VMProvisionCLI


class AgentVMModalCLI(scfg.ModalCLI):
    """Local libvirt/KVM sandbox VM manager for coding agents.

    Common flows:
      agentvm init --config .agentvm.toml
      agentvm doctor --config .agentvm.toml
      agentvm status --config .agentvm.toml
      agentvm net create --config .agentvm.toml
      agentvm fw apply --config .agentvm.toml
      agentvm image-fetch --config .agentvm.toml
      agentvm vm up --config .agentvm.toml
      agentvm vm wait-ip --config .agentvm.toml
      agentvm vm ssh-config --config .agentvm.toml
      agentvm vm provision --config .agentvm.toml
      agentvm apply --config .agentvm.toml --interactive

    Tips:
      Use `agentvm <group> --help` for grouped commands (`net`, `fw`, `vm`).
    """
    init = InitCLI
    plan = PlanCLI
    doctor = DoctorCLI
    host_install_deps = HostInstallDepsCLI
    net = NetModalCLI
    fw = FirewallModalCLI
    vm = VMModalCLI
    image_fetch = ImageFetchCLI
    apply = ApplyCLI
    status = StatusCLI


def _normalize_argv(argv: list[str]) -> list[str]:
    """Normalize accepted hyphenated spellings to scriptconfig command names."""
    if len(argv) >= 2 and argv[0] == "vm":
        if argv[1] == "wait-ip":
            return [argv[0], "wait_ip", *argv[2:]]
        if argv[1] == "ssh-config":
            return [argv[0], "ssh_config", *argv[2:]]
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
