from __future__ import annotations

import argparse
import sys
from pathlib import Path
import textwrap

from loguru import logger

from .config import AgentVMConfig, load, save
from .detect import auto_defaults
from .host import check_commands, install_deps_debian, host_is_debian_like
from .net import ensure_network, network_status, destroy_network
from .firewall import apply_firewall, firewall_status, remove_firewall
from .vm import (
    create_or_start_vm,
    destroy_vm,
    vm_status,
    wait_for_ip,
    ssh_config as mk_ssh_config,
    provision,
    fetch_image,
)

log = logger


def _setup_logging(args_verbose: int, cfg_verbosity: int) -> None:
    # TODO: make our logger have timestamps, level, and location info for debug mode.
    logger.remove()  # Remove default handler
    effective_verbosity = args_verbose if args_verbose > 0 else cfg_verbosity
    print(f"effective_verbosity={effective_verbosity}")
    level = "WARNING"
    if effective_verbosity == 1:
        level = "INFO"
    elif effective_verbosity >= 2:
        level = "DEBUG"
    logger.add(sys.stderr, level=level, format="{level}: {message}")
    log.debug("setup logging")


def _cfg_path(p: str | None) -> Path:
    return Path(p or ".agentvm.toml").resolve()


def _load_cfg(args: argparse.Namespace) -> AgentVMConfig:
    path = _cfg_path(args.config)
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found: {path}. Run: agentvm init --config {path}"
        )
    return load(path).expanded_paths()


def cmd_init(args: argparse.Namespace) -> int:
    path = _cfg_path(args.config)
    cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
    if path.exists() and not args.force:
        print(f"Refusing to overwrite existing config: {path}", file=sys.stderr)
        print("Use --force to overwrite.", file=sys.stderr)
        return 2
    save(path, cfg)
    print(f"Wrote config: {path}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
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


def cmd_doctor(args: argparse.Namespace) -> int:
    missing, missing_opt = check_commands()
    if missing:
        print("Missing required commands:", ", ".join(missing))
        print("On Debian/Ubuntu you can run: agentvm host install-deps")
        return 2
    if missing_opt:
        print("Missing optional commands:", ", ".join(missing_opt))
    print("OK: required host commands present.")
    return 0


def cmd_host_install_deps(args: argparse.Namespace) -> int:
    if not host_is_debian_like():
        print(
            "Host not detected as Debian/Ubuntu. Install dependencies manually.",
            file=sys.stderr,
        )
        return 2
    install_deps_debian(assume_yes=True)
    print("Installed host dependencies (best effort).")
    return 0


def cmd_net_create(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    ensure_network(cfg, recreate=args.recreate, dry_run=args.dry_run)
    return 0


def cmd_net_status(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    print(network_status(cfg))
    return 0


def cmd_net_destroy(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    destroy_network(cfg, dry_run=args.dry_run)
    return 0


def cmd_fw_apply(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    apply_firewall(cfg, dry_run=args.dry_run)
    return 0


def cmd_fw_status(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    print(firewall_status(cfg))
    return 0


def cmd_fw_remove(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    remove_firewall(cfg, dry_run=args.dry_run)
    return 0


def cmd_image_fetch(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    p = fetch_image(cfg, dry_run=args.dry_run)
    print(str(p))
    return 0


def cmd_vm_up(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    create_or_start_vm(cfg, dry_run=args.dry_run, recreate=args.recreate)
    return 0


def cmd_vm_wait_ip(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    ip = wait_for_ip(cfg, timeout_s=args.timeout, dry_run=args.dry_run)
    print(ip)
    return 0


def cmd_vm_status(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    print(vm_status(cfg))
    return 0


def cmd_vm_destroy(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    destroy_vm(cfg, dry_run=args.dry_run)
    return 0


def cmd_vm_ssh_config(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    print(mk_ssh_config(cfg))
    return 0


def cmd_vm_provision(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    provision(cfg, dry_run=args.dry_run)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    if args.interactive:
        cmd_plan(argparse.Namespace(config=args.config))
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentvm",
        description="Local libvirt/KVM sandbox VM manager for coding agents.",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv).",
    )
    p.add_argument(
        "--config", default=None, help="Path to config TOML (default: .agentvm.toml)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Create a config file with sensible defaults.")
    sp.add_argument("--force", action="store_true", help="Overwrite existing config.")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("plan", help="Print the suggested command flow.")
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("doctor", help="Check host dependencies.")
    sp.set_defaults(func=cmd_doctor)

    host = sub.add_parser("host", help="Host utilities.")
    host_sub = host.add_subparsers(dest="host_cmd", required=True)
    sp = host_sub.add_parser(
        "install-deps", help="Install host deps (Debian/Ubuntu, requires sudo)."
    )
    sp.set_defaults(func=cmd_host_install_deps)

    net = sub.add_parser("net", help="Manage libvirt network.")
    net_sub = net.add_subparsers(dest="net_cmd", required=True)
    sp = net_sub.add_parser("create", help="Create/ensure the libvirt NAT network.")
    sp.add_argument(
        "--recreate", action="store_true", help="Destroy and recreate if it exists."
    )
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_net_create)
    sp = net_sub.add_parser("status", help="Show network info.")
    sp.set_defaults(func=cmd_net_status)
    sp = net_sub.add_parser("destroy", help="Destroy/undefine network.")
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_net_destroy)

    fw = sub.add_parser("fw", help="Manage host firewall rules (nftables).")
    fw_sub = fw.add_subparsers(dest="fw_cmd", required=True)
    sp = fw_sub.add_parser("apply", help="Apply isolation firewall rules.")
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_fw_apply)
    sp = fw_sub.add_parser("status", help="Show current rules.")
    sp.set_defaults(func=cmd_fw_status)
    sp = fw_sub.add_parser("remove", help="Remove sandbox rules.")
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_fw_remove)

    img = sub.add_parser("image", help="Manage the Ubuntu base image cache.")
    img_sub = img.add_subparsers(dest="img_cmd", required=True)
    sp = img_sub.add_parser("fetch", help="Download base image if needed.")
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_image_fetch)

    vm = sub.add_parser("vm", help="Manage the VM.")
    vm_sub = vm.add_subparsers(dest="vm_cmd", required=True)
    sp = vm_sub.add_parser("up", help="Create or start the VM.")
    sp.add_argument(
        "--recreate", action="store_true", help="Destroy and recreate if it exists."
    )
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_vm_up)
    sp = vm_sub.add_parser("wait-ip", help="Wait for DHCP IP and print it.")
    sp.add_argument("--timeout", type=int, default=360, help="Timeout seconds.")
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_vm_wait_ip)
    sp = vm_sub.add_parser("status", help="Show VM info.")
    sp.set_defaults(func=cmd_vm_status)
    sp = vm_sub.add_parser("destroy", help="Destroy and undefine the VM.")
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_vm_destroy)
    sp = vm_sub.add_parser(
        "ssh-config", help="Print an ssh_config block for VS Code Remote-SSH."
    )
    sp.set_defaults(func=cmd_vm_ssh_config)
    sp = vm_sub.add_parser(
        "provision", help="Install docker + dev tools inside the VM (via SSH)."
    )
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_vm_provision)

    sp = sub.add_parser("apply", help="Run net + firewall + vm + provision in order.")
    sp.add_argument(
        "--interactive",
        action="store_true",
        help="Print plan and SSH config at the end.",
    )
    sp.add_argument(
        "--dry-run", action="store_true", help="Print actions without running."
    )
    sp.set_defaults(func=cmd_apply)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = _load_cfg(args)
        verbosity = cfg.verbosity
    except FileNotFoundError:
        verbosity = 1
    _setup_logging(args.verbose, verbosity)
    try:
        rc = args.func(args)
    except Exception as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        if args.verbose and args.verbose >= 2:
            raise
        raise
        sys.exit(2)
    sys.exit(rc)
