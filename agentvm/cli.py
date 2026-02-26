from __future__ import annotations

import sys
import textwrap
import re
import hashlib
from pathlib import Path

import scriptconfig as scfg
from loguru import logger

from .config import AgentVMConfig, load, save
from .detect import auto_defaults
from .firewall import apply_firewall, firewall_status, remove_firewall
from .host import check_commands, host_is_debian_like, install_deps_debian
from .net import destroy_network, ensure_network, network_status
from .registry import (
    find_attachment,
    find_vm,
    load_registry,
    read_dir_metadata,
    registry_path,
    save_registry,
    upsert_attachment,
    upsert_vm,
    write_dir_metadata,
)
from .util import ensure_dir, run_cmd, which
from .vm import (
    create_or_start_vm,
    destroy_vm,
    ensure_share_mounted,
    fetch_image,
    get_ip_cached,
    provision,
    sync_settings,
    attach_vm_share,
    ssh_config as mk_ssh_config,
    vm_has_share,
    vm_share_mappings,
    vm_exists,
    vm_status,
    wait_for_ip,
    wait_for_ssh,
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
            f"Config not found: {path}. "
            f"Run: agentvm init --config {path} "
            "or use global selection commands like `agentvm code .` / `agentvm list`."
        )
    return load(path).expanded_paths()


def _load_cfg_with_path(config_path: str | None) -> tuple[AgentVMConfig, Path]:
    path = _cfg_path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found: {path}. "
            f"Run: agentvm init --config {path} "
            "or use global selection commands like `agentvm code .` / `agentvm list`."
        )
    return load(path).expanded_paths(), path


def _record_vm(cfg: AgentVMConfig, cfg_path: Path) -> Path:
    reg = load_registry()
    upsert_vm(reg, cfg, cfg_path)
    return save_registry(reg)


def _record_attachment(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    host_src: Path,
    force: bool = False,
) -> tuple[Path, Path]:
    reg = load_registry()
    upsert_vm(reg, cfg, cfg_path)
    upsert_attachment(
        reg,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode="shared",
        guest_dst=cfg.share.guest_dst,
        tag=cfg.share.tag,
        force=force,
    )
    reg_path = save_registry(reg)
    meta_path = write_dir_metadata(
        host_src,
        vm_name=cfg.vm.name,
        config_path=str(cfg_path.resolve()),
        mode="shared",
    )
    return reg_path, meta_path


def _choose_vm_interactive(options: list[str], *, reason: str) -> str:
    if not sys.stdin.isatty():
        raise RuntimeError(
            f"VM selection is ambiguous ({reason}). Re-run with --vm or --config."
        )
    print(f"Multiple VMs match ({reason}). Select one:")
    for idx, item in enumerate(options, start=1):
        print(f"  {idx}. {item}")
    while True:
        raw = input("Select VM number: ").strip()
        if not raw.isdigit():
            print("Please enter a number.")
            continue
        choice = int(raw)
        if 1 <= choice <= len(options):
            return options[choice - 1]
        print(f"Please enter a number between 1 and {len(options)}.")


def _resolve_guest_dst(host_src: Path, guest_dst_opt: str) -> str:
    guest_dst_opt = (guest_dst_opt or "").strip()
    if guest_dst_opt:
        return guest_dst_opt
    return str(host_src)


def _auto_share_tag_for_path(host_src: Path, existing_tags: set[str]) -> str:
    max_len = 36
    raw = re.sub(r"[^A-Za-z0-9_.-]+", "-", host_src.name or "hostcode").strip("-")
    base = f"hostcode-{raw}" if raw else "hostcode"
    base = base[:max_len]
    if base not in existing_tags:
        return base
    suffix = hashlib.sha1(str(host_src).encode("utf-8")).hexdigest()[:8]
    tag = f"{base[: max_len - 1 - len(suffix)]}-{suffix}"
    if tag not in existing_tags:
        return tag
    idx = 2
    while True:
        tail = f"-{suffix[:5]}-{idx}"
        cand = f"{base[: max_len - len(tail)]}{tail}"
        if cand not in existing_tags:
            return cand
        idx += 1


def _ensure_share_tag_len(cfg: AgentVMConfig, host_src: Path, existing_tags: set[str]) -> None:
    tag = (cfg.share.tag or "").strip()
    if tag and len(tag) <= 36:
        return
    cfg.share.tag = _auto_share_tag_for_path(host_src, existing_tags)


def _status_line(ok: bool | None, label: str, detail: str = "") -> str:
    icon = "✅" if ok is True else ("➖" if ok is None else "❌")
    suffix = f" - {detail}" if detail else ""
    return f"{icon} {label}{suffix}"


def _upsert_ssh_config_entry(cfg: AgentVMConfig, *, dry_run: bool = False) -> Path:
    cfg = cfg.expanded_paths()
    ssh_dir = Path.home() / ".ssh"
    ssh_cfg = ssh_dir / "config"
    block_name = cfg.vm.name
    new_block = (
        f"# >>> agentvm:{block_name} >>>\n"
        f"{mk_ssh_config(cfg).rstrip()}\n"
        f"# <<< agentvm:{block_name} <<<\n"
    )
    if dry_run:
        log.info("DRYRUN: update SSH config block for host {} in {}", block_name, ssh_cfg)
        return ssh_cfg
    ensure_dir(ssh_dir)
    existing = ssh_cfg.read_text(encoding="utf-8") if ssh_cfg.exists() else ""
    pattern = re.compile(
        rf"(?ms)^# >>> agentvm:{re.escape(block_name)} >>>\n.*?^# <<< agentvm:{re.escape(block_name)} <<<\n?"
    )
    if pattern.search(existing):
        updated = pattern.sub(new_block, existing)
    else:
        sep = "" if not existing or existing.endswith("\n") else "\n"
        updated = f"{existing}{sep}{new_block}"
    ssh_cfg.write_text(updated, encoding="utf-8")
    return ssh_cfg


def _clip(text: str, *, max_lines: int = 60) -> str:
    lines = (text or "").strip().splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    keep = lines[:max_lines]
    keep.append(f"... ({len(lines) - max_lines} more lines)")
    return "\n".join(keep)


def _parse_sync_paths_arg(paths_arg: str) -> list[str]:
    items = [p.strip() for p in (paths_arg or "").split(",")]
    return [p for p in items if p]


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


def _check_vm_state(cfg: AgentVMConfig) -> tuple[bool, bool, str]:
    dom = run_cmd(["virsh", "dominfo", cfg.vm.name], sudo=True, check=False, capture=True)
    if dom.code != 0:
        return False, False, f"{cfg.vm.name} not defined"
    state = run_cmd(
        ["virsh", "domstate", cfg.vm.name], sudo=True, check=False, capture=True
    ).stdout.strip()
    return ("running" in state.lower(), True, f"{cfg.vm.name} state={state}")


def _check_ssh_ready(cfg: AgentVMConfig, ip: str) -> tuple[bool, str, str]:
    ident = cfg.paths.ssh_identity_file
    if not ident:
        return False, "paths.ssh_identity_file is empty", ""
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
    detail = "ready" if res.code == 0 else "not ready"
    diag = (res.stdout + "\n" + res.stderr).strip()
    return (res.code == 0, detail, diag)


def _check_provisioned(cfg: AgentVMConfig, ip: str) -> tuple[bool | None, str, str]:
    if not cfg.provision.enabled:
        return None, "disabled in config", ""
    ident = cfg.paths.ssh_identity_file
    if not ident:
        return False, "paths.ssh_identity_file is empty", ""
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
        return True, "configured packages appear present", ""
    diag = (res.stdout + "\n" + res.stderr).strip()
    return False, "one or more configured packages missing", diag


def _render_status(cfg: AgentVMConfig, path: Path, *, detail: bool = False) -> str:
    lines: list[str] = ["🧭 AgentVM Status", f"📄 Config: {path}", ""]
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

    vm_ok, vm_defined, vm_detail = _check_vm_state(cfg)
    total += 1
    done += int(vm_ok)
    lines.append(_status_line(vm_ok, "VM state", vm_detail))

    ip = get_ip_cached(cfg)
    ip_ok = bool(ip) and vm_defined
    total += 1
    done += int(ip_ok)
    if ip and not vm_defined:
        lines.append(_status_line(False, "Cached VM IP", f"{ip} (stale: VM not defined)"))
        ip = None
    else:
        lines.append(_status_line(bool(ip), "Cached VM IP", ip or "no cached IP yet"))

    ssh_ok = False
    ssh_detail = "VM/IP not ready"
    ssh_diag = ""
    if vm_ok and ip:
        ssh_ok, ssh_detail, ssh_diag = _check_ssh_ready(cfg, ip)
    total += 1
    done += int(ssh_ok)
    lines.append(_status_line(ssh_ok, "SSH readiness", ssh_detail))

    if vm_ok and ip and ssh_ok:
        prov_ok, prov_detail, prov_diag = _check_provisioned(cfg, ip)
    else:
        prov_ok, prov_detail = (
            (None, "waiting for SSH")
            if cfg.provision.enabled
            else (None, "disabled in config")
        )
        prov_diag = ""
    if prov_ok is not None:
        total += 1
        done += int(prov_ok)
    lines.append(_status_line(prov_ok, "Provisioning", prov_detail))

    lines.append("")
    lines.append(f"📊 Progress: {done}/{total} checks complete")

    if detail:
        lines.append("")
        lines.append("🔬 Detailed Diagnostics")
        lines.append("")
        lines.append("Host")
        lines.append(f"- required missing: {', '.join(missing) if missing else '(none)'}")
        lines.append(f"- optional missing: {', '.join(missing_opt) if missing_opt else '(none)'}")
        lines.append("")

        net_info = run_cmd(
            ["virsh", "net-info", cfg.network.name], sudo=True, check=False, capture=True
        )
        net_xml = run_cmd(
            ["virsh", "net-dumpxml", cfg.network.name], sudo=True, check=False, capture=True
        )
        lines.append(f"Network ({cfg.network.name})")
        lines.append("```text")
        lines.append(_clip((net_info.stdout + "\n" + net_info.stderr).strip() or "(no output)"))
        lines.append("```")
        if net_xml.code == 0 and net_xml.stdout.strip():
            lines.append("```xml")
            lines.append(_clip(net_xml.stdout, max_lines=80))
            lines.append("```")
        lines.append("")

        lines.append(f"Firewall (inet {cfg.firewall.table})")
        if cfg.firewall.enabled:
            fw_raw = run_cmd(
                ["nft", "list", "table", "inet", cfg.firewall.table],
                sudo=True,
                check=False,
                capture=True,
            )
            lines.append("```text")
            lines.append(_clip((fw_raw.stdout + "\n" + fw_raw.stderr).strip() or "(no output)"))
            lines.append("```")
        else:
            lines.append("- disabled in config")
        lines.append("")

        lines.append("Image")
        img_stat = run_cmd(
            ["bash", "-lc", f"ls -lh {base_img} 2>&1"],
            sudo=True,
            check=False,
            capture=True,
        )
        lines.append("```text")
        lines.append(_clip((img_stat.stdout + "\n" + img_stat.stderr).strip() or "(no output)"))
        lines.append("```")
        lines.append("")

        lines.append(f"VM ({cfg.vm.name})")
        for cmd in (
            ["virsh", "dominfo", cfg.vm.name],
            ["virsh", "domstate", cfg.vm.name],
            ["virsh", "domiflist", cfg.vm.name],
            ["virsh", "domifaddr", cfg.vm.name],
            ["virsh", "net-dhcp-leases", cfg.network.name],
        ):
            vm_raw = run_cmd(cmd, sudo=True, check=False, capture=True)
            lines.append(f"`{' '.join(cmd)}`")
            lines.append("```text")
            lines.append(_clip((vm_raw.stdout + "\n" + vm_raw.stderr).strip() or "(no output)"))
            lines.append("```")
        lines.append("")

        ip_file = Path(cfg.paths.state_dir) / cfg.vm.name / f"{cfg.vm.name}.ip"
        lines.append("Cache")
        lines.append(f"- ip file: {ip_file}")
        if ip_file.exists():
            lines.append(f"- ip value: {ip_file.read_text(encoding='utf-8').strip() or '(empty)'}")
        else:
            lines.append("- ip value: (missing)")
        lines.append("")

        lines.append("SSH probe")
        if ssh_diag:
            lines.append("```text")
            lines.append(_clip(ssh_diag))
            lines.append("```")
        else:
            lines.append("- no probe output")
        lines.append("")

        lines.append("Provision probe")
        if prov_diag:
            lines.append("```text")
            lines.append(_clip(prov_diag))
            lines.append("```")
        else:
            lines.append("- no probe output")

        next_steps: list[str] = []
        if missing:
            next_steps.append("agentvm host_install_deps --config .agentvm.toml")
        if not net_ok:
            next_steps.append("agentvm net create --config .agentvm.toml")
        if cfg.firewall.enabled and fw_ok is not True:
            next_steps.append("agentvm fw apply --config .agentvm.toml")
        if not img_ok:
            next_steps.append("agentvm image_fetch --config .agentvm.toml")
        if not vm_ok:
            next_steps.append("agentvm vm up --config .agentvm.toml")
        if vm_ok and not ip:
            next_steps.append("agentvm vm wait_ip --config .agentvm.toml")
        if vm_ok and ip and not ssh_ok:
            next_steps.append("agentvm vm status --config .agentvm.toml")
        if prov_ok is False:
            next_steps.append("agentvm vm provision --config .agentvm.toml")
        if next_steps:
            lines.append("")
            lines.append("🛠️ Suggested Next Commands")
            for cmd in next_steps:
                lines.append(f"- `{cmd}`")
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
        reg_path = _record_vm(cfg, path)
        print(f"Wrote config: {path}")
        print(f"Registered VM in global registry: {reg_path}")
        return 0


class PlanCLI(_BaseCommand):
    """Show the recommended end-to-end setup command sequence."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        steps = textwrap.dedent(f"""
        🗺️  AgentVM Plan
        📄 Config: {path}

        Suggested flow:

        1. 🔎 Preflight checks
           agentvm doctor --config {path}
           agentvm status --config {path}
           agentvm status --config {path} --detail
        2. 🌐 Host network
           agentvm net create --config {path}
        3. 🔥 Optional firewall isolation (recommended)
           agentvm fw apply --config {path}
        4. 📦 Base image
           agentvm image_fetch --config {path}
        5. 🖥️ VM lifecycle
           agentvm vm up --config {path}
           agentvm vm wait_ip --config {path}
        6. 🔑 Access
           agentvm vm ssh_config --config {path}   # VS Code Remote-SSH
        7. 🧰 Optional provisioning (docker + dev tools)
           agentvm vm provision --config {path}
        8. 🧩 Optional settings sync from host user profile
           agentvm vm sync_settings --config {path}
        9. 🧑‍💻 Optional VS Code one-shot open (share + remote launch)
           agentvm vm code --config {path} --host_src . --sync_settings
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
            print("❌ Missing required commands:", ", ".join(missing))
            print("💡 On Debian/Ubuntu you can run: agentvm host_install_deps")
            return 2
        if missing_opt:
            print("➖ Missing optional commands:", ", ".join(missing_opt))
        print("✅ Required host commands are present.")
        return 0


class HostInstallDepsCLI(_BaseCommand):
    """Install required host dependencies on Debian/Ubuntu."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        cls.cli(argv=argv, data=kwargs)
        if not host_is_debian_like():
            print("❌ Host not detected as Debian/Ubuntu. Install dependencies manually.", file=sys.stderr)
            return 2
        install_deps_debian(assume_yes=True)
        print("✅ Installed host dependencies (best effort).")
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
        cfg, cfg_path = _load_cfg_with_path(args.config)
        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=args.recreate)
        if not args.dry_run:
            _record_vm(cfg, cfg_path)
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


class VMSyncSettingsCLI(_BaseCommand):
    """Copy host user settings/files into the VM user home."""

    paths = scfg.Value(
        "",
        help=(
            "Optional comma-separated host paths to sync. "
            "Defaults to [sync].paths from config."
        ),
    )
    overwrite = scfg.Value(
        True,
        isflag=True,
        help="Overwrite existing files in VM (default true).",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        if args.dry_run:
            ip = "0.0.0.0"
        else:
            ip = get_ip_cached(cfg) or wait_for_ip(cfg, timeout_s=360, dry_run=False)
            wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
        chosen_paths = _parse_sync_paths_arg(args.paths) if args.paths else None
        result = sync_settings(
            cfg,
            ip,
            paths=chosen_paths,
            overwrite=bool(args.overwrite),
            dry_run=args.dry_run,
        )
        print("🧩 Settings sync summary")
        print(f"  copied: {len(result['copied'])}")
        print(f"  skipped_missing: {len(result['skipped_missing'])}")
        print(f"  skipped_exists: {len(result['skipped_exists'])}")
        print(f"  failed: {len(result['failed'])}")
        for k in ("copied", "skipped_missing", "skipped_exists", "failed"):
            for item in result[k]:
                print(f"  - {k}: {item}")
        if result["failed"]:
            return 2
        return 0


def _select_cfg_for_vm_name(vm_name: str, *, reason: str) -> tuple[AgentVMConfig, Path]:
    reg = load_registry()
    rec = find_vm(reg, vm_name)
    if rec is None:
        raise RuntimeError(f"VM not found in global registry ({reason}): {vm_name}")
    cfg_path = Path(rec.config_path).expanduser()
    if not cfg_path.exists():
        raise RuntimeError(
            f"Config path for VM {vm_name} does not exist: {cfg_path}. "
            "Re-register it with `agentvm init` or `agentvm vm up`."
        )
    return load(cfg_path).expanded_paths(), cfg_path


def _resolve_cfg_for_code(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
) -> tuple[AgentVMConfig, Path]:
    if config_opt is not None:
        return _load_cfg_with_path(config_opt)

    cwd_cfg = _cfg_path(None)
    if cwd_cfg.exists():
        return _load_cfg_with_path(None)

    if vm_opt:
        return _select_cfg_for_vm_name(vm_opt, reason="--vm")

    reg = load_registry()
    meta = read_dir_metadata(host_src)
    meta_vm = str(meta.get("vm_name", "")).strip() if isinstance(meta, dict) else ""
    if meta_vm:
        return _select_cfg_for_vm_name(meta_vm, reason="directory metadata")

    att = find_attachment(reg, host_src)
    if att is not None:
        return _select_cfg_for_vm_name(att.vm_name, reason="existing attachment")

    valid = [r for r in reg.vms if r.config_path and Path(r.config_path).expanduser().exists()]
    if not valid:
        raise RuntimeError(
            "No usable VM config found. Pass --config, run `agentvm init`, or register a VM."
        )
    if len(valid) == 1:
        only = valid[0]
        return _select_cfg_for_vm_name(only.name, reason="single registered VM")

    chosen = _choose_vm_interactive(
        [r.name for r in sorted(valid, key=lambda x: x.name)],
        reason=f"{len(valid)} registered VMs",
    )
    return _select_cfg_for_vm_name(chosen, reason="interactive choice")


class VMCodeCLI(_BaseCommand):
    """Open a host project folder in VS Code attached to the VM via Remote-SSH."""

    host_src = scfg.Value(
        ".",
        help="Host project directory to share and open (default: current directory).",
    )
    vm = scfg.Value(
        "",
        help="VM name override for selecting config from global registry.",
    )
    guest_dst = scfg.Value(
        "",
        help="Guest mount path override (default: config share.guest_dst).",
    )
    recreate_if_needed = scfg.Value(
        False,
        isflag=True,
        help="Recreate VM if existing definition lacks the requested share mapping.",
    )
    ensure_firewall = scfg.Value(
        True,
        isflag=True,
        help="Apply firewall rules when firewall.enabled=true.",
    )
    sync_settings = scfg.Value(
        False,
        isflag=True,
        help="Sync host settings files into VM before launching VS Code.",
    )
    sync_paths = scfg.Value(
        "",
        help=(
            "Optional comma-separated paths used when --sync_settings is set. "
            "Defaults to [sync].paths."
        ),
    )
    force = scfg.Value(
        False,
        isflag=True,
        help="Force attaching folder even if already attached to a different VM.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)

        host_src = Path(args.host_src).resolve()
        if not host_src.exists():
            raise FileNotFoundError(f"Host source path does not exist: {host_src}")
        if not host_src.is_dir():
            raise RuntimeError(f"Host source path is not a directory: {host_src}")

        cfg, cfg_path = _resolve_cfg_for_code(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=host_src,
        )

        cfg.share.enabled = True
        cfg.share.host_src = str(host_src)
        cfg.share.guest_dst = _resolve_guest_dst(host_src, args.guest_dst)
        _ensure_share_tag_len(cfg, host_src, set())

        ensure_network(cfg, recreate=False, dry_run=args.dry_run)
        if cfg.firewall.enabled and args.ensure_firewall:
            apply_firewall(cfg, dry_run=args.dry_run)

        recreate = False
        if not args.dry_run and vm_exists(cfg):
            mappings = vm_share_mappings(cfg)
            requested_src = str(Path(cfg.share.host_src).resolve())
            existing_tags = {tag for _, tag in mappings if tag}
            _ensure_share_tag_len(cfg, host_src, existing_tags)
            # Reuse existing tag if this source is already defined on the VM.
            for src, tag in mappings:
                if src == requested_src and tag:
                    cfg.share.tag = tag
                    break
            # Avoid tag collisions if the default tag is already bound to a different source.
            if not vm_has_share(cfg):
                for src, tag in mappings:
                    if tag == cfg.share.tag and src != requested_src:
                        cfg.share.tag = _auto_share_tag_for_path(host_src, existing_tags)
                        break

        if not args.dry_run and vm_exists(cfg) and not vm_has_share(cfg):
            if args.recreate_if_needed:
                recreate = True
            else:
                try:
                    attach_vm_share(cfg, dry_run=False)
                except Exception as ex:
                    current_maps = vm_share_mappings(cfg)
                    requested_src = str(Path(cfg.share.host_src).resolve())
                    requested_tag = cfg.share.tag
                    if current_maps:
                        found = "\n".join(
                            f"  - source={src or '(none)'} tag={tag or '(none)'}"
                            for src, tag in current_maps
                        )
                    else:
                        found = "  - (no filesystem mappings found)"
                    raise RuntimeError(
                        "Existing VM does not include requested share mapping, and live attach failed.\n"
                        f"VM: {cfg.vm.name}\n"
                        f"Requested: source={requested_src} tag={requested_tag} guest_dst={cfg.share.guest_dst}\n"
                        "Current VM filesystem mappings:\n"
                        f"{found}\n"
                        f"Live attach error: {ex}\n"
                        "Next steps:\n"
                        "  - Re-run with --recreate_if_needed to rebuild the VM definition with the new share.\n"
                        "  - Or use a VM already defined with this share mapping."
                    )

        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=recreate)

        if args.dry_run:
            print(f"DRYRUN: would open {cfg.share.guest_dst} in VS Code via host {cfg.vm.name}")
            return 0

        reg_path, meta_path = _record_attachment(
            cfg,
            cfg_path,
            host_src=host_src,
            force=bool(args.force),
        )

        ip = wait_for_ip(cfg, timeout_s=360, dry_run=False)
        wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
        ensure_share_mounted(cfg, ip, dry_run=False)

        do_sync = bool(args.sync_settings or cfg.sync.enabled)
        if do_sync:
            chosen_paths = _parse_sync_paths_arg(args.sync_paths) if args.sync_paths else None
            sync_result = sync_settings(
                cfg,
                ip,
                paths=chosen_paths,
                overwrite=cfg.sync.overwrite,
                dry_run=False,
            )
            if sync_result["failed"]:
                raise RuntimeError(
                    "Failed syncing one or more settings files:\n"
                    + "\n".join(sync_result["failed"])
                )

        ssh_cfg = _upsert_ssh_config_entry(cfg, dry_run=False)

        if which("code") is None:
            raise RuntimeError(
                "VS Code CLI `code` not found in PATH. Install VS Code and enable the shell command."
            )
        remote_target = f"ssh-remote+{cfg.vm.name}"
        run_cmd(
            ["code", "--remote", remote_target, cfg.share.guest_dst],
            sudo=False,
            check=True,
            capture=False,
        )
        print(f"Opened VS Code remote folder {cfg.share.guest_dst} on host {cfg.vm.name}")
        print(f"SSH entry updated in {ssh_cfg}")
        print(f"Folder registered in {reg_path} and {meta_path}")
        return 0


class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm = scfg.Value("", help="Optional VM name in global registry.")
    host_src = scfg.Value(".", help="Host directory to attach.")
    guest_dst = scfg.Value("", help="Guest mount path override.")
    force = scfg.Value(
        False,
        isflag=True,
        help="Allow attaching folder that is already attached to a different VM.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        host_src = Path(args.host_src).resolve()
        if not host_src.exists() or not host_src.is_dir():
            raise RuntimeError(f"host_src must be an existing directory: {host_src}")

        if args.config:
            cfg, cfg_path = _load_cfg_with_path(args.config)
        elif args.vm:
            cfg, cfg_path = _select_cfg_for_vm_name(args.vm, reason="--vm")
        else:
            cfg, cfg_path = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt="",
                host_src=host_src,
            )

        cfg.share.enabled = True
        cfg.share.host_src = str(host_src)
        cfg.share.guest_dst = _resolve_guest_dst(host_src, args.guest_dst)
        _ensure_share_tag_len(cfg, host_src, set())

        if args.dry_run:
            print(f"DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {cfg.share.guest_dst}")
            return 0

        save(cfg_path, cfg)
        if vm_exists(cfg):
            mappings = vm_share_mappings(cfg)
            requested_src = str(Path(cfg.share.host_src).resolve())
            existing_tags = {tag for _, tag in mappings if tag}
            _ensure_share_tag_len(cfg, host_src, existing_tags)
            for src, tag in mappings:
                if src == requested_src and tag:
                    cfg.share.tag = tag
                    break
            if not vm_has_share(cfg):
                for src, tag in mappings:
                    if tag == cfg.share.tag and src != requested_src:
                        cfg.share.tag = _auto_share_tag_for_path(host_src, existing_tags)
                        break
                if not vm_has_share(cfg):
                    attach_vm_share(cfg, dry_run=False)
                    save(cfg_path, cfg)
        reg_path, meta_path = _record_attachment(
            cfg,
            cfg_path,
            host_src=host_src,
            force=bool(args.force),
        )
        print(f"Attached {host_src} to VM {cfg.vm.name} (shared mode)")
        print(f"Updated config: {cfg_path}")
        print(f"Updated registry: {reg_path}")
        print(f"Updated directory metadata: {meta_path}")
        return 0


class CodeCLI(VMCodeCLI):
    """Top-level shortcut for `agentvm vm code`."""


class AttachCLI(VMAttachCLI):
    """Top-level shortcut for `agentvm vm attach`."""


class ApplyCLI(_BaseCommand):
    """Run the full setup workflow from network to provisioning."""

    interactive = scfg.Value(False, isflag=True, help="Print plan and SSH config at the end.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
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
        if not args.dry_run:
            _record_vm(cfg, cfg_path)
        log.debug("Waiting for VM IP address")
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
            raise RuntimeError(f"--section must be one of: {', '.join(sorted(allowed))}")

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
                    print(f"  - {name} | strict_firewall={'yes' if by_name[name] else 'no'}")

        if want in {"all", "folders"}:
            if want == "all":
                print("")
            print("Attached Folders")
            if not reg.attachments:
                print("  (none)")
            else:
                for att in sorted(reg.attachments, key=lambda x: (x.vm_name, x.host_path)):
                    print(
                        f"  - {att.host_path} | vm={att.vm_name} "
                        f"| mode={att.mode} | guest_dst={att.guest_dst or '(default)'}"
                    )
        print("")
        print(f"Registry: {reg_path}")
        return 0


class StatusCLI(_BaseCommand):
    """Report setup progress across host, network, VM, SSH, and provisioning."""
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
        if args.config is not None or _cfg_path(None).exists():
            cfg, path = _load_cfg_with_path(args.config)
        else:
            cfg, path = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt=args.vm,
                host_src=Path.cwd(),
            )
        print(_render_status(cfg, path, detail=args.detail))
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
    sync_settings = VMSyncSettingsCLI
    attach = VMAttachCLI
    code = VMCodeCLI


class AgentVMModalCLI(scfg.ModalCLI):
    """Local libvirt/KVM sandbox VM manager for coding agents.

    Common flows:
      agentvm init --config .agentvm.toml
      agentvm doctor --config .agentvm.toml
      agentvm status --config .agentvm.toml
      agentvm net create --config .agentvm.toml
      agentvm fw apply --config .agentvm.toml
      agentvm image_fetch --config .agentvm.toml
      agentvm vm up --config .agentvm.toml
      agentvm vm wait_ip --config .agentvm.toml
      agentvm vm ssh_config --config .agentvm.toml
      agentvm vm provision --config .agentvm.toml
      agentvm vm sync_settings --config .agentvm.toml
      agentvm vm attach --vm agentvm-2404 --host_src .
      agentvm vm code --config .agentvm.toml --host_src . --sync_settings
      agentvm code . --sync_settings
      agentvm list
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
    code = CodeCLI
    attach = AttachCLI
    image_fetch = ImageFetchCLI
    apply = ApplyCLI
    list = ListCLI
    status = StatusCLI


def _normalize_argv(argv: list[str]) -> list[str]:
    """Normalize accepted hyphenated spellings to scriptconfig command names."""
    if len(argv) >= 1 and argv[0] == "attach":
        if len(argv) >= 2 and not argv[1].startswith("-"):
            return ["attach", "--host_src", argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == "code":
        if len(argv) >= 2 and not argv[1].startswith("-"):
            return ["code", "--host_src", argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == "ls":
        return ["list", *argv[1:]]
    if len(argv) >= 2 and argv[0] == "vm":
        if argv[1] == "wait-ip":
            return [argv[0], "wait_ip", *argv[2:]]
        if argv[1] == "ssh-config":
            return [argv[0], "ssh_config", *argv[2:]]
        if argv[1] == "sync-settings":
            return [argv[0], "sync_settings", *argv[2:]]
        if argv[1] == "code" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [argv[0], "code", "--host_src", argv[2], *argv[3:]]
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
