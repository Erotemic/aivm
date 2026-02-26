from __future__ import annotations

import sys
import textwrap
import re
import hashlib
import os
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import scriptconfig as scfg
from loguru import logger

from .config import AgentVMConfig, dump_toml, load, save
from .detect import auto_defaults, detect_ssh_identity
from .firewall import apply_firewall, firewall_status, remove_firewall
from .host import check_commands, host_is_debian_like, install_deps_debian
from .net import destroy_network, ensure_network, network_status
from .registry import (
    DIR_METADATA_FILE,
    find_attachment,
    find_vm,
    load_registry,
    read_dir_metadata,
    registry_path,
    save_registry,
    upsert_attachment,
    upsert_vm,
    vm_global_config_path,
    write_dir_metadata,
)
from .runtime import require_ssh_identity, ssh_base_args, virsh_system_cmd
from .status import (
    clip as _clip_text,
    probe_firewall,
    probe_network,
    probe_provisioned,
    probe_ssh_ready,
    probe_vm_state,
    render_global_status,
    render_status,
    status_line,
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

    config = scfg.Value(None, help="Path to config TOML (default: .aivm.toml).")
    verbose = scfg.Value(
        0, short_alias=["v"], isflag="counter", help="Increase verbosity (-v, -vv)."
    )
    yes = scfg.Value(
        False, isflag=True, help="Auto-approve privileged host operations (sudo)."
    )


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
    log.debug(
        "Logging configured at {} (effective_verbosity={})", level, effective_verbosity
    )


def _cfg_path(p: str | None) -> Path:
    return Path(p or ".aivm.toml").resolve()


def _load_cfg(config_path: str | None) -> AgentVMConfig:
    cfg, _ = _load_cfg_with_path(config_path)
    return cfg


def _hydrate_runtime_defaults(cfg: AgentVMConfig) -> bool:
    """Fill missing runtime-critical defaults on legacy/stale configs."""
    changed = False
    # First prefer previously known good VM-global config values.
    if not cfg.paths.ssh_identity_file or not cfg.paths.ssh_pubkey_path:
        gpath = vm_global_config_path(cfg.vm.name)
        if gpath.exists():
            try:
                gcfg = load(gpath).expanded_paths()
            except Exception:
                gcfg = None
            if gcfg is not None:
                if not cfg.paths.ssh_identity_file and gcfg.paths.ssh_identity_file:
                    cfg.paths.ssh_identity_file = gcfg.paths.ssh_identity_file
                    changed = True
                if not cfg.paths.ssh_pubkey_path and gcfg.paths.ssh_pubkey_path:
                    cfg.paths.ssh_pubkey_path = gcfg.paths.ssh_pubkey_path
                    changed = True

    ident, pub = detect_ssh_identity()
    if not cfg.paths.ssh_identity_file and ident:
        cfg.paths.ssh_identity_file = ident
        changed = True
    if not cfg.paths.ssh_pubkey_path and pub:
        cfg.paths.ssh_pubkey_path = pub
        changed = True
    if changed:
        log.debug(
            "Hydrated runtime defaults for vm={} ssh_identity_file={} ssh_pubkey_path={}",
            cfg.vm.name,
            cfg.paths.ssh_identity_file or "(empty)",
            cfg.paths.ssh_pubkey_path or "(empty)",
        )
    return changed


def _load_cfg_with_path(
    config_path: str | None,
    *,
    hydrate_runtime_defaults: bool = True,
    persist_runtime_defaults: bool = False,
) -> tuple[AgentVMConfig, Path]:
    path = _cfg_path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found: {path}. "
            f"Run: aivm config init --config {path} "
            "or use global selection commands like `aivm code .` / `aivm list`."
        )
    cfg = load(path).expanded_paths()
    changed = False
    if hydrate_runtime_defaults:
        changed = _hydrate_runtime_defaults(cfg)
    if changed and persist_runtime_defaults:
        save(path, cfg)
    return cfg, path


def _resolve_cfg_fallback(
    config_opt: str | None, *, vm_opt: str = ""
) -> tuple[AgentVMConfig, Path]:
    """Resolve config from explicit/local path, else directory metadata/global registry."""
    if config_opt is not None or _cfg_path(None).exists():
        return _load_cfg_with_path(config_opt)
    return _resolve_cfg_for_code(config_opt=None, vm_opt=vm_opt, host_src=Path.cwd())


def _record_vm(cfg: AgentVMConfig, cfg_path: Path) -> Path:
    gpath = vm_global_config_path(cfg.vm.name)
    ensure_dir(gpath.parent)
    save(gpath, cfg)
    reg = load_registry()
    upsert_vm(reg, cfg, cfg_path, global_cfg_path=gpath)
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


def _confirm_sudo_block(*, yes: bool, purpose: str) -> None:
    if yes or os.geteuid() == 0:
        return
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Privileged host operations require confirmation, but stdin is not interactive. "
            "Re-run with --yes."
        )
    print("About to run privileged host operations via sudo:")
    print(f"  {purpose}")
    ans = input("Continue? [y/N]: ").strip().lower()
    if ans not in {"y", "yes"}:
        raise RuntimeError("Aborted by user.")


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


def _ensure_share_tag_len(
    cfg: AgentVMConfig, host_src: Path, existing_tags: set[str]
) -> None:
    tag = (cfg.share.tag or "").strip()
    if tag and len(tag) <= 36:
        return
    cfg.share.tag = _auto_share_tag_for_path(host_src, existing_tags)


def _probe_vm_running_nonsudo(vm_name: str) -> bool | None:
    res = run_cmd(
        virsh_system_cmd("domstate", vm_name),
        sudo=False,
        check=False,
        capture=True,
    )
    if res.code != 0:
        return None
    state = (res.stdout or "").strip().lower()
    return "running" in state


def _status_line(ok: bool | None, label: str, detail: str = "") -> str:
    return status_line(ok, label, detail)


def _upsert_ssh_config_entry(cfg: AgentVMConfig, *, dry_run: bool = False) -> Path:
    cfg = cfg.expanded_paths()
    ssh_dir = Path.home() / ".ssh"
    ssh_cfg = ssh_dir / "config"
    block_name = cfg.vm.name
    new_block = (
        f"# >>> aivm:{block_name} >>>\n"
        f"{mk_ssh_config(cfg).rstrip()}\n"
        f"# <<< aivm:{block_name} <<<\n"
    )
    if dry_run:
        log.info(
            "DRYRUN: update SSH config block for host {} in {}", block_name, ssh_cfg
        )
        return ssh_cfg
    ensure_dir(ssh_dir)
    existing = ssh_cfg.read_text(encoding="utf-8") if ssh_cfg.exists() else ""
    pattern = re.compile(
        rf"(?ms)^# >>> aivm:{re.escape(block_name)} >>>\n.*?^# <<< aivm:{re.escape(block_name)} <<<\n?"
    )
    if pattern.search(existing):
        updated = pattern.sub(new_block, existing)
    else:
        sep = "" if not existing or existing.endswith("\n") else "\n"
        updated = f"{existing}{sep}{new_block}"
    ssh_cfg.write_text(updated, encoding="utf-8")
    return ssh_cfg


def _clip(text: str, *, max_lines: int = 60) -> str:
    return _clip_text(text, max_lines=max_lines)


def _parse_sync_paths_arg(paths_arg: str) -> list[str]:
    items = [p.strip() for p in (paths_arg or "").split(",")]
    return [p for p in items if p]


def _check_network(cfg: AgentVMConfig, *, use_sudo: bool) -> tuple[bool | None, str]:
    out = probe_network(cfg, use_sudo=use_sudo)
    return out.ok, out.detail


def _check_firewall(cfg: AgentVMConfig, *, use_sudo: bool) -> tuple[bool | None, str]:
    out = probe_firewall(cfg, use_sudo=use_sudo)
    return out.ok, out.detail


def _file_exists(path: Path, *, use_sudo: bool) -> bool:
    return (
        run_cmd(
            ["test", "-f", str(path)], sudo=use_sudo, check=False, capture=True
        ).code
        == 0
    )


def _check_vm_state(
    cfg: AgentVMConfig, *, use_sudo: bool
) -> tuple[bool | None, bool, str]:
    out, vm_defined = probe_vm_state(cfg, use_sudo=use_sudo)
    return out.ok, vm_defined, out.detail


def _check_ssh_ready(cfg: AgentVMConfig, ip: str) -> tuple[bool, str, str]:
    out = probe_ssh_ready(cfg, ip)
    return bool(out.ok), out.detail, out.diag


def _check_provisioned(cfg: AgentVMConfig, ip: str) -> tuple[bool | None, str, str]:
    out = probe_provisioned(cfg, ip)
    return out.ok, out.detail, out.diag


def _render_status(
    cfg: AgentVMConfig,
    path: Path,
    *,
    detail: bool = False,
    use_sudo: bool = False,
) -> str:
    return render_status(cfg, path, detail=detail, use_sudo=use_sudo)


def _render_global_status() -> str:
    return render_global_status()


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


class ConfigShowCLI(_BaseCommand):
    """Show the resolved config content."""

    vm = scfg.Value(
        "",
        help="Optional VM name override when no local config file is present.",
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, path = _resolve_cfg_fallback(args.config, vm_opt=args.vm)
        print(f"# Config: {path}")
        print(dump_toml(cfg), end="")
        return 0


class ConfigEditCLI(_BaseCommand):
    """Edit the resolved config file in $EDITOR."""

    vm = scfg.Value(
        "",
        help="Optional VM name override when no local config file is present.",
    )
    editor = scfg.Value(
        "",
        help="Editor command override (default: $EDITOR/$VISUAL, then nano/vi).",
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, path = _resolve_cfg_fallback(args.config, vm_opt=args.vm)
        # Persist hydrated/defaulted values before opening an editor.
        save(path, cfg)
        editor_cmd = (
            args.editor.strip()
            if str(args.editor or "").strip()
            else (os.environ.get("EDITOR") or os.environ.get("VISUAL") or "")
        )
        if not editor_cmd:
            editor_cmd = which("nano") or which("vi") or ""
        if not editor_cmd:
            raise RuntimeError("No editor found. Set $EDITOR or pass --editor.")
        parts = shlex.split(editor_cmd) + [str(path)]
        run_cmd(parts, sudo=False, check=True, capture=False)
        return 0


class ConfigPathCLI(_BaseCommand):
    """Show in-scope config and metadata paths for current/target directory."""

    vm = scfg.Value(
        "",
        help="Optional VM name override for showing VM-global config path.",
    )
    host_src = scfg.Value(
        ".",
        help="Host directory scope to inspect (default: current directory).",
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        host_src = Path(args.host_src).resolve()
        local_cfg = host_src / ".aivm.toml"
        meta_path = host_src / DIR_METADATA_FILE
        reg_path = registry_path()
        reg = load_registry(reg_path)
        att = find_attachment(reg, host_src)
        meta = read_dir_metadata(host_src)
        meta_vm = str(meta.get("vm_name", "")).strip() if isinstance(meta, dict) else ""
        resolved_cfg_path: Path | None = None
        resolved_vm = ""
        resolve_error = ""
        try:
            resolved_cfg, resolved_cfg_path = _resolve_cfg_for_code(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=host_src,
            )
            resolved_vm = resolved_cfg.vm.name
        except Exception as ex:
            resolve_error = str(ex)

        vm_name = str(args.vm or "").strip() or resolved_vm or meta_vm
        if not vm_name and att is not None:
            vm_name = att.vm_name

        print("🧭 AIVM Config Paths")
        print(f"cwd = {host_src}")
        print(
            f"local_config = {local_cfg} "
            f"({'exists' if local_cfg.exists() else 'missing'})"
        )
        print(
            f"dir_metadata = {meta_path} "
            f"({'exists' if meta_path.exists() else 'missing'})"
        )
        if meta_vm:
            print(f"dir_metadata_vm = {meta_vm}")
        print(
            f"registry = {reg_path} "
            f"({'exists' if reg_path.exists() else 'missing'})"
        )
        if att is not None:
            print(f"registry_attachment_vm = {att.vm_name}")
        if vm_name:
            vm_cfg = vm_global_config_path(vm_name)
            print(
                f"vm_global_config = {vm_cfg} "
                f"({'exists' if vm_cfg.exists() else 'missing'})"
            )
            rec = find_vm(reg, vm_name)
            if rec is not None:
                if rec.config_path:
                    p = Path(rec.config_path).expanduser()
                    print(
                        f"registry_vm_config = {p} "
                        f"({'exists' if p.exists() else 'missing'})"
                    )
                if rec.global_config_path:
                    p = Path(rec.global_config_path).expanduser()
                    print(
                        f"registry_vm_global_config = {p} "
                        f"({'exists' if p.exists() else 'missing'})"
                    )
        if resolved_cfg_path is not None:
            print(f"resolved_config = {resolved_cfg_path}")
            if resolved_vm:
                print(f"resolved_vm = {resolved_vm}")
        else:
            print("resolved_config = (unresolved)")
            if resolve_error:
                print(f"resolution_error = {resolve_error}")
        return 0


def _discover_vm_info(vm_name: str, *, use_sudo: bool) -> dict[str, object]:
    info: dict[str, object] = {
        "name": vm_name,
        "state": "unknown",
        "autostart": "unknown",
        "network": "unknown",
        "vcpus": "unknown",
        "memory_mib": "unknown",
        "shares": [],
    }
    dominfo = run_cmd(
        virsh_system_cmd("dominfo", vm_name),
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if dominfo.code == 0:
        for line in (dominfo.stdout or "").splitlines():
            if ":" not in line:
                continue
            key, val = [x.strip() for x in line.split(":", 1)]
            low = key.lower()
            if low == "state":
                info["state"] = val or "unknown"
            elif low == "autostart":
                info["autostart"] = val or "unknown"
            elif low in {"cpu(s)", "cpus"}:
                info["vcpus"] = val or "unknown"
            elif low.startswith("max memory"):
                m = re.search(r"(\d+)", val)
                if m:
                    kib = int(m.group(1))
                    info["memory_mib"] = str(kib // 1024)
    xml = run_cmd(
        virsh_system_cmd("dumpxml", vm_name),
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if xml.code == 0 and xml.stdout.strip():
        try:
            root = ET.fromstring(xml.stdout)
            iface = root.find(".//devices/interface[@type='network']/source")
            if iface is not None:
                name = iface.attrib.get("network", "").strip()
                if name:
                    info["network"] = name
            shares: list[str] = []
            for fs in root.findall(".//devices/filesystem[@type='mount']"):
                src = fs.find("source")
                tgt = fs.find("target")
                src_dir = src.attrib.get("dir", "").strip() if src is not None else ""
                tgt_dir = tgt.attrib.get("dir", "").strip() if tgt is not None else ""
                if src_dir or tgt_dir:
                    shares.append(f"{src_dir or '?'} -> {tgt_dir or '?'}")
            info["shares"] = shares
        except Exception:
            pass
    return info


def _prompt_import_discovered_vm(vm_info: dict[str, object], *, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        return False
    print("")
    print(f"Discovered unmanaged VM: {vm_info['name']}")
    print(
        f"  state={vm_info['state']} | autostart={vm_info['autostart']} | "
        f"network={vm_info['network']} | vcpus={vm_info['vcpus']} | "
        f"memory_mib={vm_info['memory_mib']}"
    )
    shares = vm_info.get("shares", [])
    if isinstance(shares, list) and shares:
        print("  shares:")
        for item in shares[:5]:
            print(f"    - {item}")
        if len(shares) > 5:
            print(f"    - ... ({len(shares) - 5} more)")
    else:
        print("  shares: none detected")
    ans = input("Add this VM to aivm registry/config? [y/N]: ").strip().lower()
    return ans in {"y", "yes"}


class ConfigDiscoverCLI(_BaseCommand):
    """Discover existing libvirt VMs and register them in aivm config registry."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without writing config/registry.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        names_res = run_cmd(
            virsh_system_cmd("list", "--all", "--name"),
            sudo=False,
            check=False,
            capture=True,
        )
        used_sudo = False
        if names_res.code != 0:
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose="Discover existing libvirt VMs via system virsh.",
            )
            used_sudo = True
            names_res = run_cmd(
                virsh_system_cmd("list", "--all", "--name"),
                sudo=True,
                check=True,
                capture=True,
            )

        vm_names = [n.strip() for n in names_res.stdout.splitlines() if n.strip()]
        reg = load_registry()
        managed_seen = 0
        added = 0
        updated = 0
        created_cfg = 0
        skipped_unmanaged = 0
        for vm_name in vm_names:
            rec = find_vm(reg, vm_name)
            vm_info = _discover_vm_info(vm_name, use_sudo=used_sudo)
            if rec is None and not _prompt_import_discovered_vm(
                vm_info, yes=bool(args.yes)
            ):
                skipped_unmanaged += 1
                continue
            cfg_path = vm_global_config_path(vm_name)
            cfg = None
            if rec is not None:
                managed_seen += 1
                candidates = []
                if rec.config_path:
                    candidates.append(Path(rec.config_path).expanduser())
                if rec.global_config_path:
                    candidates.append(Path(rec.global_config_path).expanduser())
                for p in candidates:
                    if p.exists():
                        try:
                            cfg = load(p).expanded_paths()
                            break
                        except Exception:
                            continue
            if cfg is None:
                cfg = AgentVMConfig().expanded_paths()
                cfg.vm.name = vm_name
                cfg.network.name = str(vm_info.get("network", "unknown"))
                created_cfg += 1
            else:
                cfg.vm.name = vm_name
                if not cfg.network.name:
                    cfg.network.name = str(vm_info.get("network", "unknown"))

            if rec is None:
                added += 1
            else:
                updated += 1
            if not args.dry_run:
                ensure_dir(cfg_path.parent)
                save(cfg_path, cfg)
                upsert_vm(reg, cfg, cfg_path, global_cfg_path=cfg_path)

        reg_path = registry_path()
        if not args.dry_run:
            save_registry(reg)

        print(f"Discovered VMs: {len(vm_names)}")
        print(f"  already_managed_seen: {managed_seen}")
        print(f"  added: {added}")
        print(f"  updated: {updated}")
        print(f"  skipped_unmanaged: {skipped_unmanaged}")
        print(f"  created_config_files: {created_cfg}")
        print(f"Registry: {reg_path}")
        print("")
        print("Security caveats:")
        print("  - Discovery trusts local libvirt state only; ownership/provenance of VMs is not verified.")
        print("  - Imported configs may not reflect actual firewall isolation policy for each VM/network.")
        print("  - Imported share mappings and SSH settings may expose host paths or credentials; review before use.")
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
           aivm host doctor --config {path}
           aivm status --config {path}
           aivm status --config {path} --detail
        2. 🌐 Host network
           aivm host net create --config {path}
        3. 🔥 Optional firewall isolation (recommended)
           aivm host fw apply --config {path}
        4. 📦 Base image
           aivm host image_fetch --config {path}
        5. 🖥️ VM lifecycle
           aivm vm up --config {path}
           aivm vm wait_ip --config {path}
        6. 🔑 Access
           aivm vm ssh_config --config {path}   # VS Code Remote-SSH
        7. 🧰 Optional provisioning (docker + dev tools)
           aivm vm provision --config {path}
        8. 🧩 Optional settings sync from host user profile
           aivm vm sync_settings --config {path}
        9. 🧑‍💻 Optional VS Code one-shot open (share + remote launch)
           aivm vm code --config {path} --host_src . --sync_settings
        """).strip()
        print(steps)
        return 0


def _iter_modal_members(modal_cls: type[scfg.ModalCLI]) -> list[tuple[str, type]]:
    members: list[tuple[str, type]] = []
    for name, val in modal_cls.__dict__.items():
        if name.startswith("_"):
            continue
        if not isinstance(val, type):
            continue
        if issubclass(val, scfg.ModalCLI) or issubclass(val, scfg.DataConfig):
            members.append((name, val))
    return members


def _short_help_line(cls: type) -> str:
    doc = (getattr(cls, "__doc__", "") or "").strip()
    if not doc:
        return ""
    return doc.splitlines()[0].strip()


def _render_command_tree(modal_cls: type[scfg.ModalCLI], prefix: str = "aivm") -> str:
    root_help = _short_help_line(modal_cls)
    root_line = f"{prefix} - {root_help}" if root_help else prefix
    lines: list[str] = [root_line]

    def walk(cls: type[scfg.ModalCLI], parent: str, indent: str) -> None:
        members = _iter_modal_members(cls)
        for idx, (name, subcls) in enumerate(members):
            last = idx == len(members) - 1
            branch = "└── " if last else "├── "
            path = f"{parent} {name}"
            help_line = _short_help_line(subcls)
            if help_line:
                lines.append(f"{indent}{branch}{path} - {help_line}")
            else:
                lines.append(f"{indent}{branch}{path}")
            if issubclass(subcls, scfg.ModalCLI):
                walk(subcls, path, indent + ("    " if last else "│   "))

    walk(modal_cls, prefix, "")
    return "\n".join(lines)


class HelpTreeCLI(_BaseCommand):
    """Print the expanded aivm command tree."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        cls.cli(argv=argv, data=kwargs)
        print(_render_command_tree(AgentVMModalCLI))
        return 0


class DoctorCLI(_BaseCommand):
    """Check host prerequisites and list missing required tools."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        cls.cli(argv=argv, data=kwargs)
        missing, missing_opt = check_commands()
        if missing:
            print("❌ Missing required commands:", ", ".join(missing))
            print("💡 On Debian/Ubuntu you can run: aivm host install_deps")
            return 2
        if missing_opt:
            print("➖ Missing optional commands:", ", ".join(missing_opt))
        print("✅ Required host commands are present.")
        return 0


class HostInstallDepsCLI(_BaseCommand):
    """Install required host dependencies on Debian/Ubuntu."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        if not host_is_debian_like():
            print(
                "❌ Host not detected as Debian/Ubuntu. Install dependencies manually.",
                file=sys.stderr,
            )
            return 2
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose="Install host dependencies with apt/libvirt tooling.",
        )
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


class FirewallApplyCLI(_BaseCommand):
    """Apply nftables isolation rules for the VM network."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Apply nftables firewall rules."
        )
        apply_firewall(cfg, dry_run=args.dry_run)
        return 0


class FirewallStatusCLI(_BaseCommand):
    """Print current nftables status for the configured firewall table."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Read nftables firewall status."
        )
        print(firewall_status(cfg))
        return 0


class FirewallRemoveCLI(_BaseCommand):
    """Remove nftables rules managed by aivm."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Remove nftables firewall rules."
        )
        remove_firewall(cfg, dry_run=args.dry_run)
        return 0


class ImageFetchCLI(_BaseCommand):
    """Download/cache the configured Ubuntu base image."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = _resolve_cfg_fallback(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose="Download/cache base image under libvirt-managed storage.",
        )
        print(str(fetch_image(cfg, dry_run=args.dry_run)))
        return 0


class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose=f"Create/start/redefine VM '{cfg.vm.name}' and libvirt resources.",
        )
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
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose="Query VM networking state via virsh to resolve VM IP.",
        )
        print(
            wait_for_ip(
                _load_cfg(args.config), timeout_s=args.timeout, dry_run=args.dry_run
            )
        )
        return 0


class VMStatusCLI(_BaseCommand):
    """Show VM lifecycle status and cached IP information."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(yes=bool(args.yes), purpose="Inspect VM state via virsh.")
        print(vm_status(_load_cfg(args.config)))
        return 0


class VMDestroyCLI(_BaseCommand):
    """Destroy and undefine the VM and associated storage."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Destroy/undefine VM and attached storage."
        )
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

    vm = scfg.Value(
        "",
        help="Optional VM name override when no local config file is present.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        if args.config is not None or _cfg_path(None).exists():
            cfg = _load_cfg(args.config)
        else:
            cfg, _ = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt=args.vm,
                host_src=Path.cwd(),
            )
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose="Query VM networking state before SSH provisioning.",
        )
        provision(cfg, dry_run=args.dry_run)
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
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose="Query VM networking state before settings sync.",
            )
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
        print(f"  copied: {len(result.copied)}")
        print(f"  skipped_missing: {len(result.skipped_missing)}")
        print(f"  skipped_exists: {len(result.skipped_exists)}")
        print(f"  failed: {len(result.failed)}")
        for k in ("copied", "skipped_missing", "skipped_exists", "failed"):
            for item in getattr(result, k):
                print(f"  - {k}: {item}")
        if result.failed:
            return 2
        return 0


def _select_cfg_for_vm_name(vm_name: str, *, reason: str) -> tuple[AgentVMConfig, Path]:
    reg = load_registry()
    rec = find_vm(reg, vm_name)
    if rec is None:
        raise RuntimeError(f"VM not found in global registry ({reason}): {vm_name}")
    candidates: list[Path] = []
    if rec.config_path:
        candidates.append(Path(rec.config_path).expanduser())
    if rec.global_config_path:
        candidates.append(Path(rec.global_config_path).expanduser())
    # Backward-compatible fallback for older registry entries.
    candidates.append(vm_global_config_path(vm_name))

    seen: set[str] = set()
    for cfg_path in candidates:
        key = str(cfg_path)
        if key in seen:
            continue
        seen.add(key)
        if cfg_path.exists():
            cfg = load(cfg_path).expanded_paths()
            if _hydrate_runtime_defaults(cfg):
                save(cfg_path, cfg)
            # Self-heal registry/global snapshot for older entries.
            gpath = vm_global_config_path(vm_name)
            ensure_dir(gpath.parent)
            save(gpath, cfg)
            upsert_vm(reg, cfg, cfg_path, global_cfg_path=gpath)
            save_registry(reg)
            return cfg, cfg_path

    raise RuntimeError(
        f"No usable config file found for VM {vm_name}. "
        f"Tried: {', '.join(str(p) for p in candidates)}. "
        "Re-register it with `aivm config init` or `aivm vm up`."
    )


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

    valid: list = []
    for r in reg.vms:
        paths = []
        if r.config_path:
            paths.append(Path(r.config_path).expanduser())
        if r.global_config_path:
            paths.append(Path(r.global_config_path).expanduser())
        paths.append(vm_global_config_path(r.name))
        if any(p.exists() for p in paths):
            valid.append(r)
    if not valid:
        raise RuntimeError(
            "No usable VM config found. Pass --config, run `aivm config init`, or register a VM."
        )
    if len(valid) == 1:
        only = valid[0]
        return _select_cfg_for_vm_name(only.name, reason="single registered VM")

    chosen = _choose_vm_interactive(
        [r.name for r in sorted(valid, key=lambda x: x.name)],
        reason=f"{len(valid)} registered VMs",
    )
    return _select_cfg_for_vm_name(chosen, reason="interactive choice")


@dataclass
class PreparedSession:
    cfg: AgentVMConfig
    cfg_path: Path
    host_src: Path
    ip: str | None
    reg_path: Path | None
    meta_path: Path | None


def _prepare_attached_session(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
    guest_dst_opt: str,
    recreate_if_needed: bool,
    ensure_firewall_opt: bool,
    force: bool,
    dry_run: bool,
    yes: bool,
) -> PreparedSession:
    if not host_src.exists():
        raise FileNotFoundError(f"Host source path does not exist: {host_src}")
    if not host_src.is_dir():
        raise RuntimeError(f"Host source path is not a directory: {host_src}")

    cfg, cfg_path = _resolve_cfg_for_code(
        config_opt=config_opt,
        vm_opt=vm_opt,
        host_src=host_src,
    )

    cfg.share.enabled = True
    cfg.share.host_src = str(host_src)
    cfg.share.guest_dst = _resolve_guest_dst(host_src, guest_dst_opt)
    _ensure_share_tag_len(cfg, host_src, set())
    requested_src = str(Path(cfg.share.host_src).resolve())

    def _has_share_in_mappings(mappings: list[tuple[str, str]]) -> bool:
        return any(src == requested_src and tag == cfg.share.tag for src, tag in mappings)

    cached_ip = get_ip_cached(cfg) if not dry_run else None
    cached_ssh_ok = False
    if cached_ip:
        cached_ssh_ok, _, _ = _check_ssh_ready(cfg, cached_ip)
    vm_running_probe = _probe_vm_running_nonsudo(cfg.vm.name) if not dry_run else None
    vm_reachable = bool(cached_ssh_ok) or (vm_running_probe is True)

    net_probe, _ = _check_network(cfg, use_sudo=False)
    need_network_ensure = (net_probe is False) and not vm_reachable
    if need_network_ensure:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose=f"Ensure libvirt network '{cfg.network.name}'.",
        )
        ensure_network(cfg, recreate=False, dry_run=dry_run)

    need_firewall_apply = False
    if cfg.firewall.enabled and ensure_firewall_opt:
        fw_probe, _ = _check_firewall(cfg, use_sudo=False)
        need_firewall_apply = (fw_probe is False) and not vm_reachable
    if need_firewall_apply:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose=f"Apply/update firewall table '{cfg.firewall.table}'.",
        )
        apply_firewall(cfg, dry_run=dry_run)

    recreate = False
    vm_running = vm_running_probe
    mappings: list[tuple[str, str]] = []
    has_share = False
    if vm_running is None and cached_ssh_ok:
        vm_running = True
    if not dry_run and vm_running is True:
        mappings = vm_share_mappings(cfg, use_sudo=False)
        existing_tags = {tag for _, tag in mappings if tag}
        _ensure_share_tag_len(cfg, host_src, existing_tags)
        for src, tag in mappings:
            if src == requested_src and tag:
                cfg.share.tag = tag
                break
        has_share = _has_share_in_mappings(mappings)
        if not has_share:
            for src, tag in mappings:
                if tag == cfg.share.tag and src != requested_src:
                    cfg.share.tag = _auto_share_tag_for_path(host_src, existing_tags)
                    break
            has_share = _has_share_in_mappings(mappings)

    need_vm_start_or_create = dry_run or (vm_running is not True)
    if need_vm_start_or_create:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose=f"Create/start VM '{cfg.vm.name}' or update VM definition.",
        )
        create_or_start_vm(cfg, dry_run=dry_run, recreate=False)
        vm_running = True if dry_run else _probe_vm_running_nonsudo(cfg.vm.name)
        if not dry_run and vm_running is True:
            mappings = vm_share_mappings(cfg, use_sudo=False)
            has_share = _has_share_in_mappings(mappings)

    if not dry_run and vm_running is True and not has_share:
        if recreate_if_needed:
            recreate = True
        else:
            try:
                _confirm_sudo_block(
                    yes=bool(yes),
                    purpose=f"Attach this folder to existing VM '{cfg.vm.name}'.",
                )
                attach_vm_share(cfg, dry_run=False)
                has_share = True
            except Exception as ex:
                current_maps = mappings or vm_share_mappings(cfg, use_sudo=False)
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

    if recreate:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose=f"Recreate VM '{cfg.vm.name}' to apply new share mapping.",
        )
        create_or_start_vm(cfg, dry_run=dry_run, recreate=True)

    if dry_run:
        return PreparedSession(
            cfg=cfg,
            cfg_path=cfg_path,
            host_src=host_src,
            ip=None,
            reg_path=None,
            meta_path=None,
        )

    reg_path, meta_path = _record_attachment(
        cfg,
        cfg_path,
        host_src=host_src,
        force=bool(force),
    )

    ip = cached_ip if cached_ip else get_ip_cached(cfg)
    if ip:
        ssh_ok, _, _ = _check_ssh_ready(cfg, ip)
    else:
        ssh_ok = False
    if not ssh_ok:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose="Query VM network state via virsh to discover VM IP.",
        )
        ip = wait_for_ip(cfg, timeout_s=360, dry_run=False)
        wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
    if not ip:
        raise RuntimeError("Could not resolve VM IP address.")
    ensure_share_mounted(cfg, ip, dry_run=False)
    return PreparedSession(
        cfg=cfg,
        cfg_path=cfg_path,
        host_src=host_src,
        ip=ip,
        reg_path=reg_path,
        meta_path=meta_path,
    )


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
        session = _prepare_attached_session(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=Path(args.host_src).resolve(),
            guest_dst_opt=args.guest_dst,
            recreate_if_needed=bool(args.recreate_if_needed),
            ensure_firewall_opt=bool(args.ensure_firewall),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )
        cfg = session.cfg
        if args.dry_run:
            print(f"DRYRUN: would open {cfg.share.guest_dst} in VS Code via host {cfg.vm.name}")
            return 0
        ip = session.ip
        assert ip is not None

        do_sync = bool(args.sync_settings or cfg.sync.enabled)
        if do_sync:
            chosen_paths = (
                _parse_sync_paths_arg(args.sync_paths) if args.sync_paths else None
            )
            sync_result = sync_settings(
                cfg,
                ip,
                paths=chosen_paths,
                overwrite=cfg.sync.overwrite,
                dry_run=False,
            )
            if sync_result.failed:
                raise RuntimeError(
                    "Failed syncing one or more settings files:\n"
                    + "\n".join(sync_result.failed)
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
        print(
            f"Opened VS Code remote folder {cfg.share.guest_dst} on host {cfg.vm.name}"
        )
        print(f"SSH entry updated in {ssh_cfg}")
        print(f"Folder registered in {session.reg_path} and {session.meta_path}")
        return 0


class VMSSHCLI(_BaseCommand):
    """SSH into the VM and start a shell in the mapped guest directory."""

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
        help="Guest mount path override (default: mirrors host_src path).",
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
    force = scfg.Value(
        False,
        isflag=True,
        help="Force attaching folder even if already attached to a different VM.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        session = _prepare_attached_session(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=Path(args.host_src).resolve(),
            guest_dst_opt=args.guest_dst,
            recreate_if_needed=bool(args.recreate_if_needed),
            ensure_firewall_opt=bool(args.ensure_firewall),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )
        cfg = session.cfg
        if args.dry_run:
            print(f"DRYRUN: would SSH to {cfg.vm.user}@<ip> and cd {cfg.share.guest_dst}")
            return 0

        ip = session.ip
        assert ip is not None
        ident = require_ssh_identity(cfg.paths.ssh_identity_file)
        remote_cmd = f"cd {shlex.quote(cfg.share.guest_dst)} && exec $SHELL -l"
        run_cmd(
            [
                "ssh",
                "-t",
                *ssh_base_args(ident, strict_host_key_checking="accept-new"),
                f"{cfg.vm.user}@{ip}",
                remote_cmd,
            ],
            sudo=False,
            check=True,
            capture=False,
        )
        print(f"Connected to {cfg.vm.user}@{ip} in {cfg.share.guest_dst}")
        print(f"Folder registered in {session.reg_path} and {session.meta_path}")
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
            print(
                f"DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {cfg.share.guest_dst}"
            )
            return 0

        save(cfg_path, cfg)
        if vm_exists(cfg):
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose=f"Inspect VM '{cfg.vm.name}' share mappings and attach folder if needed.",
            )
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
                        cfg.share.tag = _auto_share_tag_for_path(
                            host_src, existing_tags
                        )
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
    """Top-level shortcut for `aivm vm code`."""


class AttachCLI(VMAttachCLI):
    """Top-level shortcut for `aivm vm attach`."""


class SSHCLI(VMSSHCLI):
    """Top-level shortcut for `aivm vm ssh`."""


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


class VMListCLI(ListCLI):
    """List managed VM records (VM-focused view)."""

    section = scfg.Value(
        "vms",
        help="One of: all, vms, networks, folders (default: vms).",
    )


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


class HelpModalCLI(scfg.ModalCLI):
    """Help and discovery commands."""

    plan = PlanCLI
    tree = HelpTreeCLI


class ConfigModalCLI(scfg.ModalCLI):
    """Config file management commands."""

    init = InitCLI
    discover = ConfigDiscoverCLI
    path = ConfigPathCLI
    show = ConfigShowCLI
    edit = ConfigEditCLI


class HostModalCLI(scfg.ModalCLI):
    """Host preparation and host-level operations."""

    doctor = DoctorCLI
    install_deps = HostInstallDepsCLI
    image_fetch = ImageFetchCLI
    net = NetModalCLI
    fw = FirewallModalCLI


class VMModalCLI(scfg.ModalCLI):
    """VM lifecycle subcommands."""

    list = VMListCLI
    up = VMUpCLI
    wait_ip = VMWaitIPCLI
    status = VMStatusCLI
    destroy = VMDestroyCLI
    ssh_config = VMSshConfigCLI
    provision = VMProvisionCLI
    ssh = VMSSHCLI
    sync_settings = VMSyncSettingsCLI
    attach = VMAttachCLI
    code = VMCodeCLI


class AgentVMModalCLI(scfg.ModalCLI):
    """Local libvirt/KVM sandbox VM manager for coding agents.

    Common flows:
      aivm config init --config .aivm.toml
      aivm config discover
      aivm config path
      aivm config show
      aivm config edit
      aivm help plan --config .aivm.toml
      aivm help tree
      aivm host doctor
      aivm status --config .aivm.toml
      aivm host net create --config .aivm.toml
      aivm host fw apply --config .aivm.toml
      aivm host image_fetch --config .aivm.toml
      aivm vm up --config .aivm.toml
      aivm vm wait_ip --config .aivm.toml
      aivm vm ssh_config --config .aivm.toml
      aivm vm provision --config .aivm.toml
      aivm vm sync_settings --config .aivm.toml
      aivm vm attach --vm aivm-2404 --host_src .
      aivm vm code --config .aivm.toml --host_src . --sync_settings
      aivm ssh .
      aivm code . --sync_settings
      aivm list
      aivm apply --config .aivm.toml --interactive

    Tips:
      Use `aivm <group> --help` for grouped commands (`config`, `help`, `host`, `vm`).
    """

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


def _normalize_argv(argv: list[str]) -> list[str]:
    """Normalize accepted hyphenated spellings to scriptconfig command names."""
    if len(argv) >= 1 and argv[0] == "init":
        return ["config", "init", *argv[1:]]
    if len(argv) >= 1 and argv[0] == "attach":
        if len(argv) >= 2 and not argv[1].startswith("-"):
            return ["attach", "--host_src", argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == "code":
        if len(argv) >= 2 and not argv[1].startswith("-"):
            return ["code", "--host_src", argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == "ssh":
        if len(argv) >= 2 and not argv[1].startswith("-"):
            return ["ssh", "--host_src", argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == "ls":
        return ["list", *argv[1:]]
    if len(argv) >= 2 and argv[0] == "vm":
        if argv[1] == "wait-ip":
            return [argv[0], "wait_ip", *argv[2:]]
        if argv[1] == "ssh-config":
            return [argv[0], "ssh_config", *argv[2:]]
        if argv[1] == "ssh" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [argv[0], "ssh", "--host_src", argv[2], *argv[3:]]
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
        log.error("Unhandled aivm error: {}", ex)
        sys.exit(2)

    if any(flag in argv for flag in ("-h", "--help")):
        sys.exit(0)
    if isinstance(rc, int):
        sys.exit(rc)
    sys.exit(0)
