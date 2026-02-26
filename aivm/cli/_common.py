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

from ..config import AgentVMConfig, dump_toml, load, save
from ..detect import auto_defaults, detect_ssh_identity
from ..firewall import apply_firewall, firewall_status, remove_firewall
from ..host import check_commands, host_is_debian_like, install_deps_debian
from ..net import destroy_network, ensure_network, network_status
from ..registry import (
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
from ..runtime import require_ssh_identity, ssh_base_args, virsh_system_cmd
from ..status import (
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
from ..util import ensure_dir, run_cmd, which
from ..vm import (
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


__all__ = [name for name in globals() if not name.startswith("__")]
