from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import ubelt as ub

from .config import AgentVMConfig

DIR_METADATA_FILE = ".aivm-dir.toml"


@dataclass
class VMRecord:
    name: str
    config_path: str
    network_name: str
    strict_firewall: bool
    global_config_path: str = ""


@dataclass
class AttachmentRecord:
    host_path: str
    vm_name: str
    mode: str = "shared"
    guest_dst: str = ""
    tag: str = ""


@dataclass
class GlobalRegistry:
    schema_version: int = 1
    vms: list[VMRecord] = field(default_factory=list)
    attachments: list[AttachmentRecord] = field(default_factory=list)


def registry_path() -> Path:
    root = ub.Path.appdir("aivm").ensuredir()
    return Path(root) / "registry.toml"


def vm_global_config_path(vm_name: str) -> Path:
    root = ub.Path.appdir("aivm").ensuredir()
    return Path(root) / "vms" / f"{vm_name}.toml"


def _norm_dir(path: str | Path) -> str:
    p = Path(path).expanduser()
    try:
        return str(p.resolve())
    except Exception:
        return str(p.absolute())


def load_registry(path: Path | None = None) -> GlobalRegistry:
    fpath = path or registry_path()
    if not fpath.exists():
        return GlobalRegistry()
    raw = tomllib.loads(fpath.read_text(encoding="utf-8"))
    reg = GlobalRegistry()
    reg.schema_version = int(raw.get("schema_version", 1))
    for item in raw.get("vms", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        reg.vms.append(
            VMRecord(
                name=name,
                config_path=str(item.get("config_path", "")).strip(),
                global_config_path=str(item.get("global_config_path", "")).strip(),
                network_name=str(item.get("network_name", "")).strip(),
                strict_firewall=bool(item.get("strict_firewall", False)),
            )
        )
    for item in raw.get("attachments", []):
        if not isinstance(item, dict):
            continue
        host_path = str(item.get("host_path", "")).strip()
        vm_name = str(item.get("vm_name", "")).strip()
        if not host_path or not vm_name:
            continue
        reg.attachments.append(
            AttachmentRecord(
                host_path=_norm_dir(host_path),
                vm_name=vm_name,
                mode=str(item.get("mode", "shared") or "shared"),
                guest_dst=str(item.get("guest_dst", "")).strip(),
                tag=str(item.get("tag", "")).strip(),
            )
        )
    return reg


def save_registry(reg: GlobalRegistry, path: Path | None = None) -> Path:
    fpath = path or registry_path()
    fpath.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [f"schema_version = {reg.schema_version}", ""]
    for vm in sorted(reg.vms, key=lambda v: v.name):
        lines.append("[[vms]]")
        lines.append(f'name = "{vm.name}"')
        lines.append(f'config_path = "{vm.config_path}"')
        lines.append(f'global_config_path = "{vm.global_config_path}"')
        lines.append(f'network_name = "{vm.network_name}"')
        lines.append(f"strict_firewall = {'true' if vm.strict_firewall else 'false'}")
        lines.append("")
    for att in sorted(reg.attachments, key=lambda a: (a.host_path, a.vm_name)):
        lines.append("[[attachments]]")
        lines.append(f'host_path = "{att.host_path}"')
        lines.append(f'vm_name = "{att.vm_name}"')
        lines.append(f'mode = "{att.mode}"')
        lines.append(f'guest_dst = "{att.guest_dst}"')
        lines.append(f'tag = "{att.tag}"')
        lines.append("")
    fpath.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return fpath


def upsert_vm(
    reg: GlobalRegistry,
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    global_cfg_path: Path | None = None,
) -> None:
    cfg = cfg.expanded_paths()
    if global_cfg_path is None:
        global_cfg_path = vm_global_config_path(cfg.vm.name)
    rec = VMRecord(
        name=cfg.vm.name,
        config_path=str(cfg_path.resolve()),
        network_name=cfg.network.name,
        strict_firewall=bool(cfg.firewall.enabled),
        global_config_path=str(global_cfg_path),
    )
    existing = [v for v in reg.vms if v.name == rec.name]
    if existing:
        i = reg.vms.index(existing[0])
        reg.vms[i] = rec
    else:
        reg.vms.append(rec)


def find_vm(reg: GlobalRegistry, vm_name: str) -> VMRecord | None:
    for rec in reg.vms:
        if rec.name == vm_name:
            return rec
    return None


def upsert_attachment(
    reg: GlobalRegistry,
    *,
    host_path: str | Path,
    vm_name: str,
    mode: str = "shared",
    guest_dst: str = "",
    tag: str = "",
    force: bool = False,
) -> None:
    norm = _norm_dir(host_path)
    conflict = [
        a for a in reg.attachments if a.host_path == norm and a.vm_name != vm_name
    ]
    if conflict and not force:
        vm_names = ", ".join(sorted({a.vm_name for a in conflict}))
        raise RuntimeError(
            f"Host folder already attached to other VM(s): {vm_names}. "
            "Use --force to override this safety check."
        )
    if force and conflict:
        reg.attachments = [a for a in reg.attachments if a.host_path != norm]
    existing = [
        a for a in reg.attachments if a.host_path == norm and a.vm_name == vm_name
    ]
    rec = AttachmentRecord(
        host_path=norm,
        vm_name=vm_name,
        mode=mode,
        guest_dst=guest_dst,
        tag=tag,
    )
    if existing:
        i = reg.attachments.index(existing[0])
        reg.attachments[i] = rec
    else:
        reg.attachments.append(rec)


def find_attachment(
    reg: GlobalRegistry, host_path: str | Path
) -> AttachmentRecord | None:
    norm = _norm_dir(host_path)
    for att in reg.attachments:
        if att.host_path == norm:
            return att
    return None


def write_dir_metadata(
    host_dir: str | Path,
    *,
    vm_name: str,
    config_path: str = "",
    mode: str = "shared",
) -> Path:
    dpath = Path(_norm_dir(host_dir))
    if not dpath.exists() or not dpath.is_dir():
        raise RuntimeError(f"Not a directory: {dpath}")
    meta = dpath / DIR_METADATA_FILE
    lines = [
        f'vm_name = "{vm_name}"',
        f'config_path = "{config_path}"',
        f'mode = "{mode}"',
        "",
    ]
    meta.write_text("\n".join(lines), encoding="utf-8")
    return meta


def read_dir_metadata(host_dir: str | Path) -> dict[str, Any]:
    dpath = Path(_norm_dir(host_dir))
    meta = dpath / DIR_METADATA_FILE
    if not meta.exists():
        return {}
    raw = tomllib.loads(meta.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}
