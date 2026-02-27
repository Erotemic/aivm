"""Single-file config store for VM definitions, attachments, and active VM selection."""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import ubelt as ub

from .config import AgentVMConfig


@dataclass
class VMEntry:
    name: str
    cfg: AgentVMConfig

    @property
    def network_name(self) -> str:
        return self.cfg.network.name

    @property
    def strict_firewall(self) -> bool:
        return bool(self.cfg.firewall.enabled)


@dataclass
class AttachmentEntry:
    host_path: str
    vm_name: str
    mode: str = 'shared'
    guest_dst: str = ''
    tag: str = ''


@dataclass
class Store:
    schema_version: int = 2
    active_vm: str = ''
    vms: list[VMEntry] = field(default_factory=list)
    attachments: list[AttachmentEntry] = field(default_factory=list)


def _appdir(appname: str, kind: str) -> Path:
    p = ub.Path.appdir(appname, type=kind).ensuredir()
    return Path(p)


def store_path() -> Path:
    return _appdir('aivm', 'config') / 'config.toml'


def _norm_dir(path: str | Path) -> str:
    p = Path(path).expanduser()
    try:
        return str(p.resolve())
    except Exception:
        return str(p.absolute())


def _cfg_from_dict(raw: dict) -> AgentVMConfig:
    cfg = AgentVMConfig()
    for section in (
        'vm',
        'network',
        'firewall',
        'image',
        'share',
        'provision',
        'sync',
        'paths',
    ):
        body = raw.get(section, None)
        if isinstance(body, dict):
            obj = getattr(cfg, section)
            for k, v in body.items():
                if hasattr(obj, k):
                    setattr(obj, k, v)
    if 'verbosity' in raw:
        cfg.verbosity = int(raw['verbosity'])
    return cfg


def _toml_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('"', '\\"')


def _emit_toml_kv(lines: list[str], key: str, val: object) -> None:
    if isinstance(val, bool):
        lines.append(f'{key} = {"true" if val else "false"}')
    elif isinstance(val, int):
        lines.append(f'{key} = {val}')
    elif isinstance(val, list):
        parts = [f'"{_toml_escape(str(item))}"' for item in val]
        lines.append(f'{key} = [{", ".join(parts)}]')
    else:
        lines.append(f'{key} = "{_toml_escape(str(val))}"')


def load_store(path: Path | None = None) -> Store:
    fpath = path or store_path()
    if not fpath.exists():
        return Store()
    raw = tomllib.loads(fpath.read_text(encoding='utf-8'))
    reg = Store()
    reg.schema_version = int(raw.get('schema_version', 2))
    reg.active_vm = str(raw.get('active_vm', '')).strip()

    for item in raw.get('vms', []):
        if not isinstance(item, dict):
            continue
        name = str(item.get('name', '')).strip()
        if not name:
            continue
        cfg = _cfg_from_dict(item).expanded_paths()
        cfg.vm.name = name
        reg.vms.append(VMEntry(name=name, cfg=cfg))

    for item in raw.get('attachments', []):
        if not isinstance(item, dict):
            continue
        host_path = str(item.get('host_path', '')).strip()
        vm_name = str(item.get('vm_name', '')).strip()
        if not host_path or not vm_name:
            continue
        reg.attachments.append(
            AttachmentEntry(
                host_path=_norm_dir(host_path),
                vm_name=vm_name,
                mode=str(item.get('mode', 'shared') or 'shared'),
                guest_dst=str(item.get('guest_dst', '')).strip(),
                tag=str(item.get('tag', '')).strip(),
            )
        )
    return reg


def save_store(reg: Store, path: Path | None = None) -> Path:
    fpath = path or store_path()
    fpath.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [f'schema_version = {reg.schema_version}']
    lines.append(f'active_vm = "{_toml_escape(reg.active_vm)}"')
    lines.append('')

    for vm in sorted(reg.vms, key=lambda v: v.name):
        lines.append('[[vms]]')
        lines.append(f'name = "{_toml_escape(vm.name)}"')
        d = asdict(vm.cfg)
        verbosity = int(d.get('verbosity', 1))
        if verbosity != 1:
            lines.append(f'verbosity = {verbosity}')
        for section in (
            'vm',
            'network',
            'firewall',
            'image',
            'share',
            'provision',
            'sync',
            'paths',
        ):
            body = d.get(section, {})
            if not isinstance(body, dict):
                continue
            lines.append(f'[vms.{section}]')
            for k, v in body.items():
                _emit_toml_kv(lines, k, v)
        lines.append('')

    for att in sorted(reg.attachments, key=lambda a: (a.host_path, a.vm_name)):
        lines.append('[[attachments]]')
        lines.append(f'host_path = "{_toml_escape(att.host_path)}"')
        lines.append(f'vm_name = "{_toml_escape(att.vm_name)}"')
        lines.append(f'mode = "{_toml_escape(att.mode)}"')
        lines.append(f'guest_dst = "{_toml_escape(att.guest_dst)}"')
        lines.append(f'tag = "{_toml_escape(att.tag)}"')
        lines.append('')

    fpath.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
    return fpath


def upsert_vm(reg: Store, cfg: AgentVMConfig) -> None:
    cfg = cfg.expanded_paths()
    name = cfg.vm.name
    rec = VMEntry(name=name, cfg=cfg)
    existing = [v for v in reg.vms if v.name == name]
    if existing:
        i = reg.vms.index(existing[0])
        reg.vms[i] = rec
    else:
        reg.vms.append(rec)
    reg.active_vm = name


def find_vm(reg: Store, vm_name: str) -> VMEntry | None:
    for rec in reg.vms:
        if rec.name == vm_name:
            return rec
    return None


def upsert_attachment(
    reg: Store,
    *,
    host_path: str | Path,
    vm_name: str,
    mode: str = 'shared',
    guest_dst: str = '',
    tag: str = '',
    force: bool = False,
) -> None:
    norm = _norm_dir(host_path)
    conflict = [
        a
        for a in reg.attachments
        if a.host_path == norm and a.vm_name != vm_name
    ]
    if conflict and not force:
        vm_names = ', '.join(sorted({a.vm_name for a in conflict}))
        raise RuntimeError(
            f'Host folder already attached to other VM(s): {vm_names}. '
            'Use --force to override this safety check.'
        )
    if force and conflict:
        reg.attachments = [a for a in reg.attachments if a.host_path != norm]
    existing = [
        a
        for a in reg.attachments
        if a.host_path == norm and a.vm_name == vm_name
    ]
    rec = AttachmentEntry(
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
    reg: Store, host_path: str | Path
) -> AttachmentEntry | None:
    norm = _norm_dir(host_path)
    for att in reg.attachments:
        if att.host_path == norm:
            return att
    return None
