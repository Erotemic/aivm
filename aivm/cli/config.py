from __future__ import annotations

import os
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import scriptconfig as scfg

from ..config import AgentVMConfig, dump_toml, load, save
from ..detect import auto_defaults
from ..registry import (
    DIR_METADATA_FILE,
    find_attachment,
    find_vm,
    load_registry,
    read_dir_metadata,
    registry_path,
    save_registry,
    upsert_vm,
    vm_global_config_path,
)
from ..runtime import virsh_system_cmd
from ..util import ensure_dir, run_cmd, which
from ._common import (
    _BaseCommand,
    _cfg_path,
    _confirm_sudo_block,
    _record_vm,
    _resolve_cfg_fallback,
    _resolve_cfg_for_code,
)


class InitCLI(_BaseCommand):
    """Initialize a new config file with auto-detected defaults."""

    force = scfg.Value(False, isflag=True, help='Overwrite existing config.')

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
        if path.exists() and not args.force:
            print(
                f'Refusing to overwrite existing config: {path}',
                file=sys.stderr,
            )
            print('Use --force to overwrite.', file=sys.stderr)
            return 2
        save(path, cfg)
        reg_path = _record_vm(cfg, path)
        print(f'Wrote config: {path}')
        print(f'Registered VM in global registry: {reg_path}')
        return 0


class ConfigShowCLI(_BaseCommand):
    """Show the resolved config content."""

    vm = scfg.Value(
        '',
        help='Optional VM name override when no local config file is present.',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, path = _resolve_cfg_fallback(args.config, vm_opt=args.vm)
        print(f'# Config: {path}')
        print(dump_toml(cfg), end='')
        return 0


class ConfigEditCLI(_BaseCommand):
    """Edit the resolved config file in $EDITOR."""

    vm = scfg.Value(
        '',
        help='Optional VM name override when no local config file is present.',
    )
    editor = scfg.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, path = _resolve_cfg_fallback(args.config, vm_opt=args.vm)
        # Persist hydrated/defaulted values before opening an editor.
        save(path, cfg)
        editor_cmd = (
            args.editor.strip()
            if str(args.editor or '').strip()
            else (os.environ.get('EDITOR') or os.environ.get('VISUAL') or '')
        )
        if not editor_cmd:
            editor_cmd = which('nano') or which('vi') or ''
        if not editor_cmd:
            raise RuntimeError('No editor found. Set $EDITOR or pass --editor.')
        parts = shlex.split(editor_cmd) + [str(path)]
        run_cmd(parts, sudo=False, check=True, capture=False)
        return 0


class ConfigPathCLI(_BaseCommand):
    """Show in-scope config and metadata paths for current/target directory."""

    vm = scfg.Value(
        '',
        help='Optional VM name override for showing VM-global config path.',
    )
    host_src = scfg.Value(
        '.',
        help='Host directory scope to inspect (default: current directory).',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        host_src = Path(args.host_src).resolve()
        local_cfg = host_src / '.aivm.toml'
        meta_path = host_src / DIR_METADATA_FILE
        reg_path = registry_path()
        reg = load_registry(reg_path)
        att = find_attachment(reg, host_src)
        meta = read_dir_metadata(host_src)
        meta_vm = (
            str(meta.get('vm_name', '')).strip()
            if isinstance(meta, dict)
            else ''
        )
        resolved_cfg_path: Path | None = None
        resolved_vm = ''
        resolve_error = ''
        try:
            resolved_cfg, resolved_cfg_path = _resolve_cfg_for_code(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=host_src,
            )
            resolved_vm = resolved_cfg.vm.name
        except Exception as ex:
            resolve_error = str(ex)

        vm_name = str(args.vm or '').strip() or resolved_vm or meta_vm
        if not vm_name and att is not None:
            vm_name = att.vm_name

        print('🧭 AIVM Config Paths')
        print(f'cwd = {host_src}')
        print(
            f'local_config = {local_cfg} '
            f'({"exists" if local_cfg.exists() else "missing"})'
        )
        print(
            f'dir_metadata = {meta_path} '
            f'({"exists" if meta_path.exists() else "missing"})'
        )
        if meta_vm:
            print(f'dir_metadata_vm = {meta_vm}')
        print(
            f'registry = {reg_path} '
            f'({"exists" if reg_path.exists() else "missing"})'
        )
        if att is not None:
            print(f'registry_attachment_vm = {att.vm_name}')
        if vm_name:
            vm_cfg = vm_global_config_path(vm_name)
            print(
                f'vm_global_config = {vm_cfg} '
                f'({"exists" if vm_cfg.exists() else "missing"})'
            )
            rec = find_vm(reg, vm_name)
            if rec is not None:
                if rec.config_path:
                    p = Path(rec.config_path).expanduser()
                    print(
                        f'registry_vm_config = {p} '
                        f'({"exists" if p.exists() else "missing"})'
                    )
                if rec.global_config_path:
                    p = Path(rec.global_config_path).expanduser()
                    print(
                        f'registry_vm_global_config = {p} '
                        f'({"exists" if p.exists() else "missing"})'
                    )
        if resolved_cfg_path is not None:
            print(f'resolved_config = {resolved_cfg_path}')
            if resolved_vm:
                print(f'resolved_vm = {resolved_vm}')
        else:
            print('resolved_config = (unresolved)')
            if resolve_error:
                print(f'resolution_error = {resolve_error}')
        return 0


class ConfigDiscoverCLI(_BaseCommand):
    """Discover existing libvirt VMs and register them in aivm config registry."""

    dry_run = scfg.Value(
        False,
        isflag=True,
        help='Print actions without writing config/registry.',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        names_res = run_cmd(
            virsh_system_cmd('list', '--all', '--name'),
            sudo=False,
            check=False,
            capture=True,
        )
        used_sudo = False
        if names_res.code != 0:
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose='Discover existing libvirt VMs via system virsh.',
            )
            used_sudo = True
            names_res = run_cmd(
                virsh_system_cmd('list', '--all', '--name'),
                sudo=True,
                check=True,
                capture=True,
            )

        vm_names = [
            n.strip() for n in names_res.stdout.splitlines() if n.strip()
        ]
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
                cfg.network.name = str(vm_info.get('network', 'unknown'))
                created_cfg += 1
            else:
                cfg.vm.name = vm_name
                if not cfg.network.name:
                    cfg.network.name = str(vm_info.get('network', 'unknown'))

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

        print(f'Discovered VMs: {len(vm_names)}')
        print(f'  already_managed_seen: {managed_seen}')
        print(f'  added: {added}')
        print(f'  updated: {updated}')
        print(f'  skipped_unmanaged: {skipped_unmanaged}')
        print(f'  created_config_files: {created_cfg}')
        print(f'Registry: {reg_path}')
        print('')
        print('Security caveats:')
        print(
            '  - Discovery trusts local libvirt state only; ownership/provenance of VMs is not verified.'
        )
        print(
            '  - Imported configs may not reflect actual firewall isolation policy for each VM/network.'
        )
        print(
            '  - Imported share mappings and SSH settings may expose host paths or credentials; review before use.'
        )
        return 0


class ConfigModalCLI(scfg.ModalCLI):
    """Config file management commands."""

    init = InitCLI
    discover = ConfigDiscoverCLI
    path = ConfigPathCLI
    show = ConfigShowCLI
    edit = ConfigEditCLI


def _discover_vm_info(vm_name: str, *, use_sudo: bool) -> dict[str, object]:
    info: dict[str, object] = {
        'name': vm_name,
        'state': 'unknown',
        'autostart': 'unknown',
        'network': 'unknown',
        'vcpus': 'unknown',
        'memory_mib': 'unknown',
        'shares': [],
    }
    dominfo = run_cmd(
        virsh_system_cmd('dominfo', vm_name),
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if dominfo.code == 0:
        for line in (dominfo.stdout or '').splitlines():
            if ':' not in line:
                continue
            key, val = [x.strip() for x in line.split(':', 1)]
            low = key.lower()
            if low == 'state':
                info['state'] = val or 'unknown'
            elif low == 'autostart':
                info['autostart'] = val or 'unknown'
            elif low in {'cpu(s)', 'cpus'}:
                info['vcpus'] = val or 'unknown'
            elif low.startswith('max memory'):
                m = re.search(r'(\d+)', val)
                if m:
                    kib = int(m.group(1))
                    info['memory_mib'] = str(kib // 1024)
    xml = run_cmd(
        virsh_system_cmd('dumpxml', vm_name),
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if xml.code == 0 and xml.stdout.strip():
        try:
            root = ET.fromstring(xml.stdout)
            iface = root.find(".//devices/interface[@type='network']/source")
            if iface is not None:
                name = iface.attrib.get('network', '').strip()
                if name:
                    info['network'] = name
            shares: list[str] = []
            for fs in root.findall(".//devices/filesystem[@type='mount']"):
                src = fs.find('source')
                tgt = fs.find('target')
                src_dir = (
                    src.attrib.get('dir', '').strip() if src is not None else ''
                )
                tgt_dir = (
                    tgt.attrib.get('dir', '').strip() if tgt is not None else ''
                )
                if src_dir or tgt_dir:
                    shares.append(f'{src_dir or "?"} -> {tgt_dir or "?"}')
            info['shares'] = shares
        except Exception:
            pass
    return info


def _prompt_import_discovered_vm(
    vm_info: dict[str, object], *, yes: bool
) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        return False
    print('')
    print(f'Discovered unmanaged VM: {vm_info["name"]}')
    print(
        f'  state={vm_info["state"]} | autostart={vm_info["autostart"]} | '
        f'network={vm_info["network"]} | vcpus={vm_info["vcpus"]} | '
        f'memory_mib={vm_info["memory_mib"]}'
    )
    shares = vm_info.get('shares', [])
    if isinstance(shares, list) and shares:
        print('  shares:')
        for item in shares[:5]:
            print(f'    - {item}')
        if len(shares) > 5:
            print(f'    - ... ({len(shares) - 5} more)')
    else:
        print('  shares: none detected')
    ans = input('Add this VM to aivm registry/config? [y/N]: ').strip().lower()
    return ans in {'y', 'yes'}
