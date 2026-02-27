"""Config-store subcommands (init, discover, show, edit, and path inspection)."""

from __future__ import annotations

import os
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import scriptconfig as scfg
from loguru import logger

from ..config import AgentVMConfig, dump_toml
from ..detect import auto_defaults
from ..store import (
    find_attachment,
    find_vm,
    load_store,
    save_store,
    upsert_vm,
)
from ..runtime import virsh_system_cmd
from ..util import run_cmd, which
from ._common import (
    _BaseCommand,
    _cfg_path,
    _confirm_sudo_block,
    _load_cfg_with_path,
    _resolve_cfg_for_code,
)

log = logger


class InitCLI(_BaseCommand):
    """Initialize global config store with one VM definition."""

    force = scfg.Value(
        False,
        isflag=True,
        help='Overwrite existing VM definition if the same name already exists.',
    )
    defaults = scfg.Value(
        False,
        isflag=True,
        help='Accept detected defaults without interactive review.',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        reg = load_store(path)
        cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
        if not bool(args.yes) and not bool(args.defaults):
            cfg = _review_init_defaults_interactive(cfg, path)
        else:
            warn_lines = _ssh_key_setup_warning_lines(cfg)
            for line in warn_lines:
                print(line)
        exists = find_vm(reg, cfg.vm.name) is not None
        if exists and not args.force:
            print(
                f"VM '{cfg.vm.name}' already exists in config store: {path}",
                file=sys.stderr,
            )
            print('Use --force to overwrite this VM definition.', file=sys.stderr)
            return 2
        upsert_vm(reg, cfg)
        save_store(reg, path)
        print(f'Updated config store: {path}')
        print(f'Active VM: {cfg.vm.name}')
        return 0


def _render_init_default_summary(cfg: AgentVMConfig, path: Path) -> str:
    lines = [
        'Detected defaults for `aivm config init`:',
        f'  config_store: {path}',
        f'  vm.name: {cfg.vm.name}',
        f'  vm.user: {cfg.vm.user}',
        f'  vm.cpus: {cfg.vm.cpus}',
        f'  vm.ram_mb: {cfg.vm.ram_mb}',
        f'  vm.disk_gb: {cfg.vm.disk_gb}',
        f'  network.name: {cfg.network.name}',
        f'  network.subnet_cidr: {cfg.network.subnet_cidr}',
        f'  network.gateway_ip: {cfg.network.gateway_ip}',
        f'  network.dhcp_start: {cfg.network.dhcp_start}',
        f'  network.dhcp_end: {cfg.network.dhcp_end}',
        f'  paths.ssh_identity_file: {cfg.paths.ssh_identity_file or "(empty)"}',
        f'  paths.ssh_pubkey_path: {cfg.paths.ssh_pubkey_path or "(empty)"}',
    ]
    return '\n'.join(lines)


def _ssh_key_setup_warning_lines(cfg: AgentVMConfig) -> list[str]:
    ident = (cfg.paths.ssh_identity_file or '').strip()
    pub = (cfg.paths.ssh_pubkey_path or '').strip()
    ident_ok = bool(ident) and Path(ident).expanduser().exists()
    pub_ok = bool(pub) and Path(pub).expanduser().exists()
    if ident_ok and pub_ok:
        return []
    log.warning(
        'SSH identity/public key not detected for config init '
        '(identity_file={}, pubkey_file={}). '
        'VM SSH/provisioning may fail until keys are configured.',
        ident or '(empty)',
        pub or '(empty)',
    )
    return [
        '⚠️ SSH keypair not detected for this VM config.',
        '  `aivm` expects an SSH identity + public key for VM access/provisioning.',
        '  Quick setup:',
        '    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""',
        '  (Advisory only: config init will continue.)',
    ]


def _prompt_with_default(prompt: str, default: str) -> str:
    raw = input(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


def _prompt_int_with_default(prompt: str, default: int) -> int:
    while True:
        raw = input(f'{prompt} [{default}]: ').strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print('Please enter a valid integer.')
            continue
        if value <= 0:
            print('Please enter a positive integer.')
            continue
        return value


def _review_init_defaults_interactive(
    cfg: AgentVMConfig, path: Path
) -> AgentVMConfig:
    if not sys.stdin.isatty():
        raise RuntimeError(
            'Config init defaults require confirmation in interactive mode. '
            'Re-run with --yes or --defaults.'
        )
    print(_render_init_default_summary(cfg, path))
    warn_lines = _ssh_key_setup_warning_lines(cfg)
    if warn_lines:
        print('')
        for line in warn_lines:
            print(line)
    while True:
        ans = input('Use these values? [Y/e/n] (e=edit): ').strip().lower()
        if ans in {'', 'y', 'yes'}:
            return cfg
        if ans in {'n', 'no'}:
            raise RuntimeError('Aborted by user.')
        if ans in {'e', 'edit'}:
            cfg.vm.name = _prompt_with_default('vm.name', cfg.vm.name)
            cfg.vm.user = _prompt_with_default('vm.user', cfg.vm.user)
            cfg.vm.cpus = _prompt_int_with_default('vm.cpus', cfg.vm.cpus)
            cfg.vm.ram_mb = _prompt_int_with_default(
                'vm.ram_mb', cfg.vm.ram_mb
            )
            cfg.vm.disk_gb = _prompt_int_with_default(
                'vm.disk_gb', cfg.vm.disk_gb
            )
            cfg.network.name = _prompt_with_default(
                'network.name', cfg.network.name
            )
            cfg.network.subnet_cidr = _prompt_with_default(
                'network.subnet_cidr', cfg.network.subnet_cidr
            )
            cfg.network.gateway_ip = _prompt_with_default(
                'network.gateway_ip', cfg.network.gateway_ip
            )
            cfg.network.dhcp_start = _prompt_with_default(
                'network.dhcp_start', cfg.network.dhcp_start
            )
            cfg.network.dhcp_end = _prompt_with_default(
                'network.dhcp_end', cfg.network.dhcp_end
            )
            cfg.paths.ssh_identity_file = _prompt_with_default(
                'paths.ssh_identity_file', cfg.paths.ssh_identity_file or ''
            )
            cfg.paths.ssh_pubkey_path = _prompt_with_default(
                'paths.ssh_pubkey_path', cfg.paths.ssh_pubkey_path or ''
            )
            print('')
            print(_render_init_default_summary(cfg, path))
            warn_lines = _ssh_key_setup_warning_lines(cfg)
            if warn_lines:
                print('')
                for line in warn_lines:
                    print(line)
            continue
        print("Please answer 'y', 'e', or 'n'.")


class ConfigShowCLI(_BaseCommand):
    """Show resolved VM config content."""

    vm = scfg.Value(
        '',
        help='Optional VM name override.',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        vm_name = str(args.vm or '').strip()
        if not vm_name:
            if path.exists():
                print(path.read_text(encoding='utf-8'), end='')
            else:
                store = load_store(path)
                save_store(store, path)
                print(path.read_text(encoding='utf-8'), end='')
            return 0
        cfg, _ = _load_cfg_with_path(
            args.config, vm_opt=vm_name, host_src=Path.cwd()
        )
        print(f'# Store: {path}')
        print(f'# VM: {cfg.vm.name}')
        print(dump_toml(cfg), end='')
        return 0


class ConfigEditCLI(_BaseCommand):
    """Edit global config store in $EDITOR."""

    editor = scfg.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        if not path.exists():
            reg = load_store(path)
            save_store(reg, path)
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
    """Show config store path and resolved VM selection context."""

    vm = scfg.Value('', help='Optional VM name override.')
    host_src = scfg.Value('.', help='Host directory scope to inspect.')

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        host_src = Path(args.host_src).resolve()
        store = _cfg_path(args.config)
        reg = load_store(store)
        att = find_attachment(reg, host_src)
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

        print('🧭 AIVM Config Paths')
        print(f'cwd = {host_src}')
        print(f'config_store = {store} ({"exists" if store.exists() else "missing"})')
        print(f'active_vm = {reg.active_vm or "(unset)"}')
        if att is not None:
            print(f'attachment_vm = {att.vm_name}')
        if resolved_cfg_path is not None:
            print(f'resolved_store = {resolved_cfg_path}')
            if resolved_vm:
                print(f'resolved_vm = {resolved_vm}')
        else:
            print('resolved_vm = (unresolved)')
            if resolve_error:
                print(f'resolution_error = {resolve_error}')
        return 0


class ConfigDiscoverCLI(_BaseCommand):
    """Discover existing libvirt VMs and add them to config store."""

    dry_run = scfg.Value(
        False,
        isflag=True,
        help='Print actions without writing config store.',
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
        store = _cfg_path(args.config)
        reg = load_store(store)
        managed_seen = 0
        added = 0
        updated = 0
        skipped_unmanaged = 0
        for vm_name in vm_names:
            rec = find_vm(reg, vm_name)
            vm_info = _discover_vm_info(vm_name, use_sudo=used_sudo)
            if rec is None and not _prompt_import_discovered_vm(
                vm_info, yes=bool(args.yes)
            ):
                skipped_unmanaged += 1
                continue
            if rec is not None:
                managed_seen += 1
                cfg = rec.cfg.expanded_paths()
            else:
                cfg = AgentVMConfig().expanded_paths()
                cfg.vm.name = vm_name
            if not cfg.network.name:
                cfg.network.name = str(vm_info.get('network', 'aivm-net'))
            upsert_vm(reg, cfg)
            if rec is None:
                added += 1
            else:
                updated += 1

        if not args.dry_run:
            save_store(reg, store)

        print(f'Discovered VMs: {len(vm_names)}')
        print(f'  already_managed_seen: {managed_seen}')
        print(f'  added: {added}')
        print(f'  updated: {updated}')
        print(f'  skipped_unmanaged: {skipped_unmanaged}')
        print(f'Config store: {store}')
        return 0


class ConfigModalCLI(scfg.ModalCLI):
    """Config store management commands."""

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
    ans = input('Add this VM to aivm config store? [y/N]: ').strip().lower()
    return ans in {'y', 'yes'}
