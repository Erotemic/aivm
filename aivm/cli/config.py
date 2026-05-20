"""Config-store CLI operations.

This command group owns the operator-facing lifecycle of the global store:
bootstrap defaults, inspect/edit state, discover unmanaged libvirt VMs, and
lint for schema drift.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import fields
from pathlib import Path
from typing import Any, cast

import scriptconfig as scfg
from loguru import logger

from ..commands import CommandManager
from ..config import (
    AgentVMConfig,
    FirewallConfig,
    ImageConfig,
    NetworkConfig,
    PathsConfig,
    ProvisionConfig,
    VMConfig,
    VirtiofsConfig,
    dump_toml,
)
from ..detect import auto_defaults
from ..resource_checks import vm_resource_warning_lines
from ..runtime import virsh_system_cmd
from ..persistent_replay import PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME
from ..vm.paths import _paths as _vm_runtime_paths
from ..store import (
    find_attachments,
    find_vm,
    materialize_vm_cfg,
    load_config_document,
    load_store,
    save_store,
    format_existing_config,
    split_fragment_paths,
    app_data_dir,
    persistent_host_state_dir,
    upsert_network,
    upsert_vm_with_network,
)
from ..util import which
from ._common import (
    _BaseCommand,
    _cfg_path,
    _load_cfg_with_path,
    _maybe_offer_create_ssh_identity,
    _resolve_cfg_for_code,
)

log = logger


class InitCLI(_BaseCommand):
    """Initialize global config-store defaults (without creating a VM)."""

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
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        reg = load_store(path)
        cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
        _maybe_offer_create_ssh_identity(
            cfg,
            yes=bool(args.yes),
            prompt_reason=(
                'Generate a dedicated SSH keypair so aivm can access and '
                'provision VMs without reusing a generic personal key name.'
            ),
        )
        if not bool(args.yes) and not bool(args.defaults):
            cfg = _review_init_defaults_interactive(cfg, path)
        else:
            _warn_high_resource_defaults(cfg)
            warn_lines = _ssh_key_setup_warning_lines(cfg)
            for line in warn_lines:
                print(line)
        if reg.defaults is not None and not args.force:
            print(
                f'Config defaults already exist in store: {path}',
                file=sys.stderr,
            )
            print('Use --force to overwrite defaults.', file=sys.stderr)
            return 2
        reg.defaults = cfg
        save_store(reg, path)
        print(f'Updated config defaults: {path}')
        print(
            'No VM created. Use `aivm vm create` to create one from defaults.'
        )
        return 0


def _format_bool(value: bool) -> str:
    """Return a stable human-readable boolean for review prompts."""
    return 'true' if bool(value) else 'false'


def _format_secret(value: str) -> str:
    """Avoid echoing configured passwords in review summaries."""
    return '(configured)' if str(value or '') else '(empty)'


def _init_default_summary_rows(
    cfg: AgentVMConfig, path: Path
) -> list[tuple[str, str, str]]:
    """Return rows for the config-init defaults review summary."""
    password_note = (
        'used for console/SSH password auth when vm.allow_password_login=true'
    )
    return [
        ('config_store', str(path), 'config destination'),
        ('vm.user', cfg.vm.user, 'guest login user'),
        ('vm.cpus', str(cfg.vm.cpus), 'virtual CPUs'),
        ('vm.ram_mb', str(cfg.vm.ram_mb), 'RAM in MiB'),
        ('vm.disk_gb', str(cfg.vm.disk_gb), 'root disk size'),
        (
            'vm.allow_password_login',
            _format_bool(cfg.vm.allow_password_login),
            'enables password login on console and SSH',
        ),
        ('vm.password', _format_secret(cfg.vm.password), password_note),
        ('network.name', cfg.network.name, 'libvirt network'),
        ('network.subnet_cidr', cfg.network.subnet_cidr, 'guest subnet'),
        ('network.gateway_ip', cfg.network.gateway_ip, 'guest gateway'),
        ('network.dhcp_start', cfg.network.dhcp_start, 'DHCP range start'),
        ('network.dhcp_end', cfg.network.dhcp_end, 'DHCP range end'),
        (
            'paths.ssh_identity_file',
            cfg.paths.ssh_identity_file or '(empty)',
            'private key used by aivm',
        ),
        (
            'paths.ssh_pubkey_path',
            cfg.paths.ssh_pubkey_path or '(empty)',
            'public key injected into the guest',
        ),
    ]


def _render_init_default_summary(cfg: AgentVMConfig, path: Path) -> str:
    """Render a plain-text review summary before persisting defaults."""
    lines = ['Detected defaults for `aivm config init`:']
    for key, value, note in _init_default_summary_rows(cfg, path):
        if note:
            lines.append(f'  {key}: {value}  # {note}')
        else:
            lines.append(f'  {key}: {value}')
    return '\n'.join(lines)


def _print_init_default_summary(cfg: AgentVMConfig, path: Path) -> None:
    """Print the config-init review summary, using Rich when available."""
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:  # pragma: no cover - exercised only without rich
        print(_render_init_default_summary(cfg, path))
        return

    table = Table(title='Detected defaults for `aivm config init`')
    table.add_column('Setting', style='bold cyan', no_wrap=True)
    table.add_column('Value', overflow='fold')
    table.add_column('Meaning', style='dim', overflow='fold')
    for key, value, note in _init_default_summary_rows(cfg, path):
        table.add_row(key, value, note)
    Console().print(table)


def _ssh_key_setup_warning_lines(cfg: AgentVMConfig) -> list[str]:
    """Return advisory warnings when SSH key paths are missing/unusable."""
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
        '    ssh-keygen -t ed25519 -f ~/.ssh/id_aivm_ed25519 -N ""',
        '  (Advisory only: config init will continue.)',
    ]


def _warn_high_resource_defaults(cfg: AgentVMConfig) -> None:
    """Log host-resource warnings for detected default VM sizing."""
    for line in vm_resource_warning_lines(cfg):
        log.warning('Config-init default resource warning: {}', line)


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


def _prompt_bool_with_default(prompt: str, default: bool) -> bool:
    default_label = 'Y/n' if default else 'y/N'
    while True:
        raw = input(f'{prompt} [{default_label}]: ').strip().lower()
        if not raw:
            return bool(default)
        if raw in {'1', 'true', 't', 'y', 'yes', 'on'}:
            return True
        if raw in {'0', 'false', 'f', 'n', 'no', 'off'}:
            return False
        print("Please answer 'y' or 'n'.")


def _review_init_defaults_interactive(
    cfg: AgentVMConfig, path: Path
) -> AgentVMConfig:
    """Interactive review/edit loop for ``aivm config init`` defaults."""
    if not sys.stdin.isatty():
        raise RuntimeError(
            'Config init defaults require confirmation in interactive mode. '
            'Re-run with --yes or --defaults.'
        )
    log.trace('Start interactive default review')
    _print_init_default_summary(cfg, path)
    _warn_high_resource_defaults(cfg)
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
            cfg.vm.user = _prompt_with_default('vm.user', cfg.vm.user)
            cfg.vm.cpus = _prompt_int_with_default('vm.cpus', cfg.vm.cpus)
            cfg.vm.ram_mb = _prompt_int_with_default('vm.ram_mb', cfg.vm.ram_mb)
            cfg.vm.disk_gb = _prompt_int_with_default(
                'vm.disk_gb', cfg.vm.disk_gb
            )
            cfg.vm.allow_password_login = _prompt_bool_with_default(
                'vm.allow_password_login', cfg.vm.allow_password_login
            )
            if cfg.vm.allow_password_login:
                cfg.vm.password = _prompt_with_default(
                    'vm.password', cfg.vm.password
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
            _print_init_default_summary(cfg, path)
            _warn_high_resource_defaults(cfg)
            warn_lines = _ssh_key_setup_warning_lines(cfg)
            if warn_lines:
                print('')
                for line in warn_lines:
                    print(line)
            continue
        print("Please answer 'y', 'e', or 'n'.")


class ConfigShowCLI(_BaseCommand):
    """Show AIVM config content.

    By default this prints the canonical source document.  For split layouts,
    that source document is the deterministic concatenation of config.toml,
    defaults.toml, networks.toml, and sorted vms/*.toml fragments.
    """

    vm = scfg.Value(
        '',
        help='Optional VM name override for --resolved output.',
        position=1,
    )
    resolved = scfg.Value(
        False,
        isflag=True,
        help='Show effective VM config after defaults/network resolution.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        vm_name = str(args.vm or '').strip()
        if bool(args.resolved) or vm_name:
            cfg, cfg_path = _load_cfg_with_path(
                args.config, vm_opt=vm_name, host_src=Path.cwd()
            )
            toml_text = '\n'.join(
                [
                    f'# Store: {cfg_path}',
                    f'# VM: {cfg.vm.name}',
                    dump_toml(cfg),
                ]
            )
        else:
            loaded = load_config_document(path)
            if loaded.sources:
                toml_text = loaded.source_text
            else:
                store = loaded.store
                save_store(store, path)
                loaded = load_config_document(path)
                toml_text = loaded.source_text or path.read_text(
                    encoding='utf-8'
                )
        import ubelt as ub

        text = ub.highlight_code(toml_text, lexer_name='toml')
        print(text, end='')
        return 0


class ConfigFormatCLI(_BaseCommand):
    """Format config into the canonical split-file layout."""

    dry_run = scfg.Value(
        False,
        isflag=True,
        help='Show the files that would be written without modifying them.',
    )
    force = scfg.Value(
        False,
        isflag=True,
        help='Rewrite existing formatted fragments from the loaded logical document.',
    )
    no_backup = scfg.Value(
        False,
        isflag=True,
        help='Do not make a config.toml.bak backup before rewriting config.toml.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        targets = format_existing_config(
            path,
            backup=not bool(args.no_backup),
            dry_run=bool(args.dry_run),
            force=bool(args.force),
        )
        if args.dry_run:
            print('Would write formatted config paths:')
        else:
            print('Wrote formatted config paths:')
        for fpath in targets:
            print(f'  {fpath}')
        if not args.dry_run:
            print('Validate with: aivm config paths && aivm config show')
        return 0


class ConfigPathsCLI(_BaseCommand):
    """Show AIVM config, data, and libvirt-related paths.

    This command replaces the older narrow config-location commands. It reports
    both editable config fragments and the host-side paths
    AIVM/libvirt use for VM disks, cloud-init seeds, cached connection state,
    and persistent attachment manifests.
    """

    target: Any = scfg.Value(
        'all',
        help=(
            'Path group to show: all, config, global, defaults, networks, '
            'vms, vm, libvirt, data. `vm` defaults to active_vm.'
        ),
        position=1,
    )
    name: Any = scfg.Value(
        '',
        help='Optional VM name for `vm`/`libvirt` path groups.',
        position=2,
    )
    vm: Any = scfg.Value('', help='Optional VM name filter.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        root = _cfg_path(args.config)
        loaded = load_config_document(root)
        target = str(args.target or 'all').strip().lower().replace('_', '-')
        vm_name = str(args.vm or args.name or '').strip()
        if target in {'active', 'active-vm'}:
            target = 'vm'
        if target == 'vm' and not vm_name:
            vm_name = loaded.store.active_vm
        if target == 'libvirt' and not vm_name:
            # Without an explicit VM, libvirt output includes global paths plus
            # all configured VM-specific paths.
            vm_name = ''

        valid = {
            'all',
            'config',
            'global',
            'root',
            'defaults',
            'networks',
            'network',
            'vms',
            'vm',
            'libvirt',
            'data',
        }
        if target not in valid:
            raise RuntimeError(
                f'Unknown path group {target!r}. Expected one of: '
                + ', '.join(sorted(valid))
            )

        print('AIVM paths')
        print(f'layout: {loaded.layout}')
        print(f'active_vm: {loaded.store.active_vm or "(unset)"}')

        show_config = target in {
            'all',
            'config',
            'global',
            'root',
            'defaults',
            'networks',
            'network',
            'vms',
            'vm',
        }
        show_data = target in {'all', 'data'}
        show_libvirt = target in {'all', 'libvirt', 'vms', 'vm'}

        if show_config:
            _print_config_paths(root, loaded, target=target, vm_name=vm_name)
        if show_data:
            _print_data_paths(loaded, vm_name=vm_name)
        if show_libvirt:
            _print_libvirt_paths(root, loaded, target=target, vm_name=vm_name)
        return 0


class ConfigEditCLI(_BaseCommand):
    """Edit a config fragment in $EDITOR.

    Targets:
      global/root/base/config  -> config.toml
      defaults                 -> defaults.toml when formatted
      networks                 -> networks.toml when formatted
      vm [NAME]                -> the named VM fragment, defaulting to active_vm
      NAME                     -> shorthand for `vm NAME` when NAME is a VM
    """

    target: Any = scfg.Value(
        'global',
        help='Edit target: global, defaults, networks, vm, active-vm, or VM name.',
        position=1,
    )
    name: Any = scfg.Value(
        '',
        help='Optional name for targets that need one, e.g. `vm aivm-2404`.',
        position=2,
    )
    editor: Any = scfg.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )
    visual: Any = scfg.Value(
        '',
        help='If true, then prefer $VISUAL over $EDITOR.',
        isflag=True,
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _resolve_config_edit_target(
            config_opt=args.config,
            target=str(args.target or 'global'),
            name=str(args.name or ''),
        )
        if path == _cfg_path(args.config) and not path.exists():
            reg = load_store(path)
            save_store(reg, path)
        _edit_path(path, args)
        return 0


def _editor_command(args: Any) -> list[str]:
    """Return the editor command prefix selected by CLI args/environment."""
    order = ['VISUAL', 'EDITOR'] if args.visual else ['EDITOR', 'VISUAL']
    candidates = [
        str(args.editor or '').strip(),
        *(os.environ.get(key, '') for key in order),
    ]
    editor_cmd = next((x for x in candidates if x), '')
    if not editor_cmd:
        editor_cmd = which('nano') or which('vi') or ''
    if not editor_cmd:
        raise RuntimeError('No editor found. Set $EDITOR or pass --editor.')
    return shlex.split(editor_cmd)


def _edit_path(path: Path, args: Any) -> None:
    """Open a config path in the selected editor."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text('', encoding='utf-8')
    parts = _editor_command(args) + [str(path)]
    CommandManager.current().run(
        parts, sudo=False, check=True, capture=False
    )


def _path_status(path: Path) -> str:
    try:
        if path.exists():
            return 'exists'
    except PermissionError:
        return 'permission-denied'
    except OSError as ex:
        return f'error:{ex.__class__.__name__}'
    return 'missing'


def _print_path(label: str, path: Path | str, *, kind: str = 'path') -> None:
    raw = str(path)
    if '*' in raw or '?' in raw or '[' in raw:
        status = 'glob'
    else:
        status = _path_status(Path(raw).expanduser())
    print(f'  {label} ({kind}, {status}): {raw}')


def _role_source(loaded: Any, role: str) -> Path | None:
    for src in loaded.sources:
        if src.role == role:
            return src.path
    return None


def _vm_config_source(root: Path, loaded: Any, vm_name: str) -> Path:
    src = loaded.vm_sources.get(vm_name)
    if src is not None:
        return src
    if loaded.layout == 'split':
        paths = split_fragment_paths(loaded.store, root)
        return paths.get(
            f'vm:{vm_name}', root.parent / 'vms' / f'{vm_name}.toml'
        )
    return root


def _print_config_paths(
    root: Path, loaded: Any, *, target: str, vm_name: str
) -> None:
    cfg_dir = root.parent
    show_all = target in {'all', 'config'}
    print('config:')
    if show_all or target in {'global', 'root'}:
        _print_path('global', root, kind='file')
    if show_all or target == 'defaults':
        _print_path(
            'defaults',
            _role_source(loaded, 'defaults') or cfg_dir / 'defaults.toml',
            kind='file',
        )
    if show_all or target in {'networks', 'network'}:
        _print_path(
            'networks',
            _role_source(loaded, 'networks') or cfg_dir / 'networks.toml',
            kind='file',
        )
    if show_all or target == 'vms':
        if loaded.store.vms:
            for vm in sorted(loaded.store.vms, key=lambda rec: rec.name):
                _print_path(
                    f'vm:{vm.name}',
                    _vm_config_source(root, loaded, vm.name),
                    kind='file',
                )
        else:
            _print_path('vms_dir', cfg_dir / 'vms', kind='dir')
    if target == 'vm':
        if not vm_name:
            raise RuntimeError('No VM specified and active_vm is unset.')
        if find_vm(loaded.store, vm_name) is None:
            raise RuntimeError(f'VM not found in config: {vm_name}')
        _print_path(
            f'vm:{vm_name}',
            _vm_config_source(root, loaded, vm_name),
            kind='file',
        )


def _print_data_paths(loaded: Any, *, vm_name: str) -> None:
    print('data:')
    _print_path('app_data_dir', app_data_dir(), kind='dir')
    names = (
        [vm_name]
        if vm_name
        else [rec.name for rec in sorted(loaded.store.vms, key=lambda r: r.name)]
    )
    for name in names:
        if not name:
            continue
        state_dir = persistent_host_state_dir(name)
        _print_path(
            f'vm:{name}:persistent_host_state_dir', state_dir, kind='dir'
        )
        _print_path(
            f'vm:{name}:persistent_host_manifest',
            state_dir / PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
            kind='file',
        )


def _print_libvirt_paths(
    root: Path, loaded: Any, *, target: str, vm_name: str
) -> None:
    names = (
        [vm_name]
        if vm_name
        else [rec.name for rec in sorted(loaded.store.vms, key=lambda r: r.name)]
    )
    cfgs = []
    for name in names:
        if not name:
            continue
        if find_vm(loaded.store, name) is None:
            if target == 'vm':
                raise RuntimeError(f'VM not found in config: {name}')
            continue
        cfgs.append(materialize_vm_cfg(loaded.store, name).expanded_paths())

    print('libvirt:')
    base_dirs = sorted({cfg.paths.base_dir for cfg in cfgs})
    if not base_dirs and loaded.store.defaults is not None:
        base_dirs = [loaded.store.defaults.expanded_paths().paths.base_dir]
    if not base_dirs:
        base_dirs = [AgentVMConfig().expanded_paths().paths.base_dir]
    for base in base_dirs:
        base_path = Path(base)
        _print_path('base_dir', base_path, kind='dir')
        _print_path(
            'legacy_virtiofsd_wrappers',
            base_path / 'virtiofsd-wrapper-*',
            kind='glob',
        )

    for cfg in cfgs:
        p = _vm_runtime_paths(cfg)
        vm = cfg.vm.name
        print(f'libvirt.vm:{vm}:')
        _print_path('vm_dir', p['base_dir'], kind='dir')
        _print_path('image_dir', p['img_dir'], kind='dir')
        _print_path(
            'base_image', p['img_dir'] / cfg.image.cache_name, kind='file'
        )
        _print_path('vm_disk', p['img_dir'] / f'{vm}.qcow2', kind='file')
        _print_path('cloud_init_dir', p['ci_dir'], kind='dir')
        _print_path(
            'cloud_init_seed', p['ci_dir'] / f'{vm}-seed.iso', kind='file'
        )
        _print_path('runtime_state_dir', p['state_dir'], kind='dir')
        _print_path('ip_file', p['ip_file'], kind='file')
        _print_path('known_hosts', p['known_hosts'], kind='file')
        _print_path(
            'persistent_host_state_dir', persistent_host_state_dir(vm), kind='dir'
        )
        _print_path(
            'persistent_host_manifest',
            persistent_host_state_dir(vm)
            / PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
            kind='file',
        )


def _resolve_config_edit_target(
    *, config_opt: str, target: str, name: str = ''
) -> Path:
    """Resolve a user-facing config edit target to a physical file."""
    root = _cfg_path(config_opt)
    loaded = load_config_document(root)
    cfg_dir = root.parent
    target_norm = (target or 'global').strip().lower().replace('_', '-')
    name = str(name or '').strip()

    if target_norm in {'global', 'root', 'base', 'config', ''}:
        return root

    if target_norm in {'defaults', 'default'}:
        src = _role_source(loaded, 'defaults')
        if src is not None:
            return src
        return cfg_dir / 'defaults.toml' if loaded.layout == 'split' else root

    if target_norm in {'networks', 'network', 'net'}:
        src = _role_source(loaded, 'networks')
        if src is not None:
            return src
        return cfg_dir / 'networks.toml' if loaded.layout == 'split' else root

    if target_norm in {'vm', 'vms', 'active-vm', 'active'}:
        vm_name = name or loaded.store.active_vm
    else:
        # Convenience: `aivm config edit aivm-2404` means that VM if it exists.
        vm_name = target

    if not vm_name:
        raise RuntimeError('No VM specified and active_vm is unset.')
    if find_vm(loaded.store, vm_name) is None:
        raise RuntimeError(f'VM not found in config: {vm_name}')
    return _vm_config_source(root, loaded, vm_name)


class ConfigDiscoverCLI(_BaseCommand):
    """Discover existing libvirt VMs and add them to config store."""

    dry_run = scfg.Value(
        False,
        isflag=True,
        help='Print actions without writing config store.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        # Discover is intentionally conservative: unmanaged VMs require explicit
        # import confirmation (unless --yes) to avoid surprising ownership grabs.
        args = cls.cli(argv=argv, data=kwargs)
        mgr = CommandManager.current()
        names_res = mgr.run(
            virsh_system_cmd('list', '--all', '--name'),
            sudo=False,
            check=False,
            capture=True,
        )
        used_sudo = False
        if names_res.code != 0:
            used_sudo = True
            names_res = mgr.run(
                virsh_system_cmd('list', '--all', '--name'),
                sudo=True,
                check=True,
                capture=True,
                summary='List libvirt VMs with system privileges',
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
            upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
            upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
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


class ConfigLintCLI(_BaseCommand):
    """Lint config store for unknown/unused keys and sections."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        loaded = load_config_document(path)
        if not loaded.sources:
            print(f'Config store not found: {path}', file=sys.stderr)
            return 2
        problems = _lint_store_text(loaded.source_text or path.read_text(encoding='utf-8'))
        label = path if loaded.layout != 'split' else f'{path.parent} (split layout)'
        if not problems:
            print(f'✅ Config lint passed: {label}')
            return 0
        print(f'❌ Config lint found {len(problems)} issue(s): {label}')
        for item in problems:
            print(f'  - {item}')
        return 2


def _field_names(cls: type) -> set[str]:
    """Small helper for dataclass-backed lint allow-lists."""
    return {f.name for f in fields(cls)}


def _lint_store_file(path: Path) -> list[str]:
    """Return schema/shape problems for the config store file."""
    return _lint_store_text(path.read_text(encoding='utf-8'))


def _lint_store_text(text: str) -> list[str]:
    """Return schema/shape problems for a canonical config document.

    Lint focuses on unknown or structurally invalid keys so users can catch
    typos and stale fields after format evolution.
    """
    raw = tomllib.loads(text)
    problems: list[str] = []

    allowed_top = {
        'schema_version',
        'active_vm',
        'behavior',
        'defaults',
        'networks',
        'vms',
        'attachments',
    }
    for key in sorted(raw.keys()):
        if key not in allowed_top:
            problems.append(f'unknown top-level key: {key!r}')

    allowed_vm_record = {
        'name',
        'network_name',
        'verbosity',
        'vm',
        'image',
        'provision',
        'paths',
        'virtiofs',
        'attachments',
    }
    section_allowed: dict[str, set[str]] = {
        'vm': _field_names(VMConfig),
        'network': _field_names(NetworkConfig),
        'firewall': _field_names(FirewallConfig),
        'image': _field_names(ImageConfig),
        'provision': _field_names(ProvisionConfig),
        'paths': _field_names(PathsConfig),
        'virtiofs': _field_names(VirtiofsConfig),
    }
    behavior = raw.get('behavior', None)
    if behavior is not None:
        if not isinstance(behavior, dict):
            problems.append('top-level key "behavior" should be a table/object')
        else:
            allowed_behavior = {
                'yes_sudo',
                'auto_approve_readonly_sudo',
                'verbose',
            }
            # mirror_shared_home_folders moved to VMConfig in schema 6;
            # tolerate the legacy key here so older files lint cleanly
            # and are migrated on parse.
            legacy_behavior = {'mirror_shared_home_folders'}
            for key in sorted(behavior.keys()):
                if key in allowed_behavior or key in legacy_behavior:
                    continue
                problems.append(f'behavior unknown key: {key!r}')
    defaults = raw.get('defaults', None)
    if defaults is not None:
        if not isinstance(defaults, dict):
            problems.append('top-level key "defaults" should be a table/object')
        else:
            allowed_defaults_record = {
                'verbosity',
                'vm',
                'network',
                'firewall',
                'image',
                'provision',
                'paths',
                'virtiofs',
            }
            for key in sorted(defaults.keys()):
                if key not in allowed_defaults_record:
                    problems.append(f'defaults unknown key/section: {key!r}')
            for sec_name, allowed in section_allowed.items():
                sec = defaults.get(sec_name, None)
                if sec is None:
                    continue
                if not isinstance(sec, dict):
                    problems.append(
                        f'defaults.{sec_name} should be a table/object'
                    )
                    continue
                for key in sorted(sec.keys()):
                    if key not in allowed:
                        problems.append(
                            f'defaults.{sec_name} unknown key: {key!r}'
                        )

    networks = raw.get('networks', [])
    if isinstance(networks, list):
        allowed_network_record = {'name', 'network', 'firewall'}
        for idx, item in enumerate(networks):
            if not isinstance(item, dict):
                problems.append(f'networks[{idx}] is not a table/object')
                continue
            item = cast(dict[str, object], item)
            for key in sorted(item.keys()):
                if key not in allowed_network_record:
                    problems.append(
                        f'networks[{idx}] unknown key/section: {key!r}'
                    )
            net_sec = item.get('network')
            if net_sec is not None:
                if not isinstance(net_sec, dict):
                    problems.append(
                        f'networks[{idx}].network should be a table/object'
                    )
                else:
                    for key in sorted(net_sec.keys()):
                        if key not in _field_names(NetworkConfig):
                            problems.append(
                                f'networks[{idx}].network unknown key: {key!r}'
                            )
            fw_sec = item.get('firewall')
            if fw_sec is not None:
                if not isinstance(fw_sec, dict):
                    problems.append(
                        f'networks[{idx}].firewall should be a table/object'
                    )
                else:
                    for key in sorted(fw_sec.keys()):
                        if key not in _field_names(FirewallConfig):
                            problems.append(
                                f'networks[{idx}].firewall unknown key: {key!r}'
                            )
    elif networks is not None:
        problems.append('top-level key "networks" should be an array of tables')

    allowed_attachment = {
        'host_path',
        'vm_name',
        'mode',
        'access',
        'guest_dst',
        'tag',
        'host_lexical_path',
    }
    vms = raw.get('vms', [])
    if isinstance(vms, list):
        for idx, item in enumerate(vms):
            if not isinstance(item, dict):
                problems.append(f'vms[{idx}] is not a table/object')
                continue
            item = cast(dict[str, object], item)
            for key in sorted(item.keys()):
                if key not in allowed_vm_record:
                    problems.append(f'vms[{idx}] unknown key/section: {key!r}')
            for sec_name, allowed in section_allowed.items():
                sec = item.get(sec_name)
                if sec is None:
                    continue
                if not isinstance(sec, dict):
                    problems.append(
                        f'vms[{idx}].{sec_name} should be a table/object'
                    )
                    continue
                for key in sorted(sec.keys()):
                    if key not in allowed:
                        problems.append(
                            f'vms[{idx}].{sec_name} unknown key: {key!r}'
                        )
            nested_atts = item.get('attachments', [])
            if isinstance(nested_atts, list):
                for att_idx, att in enumerate(nested_atts):
                    if not isinstance(att, dict):
                        problems.append(
                            f'vms[{idx}].attachments[{att_idx}] is not a table/object'
                        )
                        continue
                    for key in sorted(att.keys()):
                        if key not in allowed_attachment:
                            problems.append(
                                f'vms[{idx}].attachments[{att_idx}] unknown key: {key!r}'
                            )
            elif nested_atts is not None:
                problems.append(
                    f'vms[{idx}].attachments should be an array of tables'
                )
    elif vms is not None:
        problems.append('top-level key "vms" should be an array of tables')

    atts = raw.get('attachments', [])
    if isinstance(atts, list):
        for idx, item in enumerate(atts):
            if not isinstance(item, dict):
                problems.append(f'attachments[{idx}] is not a table/object')
                continue
            for key in sorted(item.keys()):
                if key not in allowed_attachment:
                    problems.append(f'attachments[{idx}] unknown key: {key!r}')
    elif atts is not None:
        problems.append(
            'top-level key "attachments" should be an array of tables'
        )

    return problems


class ConfigModalCLI(scfg.ModalCLI):
    """Config store management commands."""

    init = InitCLI
    discover = ConfigDiscoverCLI
    lint = ConfigLintCLI
    paths = ConfigPathsCLI
    format = ConfigFormatCLI
    show = ConfigShowCLI
    edit = ConfigEditCLI


def _discover_vm_info(vm_name: str, *, use_sudo: bool) -> dict[str, object]:
    """Collect a minimal VM summary used for discover/import prompts."""
    mgr = CommandManager.current()
    info: dict[str, object] = {
        'name': vm_name,
        'state': 'unknown',
        'autostart': 'unknown',
        'network': 'unknown',
        'vcpus': 'unknown',
        'memory_mib': 'unknown',
        'shares': [],
    }
    dominfo = mgr.run(
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
    xml = mgr.run(
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
    """Ask whether an unmanaged discovered VM should be imported into store."""
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
