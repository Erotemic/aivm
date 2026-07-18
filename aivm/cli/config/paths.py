"""``aivm config paths`` — show config/data/libvirt paths AIVM uses."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import kwconf

from ...config import AgentVMConfig
from ...config_store import (
    app_data_dir,
    find_vm,
    load_config_document,
    materialize_vm_cfg,
    persistent_host_state_dir,
    split_fragment_paths,
)
from ...errors import AIVMError
from ...persistent_replay import PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME
from ...services import cfg_path
from ...vm.paths import _paths as _vm_runtime_paths
from .._common import _BaseCommand


class ConfigPathsCLI(_BaseCommand):
    """Show AIVM config, data, and libvirt-related paths.

    This command replaces the older narrow config-location commands. It reports
    both editable config fragments and the host-side paths
    AIVM/libvirt use for VM disks, cloud-init seeds, cached connection state,
    and persistent attachment manifests.
    """

    target: str = kwconf.Value(
        'all',
        help=(
            'Path group to show: all, config, global, defaults, networks, '
            'vms, vm, libvirt, data. `vm` defaults to active_vm.'
        ),
        position=1,
    )
    name: str = kwconf.Value(
        '',
        help='Optional VM name for `vm`/`libvirt` path groups.',
        position=2,
    )
    vm: str = kwconf.Value('', help='Optional VM name filter.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        root = cfg_path(args.config)
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
            raise AIVMError(
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
            raise AIVMError('No VM specified and active_vm is unset.')
        if find_vm(loaded.store, vm_name) is None:
            raise AIVMError(f'VM not found in config: {vm_name}')
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
                raise AIVMError(f'VM not found in config: {name}')
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
