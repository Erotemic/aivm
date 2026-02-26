from __future__ import annotations

import sys
import textwrap
import re
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
    upsert_vm,
    vm_global_config_path,
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

    config = scfg.Value(None, help='Path to config TOML (default: .aivm.toml).')
    verbose = scfg.Value(
        0,
        short_alias=['v'],
        isflag='counter',
        help='Increase verbosity (-v, -vv).',
    )
    yes = scfg.Value(
        False,
        isflag=True,
        help='Auto-approve privileged host operations (sudo).',
    )


def _cfg_path(p: str | None) -> Path:
    return Path(p or '.aivm.toml').resolve()


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
                if (
                    not cfg.paths.ssh_identity_file
                    and gcfg.paths.ssh_identity_file
                ):
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
            'Hydrated runtime defaults for vm={} ssh_identity_file={} ssh_pubkey_path={}',
            cfg.vm.name,
            cfg.paths.ssh_identity_file or '(empty)',
            cfg.paths.ssh_pubkey_path or '(empty)',
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
            f'Config not found: {path}. '
            f'Run: aivm config init --config {path} '
            'or use global selection commands like `aivm code .` / `aivm list`.'
        )
    cfg = load(path).expanded_paths()
    changed = False
    if hydrate_runtime_defaults:
        changed = _hydrate_runtime_defaults(cfg)
    if changed and persist_runtime_defaults:
        save(path, cfg)
    return cfg, path


def _resolve_cfg_fallback(
    config_opt: str | None, *, vm_opt: str = ''
) -> tuple[AgentVMConfig, Path]:
    """Resolve config from explicit/local path, else directory metadata/global registry."""
    if config_opt is not None or _cfg_path(None).exists():
        return _load_cfg_with_path(config_opt)
    return _resolve_cfg_for_code(
        config_opt=None, vm_opt=vm_opt, host_src=Path.cwd()
    )


def _record_vm(cfg: AgentVMConfig, cfg_path: Path) -> Path:
    gpath = vm_global_config_path(cfg.vm.name)
    ensure_dir(gpath.parent)
    save(gpath, cfg)
    reg = load_registry()
    upsert_vm(reg, cfg, cfg_path, global_cfg_path=gpath)
    return save_registry(reg)


def _choose_vm_interactive(options: list[str], *, reason: str) -> str:
    if not sys.stdin.isatty():
        raise RuntimeError(
            f'VM selection is ambiguous ({reason}). Re-run with --vm or --config.'
        )
    print(f'Multiple VMs match ({reason}). Select one:')
    for idx, item in enumerate(options, start=1):
        print(f'  {idx}. {item}')
    while True:
        raw = input('Select VM number: ').strip()
        if not raw.isdigit():
            print('Please enter a number.')
            continue
        choice = int(raw)
        if 1 <= choice <= len(options):
            return options[choice - 1]
        print(f'Please enter a number between 1 and {len(options)}.')


def _confirm_sudo_block(*, yes: bool, purpose: str) -> None:
    if yes or os.geteuid() == 0:
        return
    if not sys.stdin.isatty():
        raise RuntimeError(
            'Privileged host operations require confirmation, but stdin is not interactive. '
            'Re-run with --yes.'
        )
    print('About to run privileged host operations via sudo:')
    print(f'  {purpose}')
    ans = input('Continue? [y/N]: ').strip().lower()
    if ans not in {'y', 'yes'}:
        raise RuntimeError('Aborted by user.')


def _resolve_cfg_for_code(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
) -> tuple[AgentVMConfig, Path]:
    # Import lazily to avoid circular import: cli.vm imports cli._common.
    from .vm import _select_cfg_for_vm_name

    if config_opt is not None:
        return _load_cfg_with_path(config_opt)

    cwd_cfg = _cfg_path(None)
    if cwd_cfg.exists():
        return _load_cfg_with_path(None)

    if vm_opt:
        return _select_cfg_for_vm_name(vm_opt, reason='--vm')

    reg = load_registry()
    meta = read_dir_metadata(host_src)
    meta_vm = (
        str(meta.get('vm_name', '')).strip() if isinstance(meta, dict) else ''
    )
    if meta_vm:
        return _select_cfg_for_vm_name(meta_vm, reason='directory metadata')

    att = find_attachment(reg, host_src)
    if att is not None:
        return _select_cfg_for_vm_name(
            att.vm_name, reason='existing attachment'
        )

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
            'No usable VM config found. Pass --config, run `aivm config init`, or register a VM.'
        )
    if len(valid) == 1:
        only = valid[0]
        return _select_cfg_for_vm_name(only.name, reason='single registered VM')

    chosen = _choose_vm_interactive(
        [r.name for r in sorted(valid, key=lambda x: x.name)],
        reason=f'{len(valid)} registered VMs',
    )
    return _select_cfg_for_vm_name(chosen, reason='interactive choice')


@dataclass
class PreparedSession:
    cfg: AgentVMConfig
    cfg_path: Path
    host_src: Path
    ip: str | None
    reg_path: Path | None
    meta_path: Path | None


__all__ = [name for name in globals() if not name.startswith('__')]
