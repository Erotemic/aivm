"""Shared CLI resolution, sudo confirmation, and config-store helpers."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import scriptconfig as scfg
from loguru import logger

from ..config import AgentVMConfig
from ..detect import detect_ssh_identity
from ..store import (
    find_attachment,
    find_vm,
    load_store,
    save_store,
    store_path,
    upsert_vm,
)
from ..util import run_cmd

log = logger

_SUDO_VALIDATED = False


class _BaseCommand(scfg.DataConfig):
    """Base options shared by all commands."""

    config = scfg.Value(
        None,
        help='Path to global aivm config store (default: ~/.config/aivm/config.toml).',
    )
    verbose = scfg.Value(
        0,
        short_alias=['v'],
        isflag='counter',
        help='Increase verbosity (-v, -vv).',
    )
    yes = scfg.Value(
        False,
        isflag=True,
        help='Auto-approve interactive confirmations.',
    )


def _cfg_path(p: str | None) -> Path:
    return Path(p).expanduser().resolve() if p else store_path().resolve()


def _hydrate_runtime_defaults(cfg: AgentVMConfig) -> bool:
    changed = False
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


def _choose_vm_interactive(options: list[str], *, reason: str) -> str:
    if not sys.stdin.isatty():
        raise RuntimeError(
            f'VM selection is ambiguous ({reason}). Re-run with --vm.'
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


def _resolve_vm_name(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path | None,
) -> tuple[str, Path]:
    store_path = _cfg_path(config_opt)
    reg = load_store(store_path)

    if vm_opt:
        if find_vm(reg, vm_opt) is None:
            raise RuntimeError(f'VM not found in config store: {vm_opt}')
        return vm_opt, store_path

    if host_src is not None:
        att = find_attachment(reg, host_src)
        if att is not None:
            return att.vm_name, store_path

    if reg.active_vm and find_vm(reg, reg.active_vm) is not None:
        return reg.active_vm, store_path

    if len(reg.vms) == 1:
        return reg.vms[0].name, store_path

    if len(reg.vms) > 1:
        chosen = _choose_vm_interactive(
            [r.name for r in sorted(reg.vms, key=lambda x: x.name)],
            reason=f'{len(reg.vms)} configured VMs',
        )
        return chosen, store_path

    raise RuntimeError(
        f'No VM definitions found in config store: {store_path}. '
        'Run `aivm config init` first.'
    )


def _load_cfg_with_path(
    config_path: str | None,
    *,
    vm_opt: str = '',
    host_src: Path | None = None,
    hydrate_runtime_defaults: bool = True,
    persist_runtime_defaults: bool = True,
) -> tuple[AgentVMConfig, Path]:
    vm_name, store_path = _resolve_vm_name(
        config_opt=config_path,
        vm_opt=vm_opt,
        host_src=host_src,
    )
    reg = load_store(store_path)
    rec = find_vm(reg, vm_name)
    if rec is None:
        raise RuntimeError(f'VM not found in config store: {vm_name}')
    cfg = rec.cfg.expanded_paths()
    changed = _hydrate_runtime_defaults(cfg) if hydrate_runtime_defaults else False
    if changed and persist_runtime_defaults:
        upsert_vm(reg, cfg)
        save_store(reg, store_path)
    return cfg, store_path


def _load_cfg(config_path: str | None, *, vm_opt: str = '') -> AgentVMConfig:
    cfg, _ = _load_cfg_with_path(
        config_path,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
    )
    return cfg


def _resolve_cfg_fallback(
    config_opt: str | None, *, vm_opt: str = ''
) -> tuple[AgentVMConfig, Path]:
    return _load_cfg_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
    )


def _record_vm(cfg: AgentVMConfig, store_file: Path | None = None) -> Path:
    target = store_file or store_path()
    reg = load_store(target)
    upsert_vm(reg, cfg)
    return save_store(reg, target)


def _has_passwordless_sudo() -> bool:
    res = run_cmd(['sudo', '-n', 'true'], sudo=False, check=False, capture=True)
    return res.code == 0


def _confirm_sudo_block(*, yes: bool, purpose: str) -> None:
    global _SUDO_VALIDATED
    if os.geteuid() == 0:
        return
    if not _SUDO_VALIDATED and _has_passwordless_sudo():
        _SUDO_VALIDATED = True
    if yes:
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
    if not _SUDO_VALIDATED:
        run_cmd(['sudo', '-v'], sudo=False, check=True, capture=False)
        _SUDO_VALIDATED = True


def _confirm_external_file_update(
    *, yes: bool, path: Path, purpose: str
) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise RuntimeError(
            'External host file updates require confirmation, but stdin is not interactive. '
            'Re-run with --yes.'
        )
    print('About to update a host file not managed by aivm:')
    print(f'  {path}')
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
    return _load_cfg_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=host_src,
    )


@dataclass
class PreparedSession:
    cfg: AgentVMConfig
    cfg_path: Path
    host_src: Path
    share_source_dir: str
    share_tag: str
    share_guest_dst: str
    ip: str | None
    reg_path: Path | None
    meta_path: Path | None


__all__ = [name for name in globals() if not name.startswith('__')]
