"""Top-level modal CLI wiring, argv normalization, and logging setup."""

from __future__ import annotations

import os
import sys
import scriptconfig as scfg
from pathlib import Path
from loguru import logger

from ..config import AgentVMConfig
from ..firewall import apply_firewall
from ..net import ensure_network
from ..store import find_vm, load_store
from ..status import (
    clip as _clip_text,
    render_global_status,
    render_status,
    status_line,
)
from ..vm import (
    create_or_start_vm,
    fetch_image,
    provision,
    ssh_config as mk_ssh_config,
    wait_for_ip,
)
from ._common import (
    _BaseCommand,
    _cfg_path,
    _confirm_sudo_block,
    _load_cfg,
    _load_cfg_with_path,
    _record_vm,
    _resolve_cfg_for_code,
    log,
)
from .config import ConfigModalCLI
from .help import HelpModalCLI
from .host import HostModalCLI
from .vm import AttachCLI, CodeCLI, SSHCLI, VMModalCLI


class ApplyCLI(_BaseCommand):
    """Run the full setup workflow from network to provisioning."""

    interactive = scfg.Value(
        False, isflag=True, help='Print plan and SSH config at the end.'
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        if args.interactive:
            from .help import PlanCLI

            PlanCLI.main(argv=False, config=args.config, verbose=args.verbose)
            print()
        log.debug('Ensuring network is set up')
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose=f"Create/update libvirt network '{cfg.network.name}'.",
        )
        ensure_network(cfg, recreate=False, dry_run=args.dry_run)
        if cfg.firewall.enabled:
            log.debug('Applying firewall rules')
            _confirm_sudo_block(
                yes=bool(args.yes), purpose='Apply nftables firewall rules.'
            )
            apply_firewall(cfg, dry_run=args.dry_run)
        log.debug('Fetching Ubuntu image')
        _confirm_sudo_block(
            yes=bool(args.yes), purpose='Download/cache VM base image.'
        )
        fetch_image(cfg, dry_run=args.dry_run)
        log.debug('Creating or starting VM')
        _confirm_sudo_block(
            yes=bool(args.yes), purpose=f"Create/start VM '{cfg.vm.name}'."
        )
        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=False)
        if not args.dry_run:
            _record_vm(cfg, cfg_path)
        log.debug('Waiting for VM IP address')
        _confirm_sudo_block(
            yes=bool(args.yes), purpose='Query VM networking state via virsh.'
        )
        wait_for_ip(cfg, timeout_s=360, dry_run=args.dry_run)
        if cfg.provision.enabled:
            log.debug('Provisioning VM with tools')
            provision(cfg, dry_run=args.dry_run)
        if args.interactive:
            print('\nSSH config for VS Code:')
            print(mk_ssh_config(cfg))
        return 0


class ListCLI(_BaseCommand):
    """List managed VMs, managed networks, and attached host folders."""

    section = scfg.Value(
        'all',
        help='One of: all, vms, networks, folders.',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        want = str(args.section or 'all').strip().lower()
        allowed = {'all', 'vms', 'networks', 'folders'}
        if want not in allowed:
            raise RuntimeError(
                f'--section must be one of: {", ".join(sorted(allowed))}'
            )

        reg_path = _cfg_path(args.config)
        reg = load_store(reg_path)

        if want in {'all', 'vms'}:
            print('Managed VMs')
            if not reg.vms:
                print('  (none)')
            else:
                by_net = {n.name: n for n in reg.networks}
                for vm in sorted(reg.vms, key=lambda x: x.name):
                    strict = (
                        bool(by_net[vm.network_name].firewall.enabled)
                        if vm.network_name in by_net
                        else False
                    )
                    print(
                        f'  - {vm.name} | network={vm.network_name} '
                        f'| strict_firewall={"yes" if strict else "no"} '
                        f'| store={reg_path}'
                    )

        if want in {'all', 'networks'}:
            if want == 'all':
                print('')
            print('Managed Networks')
            if not reg.networks:
                print('  (none)')
            else:
                usage: dict[str, int] = {n.name: 0 for n in reg.networks}
                for vm in reg.vms:
                    usage[vm.network_name] = usage.get(vm.network_name, 0) + 1
                for net in sorted(reg.networks, key=lambda n: n.name):
                    print(
                        f'  - {net.name} | strict_firewall={"yes" if net.firewall.enabled else "no"} '
                        f'| vm_count={usage.get(net.name, 0)}'
                    )

        if want in {'all', 'folders'}:
            if want == 'all':
                print('')
            print('Attached Folders')
            if not reg.attachments:
                print('  (none)')
            else:
                for att in sorted(
                    reg.attachments, key=lambda x: (x.vm_name, x.host_path)
                ):
                    print(
                        f'  - {att.host_path} | vm={att.vm_name} '
                        f'| mode={att.mode} | guest_dst={att.guest_dst or "(default)"}'
                    )
        print('')
        print(f'Config store: {reg_path}')
        return 0


class StatusCLI(_BaseCommand):
    """Report setup progress across host, network, VM, SSH, and provisioning."""

    sudo = scfg.Value(
        False,
        isflag=True,
        help='Run privileged status checks (virsh/nft/image) with sudo.',
    )
    vm = scfg.Value(
        '',
        help='Optional VM name override.',
    )
    detail = scfg.Value(
        False,
        isflag=True,
        help='Include raw diagnostics (virsh/nft/ssh probe outputs).',
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
        print(
            _render_status(
                cfg, path, detail=args.detail, use_sudo=bool(args.sudo)
            )
        )
        return 0


class AgentVMModalCLI(scfg.ModalCLI):
    """Local libvirt/KVM sandbox VM manager for coding agents."""

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


def main(argv: list[str] | None = None) -> None:
    verbosity = 1
    config_value = None
    if argv is None:
        argv = sys.argv[1:]
    argv = _normalize_argv(argv)
    if '--config' in argv:
        try:
            config_value = argv[argv.index('--config') + 1]
        except IndexError:
            pass
    elif '-c' in argv:
        try:
            config_value = argv[argv.index('-c') + 1]
        except IndexError:
            pass
    try:
        if config_value is not None:
            verbosity = _load_cfg(config_value).verbosity
        elif _cfg_path(None).exists():
            reg = load_store(_cfg_path(None))
            if reg.active_vm:
                rec = find_vm(reg, reg.active_vm)
                if rec is not None:
                    verbosity = rec.cfg.verbosity
    except Exception:
        verbosity = 1

    explicit_verbose = _count_verbose(argv)
    _setup_logging(explicit_verbose, verbosity)

    try:
        rc = AgentVMModalCLI.main(argv=argv, _noexit=True)
    except Exception as ex:
        print(f'ERROR: {ex}', file=sys.stderr)
        log.error('Unhandled aivm error: {}', ex)
        sys.exit(2)

    if any(flag in argv for flag in ('-h', '--help')):
        sys.exit(0)
    if isinstance(rc, int):
        sys.exit(rc)
    sys.exit(0)


def _status_line(ok: bool | None, label: str, detail: str = '') -> str:
    return status_line(ok, label, detail)


def _clip(text: str, *, max_lines: int = 60) -> str:
    return _clip_text(text, max_lines=max_lines)


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


def _setup_logging(args_verbose: int, cfg_verbosity: int) -> None:
    logger.remove()
    effective_verbosity = args_verbose if args_verbose > 0 else cfg_verbosity
    level = 'WARNING'
    if effective_verbosity == 1:
        level = 'INFO'
    elif effective_verbosity >= 2:
        level = 'DEBUG'
    colorize = sys.stderr.isatty() and os.getenv('NO_COLOR') is None
    logger.add(
        sys.stderr,
        level=level,
        colorize=colorize,
        format='<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>',
    )
    log.debug(
        'Logging configured at {} (effective_verbosity={}, colorize={})',
        level,
        effective_verbosity,
        colorize,
    )


def _normalize_argv(argv: list[str]) -> list[str]:
    """Normalize accepted hyphenated spellings to scriptconfig command names."""
    if len(argv) >= 1 and argv[0] == 'init':
        return ['config', 'init', *argv[1:]]
    if len(argv) >= 1 and argv[0] == 'attach':
        if len(argv) >= 2 and not argv[1].startswith('-'):
            return ['attach', '--host_src', argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == 'code':
        if len(argv) >= 2 and not argv[1].startswith('-'):
            return ['code', '--host_src', argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == 'ssh':
        if len(argv) >= 2 and not argv[1].startswith('-'):
            return ['ssh', '--host_src', argv[1], *argv[2:]]
        return argv
    if len(argv) >= 1 and argv[0] == 'ls':
        return ['list', *argv[1:]]
    if len(argv) >= 2 and argv[0] == 'vm':
        if argv[1] == 'wait-ip':
            return [argv[0], 'wait_ip', *argv[2:]]
        if argv[1] == 'ssh-config':
            return [argv[0], 'ssh_config', *argv[2:]]
        if argv[1] == 'ssh' and len(argv) >= 3 and not argv[2].startswith('-'):
            return [argv[0], 'ssh', '--host_src', argv[2], *argv[3:]]
        if argv[1] == 'sync-settings':
            return [argv[0], 'sync_settings', *argv[2:]]
        if argv[1] == 'code' and len(argv) >= 3 and not argv[2].startswith('-'):
            return [argv[0], 'code', '--host_src', argv[2], *argv[3:]]
    return argv


def _count_verbose(argv: list[str]) -> int:
    count = 0
    for item in argv:
        if item == '--verbose':
            count += 1
        elif item.startswith('-') and not item.startswith('--'):
            short = item[1:]
            if short and set(short) <= {'v'}:
                count += len(short)
    return count
