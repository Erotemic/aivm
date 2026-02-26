from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path

import scriptconfig as scfg

from ..config import AgentVMConfig
from ..firewall import apply_firewall
from ..net import ensure_network
from ..store import (
    find_vm,
    load_store,
    save_store,
    upsert_attachment,
    upsert_vm,
)
from ..runtime import require_ssh_identity, ssh_base_args, virsh_system_cmd
from ..status import (
    probe_firewall,
    probe_network,
    probe_provisioned,
    probe_ssh_ready,
    probe_vm_state,
)
from ..util import CmdError, ensure_dir, run_cmd, which
from ..vm import (
    attach_vm_share,
    create_or_start_vm,
    destroy_vm,
    ensure_share_mounted,
    get_ip_cached,
    provision,
    ssh_config as mk_ssh_config,
    sync_settings,
    vm_exists,
    vm_has_share,
    vm_share_mappings,
    vm_status,
    wait_for_ip,
    wait_for_ssh,
)
from ._common import (
    PreparedSession,
    _BaseCommand,
    _cfg_path,
    _confirm_external_file_update,
    _confirm_sudo_block,
    _load_cfg,
    _load_cfg_with_path,
    _record_vm,
    _resolve_cfg_for_code,
    log,
)


class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate = scfg.Value(
        False, isflag=True, help='Destroy and recreate if it exists.'
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose=f"Create/start/redefine VM '{cfg.vm.name}' and libvirt resources.",
        )
        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=args.recreate)
        if not args.dry_run:
            _record_vm(cfg, cfg_path)
        return 0


class VMWaitIPCLI(_BaseCommand):
    """Wait for and print the VM IPv4 address."""

    timeout = scfg.Value(360, type=int, help='Timeout seconds.')
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose='Query VM networking state via virsh to resolve VM IP.',
        )
        print(
            wait_for_ip(
                _load_cfg(args.config),
                timeout_s=args.timeout,
                dry_run=args.dry_run,
            )
        )
        return 0


class VMStatusCLI(_BaseCommand):
    """Show VM lifecycle status and cached IP information."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose='Inspect VM state via virsh.'
        )
        print(vm_status(_load_cfg(args.config)))
        return 0


class VMDestroyCLI(_BaseCommand):
    """Destroy and undefine the VM and associated storage."""

    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose='Destroy/undefine VM and attached storage.',
        )
        destroy_vm(_load_cfg(args.config), dry_run=args.dry_run)
        return 0


class VMSshConfigCLI(_BaseCommand):
    """Print an SSH config stanza for easy VM access."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(mk_ssh_config(_load_cfg(args.config)))
        return 0


class VMProvisionCLI(_BaseCommand):
    """Provision the VM with optional developer packages."""

    vm = scfg.Value(
        '',
        help='Optional VM name override.',
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        if args.config is not None or _cfg_path(None).exists():
            cfg = _load_cfg(args.config)
        else:
            cfg, _ = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt=args.vm,
                host_src=Path.cwd(),
            )
        if not args.dry_run:
            _resolve_ip_for_ssh_ops(
                cfg,
                yes=bool(args.yes),
                purpose='Query VM networking state before SSH provisioning.',
            )
        provision(cfg, dry_run=args.dry_run)
        return 0


class VMSyncSettingsCLI(_BaseCommand):
    """Copy host user settings/files into the VM user home."""

    paths = scfg.Value(
        '',
        help=(
            'Optional comma-separated host paths to sync. '
            'Defaults to [sync].paths from config.'
        ),
    )
    overwrite = scfg.Value(
        True,
        isflag=True,
        help='Overwrite existing files in VM (default true).',
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        if args.dry_run:
            ip = '0.0.0.0'
        else:
            ip = _resolve_ip_for_ssh_ops(
                cfg,
                yes=bool(args.yes),
                purpose='Query VM networking state before settings sync.',
            )
        chosen_paths = _parse_sync_paths_arg(args.paths) if args.paths else None
        result = sync_settings(
            cfg,
            ip,
            paths=chosen_paths,
            overwrite=bool(args.overwrite),
            dry_run=args.dry_run,
        )
        print('🧩 Settings sync summary')
        print(f'  copied: {len(result.copied)}')
        print(f'  skipped_missing: {len(result.skipped_missing)}')
        print(f'  skipped_exists: {len(result.skipped_exists)}')
        print(f'  failed: {len(result.failed)}')
        for k in ('copied', 'skipped_missing', 'skipped_exists', 'failed'):
            for item in getattr(result, k):
                print(f'  - {k}: {item}')
        if result.failed:
            return 2
        return 0


class VMCodeCLI(_BaseCommand):
    """Open a host project folder in VS Code attached to the VM via Remote-SSH."""

    host_src = scfg.Value(
        '.',
        help='Host project directory to share and open (default: current directory).',
    )
    vm = scfg.Value(
        '',
        help='VM name override.',
    )
    guest_dst = scfg.Value(
        '',
        help='Guest mount path override (default: config share.guest_dst).',
    )
    recreate_if_needed = scfg.Value(
        False,
        isflag=True,
        help='Recreate VM if existing definition lacks the requested share mapping.',
    )
    ensure_firewall = scfg.Value(
        True,
        isflag=True,
        help='Apply firewall rules when firewall.enabled=true.',
    )
    sync_settings = scfg.Value(
        False,
        isflag=True,
        help='Sync host settings files into VM before launching VS Code.',
    )
    sync_paths = scfg.Value(
        '',
        help=(
            'Optional comma-separated paths used when --sync_settings is set. '
            'Defaults to [sync].paths.'
        ),
    )
    force = scfg.Value(
        False,
        isflag=True,
        help='Force attaching folder even if already attached to a different VM.',
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        session = _prepare_attached_session(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=Path(args.host_src).resolve(),
            guest_dst_opt=args.guest_dst,
            recreate_if_needed=bool(args.recreate_if_needed),
            ensure_firewall_opt=bool(args.ensure_firewall),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )
        cfg = session.cfg
        if args.dry_run:
            print(
                f'DRYRUN: would open {cfg.share.guest_dst} in VS Code via host {cfg.vm.name}'
            )
            return 0
        ip = session.ip
        assert ip is not None

        do_sync = bool(args.sync_settings or cfg.sync.enabled)
        if do_sync:
            chosen_paths = (
                _parse_sync_paths_arg(args.sync_paths)
                if args.sync_paths
                else None
            )
            sync_result = sync_settings(
                cfg,
                ip,
                paths=chosen_paths,
                overwrite=cfg.sync.overwrite,
                dry_run=False,
            )
            if sync_result.failed:
                raise RuntimeError(
                    'Failed syncing one or more settings files:\n'
                    + '\n'.join(sync_result.failed)
                )

        ssh_cfg = _upsert_ssh_config_entry(
            cfg, dry_run=False, yes=bool(args.yes)
        )

        if which('code') is None:
            raise RuntimeError(
                'VS Code CLI `code` not found in PATH. Install VS Code and enable the shell command.'
            )
        remote_target = f'ssh-remote+{cfg.vm.name}'
        run_cmd(
            ['code', '--remote', remote_target, cfg.share.guest_dst],
            sudo=False,
            check=True,
            capture=False,
        )
        print(
            f'Opened VS Code remote folder {cfg.share.guest_dst} on host {cfg.vm.name}'
        )
        print(f'SSH entry updated in {ssh_cfg}')
        print(
            f'Folder registered in {session.reg_path}'
        )
        return 0


class VMSSHCLI(_BaseCommand):
    """SSH into the VM and start a shell in the mapped guest directory."""

    host_src = scfg.Value(
        '.',
        help='Host project directory to share and open (default: current directory).',
    )
    vm = scfg.Value(
        '',
        help='VM name override.',
    )
    guest_dst = scfg.Value(
        '',
        help='Guest mount path override (default: mirrors host_src path).',
    )
    recreate_if_needed = scfg.Value(
        False,
        isflag=True,
        help='Recreate VM if existing definition lacks the requested share mapping.',
    )
    ensure_firewall = scfg.Value(
        True,
        isflag=True,
        help='Apply firewall rules when firewall.enabled=true.',
    )
    force = scfg.Value(
        False,
        isflag=True,
        help='Force attaching folder even if already attached to a different VM.',
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        session = _prepare_attached_session(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=Path(args.host_src).resolve(),
            guest_dst_opt=args.guest_dst,
            recreate_if_needed=bool(args.recreate_if_needed),
            ensure_firewall_opt=bool(args.ensure_firewall),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )
        cfg = session.cfg
        if args.dry_run:
            print(
                f'DRYRUN: would SSH to {cfg.vm.user}@<ip> and cd {cfg.share.guest_dst}'
            )
            return 0

        ip = session.ip
        assert ip is not None
        ident = require_ssh_identity(cfg.paths.ssh_identity_file)
        remote_cmd = f'cd {shlex.quote(cfg.share.guest_dst)} && exec $SHELL -l'
        run_cmd(
            [
                'ssh',
                '-t',
                *ssh_base_args(ident, strict_host_key_checking='accept-new'),
                f'{cfg.vm.user}@{ip}',
                remote_cmd,
            ],
            sudo=False,
            check=True,
            capture=False,
        )
        print(f'Connected to {cfg.vm.user}@{ip} in {cfg.share.guest_dst}')
        print(
            f'Folder registered in {session.reg_path}'
        )
        return 0


class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm = scfg.Value('', help='Optional VM name override.')
    host_src = scfg.Value('.', help='Host directory to attach.')
    guest_dst = scfg.Value('', help='Guest mount path override.')
    force = scfg.Value(
        False,
        isflag=True,
        help='Allow attaching folder that is already attached to a different VM.',
    )
    dry_run = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        host_src = Path(args.host_src).resolve()
        if not host_src.exists() or not host_src.is_dir():
            raise RuntimeError(
                f'host_src must be an existing directory: {host_src}'
            )

        if args.config:
            cfg, cfg_path = _load_cfg_with_path(args.config, vm_opt=args.vm)
        elif args.vm:
            cfg, cfg_path = _load_cfg_with_path(None, vm_opt=args.vm)
        else:
            cfg, cfg_path = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt='',
                host_src=host_src,
            )

        cfg.share.enabled = True
        cfg.share.host_src = str(host_src)
        cfg.share.guest_dst = _resolve_guest_dst(host_src, args.guest_dst)
        _ensure_share_tag_len(cfg, host_src, set())

        if args.dry_run:
            print(
                f'DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {cfg.share.guest_dst}'
            )
            return 0

        _record_vm(cfg, cfg_path)
        if vm_exists(cfg):
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose=f"Inspect VM '{cfg.vm.name}' share mappings and attach folder if needed.",
            )
            mappings = vm_share_mappings(cfg)
            requested_src = str(Path(cfg.share.host_src).resolve())
            existing_tags = {tag for _, tag in mappings if tag}
            _ensure_share_tag_len(cfg, host_src, existing_tags)
            for src, tag in mappings:
                if src == requested_src and tag:
                    cfg.share.tag = tag
                    break
            if not vm_has_share(cfg):
                for src, tag in mappings:
                    if tag == cfg.share.tag and src != requested_src:
                        cfg.share.tag = _auto_share_tag_for_path(
                            host_src, existing_tags
                        )
                        break
                if not vm_has_share(cfg):
                    attach_vm_share(cfg, dry_run=False)
                    _record_vm(cfg, cfg_path)
        reg_path = _record_attachment(
            cfg,
            cfg_path,
            host_src=host_src,
            force=bool(args.force),
        )
        print(f'Attached {host_src} to VM {cfg.vm.name} (shared mode)')
        print(f'Updated config store: {cfg_path}')
        print(f'Updated attachments: {reg_path}')
        return 0


class VMListCLI(_BaseCommand):
    """List managed VM records (VM-focused view)."""

    section = scfg.Value(
        'vms',
        help='One of: all, vms, networks, folders (default: vms).',
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        from .main import ListCLI

        return ListCLI.main(
            argv=False, section=args.section, config=args.config
        )


class CodeCLI(VMCodeCLI):
    """Top-level shortcut for `aivm vm code`."""


class AttachCLI(VMAttachCLI):
    """Top-level shortcut for `aivm vm attach`."""


class SSHCLI(VMSSHCLI):
    """Top-level shortcut for `aivm vm ssh`."""


class VMModalCLI(scfg.ModalCLI):
    """VM lifecycle subcommands."""

    list = VMListCLI
    up = VMUpCLI
    wait_ip = VMWaitIPCLI
    status = VMStatusCLI
    destroy = VMDestroyCLI
    ssh_config = VMSshConfigCLI
    provision = VMProvisionCLI
    ssh = VMSSHCLI
    sync_settings = VMSyncSettingsCLI
    attach = VMAttachCLI
    code = VMCodeCLI


def _resolve_guest_dst(host_src: Path, guest_dst_opt: str) -> str:
    guest_dst_opt = (guest_dst_opt or '').strip()
    if guest_dst_opt:
        return guest_dst_opt
    return str(host_src)


def _auto_share_tag_for_path(host_src: Path, existing_tags: set[str]) -> str:
    max_len = 36
    raw = re.sub(r'[^A-Za-z0-9_.-]+', '-', host_src.name or 'hostcode').strip(
        '-'
    )
    base = f'hostcode-{raw}' if raw else 'hostcode'
    base = base[:max_len]
    if base not in existing_tags:
        return base
    suffix = hashlib.sha1(str(host_src).encode('utf-8')).hexdigest()[:8]
    tag = f'{base[: max_len - 1 - len(suffix)]}-{suffix}'
    if tag not in existing_tags:
        return tag
    idx = 2
    while True:
        tail = f'-{suffix[:5]}-{idx}'
        cand = f'{base[: max_len - len(tail)]}{tail}'
        if cand not in existing_tags:
            return cand
        idx += 1


def _ensure_share_tag_len(
    cfg: AgentVMConfig, host_src: Path, existing_tags: set[str]
) -> None:
    tag = (cfg.share.tag or '').strip()
    if tag and len(tag) <= 36:
        return
    cfg.share.tag = _auto_share_tag_for_path(host_src, existing_tags)


def _probe_vm_running_nonsudo(vm_name: str) -> bool | None:
    res = run_cmd(
        virsh_system_cmd('domstate', vm_name),
        sudo=False,
        check=False,
        capture=True,
    )
    if res.code != 0:
        return None
    state = (res.stdout or '').strip().lower()
    return 'running' in state


def _upsert_ssh_config_entry(
    cfg: AgentVMConfig, *, dry_run: bool = False, yes: bool = False
) -> Path:
    cfg = cfg.expanded_paths()
    ssh_dir = Path.home() / '.ssh'
    ssh_cfg = ssh_dir / 'config'
    block_name = cfg.vm.name
    new_block = (
        f'# >>> aivm:{block_name} >>>\n'
        f'{mk_ssh_config(cfg).rstrip()}\n'
        f'# <<< aivm:{block_name} <<<\n'
    )
    if dry_run:
        log.info(
            'DRYRUN: update SSH config block for host {} in {}',
            block_name,
            ssh_cfg,
        )
        return ssh_cfg
    _confirm_external_file_update(
        yes=bool(yes),
        path=ssh_cfg,
        purpose=f"Update SSH config entry for host '{block_name}'.",
    )
    ensure_dir(ssh_dir)
    existing = ssh_cfg.read_text(encoding='utf-8') if ssh_cfg.exists() else ''
    pattern = re.compile(
        rf'(?ms)^# >>> aivm:{re.escape(block_name)} >>>\n.*?^# <<< aivm:{re.escape(block_name)} <<<\n?'
    )
    if pattern.search(existing):
        updated = pattern.sub(new_block, existing)
    else:
        sep = '' if not existing or existing.endswith('\n') else '\n'
        updated = f'{existing}{sep}{new_block}'
    ssh_cfg.write_text(updated, encoding='utf-8')
    return ssh_cfg


def _parse_sync_paths_arg(paths_arg: str) -> list[str]:
    items = [p.strip() for p in (paths_arg or '').split(',')]
    return [p for p in items if p]


def _missing_virtiofs_dir_from_error(ex: Exception) -> str | None:
    text = str(ex)
    if isinstance(ex, CmdError):
        text = f'{ex.result.stderr}\n{ex.result.stdout}\n{text}'
    m = re.search(r"virtiofs export directory '([^']+)' does not exist", text)
    return m.group(1) if m else None


def _check_network(
    cfg: AgentVMConfig, *, use_sudo: bool
) -> tuple[bool | None, str]:
    out = probe_network(cfg, use_sudo=use_sudo)
    return out.ok, out.detail


def _check_firewall(
    cfg: AgentVMConfig, *, use_sudo: bool
) -> tuple[bool | None, str]:
    out = probe_firewall(cfg, use_sudo=use_sudo)
    return out.ok, out.detail


def _file_exists(path: Path, *, use_sudo: bool) -> bool:
    return (
        run_cmd(
            ['test', '-f', str(path)], sudo=use_sudo, check=False, capture=True
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


def _check_provisioned(
    cfg: AgentVMConfig, ip: str
) -> tuple[bool | None, str, str]:
    out = probe_provisioned(cfg, ip)
    return out.ok, out.detail, out.diag


def _resolve_ip_for_ssh_ops(
    cfg: AgentVMConfig, *, yes: bool, purpose: str
) -> str:
    ip = get_ip_cached(cfg)
    if ip:
        ssh_ok, _, _ = _check_ssh_ready(cfg, ip)
        if ssh_ok:
            return ip
    _confirm_sudo_block(yes=bool(yes), purpose=purpose)
    ip = wait_for_ip(cfg, timeout_s=360, dry_run=False)
    wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
    return ip


def _select_cfg_for_vm_name(
    vm_name: str, *, reason: str
) -> tuple[AgentVMConfig, Path]:
    del reason
    return _load_cfg_with_path(None, vm_opt=vm_name)


def _record_attachment(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    host_src: Path,
    force: bool = False,
) -> Path:
    reg = load_store(cfg_path)
    upsert_vm(reg, cfg)
    upsert_attachment(
        reg,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode='shared',
        guest_dst=cfg.share.guest_dst,
        tag=cfg.share.tag,
        force=force,
    )
    return save_store(reg, cfg_path)


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
        raise FileNotFoundError(f'Host source path does not exist: {host_src}')
    if not host_src.is_dir():
        raise RuntimeError(f'Host source path is not a directory: {host_src}')

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
        return any(
            src == requested_src and tag == cfg.share.tag
            for src, tag in mappings
        )

    cached_ip = get_ip_cached(cfg) if not dry_run else None
    cached_ssh_ok = False
    if cached_ip:
        cached_ssh_ok, _, _ = _check_ssh_ready(cfg, cached_ip)
    vm_running_probe = (
        _probe_vm_running_nonsudo(cfg.vm.name) if not dry_run else None
    )

    net_probe, _ = _check_network(cfg, use_sudo=False)
    need_network_ensure = (net_probe is False) and (not cached_ssh_ok)
    if need_network_ensure:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose=f"Ensure libvirt network '{cfg.network.name}'.",
        )
        ensure_network(cfg, recreate=False, dry_run=dry_run)

    need_firewall_apply = False
    if cfg.firewall.enabled and ensure_firewall_opt and (not cached_ssh_ok):
        fw_probe, _ = _check_firewall(cfg, use_sudo=False)
        if fw_probe is None:
            _confirm_sudo_block(
                yes=bool(yes),
                purpose=f"Inspect firewall table '{cfg.firewall.table}'.",
            )
            fw_probe, _ = _check_firewall(cfg, use_sudo=True)
        need_firewall_apply = fw_probe is not True
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
                    cfg.share.tag = _auto_share_tag_for_path(
                        host_src, existing_tags
                    )
                    break
            has_share = _has_share_in_mappings(mappings)

    need_vm_start_or_create = dry_run or (vm_running is not True)
    if need_vm_start_or_create:
        _confirm_sudo_block(
            yes=bool(yes),
            purpose=f"Create/start VM '{cfg.vm.name}' or update VM definition.",
        )
        try:
            create_or_start_vm(cfg, dry_run=dry_run, recreate=False)
        except Exception as ex:
            missing_virtiofs_dir = _missing_virtiofs_dir_from_error(ex)
            if not dry_run and missing_virtiofs_dir is not None:
                log.warning(
                    'VM {} has stale virtiofs source {}; recreating VM definition',
                    cfg.vm.name,
                    missing_virtiofs_dir,
                )
                _confirm_sudo_block(
                    yes=bool(yes),
                    purpose=f"Recreate VM '{cfg.vm.name}' to repair stale virtiofs mapping.",
                )
                create_or_start_vm(cfg, dry_run=False, recreate=True)
            else:
                raise
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
                current_maps = mappings or vm_share_mappings(
                    cfg, use_sudo=False
                )
                requested_tag = cfg.share.tag
                if current_maps:
                    found = '\n'.join(
                        f'  - source={src or "(none)"} tag={tag or "(none)"}'
                        for src, tag in current_maps
                    )
                else:
                    found = '  - (no filesystem mappings found)'
                raise RuntimeError(
                    'Existing VM does not include requested share mapping, and live attach failed.\n'
                    f'VM: {cfg.vm.name}\n'
                    f'Requested: source={requested_src} tag={requested_tag} guest_dst={cfg.share.guest_dst}\n'
                    'Current VM filesystem mappings:\n'
                    f'{found}\n'
                    f'Live attach error: {ex}\n'
                    'Next steps:\n'
                    '  - Re-run with --recreate_if_needed to rebuild the VM definition with the new share.\n'
                    '  - Or use a VM already defined with this share mapping.'
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

    reg_path = _record_attachment(
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
            purpose='Query VM network state via virsh to discover VM IP.',
        )
        ip = wait_for_ip(cfg, timeout_s=360, dry_run=False)
        wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
    if not ip:
        raise RuntimeError('Could not resolve VM IP address.')
    ensure_share_mounted(cfg, ip, dry_run=False)
    return PreparedSession(
        cfg=cfg,
        cfg_path=cfg_path,
        host_src=host_src,
        ip=ip,
        reg_path=reg_path,
        meta_path=None,
    )
