"""Focused VM CLI command implementations.

This module is split out of :mod:`aivm.cli.vm`.  Private helper
dependencies are resolved through the legacy facade so existing tests
that monkeypatch ``aivm.cli.vm.<helper>`` continue to exercise the
same code paths during this compatibility phase.
"""

from __future__ import annotations

import os
import shlex
import socket
from pathlib import Path
from typing import Any

import scriptconfig as scfg

from ..attachments.resolve import (
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT,
)
from ..commands import CommandManager
from ..vm.share import ResolvedAttachment
from ..vm.update_ops import RestartKind
from ._common import _BaseCommand
from ._vm_compat import legacy as _legacy


_ensure_attachment_available_in_guest = _legacy('_ensure_attachment_available_in_guest')
_upsert_ssh_config_entry = _legacy('_upsert_ssh_config_entry')
_install_persistent_host_bind_replay = _legacy('_install_persistent_host_bind_replay')
_prepare_persistent_attachment_host_and_vm = _legacy('_prepare_persistent_attachment_host_and_vm')
_reconcile_persistent_attachments_in_guest = _legacy('_reconcile_persistent_attachments_in_guest')
_reconcile_persistent_host_binds = _legacy('_reconcile_persistent_host_binds')
_sync_persistent_attachment_manifest_on_host = _legacy('_sync_persistent_attachment_manifest_on_host')
_normalize_attachment_access = _legacy('_normalize_attachment_access')
_normalize_attachment_mode = _legacy('_normalize_attachment_mode')
_resolve_attachment = _legacy('_resolve_attachment')
_maybe_warn_hardware_drift = _legacy('_maybe_warn_hardware_drift')
_prepare_attached_session = _legacy('_prepare_attached_session')
_record_attachment = _legacy('_record_attachment')
_resolve_ip_for_ssh_ops = _legacy('_resolve_ip_for_ssh_ops')
_detach_shared_root_guest_bind = _legacy('_detach_shared_root_guest_bind')
_detach_shared_root_host_bind = _legacy('_detach_shared_root_host_bind')
_ensure_shared_root_host_bind = _legacy('_ensure_shared_root_host_bind')
_ensure_shared_root_vm_mapping = _legacy('_ensure_shared_root_vm_mapping')
_cfg_path = _legacy('_cfg_path')
_load_cfg = _legacy('_load_cfg')
_load_cfg_with_path = _legacy('_load_cfg_with_path')
_maybe_install_missing_host_deps = _legacy('_maybe_install_missing_host_deps')
_maybe_offer_create_ssh_identity = _legacy('_maybe_offer_create_ssh_identity')
_record_vm = _legacy('_record_vm')
_resolve_cfg_for_code = _legacy('_resolve_cfg_for_code')
_edit_path = _legacy('_edit_path')
_resolve_config_edit_target = _legacy('_resolve_config_edit_target')
attach_vm_share = _legacy('attach_vm_share')
create_or_start_vm = _legacy('create_or_start_vm')
destroy_vm = _legacy('destroy_vm')
detach_vm_share = _legacy('detach_vm_share')
find_attachment_for_vm = _legacy('find_attachment_for_vm')
find_network = _legacy('find_network')
load_config_document = _legacy('load_config_document')
load_store = _legacy('load_store')
log = _legacy('log')
mk_ssh_config = _legacy('mk_ssh_config')
network_users = _legacy('network_users')
probe_vm_state = _legacy('probe_vm_state')
provision = _legacy('provision')
refresh_cloud_init_seed_for_next_boot = _legacy('refresh_cloud_init_seed_for_next_boot')
remove_attachment = _legacy('remove_attachment')
remove_vm = _legacy('remove_vm')
require_ssh_identity = _legacy('require_ssh_identity')
restart_vm = _legacy('restart_vm')
save_store = _legacy('save_store')
shutdown_vm = _legacy('shutdown_vm')
ssh_base_args = _legacy('ssh_base_args')
vm_share_mappings = _legacy('vm_share_mappings')
vm_status = _legacy('vm_status')
wait_for_ip = _legacy('wait_for_ip')
which = _legacy('which')
create_vm_from_defaults = _legacy('create_vm_from_defaults')
drift_attachment_has_mapping = _legacy('drift_attachment_has_mapping')
drift_align_attachment_tag_with_mappings = _legacy('drift_align_attachment_tag_with_mappings')
_apply_vm_update = _legacy('_apply_vm_update')
_maybe_restart_vm_after_update = _legacy('_maybe_restart_vm_after_update')
_print_vm_update_plan = _legacy('_print_vm_update_plan')
_vm_update_drift = _legacy('_vm_update_drift')


class VMWaitIPCLI(_BaseCommand):
    """Wait for and print the VM IPv4 address."""

    timeout: Any = scfg.Value(360, type=int, help='Timeout seconds.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Wait for IP for {cfg.vm.name}',
            why='Inspect the VM networking state until an IPv4 address is available.',
            role='read',
        ):
            print(
                wait_for_ip(
                    cfg,
                    timeout_s=args.timeout,
                    dry_run=args.dry_run,
                )
            )
        return 0


class VMSshConfigCLI(_BaseCommand):
    """Print an SSH config stanza for easy VM access."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        print(mk_ssh_config(_load_cfg(args.config)))
        return 0


def _vscode_can_open_locally() -> tuple[bool, str | None]:
    """Decide whether launching VS Code locally with ``code --remote`` makes sense.

    Returns ``(True, None)`` when we should run the local ``code`` binary.
    Returns ``(False, reason)`` when the launch would either fail or open a
    window on the wrong machine — in that case the CLI prints a connection
    recipe instead so the user can connect from their actual workstation.

    Rule:
      * ``SSH_CONNECTION`` set means this process is running on a remote
        machine. Even when ``VSCODE_IPC_HOOK_CLI`` is also set, the target VM
        is usually behind libvirt NAT on that remote host, so a local
        ``ssh-remote+<vm>`` connection from the user's workstation probably
        cannot reach the VM IP or the remote host's SSH config entry. Skip the
        direct launch and print tunnel / ProxyJump guidance instead.
      * Otherwise, missing ``code`` on PATH: nothing to launch. Skip.
      * Otherwise: assume local desktop; launch.
    """
    if os.environ.get('SSH_CONNECTION'):
        return False, 'running in an SSH session (SSH_CONNECTION set)'
    if which('code') is None:
        return False, 'VS Code CLI `code` not found on PATH'
    return True, None


def _remote_tunnel_name(cfg: Any) -> str:
    """Return a stable VS Code tunnel name for a VM on this hypervisor."""
    host_name = socket.gethostname().split('.')[0] or 'host'
    # VS Code accepts names like ``aivm-2404-namek``. Keep the generated name
    # conservative so it is easy to scan in the Remote Explorer UI.
    safe_host = ''.join(ch if ch.isalnum() or ch == '-' else '-' for ch in host_name)
    return f'{cfg.vm.name}-{safe_host}'


def _print_remote_session_recipe(
    cfg: Any,
    session: Any,
    ssh_cfg: Any,
    ssh_cfg_updated: bool,
    reason: str,
) -> None:
    """Print a connect-from-workstation recipe in lieu of launching code."""
    vm_name = cfg.vm.name
    guest_path = session.share_guest_dst
    tunnel_name = _legacy('_remote_tunnel_name')(cfg)
    tunnel_cmd = (
        f'cd {shlex.quote(guest_path)} && '
        f'code tunnel --name {shlex.quote(tunnel_name)} '
        '--accept-server-license-terms'
    )
    print()
    print(f'Skipping VS Code launch: {reason}.')
    print('The VM is up and the share is attached, but this shell appears to')
    print("be on a remote hypervisor. The VM IP is usually on that host's")
    print('private libvirt/NAT network, so a direct Remote-SSH connection from')
    print('your workstation may not be able to reach it.')
    print()
    print('Recommended: use a VS Code tunnel hosted from inside the VM.')
    print()
    print('  # Run this on the remote host to start the tunnel inside the VM:')
    print(f'  ssh {shlex.quote(vm_name)} {shlex.quote(tunnel_cmd)}')
    print()
    print('  # Then, on your local VS Code Desktop:')
    print('  #   1. Install/enable the Remote - Tunnels extension:')
    print('  #        code --install-extension ms-vscode.remote-server')
    print('  #   2. Sign in with the same GitHub/Microsoft account used by the tunnel.')
    print('  #   3. Open: Remote Explorer: Focus on Remotes (Tunnels/SSH) View')
    print(f'  #   4. Under Tunnels, connect to: {tunnel_name}')
    print()
    print('Alternative: Remote-SSH can work only if your workstation can reach')
    print('the VM, for example with a local SSH config entry that uses ProxyJump')
    print('through this remote host. The plain VM IP below is normally reachable')
    print('from the remote host, not directly from your workstation.')
    print()
    print('  # Plain SSH shell on the guest from this remote host:')
    print(f'  ssh {vm_name}')
    print()
    print(f'  VM:      {vm_name}')
    print(f'  Host:    {session.ip}')
    print(f'  User:    {cfg.vm.user}')
    print(f'  Path:    {guest_path}')
    print(f'  Tunnel:  {tunnel_name}')
    if ssh_cfg_updated:
        print(f'SSH entry updated on this host in {ssh_cfg}')
    print(f'Folder registered in {session.reg_path}')


class VMCodeCLI(_BaseCommand):
    """Open a host project folder in VS Code attached to the VM via Remote-SSH."""

    host_src: Any = scfg.Value(
        '.',
        position=1,
        help='Host project directory to share and open (default: current directory).',
    )
    vm: Any = scfg.Value(
        '',
        help='VM name override.',
    )
    guest_dst: Any = scfg.Value(
        '',
        help='Guest mount path override (default: mirrors host_src path).',
    )
    mode: Any = scfg.Value(
        '',
        help='Attachment mode override: shared, shared-root, persistent, or git (default: saved mode or shared-root; mode changes require detach+reattach).',
    )
    access: Any = scfg.Value(
        '',
        help='Attachment access override: rw or ro (default: saved access or rw). ro is supported for shared, shared-root, and persistent modes.',
    )
    recreate_if_needed: Any = scfg.Value(
        False,
        isflag=True,
        help='Recreate VM if existing definition lacks the requested share mapping.',
    )
    ensure_firewall: Any = scfg.Value(
        True,
        isflag=True,
        help='Apply firewall rules when firewall.enabled=true.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMCodeCLI.main host_src={} vm={} guest_dst={} dry_run={} yes={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            bool(args.dry_run),
            bool(args.yes),
        )
        try:
            session = _prepare_attached_session(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src).expanduser().absolute(),
                guest_dst_opt=args.guest_dst,
                attach_mode_opt=args.mode,
                attach_access_opt=args.access,
                recreate_if_needed=bool(args.recreate_if_needed),
                ensure_firewall_opt=bool(args.ensure_firewall),
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        except RuntimeError as ex:
            log.opt(exception=True).trace('Failed preparing code session')
            log.error(str(ex))
            return 1
        cfg = session.cfg
        if args.dry_run:
            print(
                f'DRYRUN: would open {session.share_guest_dst} in VS Code via host {cfg.vm.name}'
            )
            return 0
        ip = session.ip
        assert ip is not None

        ssh_cfg, ssh_cfg_updated = _upsert_ssh_config_entry(
            cfg, dry_run=False, yes=bool(args.yes)
        )

        can_open_local, reason = _legacy('_vscode_can_open_locally')()
        if not can_open_local:
            _legacy('_print_remote_session_recipe')(
                cfg, session, ssh_cfg, ssh_cfg_updated, reason or ''
            )
            return 0

        remote_target = f'ssh-remote+{cfg.vm.name}'
        CommandManager.current().run(
            ['code', '--remote', remote_target, session.share_guest_dst],
            sudo=False,
            check=True,
            capture=False,
        )
        print(
            f'Opened VS Code remote folder {session.share_guest_dst} on host {cfg.vm.name}'
        )
        if ssh_cfg_updated:
            print(f'SSH entry updated in {ssh_cfg}')
        print(f'Folder registered in {session.reg_path}')
        return 0


class VMSSHCLI(_BaseCommand):
    """SSH into the VM and start a shell in the mapped guest directory."""

    host_src: Any = scfg.Value(
        '.',
        position=1,
        help='Host project directory to share and open (default: current directory).',
    )
    vm: Any = scfg.Value(
        '',
        help='VM name override.',
    )
    guest_dst: Any = scfg.Value(
        '',
        help='Guest mount path override (default: mirrors host_src path).',
    )
    mode: Any = scfg.Value(
        '',
        help='Attachment mode override: shared, shared-root, persistent, or git (default: saved mode or shared-root; mode changes require detach+reattach).',
    )
    access: Any = scfg.Value(
        '',
        help='Attachment access override: rw or ro (default: saved access or rw). ro is supported for shared, shared-root, and persistent modes.',
    )
    recreate_if_needed: Any = scfg.Value(
        False,
        isflag=True,
        help='Recreate VM if existing definition lacks the requested share mapping.',
    )
    ensure_firewall: Any = scfg.Value(
        True,
        isflag=True,
        help='Apply firewall rules when firewall.enabled=true.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMSSHCLI.main host_src={} vm={} guest_dst={} dry_run={} yes={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            bool(args.dry_run),
            bool(args.yes),
        )
        try:
            session = _prepare_attached_session(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src).expanduser().absolute(),
                guest_dst_opt=args.guest_dst,
                attach_mode_opt=args.mode,
                attach_access_opt=args.access,
                recreate_if_needed=bool(args.recreate_if_needed),
                ensure_firewall_opt=bool(args.ensure_firewall),
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        except RuntimeError as ex:
            log.error(str(ex))
            return 1
        cfg = session.cfg
        if args.dry_run:
            print(
                f'DRYRUN: would SSH to {cfg.vm.user}@<ip> and cd {session.share_guest_dst}'
            )
            return 0

        ip = session.ip
        assert ip is not None
        ssh_cfg, ssh_cfg_updated = _upsert_ssh_config_entry(
            cfg, dry_run=False, yes=bool(args.yes)
        )
        ident = require_ssh_identity(cfg.paths.ssh_identity_file)
        remote_cmd = (
            f'cd {shlex.quote(session.share_guest_dst)} && exec $SHELL -l'
        )
        ssh_result = CommandManager.current().run(
            [
                'ssh',
                '-t',
                *ssh_base_args(ident, strict_host_key_checking='accept-new'),
                f'{cfg.vm.user}@{ip}',
                remote_cmd,
            ],
            sudo=False,
            check=False,
            capture=False,
        )
        if ssh_result.code != 0:
            log.error(
                'SSH command failed (exit code {}) for {}@{}',
                ssh_result.code,
                cfg.vm.user,
                ip,
            )
            return int(ssh_result.code) if ssh_result.code else 1
        print(f'SSH session ended for {cfg.vm.user}@{ip}')
        if ssh_cfg_updated:
            print(f'SSH entry updated in {ssh_cfg}')
        print(f'Folder registered in {session.reg_path}')
        return 0
