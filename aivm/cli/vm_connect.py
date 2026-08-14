"""VM SSH/code connection CLI command implementations."""

from __future__ import annotations

import json
import os
import shlex
import socket
import sys
from functools import partial
from pathlib import Path
from typing import Any, Literal

import kwconf
from loguru import logger as log

from ..attachments.guest import _upsert_ssh_config_entry
from ..attachments.persistent.transport import _install_guest_text_if_changed
from ..attachments.resolve import logical_absolute_path
from ..attachments.session import _prepare_attached_session
from ..commands import CommandManager, shell_join
from ..config import default_host_label
from ..config_scopes import ResolvedVMContext
from ..config_store import load_store
from ..errors import AIVMError
from ..runtime import require_ssh_identity, ssh_base_args
from ..services import PreparedSession, cfg_path, load_cfg
from ..tunnel_helper import (
    DEFAULT_TMUX_SESSION,
    TUNNEL_HELPER_PATH,
    tunnel_helper_source,
)
from ..util import which
from ..vm import create_ops, ssh_config as mk_ssh_config, wait_for_ip
from ..vm.provision import provision_guest_requirements
from ._common import _BaseCommand


def _bootstrap_vm_for_folder(
    ex: RuntimeError,
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
    guest_dst_opt: str,
    attach_mode_opt: str,
    attach_access_opt: str,
    yes: bool,
    dry_run: bool,
) -> None:
    """Consent flow for ``aivm code``/``ssh`` hitting a store with no VMs.

    Offers (or, with ``--yes``, performs) ``config init`` + ``vm create`` so
    the folder-oriented entry points can bootstrap a first VM. Passed into
    :func:`_prepare_attached_session` as its ``bootstrap_missing_vm`` hook;
    ``ex`` is the resolution error that triggered the bootstrap.
    """
    msg = str(ex)
    prefix = 'No VM definitions found in config store: '
    missing_store_path = cfg_path(config_opt)
    if msg.startswith(prefix):
        tail = msg[len(prefix) :]
        # Avoid brittle regex parsing: split at our known guidance suffix.
        store_str = tail.split('. Run `aivm config init`', 1)[0].strip()
        if store_str:
            missing_store_path = Path(store_str).expanduser().resolve()
    missing_store = load_store(missing_store_path)
    need_init = missing_store.defaults is None
    if not yes:
        if not sys.stdin.isatty():
            raise AIVMError(
                'No managed VM found for this folder. Re-run with --yes to create one automatically.'
            ) from ex
        print('No managed VM found for this folder.')
        if need_init:
            prompt = 'Run `aivm config init` and `aivm vm create` now? [Y/n]: '
        else:
            prompt = 'Run `aivm vm create` now using existing config defaults? [Y/n]: '
        ans = input(prompt).strip().lower()
        if ans not in {'', 'y', 'yes'}:
            raise AIVMError('Aborted by user.') from ex
    if need_init:
        from .config.init import initialize_config_defaults

        init_rc = initialize_config_defaults(
            config_opt=str(missing_store_path),
            yes=yes,
            defaults=yes,
            force=False,
            standalone_guidance=False,
        )
        if init_rc != 0:
            raise AIVMError(
                'Could not initialize config defaults for VM creation.'
            ) from ex
    create_ops.create_vm_from_defaults(
        missing_store_path,
        vm_override=vm_opt if vm_opt else None,
        set_default=False,
        force=False,
        dry_run=dry_run,
        yes=yes,
        configuration_reviewed=need_init and not yes,
        initial_attachment_host_src=host_src,
        initial_attachment_guest_dst=guest_dst_opt,
        initial_attachment_mode=attach_mode_opt,
        initial_attachment_access=attach_access_opt,
    )


class VMWaitIPCLI(_BaseCommand):
    """Wait for and print the VM IPv4 address."""

    timeout: int = kwconf.Value(360, parser=int, help='Timeout seconds.')
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg = load_cfg(args.config)
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
        print(mk_ssh_config(load_cfg(args.config)))
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
    safe_host = default_host_label(socket.gethostname())
    vm_name = str(cfg.vm.name or '').strip() or 'aivm'
    # New default VM names already include the host label, which also keeps the
    # guest hostname and SSH alias canonical. Preserve that name instead of
    # doubling the host suffix in VS Code Remote Tunnels.
    if vm_name.endswith(f'-{safe_host}'):
        return vm_name
    return f'{vm_name}-{safe_host}'


_TUNNEL_TMUX_SESSION = DEFAULT_TMUX_SESSION


def _ensure_guest_tunnel_helper(
    context: ResolvedVMContext,
    ip: str,
) -> None:
    """Install the inspectable guest tunnel helper when its content changed."""
    _install_guest_text_if_changed(
        context.effective_cfg,
        ip,
        target=TUNNEL_HELPER_PATH,
        text=tunnel_helper_source(),
        mode='0755',
        label='VS Code tunnel helper',
        dry_run=False,
    )


def _remote_tunnel_missing_commands(
    context: ResolvedVMContext,
    ip: str,
) -> tuple[str, ...]:
    """Return missing guest commands required by ``code --tunnel``."""
    ident = require_ssh_identity(context.profile.ssh_identity_file)
    remote = f'{shlex.quote(TUNNEL_HELPER_PATH)} check'
    result = CommandManager.current().run(
        [
            'ssh',
            *ssh_base_args(ident),
            context.ssh_target(ip),
            remote,
        ],
        sudo=False,
        role='read',
        user_driven=True,
        check=True,
        capture=True,
        summary='Check VS Code tunnel prerequisites',
        detail=f'guest_helper={TUNNEL_HELPER_PATH}',
    )
    try:
        payload = json.loads(result.stdout.strip())
        missing_raw = payload['missing']
        if not isinstance(missing_raw, list):
            raise TypeError('missing is not a list')
        missing = tuple(str(name) for name in missing_raw)
    except (json.JSONDecodeError, KeyError, TypeError) as ex:
        raise AIVMError(
            'Guest VS Code tunnel helper returned an invalid prerequisite report.'
        ) from ex
    unexpected = sorted(set(missing) - {'tmux', 'code'})
    if unexpected:
        raise AIVMError(
            'Guest VS Code tunnel helper reported unknown prerequisite(s): '
            + ', '.join(unexpected)
        )
    return missing


def _ensure_remote_tunnel_prerequisites(
    context: ResolvedVMContext,
    ip: str,
) -> None:
    """One-shot provision only what the requested tunnel workflow is missing."""
    missing = _remote_tunnel_missing_commands(context, ip)
    if not missing:
        return

    cfg = context.effective_cfg
    if not cfg.provision.enabled:
        raise AIVMError(
            'VS Code tunnel prerequisites are missing in the guest ('
            + ', '.join(missing)
            + '), but guest provisioning is disabled. Install them manually '
            'or enable [provision].enabled.'
        )

    log.info(
        'VS Code tunnel prerequisites missing in guest: {}. Installing them '
        'for this tunnel request.',
        ', '.join(missing),
    )
    provision_guest_requirements(
        cfg,
        ip,
        packages=('tmux',) if 'tmux' in missing else (),
        tools=('code',) if 'code' in missing else (),
        dry_run=False,
    )
    remaining = _remote_tunnel_missing_commands(context, ip)
    if remaining:
        raise AIVMError(
            'VS Code tunnel prerequisites are still missing after install: '
            + ', '.join(remaining)
        )


def _start_remote_tunnel_session(
    context: ResolvedVMContext,
    ip: str,
    guest_path: str,
    tunnel_name: str,
) -> None:
    """Idempotently ensure prerequisites and start the guest tunnel session."""
    _ensure_guest_tunnel_helper(context, ip)
    _ensure_remote_tunnel_prerequisites(context, ip)
    ident = require_ssh_identity(context.profile.ssh_identity_file)
    remote = shell_join(
        [
            TUNNEL_HELPER_PATH,
            'start',
            '--guest-path',
            guest_path,
            '--name',
            tunnel_name,
            '--session',
            _TUNNEL_TMUX_SESSION,
        ]
    )
    cmd = [
        'ssh',
        *ssh_base_args(ident),
        context.ssh_target(ip),
        remote,
    ]
    CommandManager.current().run(
        cmd,
        sudo=False,
        user_driven=True,
        check=True,
        capture=False,
        summary='Start VS Code tunnel session',
        detail=f'guest_helper={TUNNEL_HELPER_PATH} guest_path={guest_path}',
    )


def _attach_remote_tunnel_session(context: ResolvedVMContext, ip: str) -> int:
    """Interactively attach to the ``aivm-tunnel`` tmux session in the guest.

    Replaces the current process so stdio, signals, and TTY handling match
    a plain ``ssh -t`` invocation. Returns nonzero only if exec fails.

    This is the one deliberate exception to routing commands through
    :class:`CommandManager`: a subprocess cannot hand the caller's TTY back
    cleanly, so the command is logged here for auditability and then exec'd.
    """
    ident = require_ssh_identity(context.profile.ssh_identity_file)
    cmd = [
        'ssh',
        '-t',
        *ssh_base_args(ident),
        context.ssh_target(ip),
        f'tmux attach -t {shlex.quote(_TUNNEL_TMUX_SESSION)}',
    ]
    log.info('RUN (exec, replaces this process): {}', shell_join(cmd))
    os.execvp(cmd[0], cmd)
    return 1  # unreachable; execvp replaces the process


def _print_remote_session_recipe(
    context: ResolvedVMContext,
    session: Any,
    ssh_cfg: Any,
    ssh_cfg_updated: bool,
    reason: str,
) -> None:
    """Print a connect-from-workstation recipe in lieu of launching code."""
    cfg = context.effective_cfg
    vm_name = context.machine.vm.name
    guest_path = session.share_guest_dst
    tunnel_name = _remote_tunnel_name(cfg)
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
    print(
        '  #   2. Sign in with the same GitHub/Microsoft account used by the tunnel.'
    )
    print('  #   3. Open: Remote Explorer: Focus on Remotes (Tunnels/SSH) View')
    print(f'  #   4. Under Tunnels, connect to: {tunnel_name}')
    print()
    print('Alternative: Remote-SSH can work only if your workstation can reach')
    print(
        'the VM, for example with a local SSH config entry that uses ProxyJump'
    )
    print(
        'through this remote host. The plain VM IP below is normally reachable'
    )
    print('from the remote host, not directly from your workstation.')
    print()
    print('  # Plain SSH shell on the guest from this remote host:')
    print(f'  ssh {vm_name}')
    print()
    print(f'  VM:      {vm_name}')
    print(f'  Host:    {session.ip}')
    print(f'  User:    {context.guest_user}')
    print(f'  Path:    {guest_path}')
    print(f'  Tunnel:  {tunnel_name}')
    if ssh_cfg_updated:
        print(f'SSH entry updated on this host in {ssh_cfg}')
    print(f'Folder registered in {session.reg_path}')


def _prepare_foreground_session(args: Any) -> PreparedSession:
    """Run the one shared startup pipeline for SSH and editor sessions.

    ``aivm ssh`` and every ``aivm code`` launcher intentionally share this
    exact preparation path.  The launcher is the only behavior that differs
    after the VM, attachment, and live-state checks are complete.
    """
    host_src = logical_absolute_path(args.host_src)
    return _prepare_attached_session(
        config_opt=args.config,
        vm_opt=args.vm,
        host_src=host_src,
        guest_dst_opt=args.guest_dst,
        attach_mode_opt=args.mode,
        attach_access_opt=args.access,
        recreate_if_needed=args.recreate_if_needed,
        ensure_firewall_opt=args.ensure_firewall,
        dry_run=args.dry_run,
        yes=args.yes,
        bootstrap_missing_vm=partial(
            _bootstrap_vm_for_folder,
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=host_src,
            guest_dst_opt=args.guest_dst,
            attach_mode_opt=args.mode,
            attach_access_opt=args.access,
            yes=args.yes,
            dry_run=args.dry_run,
        ),
    )


class VMCodeCLI(_BaseCommand):
    """Open a host project folder in VS Code attached to the VM via Remote-SSH."""

    host_src: str = kwconf.Value(
        '.',
        position=1,
        help='Host project directory to share and open (default: current directory).',
    )
    vm: str = kwconf.Value(
        '',
        help='VM name override.',
    )
    guest_dst: str = kwconf.Value(
        '',
        help='Guest mount path override (default: mirrors host_src path).',
    )
    mode: Literal['', 'direct-virtiofs', 'shared-root', 'persistent', 'git'] = (
        kwconf.Value(
            '',
            help=(
                'Override. Attachment mode: persistent, shared-root, git, or direct-virtiofs (default: saved mode or persistent; mode changes require detach+reattach). direct-virtiofs gives the folder its own virtiofs device and so consumes one of the guest PCIe slots -- prefer it only when a per-folder device is actually needed, such as when you have no host sudo.'
            ),
        )
    )
    access: Literal['', 'rw', 'ro'] = kwconf.Value(
        '',
        help=(
            'Override. Attachment access: rw or ro (default: saved access or rw). ro is supported for direct-virtiofs, shared-root, and persistent modes.'
        ),
    )
    recreate_if_needed: bool = kwconf.Flag(
        False,
        help='Recreate VM if existing definition lacks the requested share mapping.',
    )
    ensure_firewall: bool = kwconf.Flag(
        True,
        help='Apply firewall rules when firewall.enabled=true.',
    )
    tunnel: bool = kwconf.Flag(
        False,
        help=(
            'Start (if needed) a `code tunnel` inside the VM under tmux and '
            'attach so first-run device auth is interactive. Subsequent runs '
            'reconnect to the existing tunnel session.'
        ),
    )
    no_attach: bool = kwconf.Flag(
        False,
        help=(
            'With --tunnel, only ensure the tunnel session is running; do not '
            'attach. Useful for scripts / non-interactive callers.'
        ),
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMCodeCLI.main host_src={} vm={} guest_dst={} dry_run={} yes={} tunnel={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            args.dry_run,
            args.yes,
            args.tunnel,
        )
        try:
            session = _prepare_foreground_session(args)
        except RuntimeError as ex:
            log.opt(exception=True).trace('Failed preparing code session')
            log.error(str(ex))
            return 1
        context = session.context
        cfg = context.effective_cfg
        if args.dry_run:
            if args.tunnel:
                print(
                    f'DRYRUN: would ensure `code tunnel` running under tmux '
                    f'session {_TUNNEL_TMUX_SESSION!r} in {cfg.vm.name} at '
                    f'{session.share_guest_dst}'
                )
            else:
                print(
                    f'DRYRUN: would open {session.share_guest_dst} in VS Code via host {cfg.vm.name}'
                )
            return 0
        ip = session.ip
        assert ip is not None

        ssh_cfg, ssh_cfg_updated = _upsert_ssh_config_entry(
            cfg, dry_run=False, yes=args.yes
        )

        if args.tunnel:
            tunnel_name = _remote_tunnel_name(cfg)
            _start_remote_tunnel_session(
                context, ip, session.share_guest_dst, tunnel_name
            )
            print(f'Tunnel name: {tunnel_name}')
            print(f'VM:          {cfg.vm.name}')
            print(f'Guest path:  {session.share_guest_dst}')
            print(
                f'Attach later with: ssh {cfg.vm.name} -t tmux attach -t '
                f'{_TUNNEL_TMUX_SESSION}'
            )
            print(
                'In VS Code Desktop, install the "Remote - Tunnels" extension '
                'and sign in with the same account used by the tunnel; the '
                'tunnel will then appear under Remote Explorer -> Tunnels.'
            )
            if ssh_cfg_updated:
                print(f'SSH entry updated in {ssh_cfg}')
            if args.no_attach:
                return 0
            # Replaces this process with `ssh -t` so the tmux UI is interactive
            # (device-code auth on first run; tunnel log thereafter).
            return _attach_remote_tunnel_session(context, ip)

        can_open_local, reason = _vscode_can_open_locally()
        if not can_open_local:
            _print_remote_session_recipe(
                context, session, ssh_cfg, ssh_cfg_updated, reason or ''
            )
            return 0

        remote_target = f'ssh-remote+{cfg.vm.name}'
        CommandManager.current().run(
            ['code', '--remote', remote_target, session.share_guest_dst],
            sudo=False,
            user_driven=True,
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

    host_src: str = kwconf.Value(
        '.',
        position=1,
        help='Host project directory to share and open (default: current directory).',
    )
    vm: str = kwconf.Value(
        '',
        help='VM name override.',
    )
    guest_dst: str = kwconf.Value(
        '',
        help='Guest mount path override (default: mirrors host_src path).',
    )
    mode: Literal['', 'direct-virtiofs', 'shared-root', 'persistent', 'git'] = (
        kwconf.Value(
            '',
            help=(
                'Override. Attachment mode: persistent, shared-root, git, or direct-virtiofs (default: saved mode or persistent; mode changes require detach+reattach). direct-virtiofs gives the folder its own virtiofs device and so consumes one of the guest PCIe slots -- prefer it only when a per-folder device is actually needed, such as when you have no host sudo.'
            ),
        )
    )
    access: Literal['', 'rw', 'ro'] = kwconf.Value(
        '',
        help=(
            'Override. Attachment access: rw or ro (default: saved access or rw). ro is supported for direct-virtiofs, shared-root, and persistent modes.'
        ),
    )
    recreate_if_needed: bool = kwconf.Flag(
        False,
        help='Recreate VM if existing definition lacks the requested share mapping.',
    )
    ensure_firewall: bool = kwconf.Flag(
        True,
        help='Apply firewall rules when firewall.enabled=true.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMSSHCLI.main host_src={} vm={} guest_dst={} dry_run={} yes={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            args.dry_run,
            args.yes,
        )
        try:
            session = _prepare_foreground_session(args)
        except RuntimeError as ex:
            log.error(str(ex))
            return 1
        context = session.context
        cfg = context.effective_cfg
        if args.dry_run:
            print(
                f'DRYRUN: would SSH to {context.guest_user}@<ip> and cd {session.share_guest_dst}'
            )
            return 0

        ip = session.ip
        assert ip is not None
        ssh_cfg, ssh_cfg_updated = _upsert_ssh_config_entry(
            cfg, dry_run=False, yes=args.yes
        )
        ident = require_ssh_identity(context.profile.ssh_identity_file)
        remote_cmd = (
            f'cd {shlex.quote(session.share_guest_dst)} && exec $SHELL -l'
        )
        ssh_result = CommandManager.current().run(
            [
                'ssh',
                '-t',
                *ssh_base_args(
                    ident,
                    strict_host_key_checking='accept-new',
                ),
                context.ssh_target(ip),
                remote_cmd,
            ],
            sudo=False,
            user_driven=True,
            check=False,
            capture=False,
        )
        if ssh_result.code == 255:
            # 255 is ssh's own exit status: the connection or transport
            # failed. Anything else is simply what the user's login shell
            # last returned (`exit` after a failed command propagates that
            # command's status) and is not aivm's error to report.
            log.error(
                'SSH connection to {}@{} failed; check that the VM is '
                'running and reachable (aivm status).',
                context.guest_user,
                ip,
            )
            return 1
        print(f'SSH session ended for {context.ssh_target(ip)}')
        if ssh_result.code:
            log.debug(
                'Interactive shell exited with status {}', ssh_result.code
            )
        if ssh_cfg_updated:
            print(f'SSH entry updated in {ssh_cfg}')
        print(f'Folder registered in {session.reg_path}')
        return 0
