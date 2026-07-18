"""VM cache maintenance CLI commands."""

from __future__ import annotations

import shlex
from typing import Any

import kwconf
from loguru import logger as log

from ..attachments.session import _resolve_ip_for_ssh_ops
from ..commands import CommandManager, shell_join
from ..errors import AIVMError
from ..runtime import require_ssh_identity, ssh_base_args
from ..services import load_cfg
from ._common import _BaseCommand

_DROP_CACHES_HELP = (
    'Comma-separated /proc/sys/vm/drop_caches levels to write in the guest. '
    '1=pagecache, 2=dentries+inodes, 3=both. Default 2 is the targeted '
    'virtiofsd-FD recovery mode observed in the 2026-05-17 incident.'
)


def _parse_drop_cache_levels(raw: str) -> list[int]:
    """Parse and validate a drop_caches level list."""
    text = str(raw or '').strip()
    if not text:
        raise ValueError('at least one drop_caches level is required')
    levels: list[int] = []
    for part in text.split(','):
        item = part.strip()
        if not item:
            continue
        try:
            level = int(item)
        except ValueError as ex:
            raise ValueError(
                f'invalid drop_caches level {item!r}; expected 1, 2, or 3'
            ) from ex
        if level not in {1, 2, 3}:
            raise ValueError(
                f'invalid drop_caches level {level!r}; expected 1, 2, or 3'
            )
        levels.append(level)
    if not levels:
        raise ValueError('at least one drop_caches level is required')
    return levels


def _guest_drop_caches_script(
    levels: list[int], *, settle_seconds: int = 0
) -> str:
    """Build the guest-side shell script for cache eviction.

    ``drop_caches=2`` is intentionally the default recovery action because it
    targets dentries and inodes, which were implicated by the virtiofsd FD
    retention incident. ``drop_caches=3`` also clears page cache and is available
    when requested, but it is more disruptive to guest warm-cache performance.
    """
    if settle_seconds < 0:
        raise ValueError('settle_seconds must be >= 0')
    lines = [
        'set -eu',
        'echo "aivm: syncing guest filesystems"',
        'sync',
    ]
    for idx, level in enumerate(levels):
        payload = f'echo {level} > /proc/sys/vm/drop_caches'
        lines.append(f'echo "aivm: writing drop_caches={level}"')
        lines.append(f'sudo -n sh -c {shlex.quote(payload)}')
        if settle_seconds and idx < len(levels) - 1:
            lines.append(f'echo "aivm: waiting {settle_seconds}s"')
            lines.append(f'sleep {int(settle_seconds)}')
    lines.append('echo "aivm: guest cache flush complete"')
    return '\n'.join(lines)


class VMFlushCachesCLI(_BaseCommand):
    """Flush guest inode/dentry caches to recover virtiofsd FD pressure."""

    vm: str = kwconf.Value(
        '',
        help='VM name override.',
    )
    levels: str = kwconf.Value(
        '2',
        parser=str,
        help=_DROP_CACHES_HELP,
    )
    settle_seconds: int = kwconf.Value(
        0,
        parser=int,
        help='Seconds to wait between multiple drop_caches levels.',
    )
    timeout: int = kwconf.Value(
        60,
        parser=int,
        help='SSH command timeout in seconds.',
    )
    dry_run: bool = kwconf.Flag(
        False,
        help='Print the guest command without running it.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        try:
            levels = _parse_drop_cache_levels(str(args.levels))
            script = _guest_drop_caches_script(
                levels,
                settle_seconds=int(args.settle_seconds or 0),
            )
        except ValueError as ex:
            raise AIVMError(str(ex)) from ex

        cfg = load_cfg(args.config, vm_opt=str(args.vm or ''))
        vm_name = cfg.vm.name
        # Quote the guest script so the remote login shell hands it to
        # `sh -c` as one argument. Without this the remote shell executed
        # each script line independently, so `set -eu` never applied and a
        # failed drop_caches write (e.g. missing passwordless sudo) still
        # exited 0 and reported success.
        remote_command = f'sh -c {shlex.quote(script)}'
        if args.dry_run:
            print(f'DRYRUN: would flush guest caches for VM {vm_name}')
            print('Guest script:')
            print(script)
            print('SSH shape:')
            print(f'ssh <ssh-options> {cfg.vm.user}@<vm-ip> {remote_command}')
            return 0

        mgr = CommandManager.current()
        with mgr.intent(
            f'Flush guest caches for {vm_name}',
            why=(
                'Recover virtiofsd host-side FD pressure by evicting guest '
                'dentry/inode caches, which can cause virtiofsd to release '
                'retained path-backed descriptors.'
            ),
            role='modify',
        ):
            ip = _resolve_ip_for_ssh_ops(
                cfg,
                yes=bool(args.yes),
                purpose='Resolve VM networking before flushing guest caches.',
            )
            ident = require_ssh_identity(cfg.paths.ssh_identity_file)
            cmd = [
                'ssh',
                *ssh_base_args(
                    ident,
                    strict_host_key_checking='accept-new',
                    connect_timeout=10,
                    batch_mode=True,
                ),
                f'{cfg.vm.user}@{ip}',
                remote_command,
            ]
            log.debug('Running guest cache flush command: {}', shell_join(cmd))
            res = mgr.run(
                cmd,
                sudo=False,
                check=False,
                capture=True,
                timeout=int(args.timeout or 60),
                summary=f'Flush guest caches in VM {vm_name}',
                detail=(
                    'Runs sync and writes the requested value(s) to '
                    '/proc/sys/vm/drop_caches inside the guest via sudo -n.'
                ),
            )

        if res.stdout:
            print(res.stdout, end='' if res.stdout.endswith('\n') else '\n')
        if res.stderr:
            print(res.stderr, end='' if res.stderr.endswith('\n') else '\n')
        if res.code != 0:
            print(
                f'Guest cache flush failed for {vm_name} (exit code {res.code}). '
                'The guest user may lack passwordless sudo, or SSH may be unavailable.'
            )
            return int(res.code) if res.code else 1
        print(
            f'Flushed guest caches for {vm_name} with drop_caches='
            f'{",".join(str(level) for level in levels)}.'
        )
        print(
            'For virtiofsd EMFILE incidents, verify recovery on the host with: '
            '`sudo ls /proc/<virtiofsd-pid>/fd | wc -l`.'
        )
        return 0


__all__ = [
    'VMFlushCachesCLI',
    '_guest_drop_caches_script',
    '_parse_drop_cache_levels',
]
