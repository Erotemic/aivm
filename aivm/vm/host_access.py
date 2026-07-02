"""Host-side privileged filesystem access helpers for system-libvirt VMs."""

from __future__ import annotations

import stat as stat_mod
from pathlib import Path

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig

log = logger

def _local_stat_answer(path: Path, *, want_file: bool) -> bool | None:
    """Try to answer an existence check without privileges.

    Returns True/False when the local stat is authoritative and None when
    the answer needs a privileged probe. A successful stat is definitive,
    and ENOENT is definitive non-existence (the kernel resolved every parent
    we were allowed to traverse); EACCES and friends are inconclusive.
    """
    try:
        st = path.stat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    if want_file:
        return stat_mod.S_ISREG(st.st_mode)
    return True

def _sudo_path_exists(path: Path) -> bool:
    """Return True if ``path`` exists, using sudo only when necessary.

    The privileged probe only runs when an unprivileged stat cannot answer
    (for example under a root-only image directory).
    """
    local = _local_stat_answer(path, want_file=False)
    if local is not None:
        return local
    mgr = CommandManager.current()
    return (
        mgr.run(
            ['test', '-e', str(path)],
            sudo=True,
            role='read',
            check=False,
            capture=True,
        ).code
        == 0
    )

def _sudo_file_exists(path: Path) -> bool:
    """Return True if ``path`` is a regular file, using sudo only when necessary.

    See :func:`_sudo_path_exists` for the escalation rationale.
    """
    local = _local_stat_answer(path, want_file=True)
    if local is not None:
        return local
    mgr = CommandManager.current()
    return (
        mgr.run(
            ['test', '-f', str(path)],
            sudo=True,
            role='read',
            check=False,
            capture=True,
        ).code
        == 0
    )

def _submit_qemu_dir_prepare(
    mgr: CommandManager,
    path: Path,
    *,
    group: str,
    mode: str,
    summary_prefix: str,
    recursive: bool,
) -> None:
    mgr.submit(
        ['mkdir', '-p', str(path)],
        sudo=True,
        role='modify',
        check=True,
        capture=True,
        summary=f'Create {summary_prefix}',
    )
    mgr.submit(
        ['chown', *(['-R'] if recursive else []), f'root:{group}', str(path)],
        sudo=True,
        role='modify',
        check=True,
        capture=True,
        summary=f'Set libvirt ownership for {summary_prefix}',
    )
    mgr.submit(
        ['chmod', mode, str(path)],
        sudo=True,
        role='modify',
        check=True,
        capture=True,
        summary=f'Set permissions for {summary_prefix}',
    )

def _ensure_qemu_access(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    cfg = cfg.expanded_paths()
    base_root = Path(cfg.paths.base_dir) / cfg.vm.name
    grp = 'libvirt-qemu'
    if (
        CommandManager.current()
        .run(['getent', 'group', 'libvirt-qemu'], check=False, capture=True)
        .code
        != 0
    ):
        grp = 'kvm'
    if dry_run:
        log.info(
            'DRYRUN: chown/chmod {} for qemu access (group={})', base_root, grp
        )
        return
    mgr = CommandManager.current()
    with mgr.intent(
        'Prepare VM storage',
        why=(
            'libvirt/qemu need host directories with predictable ownership and '
            'permissions before images and cloud-init artifacts are written.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Prepare qemu-accessible VM directories',
            why=(
                'Create the VM root plus image and cloud-init directories with '
                'libvirt-readable ownership and permissions.'
            ),
            approval_scope=f'vm-storage:{base_root}',
        ):
            _submit_qemu_dir_prepare(
                mgr,
                base_root,
                group=grp,
                mode='0751',
                summary_prefix='VM root directory',
                recursive=False,
            )
            _submit_qemu_dir_prepare(
                mgr,
                base_root / 'images',
                group=grp,
                mode='0750',
                summary_prefix='VM image directory',
                recursive=True,
            )
            _submit_qemu_dir_prepare(
                mgr,
                base_root / 'cloud-init',
                group=grp,
                mode='0750',
                summary_prefix='cloud-init directory',
                recursive=True,
            )
