"""Host-side privileged filesystem access helpers for system-libvirt VMs."""

from __future__ import annotations

import stat as stat_mod
from pathlib import Path

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..errors import SudoRequiredError
from ..privilege import (
    LIBVIRT_QEMU_USER,
    path_needs_sudo,
    qemu_traversal_blockers,
    sudo_allowed,
    user_can_write_path,
)
from ..util import which

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

def _undetermined_existence_error(path: Path, what: str) -> SudoRequiredError:
    """Build the error raised when an existence check cannot be answered."""
    return SudoRequiredError(
        f'Cannot determine whether the {what} already exists.\n'
        f'Path: {path}\n'
        'The path is not readable without privileged access, and '
        "behavior.privilege_mode = 'never' forbids escalation. Assuming it is "
        'absent would overwrite or re-download existing state.\n'
        "Set behavior.privilege_mode to 'as-needed' to allow the privileged probe, "
        'or move VM storage to a user-owned directory '
        '(`aivm host sudoless setup`).'
    )

# The privileged probe reports its answer on stdout because the exit status
# cannot carry one: `test -e` exits 1 for "absent", and `sudo` also exits 1
# when authentication fails or the sudoers policy refuses the command. Only a
# shell that actually ran `test` can print a sentinel, so stdout separates
# "the probe answered" from "the probe never ran".
_PROBE_PRESENT = 'AIVM_PROBE_PRESENT'
_PROBE_ABSENT = 'AIVM_PROBE_ABSENT'

def _existence_probe_argv(path: Path, *, want_file: bool) -> list[str]:
    """Build the privileged existence probe command for ``path``.

    ``path`` is passed as a shell positional rather than interpolated into the
    script, so a path containing quotes or spaces cannot alter the test.
    """
    flag = '-f' if want_file else '-e'
    script = (
        f'if test {flag} "$1"; then printf %s {_PROBE_PRESENT}; '
        f'else printf %s {_PROBE_ABSENT}; fi'
    )
    return ['sh', '-c', script, 'sh', str(path)]

def _sudo_existence_probe(path: Path, *, want_file: bool) -> bool | None:
    """Answer an existence check with sudo, or None if sudo could not answer."""
    res = CommandManager.current().run(
        _existence_probe_argv(path, want_file=want_file),
        sudo=True,
        role='read',
        check=False,
        capture=True,
    )
    answer = (res.stdout or '').strip()
    if answer == _PROBE_PRESENT:
        return True
    if answer == _PROBE_ABSENT:
        return False
    return None

def _sudo_path_exists(path: Path) -> bool | None:
    """Return whether ``path`` exists, or None when that cannot be determined.

    The privileged probe only runs when an unprivileged stat cannot answer
    (for example under a root-only image directory). When neither can answer
    -- sudo is forbidden, refused, or failed -- the result is None, *unknown*,
    which is not the same as absent. Callers must not read None as a green
    light to create.
    """
    local = _local_stat_answer(path, want_file=False)
    if local is not None:
        return local
    if not sudo_allowed():
        return None
    return _sudo_existence_probe(path, want_file=False)

def _sudo_file_exists(path: Path) -> bool | None:
    """Return whether ``path`` is a regular file, or None when undeterminable.

    See :func:`_sudo_path_exists` for the escalation and None semantics.
    """
    local = _local_stat_answer(path, want_file=True)
    if local is not None:
        return local
    if not sudo_allowed():
        return None
    return _sudo_existence_probe(path, want_file=True)

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

def _ensure_qemu_access_unprivileged(
    base_root: Path, *, dry_run: bool = False
) -> None:
    """Prepare a user-owned VM storage tree that system libvirt can use.

    The directories stay owned by the invoking user. QEMU (running as
    libvirt-qemu) only needs search permission on the path chain, because
    libvirt's dynamic-ownership DAC relabeling chowns the image files
    themselves at domain start. Traversal is granted with targeted POSIX
    ACLs (``setfacl -m u:libvirt-qemu:x``) so no privileged commands and no
    world-readable permission bits are needed.
    """
    if dry_run:
        log.info(
            'DRYRUN: mkdir/setfacl {} for unprivileged qemu access', base_root
        )
        return
    mgr = CommandManager.current()
    subdirs = (base_root, base_root / 'images', base_root / 'cloud-init')
    with mgr.intent(
        'Prepare VM storage',
        why=(
            'libvirt/qemu need traversable host directories before images '
            'and cloud-init artifacts are written.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Prepare user-owned VM directories',
            why=(
                'Create the VM root plus image and cloud-init directories '
                'and grant libvirt-qemu traversal via POSIX ACLs, keeping '
                'the tree owned by the invoking user.'
            ),
            approval_scope=f'vm-storage:{base_root}',
        ):
            for d in subdirs:
                mgr.submit(
                    ['mkdir', '-p', str(d)],
                    sudo=False,
                    role='modify',
                    check=True,
                    capture=True,
                    summary=f'Create {d.name or "VM"} directory',
                    detail=f'target={d}',
                )
    # Grant traversal on the VM tree itself (idempotent) plus any user-owned
    # ancestor that currently blocks libvirt-qemu (setup handles the rest).
    blockers = [
        b
        for b in (qemu_traversal_blockers(base_root) or [])
        if b not in subdirs
    ]
    own_blockers = [b for b in blockers if user_can_write_path(b)]
    foreign_blockers = [b for b in blockers if not user_can_write_path(b)]
    with mgr.intent(
        'Grant qemu traversal',
        why=(
            'QEMU runs as libvirt-qemu and must be able to reach the VM '
            'image tree through every ancestor directory.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Grant libvirt-qemu traversal ACLs',
            why=(
                'Add per-user execute ACLs instead of loosening world '
                'permissions or changing ownership.'
            ),
            approval_scope=f'vm-storage-acl:{base_root}',
        ):
            for d in [*subdirs, *own_blockers]:
                mgr.submit(
                    ['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(d)],
                    sudo=False,
                    role='modify',
                    check=True,
                    capture=True,
                    summary=f'Allow libvirt-qemu to traverse {d}',
                )
    if foreign_blockers:
        log.warning(
            'libvirt-qemu cannot traverse {} (not owned by you). '
            'Run `aivm host sudoless setup` or grant execute access '
            'manually.',
            ', '.join(str(b) for b in foreign_blockers),
        )


def _ensure_qemu_access(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    cfg = cfg.expanded_paths()
    base_root = Path(cfg.paths.base_dir) / cfg.vm.name
    if not path_needs_sudo(base_root):
        if which('setfacl') is not None:
            _ensure_qemu_access_unprivileged(base_root, dry_run=dry_run)
            return
        if not sudo_allowed():
            raise SudoRequiredError(
                'Sudo-free VM storage preparation needs `setfacl` to grant '
                'libvirt-qemu traversal, but it is not installed. Install '
                "the `acl` package, or set behavior.privilege_mode to "
                "'as-needed'."
            )
        log.warning(
            'setfacl is unavailable; falling back to sudo chown/chmod for '
            'VM storage under {}. Install the `acl` package for sudo-free '
            'storage preparation.',
            base_root,
        )
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
