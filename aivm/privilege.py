"""Privilege-mode policy and host capability probes.

All three modes answer one question --- *when does aivm invoke sudo?* ---
configured via ``behavior.privilege_mode`` (or forced to ``'never'`` for
one invocation with ``--never_sudo``):

* ``'never'``     -- refuse rather than escalate. Operations that
  genuinely require root (nftables firewall management, dependency
  installation, establishing a *new* host bind mount) fail with
  actionable guidance. An assertion for CI, not a daily posture.
* ``'as-needed'`` -- default: probe what already works without privileges
  (system-libvirt access via the ``libvirt`` group, user-writable image
  trees) and use sudo only where the probe says it is required.
* ``'always'``    -- classic behavior: privileged host operations run via
  sudo, with the usual approval prompts.

The mode itself lives on :class:`aivm.commands.CommandManager` so the
never-sudo guarantee is enforced at the one chokepoint every subprocess
goes through --- keyed on the command actually being run, never on the
feature requesting it. The helpers here answer the per-family question
"does this kind of command need sudo right now?" for call sites:

* :func:`virsh_needs_sudo` -- libvirt client commands (virsh,
  virt-install). Unprivileged access to ``qemu:///system`` works when the
  user is in the ``libvirt`` group (polkit rule shipped by
  libvirt-daemon-system).
* :func:`path_needs_sudo` -- host filesystem operations under the VM
  image/state tree. Unprivileged when the target (or its nearest existing
  ancestor) is writable by the current user.
* :func:`file_write_needs_sudo` -- in-place writes to an existing file
  (for example ``qemu-img resize``). Judged by the file's own mode rather
  than its parent directory.

Run ``aivm host sudoless check`` / ``aivm host sudoless setup`` to inspect
or establish the host state these probes look for. "Sudoless" names a
property of the *host* (aivm need never escalate on it), which is why that
command keeps the name while the mode values do not.

Security note: ``'never'`` is a *no-sudo-invocation* guarantee, not a
reduced-privilege guarantee. Membership in the libvirt group grants control
of the root system libvirt daemon, which is effectively root-equivalent on
the host. State-changing hypervisor commands therefore keep the same
interactive approval contract they had when they ran through sudo (see
CommandManager._command_needs_approval).
"""

from __future__ import annotations

import getpass
import grp
import os
import pwd
import stat as stat_mod
from pathlib import Path

from loguru import logger

from .commands import CommandManager
from .errors import SudoRequiredError
from .modes import (
    PRIVILEGE_MODES,
    PrivilegeMode,
    normalize_privilege_mode,
)
from .runtime import virsh_cmd

log = logger

__all__ = [
    'PRIVILEGE_MODES',
    'PrivilegeMode',
    'normalize_privilege_mode',
    'current_privilege_mode',
    'libvirt_unprivileged_ok',
    'virsh_needs_sudo',
    'sudo_allowed',
    'path_needs_sudo',
    'file_write_needs_sudo',
    'require_sudo_allowed',
    'user_can_write_path',
    'user_owns_path',
    'user_can_write_file',
    'user_in_libvirt_group',
    'qemu_traversal_blockers',
    'qemu_user_can_traverse',
    'nearest_existing_ancestor',
    'LIBVIRT_QEMU_USER',
    'LIBVIRT_GROUP',
]

#: The user that Ubuntu system-libvirt runs QEMU processes as. Disk images
#: and every ancestor directory must be traversable by this user.
LIBVIRT_QEMU_USER = 'libvirt-qemu'

#: Membership in this group grants unprivileged access to qemu:///system.
LIBVIRT_GROUP = 'libvirt'


def current_privilege_mode() -> PrivilegeMode:
    """Return the active manager's privilege mode."""
    return CommandManager.current().privilege_mode


def libvirt_unprivileged_ok() -> bool:
    """Return True when qemu:///system is reachable without privileges.

    The probe result is cached on the current CommandManager for the
    lifetime of the run (group membership does not change mid-invocation).
    """
    if os.geteuid() == 0:
        return True
    mgr = CommandManager.current()
    cache = mgr.probe_cache.setdefault('privilege', {})
    cached = cache.get('libvirt_unprivileged_ok')
    if cached is not None:
        return bool(cached)
    # Run as a loose command outside any open plan: virsh_needs_sudo() is
    # often evaluated while building a step, and the probe must not become
    # that step's first previewed/approved command.
    saved_plan_stack = mgr.plan_stack
    mgr.plan_stack = []
    try:
        res = mgr.run(
            virsh_cmd('list', '--name'),
            sudo=False,
            role='read',
            check=False,
            capture=True,
            input_text='',
            env={**os.environ, 'LC_ALL': 'C'},
            summary='Probe unprivileged system-libvirt access',
            detail=(
                'Determine whether virsh can reach qemu:///system without '
                'sudo (libvirt group membership).'
            ),
        )
    finally:
        mgr.plan_stack = saved_plan_stack
    ok = res.code == 0
    cache['libvirt_unprivileged_ok'] = ok
    return ok


def virsh_needs_sudo() -> bool:
    """Return whether libvirt client commands should run via sudo."""
    mode = current_privilege_mode()
    if mode == PrivilegeMode.ALWAYS:
        return True
    if mode == PrivilegeMode.NEVER:
        return False
    return not libvirt_unprivileged_ok()


def sudo_allowed() -> bool:
    """Return False when the active mode forbids sudo entirely."""
    return current_privilege_mode() != PrivilegeMode.NEVER


def _stat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.stat(path)
    except OSError:
        return None


def nearest_existing_ancestor(path: Path) -> Path | None:
    """Return ``path`` or its nearest stat-able ancestor, if any."""
    p = Path(path)
    if not p.is_absolute():
        # Relative paths would stop the ancestor walk at '.', hiding the
        # real chain (cwd, $HOME, ...).
        p = Path.cwd() / p
    while True:
        if _stat_or_none(p) is not None:
            return p
        parent = p.parent
        if parent == p:
            return None
        p = parent


def user_owns_path(path: Path | str) -> bool:
    """True when the invoking user owns ``path``.

    ``chmod``/``setfacl`` require ownership, not writability: a
    group-writable directory (e.g. adopted ``root:libvirt`` storage) passes
    :func:`user_can_write_path` yet still refuses unprivileged ACL changes.
    """
    st = _stat_or_none(Path(path))
    return st is not None and st.st_uid == os.geteuid()


def user_can_write_path(path: Path | str) -> bool:
    """Return True when the user can create or modify ``path`` unprivileged.

    A directory must be writable+traversable. An existing file is judged by
    its parent directory (the common operations — replace, move, delete —
    need directory write, not just file write); a missing target requires a
    writable+traversable nearest existing ancestor.
    """
    target = Path(path)
    anchor = nearest_existing_ancestor(target)
    if anchor is None:
        return False
    st = _stat_or_none(anchor)
    if st is None:
        return False
    if not stat_mod.S_ISDIR(st.st_mode):
        anchor = anchor.parent
        st = _stat_or_none(anchor)
        if st is None or not stat_mod.S_ISDIR(st.st_mode):
            return False
    return os.access(anchor, os.W_OK | os.X_OK)


def path_needs_sudo(path: Path | str) -> bool:
    """Return whether filesystem operations on ``path`` should use sudo."""
    mode = current_privilege_mode()
    if mode == PrivilegeMode.ALWAYS:
        return True
    if mode == PrivilegeMode.NEVER:
        return False
    return not user_can_write_path(path)


def user_can_write_file(path: Path | str) -> bool:
    """Return True when the user can open ``path`` itself for writing.

    Unlike :func:`user_can_write_path`, an existing file is judged by its
    own mode, not its parent directory: in-place modifications (for example
    ``qemu-img resize``) open the file O_RDWR and never touch the directory
    entry. A missing target falls back to the directory-based check.
    """
    if _stat_or_none(Path(path)) is None:
        return user_can_write_path(path)
    return os.access(path, os.W_OK)


def file_write_needs_sudo(path: Path | str) -> bool:
    """Return whether an in-place write to ``path`` should use sudo."""
    mode = current_privilege_mode()
    if mode == PrivilegeMode.ALWAYS:
        return True
    if mode == PrivilegeMode.NEVER:
        return False
    return not user_can_write_file(path)


def require_sudo_allowed(*, feature: str, hint: str) -> None:
    """Fail fast when an unconditionally root-only feature meets ``never``.

    Only for operations that need root on *every* invocation (nftables,
    package installation), so users get feature-level guidance instead of a
    failed command deep inside a flow.

    Do not use this to gate a feature that merely *can* need root. A
    persistent/shared-root attachment needs a privileged ``mount --bind``
    only when the bind is missing; reconciling an established one issues no
    privileged command at all. Gating on the feature refuses work that
    would have succeeded. Such call sites need no gate: every sudo command
    passes through CommandManager._reject_sudo_if_forbidden, which rejects
    on the command actually being run rather than on what might be run.
    """
    if current_privilege_mode() != PrivilegeMode.NEVER:
        return
    raise SudoRequiredError(
        f'{feature} requires privileged host access, but sudo is forbidden '
        '(behavior.privilege_mode = "never").\n'
        f'{hint}'
    )


def user_in_libvirt_group() -> bool:
    """Return True when the invoking user is in the libvirt group.

    Checks the group database, not just the current process credentials,
    so a fresh ``usermod -aG libvirt`` counts even before re-login (the
    live probe in :func:`libvirt_unprivileged_ok` is still authoritative
    for whether access works *now*).
    """
    try:
        group = grp.getgrnam(LIBVIRT_GROUP)
    except KeyError:
        return False
    if group.gr_gid in os.getgroups():
        return True
    try:
        return getpass.getuser() in (group.gr_mem or [])
    except Exception:
        return False


def qemu_traversal_blockers(path: Path | str) -> list[Path] | None:
    """Return directories that block libvirt-qemu from traversing to ``path``.

    Walks each existing ancestor and checks execute permission for the
    libvirt-qemu user via mode bits and POSIX ACLs (``getfacl``). Returns
    an empty list when the whole chain is traversable, and None when the
    answer cannot be determined (e.g. the libvirt-qemu user does not exist
    because libvirt is not installed).
    """
    try:
        qemu_pw = pwd.getpwnam(LIBVIRT_QEMU_USER)
    except KeyError:
        return None
    qemu_gids = {qemu_pw.pw_gid}
    try:
        qemu_gids.update(
            g.gr_gid for g in grp.getgrall() if qemu_pw.pw_name in g.gr_mem
        )
    except Exception:
        pass

    target = nearest_existing_ancestor(Path(path))
    if target is None:
        return None
    blockers: list[Path] = []
    chain: list[Path] = [target, *target.parents]
    for part in chain:
        st = _stat_or_none(part)
        if st is None:
            return None
        if not stat_mod.S_ISDIR(st.st_mode):
            continue
        if st.st_mode & stat_mod.S_IXOTH:
            continue
        if st.st_uid == qemu_pw.pw_uid and st.st_mode & stat_mod.S_IXUSR:
            continue
        if st.st_gid in qemu_gids and st.st_mode & stat_mod.S_IXGRP:
            continue
        if _acl_grants_execute(part, qemu_pw.pw_name):
            continue
        blockers.append(part)
    return blockers


def qemu_user_can_traverse(path: Path | str) -> bool | None:
    """Best-effort check that libvirt-qemu can traverse to ``path``."""
    blockers = qemu_traversal_blockers(path)
    if blockers is None:
        return None
    return not blockers


def _acl_grants_execute(path: Path, user: str) -> bool:
    """Return True when a POSIX ACL grants ``user`` execute on ``path``."""
    mgr = CommandManager.current()
    res = mgr.run(
        ['getfacl', '-p', str(path)],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        summary=f'Inspect ACL entries on {path}',
    )
    if res.code != 0:
        return False
    for line in res.stdout.splitlines():
        entry, _, comment = line.strip().partition('#')
        entry = entry.strip()
        if not entry.startswith(f'user:{user}:'):
            continue
        perms = entry.split(':', 2)[2]
        comment = comment.strip()
        if comment.startswith('effective:'):
            # The ACL mask reduces this entry; trust the effective perms.
            perms = comment.split(':', 1)[1].strip()
        if 'x' in perms:
            return True
    return False
