"""Attachment resolution helpers: path computation, mode/access normalisation."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from loguru import logger as log

from ..config import AgentVMConfig
from ..config_store import find_attachment_for_vm, load_store
from ..privilege import require_sudo_allowed, sudo_allowed
from ..runtime import require_system_runtime, runtime_is_session
from ..vm.share import (
    AttachmentAccess,
    AttachmentMode,
    ResolvedAttachment,
    _ensure_share_tag_len,
)


def logical_absolute_path(raw: str | Path) -> Path:
    """Convert a user-supplied path to an absolute path that preserves symlinks.

    The default ``Path('.').absolute()`` uses ``os.getcwd()``, which on Linux
    returns the kernel-canonical path (symlinks already resolved). For a CLI
    that promises "the location you type is the location you get", we want
    the shell's logical view: e.g. ``cd /data/proj`` (where ``/data`` is a
    symlink) should keep ``/data/proj`` as the typed path even when the
    kernel sees ``/media/raid/proj``.

    Resolution rules:

    * Absolute inputs are returned via ``expanduser()`` only. No symlink
      resolution — preserve exactly what the user typed.
    * Relative inputs are joined with ``$PWD`` *iff* ``Path($PWD).resolve()``
      equals ``Path(os.getcwd())``. That validation guards against a stale
      or spoofed ``PWD`` (e.g. set by a parent shell and not refreshed after
      ``cd``). When the check fails, we fall back to ``Path.absolute()``,
      accepting the kernel-canonical form rather than risking the wrong dir.

    Note: this returns a lexical path. It is not a substitute for
    ``Path.resolve()`` when callers genuinely need a canonical path (e.g.
    a bind-mount source). Use both: the lexical form for what to show the
    user, and ``resolve()`` for what to mount.
    """
    p = Path(str(raw)).expanduser()
    if p.is_absolute():
        return p
    pwd = os.environ.get('PWD')
    if pwd:
        try:
            pwd_path = Path(pwd)
            if pwd_path.is_absolute() and pwd_path.resolve() == Path(os.getcwd()):
                return (pwd_path / p).expanduser()
        except OSError:
            # PWD points at something we can't stat — fall through.
            log.debug(
                'logical_absolute_path: $PWD={} could not be validated; '
                'falling back to os.getcwd()',
                pwd,
            )
    return p.absolute()

# Attachment mode constants (string aliases for mode values)
ATTACHMENT_MODE_SHARED = AttachmentMode.SHARED.value
ATTACHMENT_MODE_SHARED_ROOT = AttachmentMode.SHARED_ROOT.value
ATTACHMENT_MODE_PERSISTENT = AttachmentMode.PERSISTENT.value
ATTACHMENT_MODE_GIT = AttachmentMode.GIT.value

# Attachment access constants (string aliases for access values)
ATTACHMENT_ACCESS_RW = AttachmentAccess.RW.value
ATTACHMENT_ACCESS_RO = AttachmentAccess.RO.value

# Attachment mode and access sets for validation
ATTACHMENT_MODES = {
    ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT,
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_GIT,
}
ATTACHMENT_ACCESS_MODES = {
    ATTACHMENT_ACCESS_RW,
    ATTACHMENT_ACCESS_RO,
}


def _default_primary_guest_dst(host_src: Path) -> str:
    """Compute the default primary guest destination for an attachment.

    The primary guest path is always the canonical resolved host path. If the
    user typed any path that resolves to a different lexical form (terminal
    symlink, intermediate symlink, or relative path captured against a
    symlinked ``$PWD``), the typed lexical paths become *aliases* recorded
    separately on the attachment and materialized in the guest as symlinks
    pointing at this canonical guest_dst.
    """
    try:
        return str(host_src.resolve())
    except OSError:
        return str(host_src.expanduser().absolute())


def _resolve_guest_dst(host_src: Path, guest_dst_opt: str) -> str:
    guest_dst_opt = (guest_dst_opt or '').strip()
    if guest_dst_opt:
        return guest_dst_opt
    return _default_primary_guest_dst(host_src)


def _host_symlink_lexical_path(host_src: Path) -> str | None:
    """Return the lexical (typed) form of ``host_src`` if it differs from the resolved form.

    Differs from the older "is terminal-component a symlink?" check so that
    intermediate symlinks (e.g. ``/data/.../foo`` where ``/data`` is a
    symlink) and PWD-captured relative paths through symlinked cwds are both
    detected. Returns ``None`` when lexical and resolved coincide — there is
    no alias worth recording.
    """
    lexical = host_src.expanduser().absolute()
    try:
        resolved = host_src.resolve()
    except OSError:
        return None
    if str(lexical) == str(resolved):
        return None
    return str(lexical)


def _compute_mirror_home_symlink(
    cfg: AgentVMConfig,
    host_src: Path,
    guest_dst: str,
    *,
    is_default_dst: bool,
) -> str | None:
    """Compute the mirror-home symlink path if vm.mirror_shared_home_folders is enabled.

    Returns the guest symlink path to create (pointing to guest_dst), or None if
    the mirror should not be created.

    Skip conditions:
    - mirror_shared_home_folders setting is false
    - attachment used an explicit custom guest_dst
    - host path is not under the host user home
    - guest home equals host home (no point mirroring)
    - mirror path would be identical to primary guest_dst
    """
    if not is_default_dst:
        return None
    host_home = Path.home()
    guest_home = PurePosixPath('/home') / cfg.vm.user
    if str(guest_home) == str(host_home):
        return None
    lexical = host_src.expanduser().absolute()
    try:
        rel = lexical.relative_to(host_home)
    except ValueError:
        return None  # host path not under host home
    mirror = str(guest_home / rel)
    if mirror == guest_dst:
        return None  # mirror path same as primary, no-op
    return mirror


def _normalize_attachment_mode(mode: str) -> AttachmentMode:
    raw = str(mode or '').strip().lower()
    if not raw:
        return AttachmentMode(ATTACHMENT_MODE_PERSISTENT)
    aliases = {
        'clone': ATTACHMENT_MODE_GIT,
        'cloned': ATTACHMENT_MODE_GIT,
        'repo': ATTACHMENT_MODE_GIT,
        'git': ATTACHMENT_MODE_GIT,
        'sharedroot': ATTACHMENT_MODE_SHARED_ROOT,
        'shared_root': ATTACHMENT_MODE_SHARED_ROOT,
        'root': ATTACHMENT_MODE_SHARED_ROOT,
        'persistent': ATTACHMENT_MODE_PERSISTENT,
        ATTACHMENT_MODE_SHARED: ATTACHMENT_MODE_SHARED,
        ATTACHMENT_MODE_SHARED_ROOT: ATTACHMENT_MODE_SHARED_ROOT,
        ATTACHMENT_MODE_PERSISTENT: ATTACHMENT_MODE_PERSISTENT,
    }
    resolved = aliases.get(raw, raw)
    if resolved not in ATTACHMENT_MODES:
        allowed = ', '.join(sorted(ATTACHMENT_MODES))
        raise RuntimeError(f'--mode must be one of: {allowed}')
    return AttachmentMode(resolved)


def _normalize_attachment_access(access: str) -> AttachmentAccess:
    raw = str(access or '').strip().lower()
    if not raw:
        return AttachmentAccess(ATTACHMENT_ACCESS_RW)
    aliases = {
        'readonly': ATTACHMENT_ACCESS_RO,
        'read-only': ATTACHMENT_ACCESS_RO,
        'read_only': ATTACHMENT_ACCESS_RO,
        ATTACHMENT_ACCESS_RO: ATTACHMENT_ACCESS_RO,
        'readwrite': ATTACHMENT_ACCESS_RW,
        'read-write': ATTACHMENT_ACCESS_RW,
        'read_write': ATTACHMENT_ACCESS_RW,
        ATTACHMENT_ACCESS_RW: ATTACHMENT_ACCESS_RW,
    }
    resolved = aliases.get(raw, raw)
    if resolved not in ATTACHMENT_ACCESS_MODES:
        allowed = ', '.join(sorted(ATTACHMENT_ACCESS_MODES))
        raise RuntimeError(f'--access must be one of: {allowed}')
    return AttachmentAccess(resolved)


def _resolve_attachment(
    cfg: AgentVMConfig,
    cfg_path: Path,
    host_src: Path,
    guest_dst_opt: str,
    mode_opt: str = '',
    access_opt: str = '',
) -> ResolvedAttachment:
    source_dir = str(host_src.resolve())
    guest_dst = _resolve_guest_dst(host_src, guest_dst_opt)
    tag = _ensure_share_tag_len('', host_src, set())
    if not mode_opt and runtime_is_session():
        # Session VMs cannot mount host folders at all yet: libvirt-managed
        # virtiofsd needs the system daemon, and bind-mount modes need root.
        # Git sync is the one transport that works everywhere.
        mode = _normalize_attachment_mode(ATTACHMENT_MODE_GIT)
    elif not mode_opt and not sudo_allowed():
        # The default persistent mode relies on host bind mounts, which
        # need root; sudoless attachments default to direct virtiofs.
        mode = _normalize_attachment_mode(ATTACHMENT_MODE_SHARED)
    else:
        mode = _normalize_attachment_mode(mode_opt)
    access = _normalize_attachment_access(access_opt)
    reg = load_store(cfg_path)
    att = find_attachment_for_vm(reg, host_src, cfg.vm.name)
    if att is not None:
        saved_mode = _normalize_attachment_mode(att.mode)
        saved_access = _normalize_attachment_access(att.access)
        if mode_opt and mode != saved_mode:
            raise RuntimeError(
                'Attachment mode mismatch for existing folder attachment.\n'
                f'VM: {cfg.vm.name}\n'
                f'Host folder: {host_src}\n'
                f'Saved mode: {saved_mode}\n'
                f'Requested mode: {mode}\n'
                'Changing attachment mode requires an explicit detach + reattach.\n'
                'Run:\n'
                f'  aivm detach {host_src}\n'
                f'  aivm attach {host_src} --mode {mode}'
            )
        if access_opt and access != saved_access:
            raise RuntimeError(
                'Attachment access mismatch for existing folder attachment.\n'
                f'VM: {cfg.vm.name}\n'
                f'Host folder: {host_src}\n'
                f'Saved access: {saved_access}\n'
                f'Requested access: {access}\n'
                'Changing attachment access requires an explicit detach + reattach.\n'
                'Run:\n'
                f'  aivm detach {host_src}\n'
                f'  aivm attach {host_src} --access {access}'
            )
        if not mode_opt and att.mode:
            mode = saved_mode
        if not access_opt:
            access = saved_access
        if not guest_dst_opt and att.guest_dst:
            guest_dst = att.guest_dst
        if att.tag:
            tag = att.tag
    if access == ATTACHMENT_ACCESS_RO and mode == ATTACHMENT_MODE_GIT:
        raise NotImplementedError(
            'Read-only attachments are currently only implemented for '
            f"'{ATTACHMENT_MODE_SHARED}' and '{ATTACHMENT_MODE_SHARED_ROOT}' modes. "
            f'Requested mode: {mode}'
        )
    if mode != ATTACHMENT_MODE_GIT:
        require_system_runtime(
            feature=f"The '{mode}' attachment mode",
            hint=(
                'Session-runtime VMs currently support only git-mode '
                'attachments: virtiofs sharing needs the system libvirt '
                'daemon (or a future unprivileged virtiofsd backend), and '
                'bind-mount modes need root. Existing attachments keep '
                'their saved mode, so detach first:\n'
                f'  aivm detach {host_src}\n'
                f'  aivm attach {host_src} --mode git\n'
                "Or use a VM with runtime.mode = 'system'."
            ),
        )
    if mode in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}:
        require_sudo_allowed(
            feature=f"The '{mode}' attachment mode (host bind mounts)",
            hint=(
                'Use the sudoless-compatible shared mode instead (existing '
                'attachments keep their saved mode, so detach first):\n'
                f'  aivm detach {host_src}\n'
                f'  aivm attach {host_src} --mode shared\n'
                "Or set behavior.privilege_mode to 'auto' to allow sudo."
            ),
        )
    if mode == ATTACHMENT_MODE_GIT:
        tag = ''
    return ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=mode,
        access=access,
        source_dir=source_dir,
        guest_dst=guest_dst,
        tag=tag,
    )
