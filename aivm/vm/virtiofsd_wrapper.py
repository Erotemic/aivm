"""Helpers for recognizing legacy AIVM virtiofsd wrapper paths.

A previous implementation attempted to pass virtiofsd's
``--inode-file-handles`` option by generating host-side wrapper scripts under
``paths.base_dir`` and pointing libvirt ``<filesystem>/<binary path=...>`` at
those scripts. That violated AIVM's host trust model: normal VM updates should
use well-known, distro-provided host binaries, not AIVM-generated privileged
host executables/scripts.

Current managed-libvirt mode therefore does **not** install wrappers and does
**not** request wrapper paths for new virtiofs attachments. This module remains
only so update drift detection can recognize old AIVM-managed wrapper paths and
remove them from existing VM XML.

See ``dev/design/future/virtiofsd-inode-file-handles.md`` before reintroducing
any inode-file-handles strategy.
"""

from __future__ import annotations

from pathlib import Path

VALID_MODES = ('never', 'prefer', 'mandatory')
DEFAULT_VIRTIOFSD_BINARY = '/usr/libexec/virtiofsd'
WRAPPER_BASENAME_TEMPLATE = 'virtiofsd-wrapper-{mode}.sh'
WRAPPER_BASENAME_NOEXT_TEMPLATE = 'virtiofsd-wrapper-{mode}'
ALL_WRAPPER_BASENAMES = tuple(
    name
    for mode in VALID_MODES
    for name in (
        WRAPPER_BASENAME_TEMPLATE.format(mode=mode),
        WRAPPER_BASENAME_NOEXT_TEMPLATE.format(mode=mode),
    )
)


def normalize_mode(value: str | None) -> str:
    """Return the currently supported managed-libvirt override mode.

    All values intentionally resolve to ``''``. The old non-empty modes are
    retained in config parsing only for backward compatibility and migration;
    normal AIVM-managed libvirt operation must not generate host-side wrapper
    scripts.
    """
    del value
    return ''


def wrapper_path(base_dir: str, mode: str) -> str:
    """Return the legacy wrapper path for a historical mode.

    This helper is intentionally for tests/migration diagnostics only. It does
    not imply that AIVM should install or use the returned path.
    """
    m = str(mode or '').strip().lower()
    if m not in VALID_MODES:
        raise ValueError(f'invalid virtiofsd inode-file-handles mode: {mode!r}')
    return str(Path(base_dir) / WRAPPER_BASENAME_TEMPLATE.format(mode=m))


def is_managed_wrapper_path(base_dir: str, path: str) -> bool:
    """True iff ``path`` is one of AIVM's legacy wrapper paths.

    Older cleanup logic matched only exact paths under the *current*
    ``cfg.paths.base_dir``. That was too narrow for repair: if a local config
    changed ``base_dir`` or an old experiment wrote a wrapper at the historical
    default, ``aivm vm update`` could incorrectly report the VM as in sync while
    libvirt still tried to spawn ``virtiofsd-wrapper-prefer.sh``.

    Keep the exact base-dir check, but also recognize the legacy wrapper
    basenames under AIVM-owned libvirt locations. This is intentionally still
    scoped to AIVM-looking paths; it does not remove arbitrary user binaries.
    """
    if not path:
        return False

    candidate = Path(path)
    name = candidate.name
    if name not in ALL_WRAPPER_BASENAMES:
        return False

    bd = Path(base_dir)
    if path == str(bd / name):
        return True

    # Historical default used by the old wrapper implementation. This lets the
    # repair path work even if the user's current config has a different
    # ``paths.base_dir``.
    if path == str(Path('/var/lib/libvirt/aivm') / name):
        return True

    # Compiled-wrapper experiments and other interrupted patches may have left
    # the same basename under a VM-specific AIVM directory. Treat paths under
    # /var/lib/libvirt/aivm as AIVM-owned legacy wrappers, but avoid matching
    # arbitrary paths elsewhere.
    try:
        candidate.relative_to('/var/lib/libvirt/aivm')
    except ValueError:
        return False
    else:
        return True


def desired_binary_path(base_dir: str, mode: str) -> str | None:
    """Return the managed-libvirt ``<binary path>`` override for ``mode``.

    The only supported normal behavior is no override. The arguments are kept
    for compatibility with older callers and to make rollback overlays safe to
    apply over partially-refactored trees.
    """
    del base_dir, mode
    return None


def wrapper_content(mode: str, real_binary: str = DEFAULT_VIRTIOFSD_BINARY) -> str:
    """Do not generate host-side virtiofsd wrapper scripts.

    Kept as an explicit failure point so stale callers fail loudly instead of
    silently reintroducing the unsafe host-wrapper strategy.
    """
    del real_binary
    raise RuntimeError(
        'AIVM-generated host-side virtiofsd wrappers are disabled. '
        f'Requested inode-file-handles mode was {mode!r}. See '
        'dev/design/future/virtiofsd-inode-file-handles.md.'
    )


def ensure_wrapper_installed(
    base_dir: str, mode: str, *, dry_run: bool = False
) -> str | None:
    """Never install a generated host-side virtiofsd wrapper."""
    del base_dir, dry_run
    if not str(mode or '').strip():
        return None
    raise RuntimeError(
        'AIVM-generated host-side virtiofsd wrappers are disabled. '
        f'Requested inode-file-handles mode was {mode!r}. See '
        'dev/design/future/virtiofsd-inode-file-handles.md.'
    )
