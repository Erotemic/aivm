"""Attachment/session subsystem for aivm.

Public surface re-exported below is intentionally limited to the names
imported by callers outside this subpackage. Private helpers (leading
underscore) live in the submodules that own them and should be imported
directly from those submodules.
"""

from .persistent import (
    PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    PERSISTENT_ROOT_GUEST_MOUNT_ROOT,
    PERSISTENT_ROOT_VIRTIOFS_TAG,
)
from .resolve import (
    ATTACHMENT_ACCESS_MODES,
    ATTACHMENT_ACCESS_RO,
    ATTACHMENT_ACCESS_RW,
    ATTACHMENT_MODE_GIT,
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT,
    ATTACHMENT_MODES,
)
from .session import (
    ReconcilePolicy,
    ReconcileResult,
)
from .shared_root import (
    SHARED_ROOT_GUEST_MOUNT_ROOT,
)

__all__ = [
    'ATTACHMENT_ACCESS_MODES',
    'ATTACHMENT_ACCESS_RO',
    'ATTACHMENT_ACCESS_RW',
    'ATTACHMENT_MODES',
    'ATTACHMENT_MODE_GIT',
    'ATTACHMENT_MODE_PERSISTENT',
    'ATTACHMENT_MODE_SHARED',
    'ATTACHMENT_MODE_SHARED_ROOT',
    'PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME',
    'PERSISTENT_ATTACHMENT_REPLAY_SERVICE',
    'PERSISTENT_ROOT_GUEST_MOUNT_ROOT',
    'PERSISTENT_ROOT_VIRTIOFS_TAG',
    'ReconcilePolicy',
    'ReconcileResult',
    'SHARED_ROOT_GUEST_MOUNT_ROOT',
]
