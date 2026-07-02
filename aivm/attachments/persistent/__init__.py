"""Persistent attachment subsystem.

Host state is authoritative. The desired persistent-attachment manifest is
stored on the host outside the virtiofs export tree, then synced one-way into
the guest-local replay input at /var/lib/aivm/attachments.json. The guest
replay helper only reads that local file and reapplies mounts from there.

The implementation is split across four submodules:

- ``transport`` — SSH/rsync retry plumbing and "install text file if hash
  differs" primitives (used on both host and guest).
- ``manifest`` — desired-state record dataclass + canonical host write +
  one-way push to the guest via rsync.
- ``host_bind`` — host-side bind reconcile and the systemd unit that
  replays binds at boot.
- ``replay`` — guest-side replay install + top-level reconcile.

Cross-module calls inside the package go through the module reference
(``manifest._sync_persistent_attachment_manifest_on_host`` rather than a
locally-imported name), so tests can patch a single canonical location
regardless of which submodule's call path they exercise.
"""

from __future__ import annotations

from ...commands import CommandManager
from ...persistent_replay import (
    PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    PERSISTENT_ROOT_GUEST_MOUNT_ROOT,
    PERSISTENT_ROOT_VIRTIOFS_TAG,
)
from ...vm.paths import persistent_root_host_dir as _persistent_root_host_dir
from . import host_bind, manifest, replay, transport
from .host_bind import (
    _ensure_persistent_root_host_bind,
    _ensure_persistent_root_parent_dir,
    _ensure_persistent_root_vm_mapping,
    _install_persistent_host_bind_replay,
    _prepare_persistent_attachment_host_and_vm,
    _reconcile_persistent_host_binds,
)
from .manifest import (
    PersistentAttachmentRecord,
    _persistent_attachment_manifest_text,
    _persistent_attachment_records_for_vm,
    _persistent_host_manifest_path,
    _persistent_host_replay_service_name,
    _persistent_host_state_dir,
    _sync_persistent_attachment_manifest_on_host,
    _sync_persistent_attachment_manifest_to_guest,
)
from .replay import (
    _install_persistent_attachment_replay,
    _reconcile_persistent_attachments_in_guest,
)
from .transport import (
    _install_guest_text_if_changed,
    _install_host_text_if_changed,
    _is_transient_ssh_transport_failure,
    _run_guest_root_script,
    _run_guest_ssh_script_with_retry,
    _run_rsync_with_retry,
    _write_text_if_changed,
)

__all__ = [
    'CommandManager',
    'PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME',
    'PERSISTENT_ATTACHMENT_REPLAY_SERVICE',
    'PERSISTENT_ROOT_GUEST_MOUNT_ROOT',
    'PERSISTENT_ROOT_VIRTIOFS_TAG',
    'PersistentAttachmentRecord',
    '_ensure_persistent_root_host_bind',
    '_ensure_persistent_root_parent_dir',
    '_ensure_persistent_root_vm_mapping',
    '_install_guest_text_if_changed',
    '_install_host_text_if_changed',
    '_install_persistent_attachment_replay',
    '_install_persistent_host_bind_replay',
    '_is_transient_ssh_transport_failure',
    '_persistent_attachment_manifest_text',
    '_persistent_attachment_records_for_vm',
    '_persistent_host_manifest_path',
    '_persistent_host_replay_service_name',
    '_persistent_host_state_dir',
    '_persistent_root_host_dir',
    '_prepare_persistent_attachment_host_and_vm',
    '_reconcile_persistent_attachments_in_guest',
    '_reconcile_persistent_host_binds',
    '_run_guest_root_script',
    '_run_guest_ssh_script_with_retry',
    '_run_rsync_with_retry',
    '_sync_persistent_attachment_manifest_on_host',
    '_sync_persistent_attachment_manifest_to_guest',
    '_write_text_if_changed',
    'host_bind',
    'manifest',
    'replay',
    'transport',
]
