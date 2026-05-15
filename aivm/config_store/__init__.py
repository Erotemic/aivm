"""Implementation modules for AIVM's desired-state config store."""

from .io import load_store, save_store
from .models import AttachmentEntry, NetworkEntry, Store, VMEntry
from .mutate import (
    remove_attachment,
    remove_network,
    remove_vm,
    upsert_attachment,
    upsert_network,
    upsert_vm,
    upsert_vm_with_network,
)
from .paths import app_data_dir, app_data_path, persistent_host_state_dir, store_path
from .render import render_store_toml
from .resolve import (
    find_attachment,
    find_attachment_for_vm,
    find_attachments,
    find_attachments_for_vm,
    find_network,
    find_vm,
    materialize_vm_cfg,
    network_users,
)

__all__ = [
    'AttachmentEntry',
    'NetworkEntry',
    'Store',
    'VMEntry',
    'app_data_dir',
    'app_data_path',
    'find_attachment',
    'find_attachment_for_vm',
    'find_attachments',
    'find_attachments_for_vm',
    'find_network',
    'find_vm',
    'load_store',
    'materialize_vm_cfg',
    'network_users',
    'persistent_host_state_dir',
    'remove_attachment',
    'remove_network',
    'remove_vm',
    'render_store_toml',
    'save_store',
    'store_path',
    'upsert_attachment',
    'upsert_network',
    'upsert_vm',
    'upsert_vm_with_network',
]
