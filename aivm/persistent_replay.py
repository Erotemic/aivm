"""Persistent-attachment replay paths and standalone resource access."""

from __future__ import annotations

import textwrap
from importlib import resources

PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME = 'persistent-attachments.json'
PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR = '/var/lib/aivm/persistent-host'
PERSISTENT_ATTACHMENT_GUEST_STATE_DIR = '/var/lib/aivm'
PERSISTENT_ATTACHMENT_GUEST_STATE_PATH = (
    f'{PERSISTENT_ATTACHMENT_GUEST_STATE_DIR}/attachments.json'
)
PERSISTENT_ATTACHMENT_REPLAY_BIN = (
    '/usr/local/libexec/aivm-persistent-attachment-replay'
)
PERSISTENT_ATTACHMENT_REPLAY_SERVICE = (
    'aivm-persistent-attachment-replay.service'
)
PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN = (
    '/usr/local/libexec/aivm-persistent-host-bind-replay'
)
PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX = (
    'aivm-persistent-host-bind-replay'
)
PERSISTENT_ROOT_VIRTIOFS_TAG = 'aivm-persistent-root'
PERSISTENT_ROOT_GUEST_MOUNT_ROOT = '/mnt/aivm-persistent'
PERSISTENT_REPLAY_DEGRADED_EXIT = 3
PERSISTENT_BIND_TOKEN_PATTERN = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'


def _resource_text(*parts: str) -> str:
    return resources.files('aivm').joinpath('rc', *parts).read_text(encoding='utf-8')


def persistent_replay_python() -> str:
    """Return the standalone persistent replay program installed in guests."""
    return _resource_text('guest', 'persistent_attachment_replay.py')


def persistent_replay_service_unit() -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description=aivm persistent attachment replay
        After=local-fs.target
        ConditionPathExists={PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}

        [Service]
        Type=oneshot
        ExecStart={PERSISTENT_ATTACHMENT_REPLAY_BIN}

        [Install]
        WantedBy=multi-user.target
        """
    )


def persistent_host_replay_python() -> str:
    """Return the standalone privileged persistent host-bind replay program."""
    return _resource_text('host', 'persistent_host_bind_replay.py')


def _systemd_exec_arg(value: str) -> str:
    if '\n' in value or '\r' in value:
        raise ValueError('systemd arguments must not contain newlines')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def persistent_host_replay_service_unit(
    *,
    vm_name: str,
    manifest_path: str,
    export_root: str,
) -> str:
    service_name = (
        f'{PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX}-{vm_name}'
    )
    manifest_q = _systemd_exec_arg(manifest_path)
    export_q = _systemd_exec_arg(export_root)
    vm_q = _systemd_exec_arg(vm_name)
    return textwrap.dedent(
        f"""        [Unit]
        Description={service_name}
        After=local-fs.target
        ConditionPathExists={manifest_path}

        [Service]
        Type=oneshot
        User=root
        Group=root
        UMask=0022
        NoNewPrivileges=yes
        PrivateTmp=yes
        ExecStart={PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN} --manifest {manifest_q} --export-root {export_q} --vm-name {vm_q} --prune-stale

        [Install]
        WantedBy=multi-user.target
        """
    )
