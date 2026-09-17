"""VM CLI modal registration.

The CLI command classes live in focused ``aivm.cli.vm_*`` modules.  This
module is intentionally only the ModalCLI registration point plus public class
re-exports used by the top-level CLI.  Private helpers should be imported from
and monkeypatched at their owning modules, not through this facade.
"""

from __future__ import annotations

import kwconf

from .vm_access import VMAccessModalCLI
from .vm_attach import (
    VMAttachCLI,
    VMDetachCLI,
    VMInstallPersistentHostReplayServiceCLI,
    VMPersistentHostReplayCLI,
)
from .vm_cache import VMFlushCachesCLI
from .vm_config import VMEditCLI
from .vm_connect import VMSSHCLI, VMCodeCLI, VMSshConfigCLI, VMWaitIPCLI
from .vm_creds import VMCredsModalCLI
from .vm_guard import VMFdGuardCLI
from .vm_lifecycle import (
    VMCreateCLI,
    VMDeleteCLI,
    VMDownCLI,
    VMListCLI,
    VMProvisionCLI,
    VMRenameCLI,
    VMRestartCLI,
    VMStatusCLI,
    VMUpCLI,
)
from .vm_update import VMUpdateCLI


class VMModalCLI(kwconf.ModalCLI):
    """VM lifecycle subcommands."""

    list = VMListCLI
    create = VMCreateCLI
    up = VMUpCLI
    down = VMDownCLI
    restart = VMRestartCLI
    wait_ip = VMWaitIPCLI
    status = VMStatusCLI
    update = VMUpdateCLI
    edit = VMEditCLI
    delete = VMDeleteCLI
    rename = VMRenameCLI
    ssh_config = VMSshConfigCLI
    provision = VMProvisionCLI
    ssh = VMSSHCLI
    attach = VMAttachCLI
    detach = VMDetachCLI
    persistent_host_replay = VMPersistentHostReplayCLI
    install_persistent_host_replay_service = (
        VMInstallPersistentHostReplayServiceCLI
    )
    code = VMCodeCLI
    flush_caches = VMFlushCachesCLI
    fdguard = VMFdGuardCLI
    creds = VMCredsModalCLI
    access = VMAccessModalCLI


__all__ = [
    'VMModalCLI',
    'VMUpCLI',
    'VMDownCLI',
    'VMRestartCLI',
    'VMCreateCLI',
    'VMWaitIPCLI',
    'VMStatusCLI',
    'VMDeleteCLI',
    'VMRenameCLI',
    'VMSshConfigCLI',
    'VMProvisionCLI',
    'VMCodeCLI',
    'VMSSHCLI',
    'VMAttachCLI',
    'VMDetachCLI',
    'VMPersistentHostReplayCLI',
    'VMInstallPersistentHostReplayServiceCLI',
    'VMListCLI',
    'VMEditCLI',
    'VMUpdateCLI',
    'VMFlushCachesCLI',
    'VMFdGuardCLI',
    'VMCredsModalCLI',
    'VMAccessModalCLI',
]
