"""VM CLI modal registration.

The CLI command classes live in focused ``aivm.cli.vm_*`` modules.  This
module is intentionally only the ModalCLI registration point plus public class
re-exports used by the top-level CLI.  Private helpers should be imported from
and monkeypatched at their owning modules, not through this facade.
"""

from __future__ import annotations

import scriptconfig as scfg

from .vm_attach import (
    VMAttachCLI,
    VMDetachCLI,
    VMInstallPersistentHostReplayServiceCLI,
    VMPersistentHostReplayCLI,
)
from .vm_config import VMEditCLI
from .vm_cache import VMFlushCachesCLI
from .vm_connect import VMCodeCLI, VMSSHCLI, VMSshConfigCLI, VMWaitIPCLI
from .vm_lifecycle import (
    VMCreateCLI,
    VMDownCLI,
    VMDestroyCLI,
    VMListCLI,
    VMProvisionCLI,
    VMRestartCLI,
    VMStatusCLI,
    VMUpCLI,
)
from .vm_update import VMUpdateCLI


class VMModalCLI(scfg.ModalCLI):
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
    destroy = VMDestroyCLI
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


__all__ = [
    'VMModalCLI',
    'VMUpCLI',
    'VMDownCLI',
    'VMRestartCLI',
    'VMCreateCLI',
    'VMWaitIPCLI',
    'VMStatusCLI',
    'VMDestroyCLI',
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
]
