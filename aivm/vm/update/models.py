"""Models shared by VM update detection, rendering, and application."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RestartKind(StrEnum):
    """How invasive a post-update restart needs to be.

    NONE  - no restart required (e.g. disk grow via qemu-img is live)
    SOFT  - guest-OS reboot only; qemu process persists
            (``virsh reboot``). Right for changes the guest reads on its
            own boot.
    HARD  - full power cycle; kill qemu and respawn it
            (``virsh shutdown`` + ``virsh start``). Required when the
            change is at the qemu/virtiofsd layer rather than inside the
            guest: CPU and RAM are configured with ``--config`` only and
            so are picked up on next qemu start, not on guest reboot;
            virtiofsd's ``<binary path>`` likewise can only change when
            qemu spawns a fresh virtiofsd.
    """

    NONE = 'none'
    SOFT = 'soft'
    HARD = 'hard'


def _escalate(current: RestartKind, candidate: RestartKind) -> RestartKind:
    """Return whichever of the two is "more invasive"."""
    order = {RestartKind.NONE: 0, RestartKind.SOFT: 1, RestartKind.HARD: 2}
    return current if order[current] >= order[candidate] else candidate


@dataclass(frozen=True)
class VirtiofsBinaryDrift:
    """A single ``<filesystem>`` device whose ``<binary path>`` is wrong.

    ``tag`` is the virtiofs target dir (the libvirt-side identifier);
    ``current`` is what the XML currently has (empty string if the
    ``<binary>`` element is absent); ``desired`` is the path we want
    libvirt to launch.
    """

    tag: str
    current: str
    desired: str


@dataclass(frozen=True)
class FdGuardDrift:
    """Guest-side virtiofs fd guard state that differs from config.

    ``action`` is ``install`` (covers first install, re-enable, and
    refreshing stale files after a config/aivm change — the install script
    is idempotent) or ``uninstall``. ``reason`` is the human-readable
    explanation shown in the plan. ``ip`` carries the guest address the
    detection probe already verified so apply does not re-resolve it.
    """

    action: str
    reason: str
    ip: str = ''


@dataclass(frozen=True)
class VMUpdateDrift:
    cpus: tuple[int, int] | None = None
    ram_mb: tuple[int, int] | None = None
    disk_bytes: tuple[int, int] | None = None
    disk_path: str = ''
    virtiofs_binary: tuple[VirtiofsBinaryDrift, ...] = ()
    virtiofsd_mode: str = ''
    fd_guard: FdGuardDrift | None = None
    notes: tuple[str, ...] = ()

    def has_changes(self) -> bool:
        return any(
            (
                self.cpus,
                self.ram_mb,
                self.disk_bytes,
                self.virtiofs_binary,
                self.fd_guard,
            )
        )
