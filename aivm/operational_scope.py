"""Human-readable scope summaries for machine-wide operations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .access_control import TRUST_MODE
from .config_store import Store, load_store, network_users
from .scoped_store import resolve_store_scope


@dataclass(frozen=True)
class MachineImpact:
    """Non-secret inventory affected by one machine-global operation."""

    vm_count: int
    identity_count: int
    attachment_count: int
    credential_count: int

    def render(self, action: str, subject: str) -> str:
        return (
            f'Machine-wide action: {action} {subject}; affects '
            f'{self.vm_count} VM(s), {self.identity_count} access identity '
            f'record(s), {self.attachment_count} attachment record(s), and '
            f'{self.credential_count} credential record(s) '
            f'(trust_mode={TRUST_MODE}).'
        )


def _machine_store(path: Path) -> Store | None:
    scope = resolve_store_scope(str(path))
    if not scope.is_machine:
        return None
    return load_store(scope.store_path)


def vm_machine_impact(path: Path, vm_name: str) -> MachineImpact | None:
    """Return the global inventory affected by one VM operation."""
    reg = _machine_store(path)
    if reg is None:
        return None
    return MachineImpact(
        vm_count=sum(1 for item in reg.vms if item.name == vm_name),
        identity_count=sum(
            1 for item in reg.principals if item.vm_name == vm_name
        ),
        attachment_count=sum(
            1 for item in reg.attachments if item.vm_name == vm_name
        ),
        credential_count=sum(
            1 for item in reg.credentials if item.vm_name == vm_name
        ),
    )


def network_machine_impact(
    path: Path, network_name: str
) -> MachineImpact | None:
    """Return the global inventory affected by one network operation."""
    reg = _machine_store(path)
    if reg is None:
        return None
    vm_names = set(network_users(reg, network_name))
    return MachineImpact(
        vm_count=len(vm_names),
        identity_count=sum(
            1 for item in reg.principals if item.vm_name in vm_names
        ),
        attachment_count=sum(
            1 for item in reg.attachments if item.vm_name in vm_names
        ),
        credential_count=sum(
            1 for item in reg.credentials if item.vm_name in vm_names
        ),
    )


def announce_vm_machine_impact(
    path: Path, vm_name: str, *, action: str
) -> None:
    impact = vm_machine_impact(path, vm_name)
    if impact is not None:
        print(impact.render(action, f'VM {vm_name!r}'))


def announce_network_machine_impact(
    path: Path, network_name: str, *, action: str
) -> None:
    impact = network_machine_impact(path, network_name)
    if impact is not None:
        print(impact.render(action, f'network {network_name!r}'))


__all__ = [
    'MachineImpact',
    'announce_network_machine_impact',
    'announce_vm_machine_impact',
    'network_machine_impact',
    'vm_machine_impact',
]
