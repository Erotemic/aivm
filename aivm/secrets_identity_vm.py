"""Trusted AIVM adapter from managed libvirt VM to pure identity subject.

The other sibling package, ``aivm_secrets``, never imports AIVM. In particular
no guest-supplied VM name, username, path or UUID enters this binding.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aivm_secrets.errors import SecretsError

from .commands import CommandManager
from .config_store import find_principal, load_store
from .privilege import virsh_needs_sudo
from .runtime import virsh_cmd
from .config_scopes import ResolvedVMContext


def _vm_subject(binding: dict[str, object]) -> str:
    """AIVM's independent adapter for the frozen v1 subject wire contract.

    The secret service does not get imported into AIVM. This small hash
    operation is independently checked against the Python and future Rust
    implementations through shared vectors. Only host-authoritative values
    can reach this function.
    """
    payload = json.dumps(binding, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    return 'vm-' + hashlib.sha256(b'aivm-secrets/managed-vm/v1\x00' + payload).hexdigest()

@dataclass(frozen=True)
class ManagedIdentity:
    subject: str
    vm: str
    uuid: str
    principal_id: str
    guest_user: str
    host_uid: int


def live_uuid(name: str) -> str:
    """Read the *live system-libvirt* domain identity, never guest output.

    This is the same system-libvirt read as every other ``virsh`` probe, so
    it escalates exactly when they do: a host user outside the libvirt group
    reaches ``qemu:///system`` only through sudo. It stays ``role='read'``,
    and an escalated read is still announced at INFO under the sudo
    call-out policy.
    """
    reply = CommandManager.current().run(
        virsh_cmd('domuuid', name), sudo=virsh_needs_sudo(), check=False,
        capture=True, role='read', timeout=15,
        summary='Identify the managed VM incarnation',
    )
    if reply.code:
        raise SecretsError('guest_setup', detail='libvirt UUID unavailable')
    candidate = reply.stdout.strip()
    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError):
        raise SecretsError('guest_setup', detail='invalid libvirt UUID') from None
    if str(parsed) != candidate:
        raise SecretsError('guest_setup', detail='noncanonical libvirt UUID')
    return candidate


def resolve_managed_identity(
    context: ResolvedVMContext, store: Path, *,
    uuid_reader: Callable[[str], str] = live_uuid,
) -> ManagedIdentity:
    """Fail closed unless the caller owns an active managed access identity."""
    principal = context.principal
    if (principal.state != 'active' or principal.host_uid != os.getuid()
            or not principal.id or not principal.guest_user):
        raise SecretsError('wrong_owner')
    # This is the machine authority selected by AIVM's own session resolver,
    # not an arbitrary path or store name supplied by the guest.
    store_path = Path(store).expanduser().resolve(strict=True)
    registry = load_store(store_path)
    if registry.store_kind != 'machine':
        raise SecretsError('denied', detail='requires a managed machine store')
    vm_name = context.machine.vm.name
    if sum(item.name == vm_name for item in registry.vms) != 1:
        raise SecretsError('denied', detail='VM is not uniquely managed')
    current = find_principal(registry, vm_name=vm_name, principal_id=principal.id)
    if (current is None or current.state != 'active'
            or current.host_uid != principal.host_uid
            or current.guest_user != principal.guest_user):
        raise SecretsError('wrong_owner')
    domain_uuid = uuid_reader(vm_name)
    binding = {
        'schema': 1,
        'store': hashlib.sha256(os.fsencode(store_path)).hexdigest(),
        'vm': vm_name,
        'domain_uuid': domain_uuid,
        'principal': principal.id,
        'host_uid': principal.host_uid,
        'guest_user': principal.guest_user,
    }
    return ManagedIdentity(
        subject=_vm_subject(binding), vm=vm_name, uuid=domain_uuid,
        principal_id=principal.id, guest_user=principal.guest_user,
        host_uid=principal.host_uid,
    )
