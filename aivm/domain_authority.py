"""Which machine store owns a libvirt domain.

AIVM's rule that one managed domain has at most one authoritative record was
previously *emergent*: a host held one store, so a domain that appeared in it
was owned by it, and everything else was ``unmanaged``. Supporting a personal
store beside the shared one removes that guarantee, because two stores can
name the same domain and neither can see the other.

So ownership is recorded where the contested resource actually lives -- in the
domain's own libvirt ``<metadata>`` -- rather than inferred from which file
happened to be loaded. A store refuses to drive a domain another store
stamped, and says which one owns it. That also gives the pre-existing
``unmanaged same-name domain`` rule something to check instead of assume.

Domains created before this marker existed carry no stamp. An unstamped
domain is accepted: refusing would break every VM created by an earlier
release, and an absent stamp is not evidence of a competing owner.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .commands import CommandManager
from .errors import AIVMError
from .host_identity import current_host_identity
from .machine_store import (
    MachineStoreLayout,
    candidate_machine_store_roots,
)
from .privilege import virsh_needs_sudo
from .runtime import pin_locale, virsh_cmd
from .xmlutil import parse_domain_xml

#: Namespace for AIVM's domain metadata element. Versioned so a later schema
#: can be added beside this one rather than reinterpreting these documents.
AUTHORITY_NAMESPACE = 'https://github.com/Erotemic/aivm/xmlns/authority/1'

#: The XML prefix libvirt binds the namespace to in the stored document.
AUTHORITY_KEY = 'aivm'

_CACHE: dict[str, DomainAuthority | None] = {}


@dataclass(frozen=True)
class DomainAuthority:
    """The machine store that claims one libvirt domain."""

    store_root: Path
    host_user: str


def reset_authority_cache() -> None:
    """Forget probed ownership, for tests and after a stamp."""
    _CACHE.clear()


def _authority_element(text: str) -> DomainAuthority | None:
    root = parse_domain_xml(text)
    if root is None:
        return None
    store = str(root.attrib.get('store', '')).strip()
    if not store:
        return None
    return DomainAuthority(
        store_root=Path(store),
        host_user=str(root.attrib.get('user', '')).strip(),
    )


def read_domain_authority(vm_name: str) -> DomainAuthority | None:
    """Return the store that stamped ``vm_name``, or ``None`` if unstamped.

    A domain that does not exist, a libvirt that cannot be reached, and a
    domain with no AIVM metadata are all reported the same way: nothing
    claims it. None of them is a reason to fail a command that had other
    work to do, and each surfaces on its own in the flows that care.
    """
    if vm_name in _CACHE:
        return _CACHE[vm_name]
    mgr = CommandManager.current()
    result = mgr.run(
        pin_locale(
            virsh_cmd(
                'metadata',
                vm_name,
                '--uri',
                AUTHORITY_NAMESPACE,
                '--config',
            )
        ),
        role='read',
        sudo=virsh_needs_sudo(),
        check=False,
        capture=True,
    )
    found = (
        _authority_element(result.stdout)
        if result.code == 0 and result.stdout.strip()
        else None
    )
    _CACHE[vm_name] = found
    return found


def stamp_domain_authority(
    vm_name: str,
    layout: MachineStoreLayout,
    *,
    dry_run: bool = False,
) -> None:
    """Record ``layout`` as the owner of ``vm_name`` in libvirt metadata."""
    identity = current_host_identity().username
    document = f'<authority store="{layout.root}" user="{identity}"/>'
    if dry_run:
        print(f'DRYRUN: stamp {vm_name} as owned by {layout.root}')
        return
    mgr = CommandManager.current()
    # A libvirt too old for domain metadata, or a domain that vanished between
    # define and stamp, must not fail a VM that is otherwise created and
    # running. An unstamped domain is the pre-marker state, which every check
    # already accepts.
    with mgr.attempt(
        f'Record {vm_name} as owned by this AIVM store',
        why=(
            'A second machine store on this host can then tell that this '
            'domain is not its own.'
        ),
    ):
        with mgr.step(
            'Stamp domain ownership',
            why='Ownership belongs on the domain, not on a store file.',
            approval_scope='domain-authority-stamp',
        ):
            mgr.submit(
                virsh_cmd(
                    'metadata',
                    vm_name,
                    '--uri',
                    AUTHORITY_NAMESPACE,
                    '--key',
                    AUTHORITY_KEY,
                    '--set',
                    document,
                    '--config',
                ),
                sudo=virsh_needs_sudo(),
                role='modify',
                check=True,
                capture=True,
                summary=f'Record {vm_name} as owned by this AIVM store',
                detail=f'store={layout.root}',
            )
    reset_authority_cache()


def _competing_store_possible(layout: MachineStoreLayout) -> bool:
    """Return whether a second store could exist to contest this domain.

    A store that is not on disk owns nothing, so the usual single-store host
    answers no and never pays for the libvirt probe below. Only a host that
    has both roots -- one migrated from personal to shared, say -- has a
    question worth asking.
    """
    for root in candidate_machine_store_roots():
        if root == layout.root:
            continue
        if root.exists():
            return True
    return False


def require_domain_authority(vm_name: str, layout: MachineStoreLayout) -> None:
    """Refuse to act on a domain another machine store already claims."""
    if not _competing_store_possible(layout):
        return
    owner = read_domain_authority(vm_name)
    if owner is None or owner.store_root == layout.root:
        return
    who = f' by {owner.host_user}' if owner.host_user else ''
    raise AIVMError(
        f'Libvirt domain {vm_name!r} is owned by the AIVM machine store at '
        f'{owner.store_root}{who}, but this command is using the store at '
        f'{layout.root}.\n'
        'Two stores must never drive one domain: their attachment and '
        'principal records would each be half the truth. Use the owning '
        'store, or migrate this one into it with `aivm config migrate plan`.'
    )
