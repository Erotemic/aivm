"""Coverage for the libvirt domain ownership marker.

The marker exists so that "one managed domain has at most one authoritative
record" is checked rather than assumed. Before two store layouts existed, a
host held one store and the property came for free; these tests pin the
behavior that replaces it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.domain_authority import (
    AUTHORITY_NAMESPACE,
    read_domain_authority,
    require_domain_authority,
    reset_authority_cache,
    stamp_domain_authority,
)
from aivm.errors import AIVMError
from aivm.machine_store import MachineStoreLayout
from tests.helpers import FakeProc, activate_manager, command_recorder

VM = 'aivm-2404'


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Ownership is memoized per process; a stale entry would leak."""
    reset_authority_cache()


def _stamp_xml(store_root: Path, user: str = 'joncrall') -> str:
    return f'<authority store="{store_root}" user="{user}"/>'


def _two_store_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> MachineStoreLayout:
    """A host carrying both a shared and a personal root.

    Only such a host can have a contested domain, and only such a host pays
    for the libvirt probe.
    """
    shared = tmp_path / 'shared'
    shared.mkdir()
    personal = tmp_path / 'personal'
    personal.mkdir()
    monkeypatch.delenv('AIVM_MACHINE_STORE_ROOT', raising=False)
    monkeypatch.setattr(
        'aivm.machine_store.DEFAULT_MACHINE_STORE_ROOT', shared
    )
    monkeypatch.setattr(
        'aivm.domain_authority.candidate_machine_store_roots',
        lambda: (shared, personal),
    )
    return MachineStoreLayout.from_root(personal)


def test_domain_claimed_by_another_store_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    layout = _two_store_host(monkeypatch, tmp_path)
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch,
        {
            'virsh metadata': FakeProc(
                stdout=_stamp_xml(tmp_path / 'shared', user='alice')
            )
        },
    )

    with pytest.raises(AIVMError) as caught:
        require_domain_authority(VM, layout)

    message = str(caught.value)
    assert VM in message
    assert str(tmp_path / 'shared') in message
    assert 'alice' in message
    # The remedy names the owning store, not a way to take the domain over.
    assert 'aivm config migrate plan' in message


def test_domain_claimed_by_this_store_is_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    layout = _two_store_host(monkeypatch, tmp_path)
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch,
        {'virsh metadata': FakeProc(stdout=_stamp_xml(layout.root))},
    )

    require_domain_authority(VM, layout)


def test_unstamped_domain_is_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Domains created before the marker existed must keep working.

    virsh exits nonzero when the namespace is absent. That is the ordinary
    state of every VM from an earlier release, not evidence of a rival owner.
    """
    layout = _two_store_host(monkeypatch, tmp_path)
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch,
        {
            'virsh metadata': FakeProc(
                returncode=1, stderr='metadata not found'
            )
        },
    )

    require_domain_authority(VM, layout)
    assert read_domain_authority(VM) is None


def test_single_store_host_never_probes_libvirt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A store that is not on disk owns nothing, so there is nothing to ask.

    This keeps the guard free on the ordinary single-user host: it runs on
    every VM load, and an unconditional virsh call there would put a probe
    (and under `as-needed`, a sudo announcement) in front of every command.
    """
    personal = tmp_path / 'personal'
    personal.mkdir()
    monkeypatch.setattr(
        'aivm.domain_authority.candidate_machine_store_roots',
        lambda: (tmp_path / 'absent-shared', personal),
    )
    activate_manager(monkeypatch, yes=True)
    rec = command_recorder(monkeypatch)

    require_domain_authority(VM, MachineStoreLayout.from_root(personal))

    assert rec.normalized == []


def test_stamp_records_the_owning_store_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'personal')
    activate_manager(monkeypatch, yes=True)
    rec = command_recorder(monkeypatch, {'virsh metadata': FakeProc()})

    stamp_domain_authority(VM, layout)

    cmd = rec.only('virsh', 'metadata')
    assert VM in cmd
    assert AUTHORITY_NAMESPACE in cmd
    # --config, not --live: the claim belongs to the persistent definition, so
    # it survives a shutdown and applies to a domain that is not running.
    assert '--config' in cmd
    assert '--live' not in cmd
    document = cmd[cmd.index('--set') + 1]
    assert str(layout.root) in document
