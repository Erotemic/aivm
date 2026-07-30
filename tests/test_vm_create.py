"""VM creation and the create-or-start reconcile path.

Covers ``aivm.vm.create``/``aivm.vm.lifecycle``: UEFI firmware fallback
during ``virt-install``, deciding whether to start/resume/refuse an
existing domain based on its state, and mapping raw ``virt-install``
failures (missing virtiofsd, unallocatable guest RAM) onto actionable
error messages.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager
from aivm.config import AgentVMConfig
from aivm.errors import AIVMError
from aivm.scoped_store import StoreScope
from aivm.util import CmdError, CmdResult
from aivm.vm import create_or_start_vm
from aivm.vm.domain import DomainRemovalReport
from tests.helpers import (
    FakeProc,
    activate_manager,
    command_recorder,
    is_locale_pinned,
    make_cfg,
)


def _stub_create_inputs(monkeypatch: MonkeyPatch) -> None:
    """Stub the image/seed/disk preparation that precedes ``virt-install``."""
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: False)
    monkeypatch.setattr(
        'aivm.vm.create.fetch_image', lambda *a, **k: Path('/tmp/base.img')
    )
    monkeypatch.setattr(
        'aivm.vm.create._write_cloud_init',
        lambda *a, **k: {'seed_iso': Path('/tmp/seed.iso')},
    )
    monkeypatch.setattr(
        'aivm.vm.create._ensure_disk', lambda *a, **k: Path('/tmp/vm.qcow2')
    )


def test_create_vm_fallback_when_uefi_firmware_missing(
    monkeypatch: MonkeyPatch,
) -> None:
    """A missing UEFI binary retries ``virt-install`` without ``--boot``."""
    cfg = AgentVMConfig()
    _stub_create_inputs(monkeypatch)

    calls = []

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        calls.append(cmd)
        if cmd[0] == 'virt-install' and '--boot' in cmd:
            raise CmdError(
                cmd,
                CmdResult(
                    1,
                    '',
                    'ERROR    Did not find any UEFI binary path for arch '
                    "'x86_64'",
                ),
            )
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)
    create_or_start_vm(
        cfg, dry_run=False, recreate=False, ensure_firewall=False
    )

    virt_calls = [c for c in calls if c and c[0] == 'virt-install']
    assert len(virt_calls) == 2
    assert '--memorybacking' in virt_calls[0]
    assert '--memorybacking' in virt_calls[1]
    assert '--tpm' in virt_calls[0]
    assert 'none' in virt_calls[0]
    assert '--tpm' in virt_calls[1]
    assert 'none' in virt_calls[1]
    assert '--boot' in virt_calls[0]
    assert 'uefi,loader.secure=no,bios.useserial=on' in virt_calls[0]
    assert '--boot' not in virt_calls[1]


def test_create_vm_prefers_uefi_even_when_host_looks_nested(
    monkeypatch: MonkeyPatch,
) -> None:
    """UEFI boot is attempted first even under nested virtualization."""
    cfg = AgentVMConfig()
    _stub_create_inputs(monkeypatch)

    calls = []

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        calls.append(cmd)
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)
    create_or_start_vm(
        cfg, dry_run=False, recreate=False, ensure_firewall=False
    )

    virt_calls = [c for c in calls if c and c[0] == 'virt-install']
    assert len(virt_calls) == 1
    assert '--memorybacking' in virt_calls[0]
    assert '--tpm' in virt_calls[0]
    assert 'none' in virt_calls[0]
    assert '--boot' in virt_calls[0]
    assert 'uefi,loader.secure=no,bios.useserial=on' in virt_calls[0]


def test_machine_store_create_seeds_bootstrap_public_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Only machine-store VM creation installs the enrollment bootstrap key."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    cfg.paths.base_dir = str(tmp_path / 'base')
    machine_config = tmp_path / 'machine' / 'config.toml'
    monkeypatch.setenv('AIVM_MACHINE_STORE_ROOT', str(machine_config.parent))
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: False)
    monkeypatch.setattr(
        'aivm.vm.create.fetch_image', lambda *a, **k: Path('/tmp/base.img')
    )
    monkeypatch.setattr(
        'aivm.vm.create._ensure_disk', lambda *a, **k: Path('/tmp/vm.qcow2')
    )
    monkeypatch.setattr(
        'aivm.vm.create.ensure_bootstrap_identity',
        lambda *a, **k: SimpleNamespace(
            public_key='ssh-ed25519 AAAABOOTSTRAP bootstrap@test'
        ),
    )
    captured: dict[str, str] = {}

    def fake_cloud_init(
        cfg: AgentVMConfig,
        *,
        dry_run: bool,
        bootstrap_public_key: str = '',
    ) -> dict[str, Path]:
        del cfg, dry_run
        captured['bootstrap_public_key'] = bootstrap_public_key
        return {'seed_iso': Path('/tmp/seed.iso')}

    monkeypatch.setattr('aivm.vm.create._write_cloud_init', fake_cloud_init)
    monkeypatch.setattr(
        'aivm.vm.create.CommandManager.run',
        lambda *a, **k: CmdResult(0, '', ''),
    )

    create_or_start_vm(
        cfg,
        dry_run=False,
        recreate=False,
        config_store_path=machine_config,
        ensure_firewall=False,
    )

    assert captured == {
        'bootstrap_public_key': 'ssh-ed25519 AAAABOOTSTRAP bootstrap@test'
    }


def test_create_or_start_existing_vm_uses_step_for_state_and_start(
    monkeypatch: MonkeyPatch,
) -> None:
    """An existing, stopped VM is inspected and started under a named step."""
    cfg = make_cfg(None, **{'vm.name': 'vm-existing'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)

    step_titles: list[str] = []
    orig_step = CommandManager.step

    def track_step(self: Any, title: str, **kwargs: Any) -> object:
        step_titles.append(title)
        return orig_step(self, title, **kwargs)

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.step', track_step)
    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, 'shut off\n', ''),
            'virsh start': FakeProc(0, '', ''),
        },
    )
    create_or_start_vm(
        cfg, dry_run=False, recreate=False, ensure_firewall=False
    )

    assert step_titles == ['Ensure existing VM is running']
    assert rec.normalized == [
        ['virsh', 'domstate', 'vm-existing'],
        ['virsh', 'start', 'vm-existing'],
    ]


def test_starting_an_existing_vm_verifies_the_firewall_first(
    monkeypatch: MonkeyPatch,
) -> None:
    """Starting a guest checks its sandbox rules, not only creating one.

    The managed nftables table lives in the live kernel ruleset, so a host
    reboot removes it while the VM definition survives. Without this, the
    first ``vm up`` after a reboot booted a guest with no sandbox rules and
    nothing said so.
    """
    cfg = make_cfg(None, **{'vm.name': 'vm-cold-boot'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch, yes_sudo=True)
    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, 'shut off\n', ''),
            'virsh start': FakeProc(0, '', ''),
            # The table is gone, as it always is after a host reboot.
            'nft list table': FakeProc(1, '', 'Error: No such file'),
            'nft': FakeProc(0, '', ''),
            'virsh net-dumpxml': FakeProc(
                0, "<network><bridge name='virbr-aivm'/></network>", ''
            ),
            # `sudo -n true`, normalized: credentials are already cached.
            'true': FakeProc(0),
        },
    )

    create_or_start_vm(cfg, dry_run=False, recreate=False)

    assert rec.ran('nft', 'list', 'table')
    assert rec.ran('nft', '-f')
    # ... and the rules are in place before the guest can use the bridge.
    assert rec.normalized.index(['nft', '-f', '-']) < rec.normalized.index(
        ['virsh', 'start', 'vm-cold-boot']
    )


def test_create_or_start_pins_c_locale_for_the_state_decision(
    monkeypatch: MonkeyPatch,
) -> None:
    """Start/resume/refuse is chosen by English state names, so pin them.

    Regression: this probe ran in the operator's locale, so on a localized
    host a perfectly ordinary stopped VM matched none of the branches and
    `aivm vm create` refused to start it as 'an unexpected state'.
    """
    cfg = make_cfg(None, **{'vm.name': 'vm-locale'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, 'shut off\n', ''),
            'virsh start': FakeProc(0, '', ''),
        },
    )

    create_or_start_vm(
        cfg, dry_run=False, recreate=False, ensure_firewall=False
    )

    assert [call for call in rec.calls if 'domstate' in call] == [
        call for call in rec.calls if is_locale_pinned(call)
    ]


@pytest.mark.parametrize('paused_state', ['paused', 'pmsuspended'])
def test_create_or_start_paused_vm_resumes_instead_of_starting(
    monkeypatch: MonkeyPatch, paused_state: str
) -> None:
    """A paused or suspended VM is resumed rather than started."""
    cfg = make_cfg(None, **{'vm.name': 'vm-paused'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)

    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, f'{paused_state}\n', ''),
            'virsh resume': FakeProc(0, '', ''),
        },
    )
    create_or_start_vm(
        cfg, dry_run=False, recreate=False, ensure_firewall=False
    )

    assert rec.normalized == [
        ['virsh', 'domstate', 'vm-paused'],
        ['virsh', 'resume', 'vm-paused'],
    ]
    assert not rec.ran('virsh', 'start'), (
        'paused VM must be resumed, not started'
    )


def test_create_or_start_shutting_down_vm_raises_friendly_error(
    monkeypatch: MonkeyPatch,
) -> None:
    """A VM mid-shutdown raises a clear error instead of racing it."""
    cfg = make_cfg(None, **{'vm.name': 'vm-shutting-down'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch, {'virsh domstate': FakeProc(0, 'in shutdown\n', '')}
    )

    with pytest.raises(RuntimeError, match='shutting down'):
        create_or_start_vm(
        cfg, dry_run=False, recreate=False, ensure_firewall=False
    )


def _run_virtiofsd_missing(
    self: object, cmd: list[str], **kwargs: Any
) -> CmdResult:
    del self, kwargs
    if cmd and cmd[0] == 'virt-install':
        raise CmdError(
            cmd,
            CmdResult(
                1,
                '',
                'operation failed: Unable to find a satisfying virtiofsd',
            ),
        )
    return CmdResult(0, '', '')


def _run_guest_memory_unavailable(
    self: object, cmd: list[str], **kwargs: Any
) -> CmdResult:
    del self, kwargs
    if cmd and cmd[0] == 'virt-install' and '--boot' in cmd:
        raise CmdError(
            cmd,
            CmdResult(
                1,
                '',
                "ERROR    Did not find any UEFI binary path for arch 'x86_64'",
            ),
        )
    if cmd and cmd[0] == 'virt-install':
        raise CmdError(
            cmd,
            CmdResult(
                1,
                '',
                "qemu-system-x86_64: cannot set up guest memory 'pc.ram': "
                'Cannot allocate memory',
            ),
        )
    return CmdResult(0, '', '')


@pytest.mark.parametrize(
    ('cfg_overrides', 'use_share', 'run_fn', 'match'),
    [
        pytest.param(
            {'vm.name': 'vmx'},
            True,
            _run_virtiofsd_missing,
            'virtiofsd is not available',
            id='when_virtiofsd_missing',
        ),
        pytest.param(
            {'vm.name': 'vmx', 'vm.ram_mb': 8192, 'vm.cpus': 4},
            False,
            _run_guest_memory_unavailable,
            'could not allocate guest RAM',
            id='when_guest_memory_unavailable',
        ),
    ],
)
def test_create_vm_raises_clear_error(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    cfg_overrides: dict[str, Any],
    use_share: bool,
    run_fn: Any,
    match: str,
) -> None:
    """Raw ``virt-install`` failures map onto actionable error messages.

    A missing virtiofsd binary and an unallocatable guest-memory failure
    both surface as ``RuntimeError`` with guidance rather than the opaque
    libvirt/qemu text.
    """
    cfg = make_cfg(**cfg_overrides)
    _stub_create_inputs(monkeypatch)
    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', run_fn)

    create_kwargs: dict[str, Any] = {}
    if use_share:
        create_kwargs = {
            'share_source_dir': str(tmp_path),
            'share_tag': 'hostcode',
        }

    with pytest.raises(RuntimeError, match=match):
        create_or_start_vm(
            cfg,
            dry_run=False,
            recreate=False,
            ensure_firewall=False,
            **create_kwargs,
        )


def _domain_storage_xml(*disks: tuple[str, object]) -> str:
    """Render ``virsh dumpxml`` output with one ``(device, path)`` per disk."""
    rendered = ''.join(
        f"<disk type='file' device='{device}'><source file='{path}'/></disk>"
        for device, path in disks
    )
    return f'<domain><devices>{rendered}</devices></domain>'


def test_recreate_refuses_to_continue_when_old_storage_remains(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Recreate never provisions over an incompletely deleted old VM."""
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-retained-storage'})
    retained = (
        Path(cfg.paths.base_dir)
        / 'vm-retained-storage'
        / 'images'
        / 'vm-retained-storage.qcow2'
    )
    cfg_path = tmp_path / 'config.toml'
    from aivm.config_store import Store, save_store

    save_store(Store(), cfg_path)
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch,
        {
            'virsh dominfo': FakeProc(0, 'Id: 1\n', ''),
            'virsh dumpxml': FakeProc(
                0, _domain_storage_xml(('disk', retained)), ''
            ),
        },
    )
    monkeypatch.setattr(
        'aivm.vm.create._destroy_and_undefine_vm',
        lambda name, *, storage_paths=None: DomainRemovalReport(
            (retained,), (retained,)
        ),
    )
    monkeypatch.setattr(
        'aivm.vm.create.fetch_image',
        lambda *a, **k: pytest.fail('new image preparation must not begin'),
    )

    with pytest.raises(AIVMError, match='storage remains'):
        create_or_start_vm(
            cfg,
            dry_run=False,
            recreate=True,
            config_store_path=cfg_path,
            ensure_firewall=False,
        )


@pytest.mark.parametrize(
    'external_device',
    [
        pytest.param('disk', id='external_disk'),
        pytest.param('cdrom', id='external_cdrom_media'),
    ],
)
def test_recreate_refuses_unmanaged_domain_storage(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    external_device: str,
) -> None:
    """Recreate never lets ``--remove-all-storage`` reach unmanaged files.

    A live domain disk outside the AIVM-managed tree --- a user-attached
    volume or inserted ISO --- refuses the recreate by name before any
    destructive libvirt command is issued.
    """
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-external-storage'})
    managed = (
        Path(cfg.paths.base_dir)
        / 'vm-external-storage'
        / 'images'
        / 'vm-external-storage.qcow2'
    )
    external = tmp_path / 'outside' / 'user-volume.img'
    cfg_path = tmp_path / 'config.toml'
    from aivm.config_store import Store, save_store

    save_store(Store(), cfg_path)
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            'virsh dominfo': FakeProc(0, 'Id: 1\n', ''),
            'virsh dumpxml': FakeProc(
                0,
                _domain_storage_xml(
                    ('disk', managed), (external_device, external)
                ),
                '',
            ),
        },
    )
    monkeypatch.setattr(
        'aivm.vm.create.fetch_image',
        lambda *a, **k: pytest.fail('new image preparation must not begin'),
    )

    with pytest.raises(AIVMError) as excinfo:
        create_or_start_vm(
            cfg,
            dry_run=False,
            recreate=True,
            config_store_path=cfg_path,
            ensure_firewall=False,
        )

    assert 'outside its AIVM-managed tree' in str(excinfo.value)
    assert 'Refusing recreate' in str(excinfo.value)
    assert str(external) in str(excinfo.value)
    assert not rec.ran('virsh', 'destroy')
    assert not rec.ran('virsh', 'undefine')


def test_create_or_start_refuses_unfinished_deletion_journal(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(None, **{'vm.name': 'vm-being-deleted'})
    cfg_path = tmp_path / 'config.toml'
    checked: list[Path] = []

    def block_creation(
        scope: StoreScope, checked_cfg: AgentVMConfig, path: Path
    ) -> None:
        assert scope.store_path == cfg_path.resolve()
        assert checked_cfg.vm.name == cfg.vm.name
        checked.append(path)
        raise AIVMError('unfinished deletion journal')

    monkeypatch.setattr(
        'aivm.vm.deletion.require_vm_creation_not_blocked', block_creation
    )

    with pytest.raises(AIVMError, match='unfinished deletion journal'):
        create_or_start_vm(
            cfg, config_store_path=cfg_path, ensure_firewall=False
        )

    assert checked == [cfg_path.resolve()]
