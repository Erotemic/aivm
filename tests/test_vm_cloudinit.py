"""cloud-init seed generation for the guest.

Covers ``aivm.vm.cloudinit``: that the generated user-data avoids
datasource keys cloud-init would reject, that the seed ISO is unlinked
before ``cloud-localds`` rebuilds it in place, and that refreshing the
seed bumps the instance-id so the guest re-runs first-boot logic.
"""

from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.vm import refresh_cloud_init_seed_for_next_boot
from aivm.vm.cloudinit import _write_cloud_init
from tests.helpers import FakeProc, activate_manager, command_recorder


def _cfg_with_pubkey(tmp_path: Path) -> AgentVMConfig:
    """Build a config whose SSH pubkey exists under ``tmp_path``."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(tmp_path / 'base')
    pubkey_path = tmp_path / 'id_ed25519.pub'
    pubkey_path.write_text(
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey agent@test\n',
        encoding='utf-8',
    )
    cfg.paths.ssh_pubkey_path = str(pubkey_path)
    return cfg


def _heredoc_for(commands: list[list[str]], marker: str) -> str:
    """Return the ``bash -c 'cat > ...'`` script that writes ``marker``."""
    for cmd in commands:
        if (
            cmd[:2] == ['bash', '-c']
            and 'cat > ' in cmd[2]
            and marker in cmd[2]
        ):
            return cmd[2]
    raise AssertionError(f'no heredoc writing {marker!r} in {commands!r}')


def test_write_cloud_init_user_data_avoids_invalid_datasource_keys(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """The user-data omits datasource keys cloud-init would reject."""
    cfg = _cfg_with_pubkey(tmp_path)
    monkeypatch.setattr(
        'aivm.vm.cloudinit._ensure_qemu_access', lambda *a, **k: None
    )
    activate_manager(monkeypatch, isatty=True)
    rec = command_recorder(monkeypatch, {}, default=FakeProc(0, '', ''))

    _write_cloud_init(cfg, dry_run=False)

    user_data_script = _heredoc_for(rec.normalized, 'user-data')
    assert '#cloud-config' in user_data_script
    assert 'datasource_list:' not in user_data_script
    assert '\ndatasource:\n' not in user_data_script
    assert '  - rsync' in user_data_script
    assert (
        '/usr/local/libexec/aivm-persistent-attachment-replay'
        in user_data_script
    )
    assert 'aivm-persistent-attachment-replay.service' in user_data_script
    assert (
        'systemctl enable aivm-persistent-attachment-replay.service'
        in user_data_script
    )


def test_write_cloud_init_unlinks_seed_iso_before_rebuild(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """libvirt DAC relabeling can leave an existing seed ISO owned by
    libvirt-qemu, and cloud-localds truncates its target in place - so the
    rebuild must unlink the old seed (a directory-write operation) first.
    """
    cfg = _cfg_with_pubkey(tmp_path)
    monkeypatch.setattr(
        'aivm.vm.cloudinit._ensure_qemu_access', lambda *a, **k: None
    )
    activate_manager(monkeypatch, isatty=True)
    rec = command_recorder(monkeypatch, {}, default=FakeProc(0, '', ''))

    _write_cloud_init(cfg, dry_run=False)

    commands = rec.normalized
    rm_idx = [
        i
        for i, cmd in enumerate(commands)
        if cmd[:2] == ['rm', '-f'] and cmd[-1].endswith('seed.iso')
    ]
    localds_idx = [
        i for i, cmd in enumerate(commands) if cmd[:1] == ['cloud-localds']
    ]
    assert rm_idx and localds_idx
    assert rm_idx[0] < localds_idx[0]


def test_refresh_cloud_init_seed_for_next_boot_bumps_instance_id(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Refreshing the seed advances the instance-id for the next boot."""
    cfg = _cfg_with_pubkey(tmp_path)
    cfg.paths.state_dir = str(tmp_path / 'state')
    monkeypatch.setattr(
        'aivm.vm.cloudinit._ensure_qemu_access', lambda *a, **k: None
    )
    activate_manager(monkeypatch, isatty=True)
    rec = command_recorder(monkeypatch, {}, default=FakeProc(0, '', ''))

    refresh_cloud_init_seed_for_next_boot(cfg, dry_run=False)

    meta_data_script = _heredoc_for(rec.normalized, 'meta-data')
    assert 'instance-id: vmx-1' in meta_data_script
