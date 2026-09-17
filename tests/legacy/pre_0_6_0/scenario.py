"""Synthetic released-store scenario used only by pre-0.6 tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tests.helpers import make_cfg, write_store


@dataclass(frozen=True)
class SyntheticPrincipal:
    """One host user's identity and released per-user compatibility store."""

    host_user: str
    host_uid: int
    host_gid: int
    guest_user: str
    home: Path
    config_path: Path
    host_src: Path


@dataclass(frozen=True)
class SharedMachineScenario:
    """Two released user stores describing one synthetic machine identity."""

    vm_name: str
    machine_root: Path
    alice: SyntheticPrincipal
    bob: SyntheticPrincipal


def make_shared_machine_scenario(tmp_path: Path) -> SharedMachineScenario:
    """Create isolated Alice/Bob stores that describe the same released VM."""
    vm_name = 'aivm-2404-shared-host'
    machine_root = tmp_path / 'machine'
    base_dir = machine_root / 'libvirt'

    principals: dict[str, SyntheticPrincipal] = {}
    for username, uid, guest_user in (
        ('alice', 1001, 'alice-agent'),
        ('bob', 1002, 'bob-agent'),
    ):
        home = tmp_path / 'users' / username
        ssh_dir = home / '.ssh'
        config_path = home / '.config' / 'aivm' / 'config.toml'
        host_src = home / 'code' / 'project'
        ssh_dir.mkdir(parents=True)
        host_src.mkdir(parents=True)
        private_key = ssh_dir / 'id_aivm_ed25519'
        public_key = Path(str(private_key) + '.pub')
        private_key.write_text(f'PRIVATE-{username}\n', encoding='utf-8')
        public_key.write_text(
            f'ssh-ed25519 PUBLIC-{username}\n', encoding='utf-8'
        )

        cfg = make_cfg(
            None,
            **{
                'vm.name': vm_name,
                'vm.user': guest_user,
                'paths.base_dir': str(base_dir),
                'paths.state_dir': str(home / '.local' / 'state' / 'aivm'),
                'paths.ssh_identity_file': str(private_key),
                'paths.ssh_pubkey_path': str(public_key),
            },
        )
        write_store(config_path, cfg, active_vm=vm_name)
        principals[username] = SyntheticPrincipal(
            host_user=username,
            host_uid=uid,
            host_gid=uid,
            guest_user=guest_user,
            home=home,
            config_path=config_path,
            host_src=host_src,
        )

    return SharedMachineScenario(
        vm_name=vm_name,
        machine_root=machine_root,
        alice=principals['alice'],
        bob=principals['bob'],
    )
