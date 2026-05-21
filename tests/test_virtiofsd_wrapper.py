"""Tests for legacy virtiofsd wrapper cleanup plumbing.

AIVM no longer installs generated host-side virtiofsd wrappers in normal
managed-libvirt mode. These tests keep enough recognition logic to remove old
wrapper paths from existing VM XML and to preserve config round-trips.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aivm import config, config_store as store
from aivm.vm import update, virtiofsd_wrapper

BASE = '/var/lib/libvirt/aivm'
PREFER_PATH = f'{BASE}/virtiofsd-wrapper-prefer.sh'
PREFER_NOEXT_PATH = f'{BASE}/virtiofsd-wrapper-prefer'
NEVER_PATH = f'{BASE}/virtiofsd-wrapper-never.sh'
MANDATORY_PATH = f'{BASE}/virtiofsd-wrapper-mandatory.sh'


def test_normalize_mode_disables_generated_host_wrappers() -> None:
    assert virtiofsd_wrapper.normalize_mode('prefer') == ''
    assert virtiofsd_wrapper.normalize_mode('PREFER') == ''
    assert virtiofsd_wrapper.normalize_mode('  mandatory  ') == ''
    assert virtiofsd_wrapper.normalize_mode('never') == ''
    assert virtiofsd_wrapper.normalize_mode('') == ''
    assert virtiofsd_wrapper.normalize_mode(None) == ''
    assert virtiofsd_wrapper.normalize_mode('bogus') == ''


def test_wrapper_path_is_mode_suffixed() -> None:
    assert virtiofsd_wrapper.wrapper_path(BASE, 'prefer') == PREFER_PATH
    assert virtiofsd_wrapper.wrapper_path(BASE, 'never') == NEVER_PATH
    assert virtiofsd_wrapper.wrapper_path(BASE, 'mandatory') == MANDATORY_PATH


def test_wrapper_path_rejects_invalid_mode() -> None:
    with pytest.raises(ValueError):
        virtiofsd_wrapper.wrapper_path(BASE, '')
    with pytest.raises(ValueError):
        virtiofsd_wrapper.wrapper_path(BASE, 'bogus')


def test_desired_binary_path_never_returns_generated_wrapper() -> None:
    assert virtiofsd_wrapper.desired_binary_path(BASE, 'prefer') is None
    assert virtiofsd_wrapper.desired_binary_path(BASE, '') is None
    assert virtiofsd_wrapper.desired_binary_path(BASE, 'bogus') is None


def test_is_managed_wrapper_path_matches_any_mode_suffix() -> None:
    for p in (PREFER_PATH, PREFER_NOEXT_PATH, NEVER_PATH, MANDATORY_PATH):
        assert virtiofsd_wrapper.is_managed_wrapper_path(BASE, p), p
    assert not virtiofsd_wrapper.is_managed_wrapper_path(BASE, '')
    assert not virtiofsd_wrapper.is_managed_wrapper_path(
        BASE, '/usr/libexec/virtiofsd'
    )


def test_is_managed_wrapper_path_recognizes_historical_default_base() -> None:
    # Repair must still work if the current config has a custom paths.base_dir.
    assert virtiofsd_wrapper.is_managed_wrapper_path('/other', PREFER_PATH)
    assert virtiofsd_wrapper.is_managed_wrapper_path(
        '/other', '/var/lib/libvirt/aivm/aivm-2404/virtiofsd-wrapper-prefer.sh'
    )
    assert not virtiofsd_wrapper.is_managed_wrapper_path(
        '/other', '/tmp/virtiofsd-wrapper-prefer.sh'
    )


def test_wrapper_content_is_disabled() -> None:
    with pytest.raises(RuntimeError, match='host-side virtiofsd wrappers are disabled'):
        virtiofsd_wrapper.wrapper_content('prefer')


def test_virtiofs_config_defaults_to_managed_libvirt() -> None:
    cfg = config.AgentVMConfig()
    assert cfg.virtiofs.inode_file_handles == ''


def test_behavior_config_unchanged_by_virtiofs_relocation() -> None:
    # Defensive: confirm the field stayed off BehaviorConfig where it
    # never belonged.
    bc = config.BehaviorConfig()
    assert not hasattr(bc, 'virtiofsd_inode_file_handles')
    assert not hasattr(bc, 'inode_file_handles')


def test_store_round_trips_virtiofs_per_vm(tmp_path: Path) -> None:
    reg = store.Store()
    cfg = config.AgentVMConfig()
    cfg.vm.name = 'aivm-rt'
    cfg.virtiofs.inode_file_handles = 'mandatory'
    store.upsert_vm_with_network(reg, cfg, network_name='aivm-net')

    f = tmp_path / 'config.toml'
    store.save_store(reg, f)
    written = f.read_text()
    assert '[vms.virtiofs]' in written
    assert 'inode_file_handles = "mandatory"' in written

    loaded = store.load_store(f)
    [vm] = loaded.vms
    assert vm.cfg.virtiofs.inode_file_handles == 'mandatory'

    # Empty round-trip should preserve the empty string.
    cfg.virtiofs.inode_file_handles = ''
    store.upsert_vm_with_network(reg, cfg, network_name='aivm-net')
    store.save_store(reg, f)
    loaded2 = store.load_store(f)
    [vm2] = loaded2.vms
    assert vm2.cfg.virtiofs.inode_file_handles == ''


def _xml_with_two_virtiofs_devices(wrapper_path: str | None) -> str:
    second_binary = (
        f"<binary path='{wrapper_path}'/>" if wrapper_path else ''
    )
    return textwrap.dedent(
        f"""\
        <domain>
          <devices>
            <filesystem type='mount'>
              <driver type='virtiofs'/>
              <source dir='/srv/a'/>
              <target dir='aivm-shared-root'/>
            </filesystem>
            <filesystem type='mount'>
              <driver type='virtiofs'/>
              {second_binary}
              <source dir='/srv/b'/>
              <target dir='aivm-persistent-root'/>
            </filesystem>
          </devices>
        </domain>
        """
    )


def _cfg_with_mode(mode: str) -> config.AgentVMConfig:
    cfg = config.AgentVMConfig()
    cfg.vm.name = 'aivm-test'
    cfg.paths.base_dir = BASE
    cfg.virtiofs.inode_file_handles = mode
    return cfg


def test_drift_detection_ignores_requested_prefer_when_no_wrapper_present() -> None:
    cfg = _cfg_with_mode('prefer')
    mode, drift = update._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=None)
    )
    assert mode == ''
    assert drift == ()


def test_drift_detection_removes_old_wrapper_even_if_config_requests_prefer() -> None:
    cfg = _cfg_with_mode('prefer')
    mode, drift = update._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=PREFER_PATH)
    )
    assert mode == ''
    tags = [d.tag for d in drift]
    assert tags == ['aivm-persistent-root']
    assert drift[0].current == PREFER_PATH
    assert drift[0].desired == ''


def test_drift_detection_reverse_when_wrapper_disabled() -> None:
    cfg = _cfg_with_mode('')
    # Even a different-mode wrapper counts as "managed" and should be
    # reverted to default when the config disables overrides.
    mode, drift = update._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=NEVER_PATH)
    )
    assert mode == ''
    tags = [d.tag for d in drift]
    assert tags == ['aivm-persistent-root']
    assert drift[0].current == NEVER_PATH
    assert drift[0].desired == ''



def test_drift_detection_repairs_wrapper_even_when_base_dir_changed() -> None:
    cfg = _cfg_with_mode('')
    cfg.paths.base_dir = '/custom/aivm-base'
    mode, drift = update._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=PREFER_PATH)
    )
    assert mode == ''
    assert [d.tag for d in drift] == ['aivm-persistent-root']
    assert drift[0].current == PREFER_PATH
    assert drift[0].desired == ''
