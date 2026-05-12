"""Tests for the virtiofsd wrapper / inode-file-handles plumbing.

Covers the pure logic (no subprocess): mode normalization, wrapper-path
resolution (mode-suffixed), content generation, drift detection against
synthetic dumpxml input, and store round-trip of the new per-VM
``virtiofs.inode_file_handles`` field.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aivm import config, store
from aivm.vm import update_ops, virtiofsd_wrapper

BASE = '/var/lib/libvirt/aivm'
PREFER_PATH = f'{BASE}/virtiofsd-wrapper-prefer.sh'
NEVER_PATH = f'{BASE}/virtiofsd-wrapper-never.sh'
MANDATORY_PATH = f'{BASE}/virtiofsd-wrapper-mandatory.sh'


def test_normalize_mode_accepts_valid_and_rejects_garbage() -> None:
    assert virtiofsd_wrapper.normalize_mode('prefer') == 'prefer'
    assert virtiofsd_wrapper.normalize_mode('PREFER') == 'prefer'
    assert virtiofsd_wrapper.normalize_mode('  mandatory  ') == 'mandatory'
    assert virtiofsd_wrapper.normalize_mode('never') == 'never'
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


def test_desired_binary_path_returns_wrapper_for_valid_mode() -> None:
    assert virtiofsd_wrapper.desired_binary_path(BASE, 'prefer') == PREFER_PATH
    assert virtiofsd_wrapper.desired_binary_path(BASE, '') is None
    assert virtiofsd_wrapper.desired_binary_path(BASE, 'bogus') is None


def test_is_managed_wrapper_path_matches_any_mode_suffix() -> None:
    for p in (PREFER_PATH, NEVER_PATH, MANDATORY_PATH):
        assert virtiofsd_wrapper.is_managed_wrapper_path(BASE, p), p
    assert not virtiofsd_wrapper.is_managed_wrapper_path(BASE, '')
    assert not virtiofsd_wrapper.is_managed_wrapper_path(
        BASE, '/usr/libexec/virtiofsd'
    )
    # A different base_dir shouldn't claim our wrapper.
    assert not virtiofsd_wrapper.is_managed_wrapper_path('/other', PREFER_PATH)


def test_wrapper_content_has_exec_line_for_each_mode() -> None:
    for mode in ('never', 'prefer', 'mandatory'):
        body = virtiofsd_wrapper.wrapper_content(mode)
        assert body.startswith('#!/bin/bash\n')
        assert (
            f'exec /usr/libexec/virtiofsd --inode-file-handles={mode} "$@"'
            in body
        )


def test_wrapper_content_rejects_invalid_mode() -> None:
    with pytest.raises(ValueError):
        virtiofsd_wrapper.wrapper_content('bogus')


def test_virtiofs_config_defaults_to_prefer_per_vm() -> None:
    cfg = config.AgentVMConfig()
    assert cfg.virtiofs.inode_file_handles == 'prefer'


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


def test_drift_detection_finds_missing_and_default_binary() -> None:
    cfg = _cfg_with_mode('prefer')
    mode, drift = update_ops._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=None)
    )
    assert mode == 'prefer'
    tags = [d.tag for d in drift]
    assert tags == ['aivm-shared-root', 'aivm-persistent-root']
    assert all(d.desired == PREFER_PATH for d in drift)


def test_drift_detection_skips_correctly_wrapped_devices() -> None:
    cfg = _cfg_with_mode('prefer')
    mode, drift = update_ops._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=PREFER_PATH)
    )
    assert mode == 'prefer'
    tags = [d.tag for d in drift]
    # Only the first device (no <binary>) drifts; the second is already
    # pointing at the right wrapper.
    assert tags == ['aivm-shared-root']


def test_drift_detection_reverse_when_wrapper_disabled() -> None:
    cfg = _cfg_with_mode('')
    # Even a different-mode wrapper counts as "managed" and should be
    # reverted to default when the config disables overrides.
    mode, drift = update_ops._virtiofs_binary_drift(
        cfg, _xml_with_two_virtiofs_devices(wrapper_path=NEVER_PATH)
    )
    assert mode == ''
    tags = [d.tag for d in drift]
    assert tags == ['aivm-persistent-root']
    assert drift[0].current == NEVER_PATH
    assert drift[0].desired == ''
