"""Tests for test config."""

from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from aivm.config import (
    AgentVMConfig,
    default_host_label,
    default_vm_name,
    dump_toml,
    load,
    save,
)


def test_dump_load_roundtrip(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'my "vm"'
    cfg.paths.state_dir = '~/code/${USER}/state'
    cfg.verbosity = 3
    fpath = tmp_path / '.aivm.toml'
    save(fpath, cfg)

    cfg2 = load(fpath)
    assert cfg2.vm.name == cfg.vm.name
    assert cfg2.paths.state_dir == cfg.paths.state_dir
    assert cfg2.verbosity == 3


def test_dump_toml_verbosity_default_omitted() -> None:
    cfg = AgentVMConfig()
    text = dump_toml(cfg)
    assert 'verbosity =' not in text


def test_expanded_paths_expands_env(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv('AIVM_TEST_DIR', '/tmp/aivm-x')
    cfg = AgentVMConfig()
    cfg.paths.state_dir = '$AIVM_TEST_DIR/state'
    cfg.paths.ssh_identity_file = '$AIVM_TEST_DIR/id_ed25519'
    out = cfg.expanded_paths()
    assert out.paths.state_dir == '/tmp/aivm-x/state'
    assert out.paths.ssh_identity_file == '/tmp/aivm-x/id_ed25519'


def test_default_allows_password_login() -> None:
    cfg = AgentVMConfig()
    assert cfg.vm.allow_password_login is True


def test_default_vm_name_uses_sanitized_short_hostname(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.config.socket.gethostname', lambda: 'Build_Box.example.test'
    )
    cfg = AgentVMConfig()
    assert cfg.vm.name == 'aivm-2404-build-box'
    assert default_host_label('Build_Box.example.test') == 'build-box'
    assert default_vm_name('Build_Box.example.test') == 'aivm-2404-build-box'


def test_default_vm_name_is_guest_hostname_safe() -> None:
    long_host = 'Very_Long.Hostname_' + ('x' * 100)
    got = default_vm_name(long_host)
    assert got.startswith('aivm-2404-very-long')
    assert len(got) <= 63
    assert got == got.lower()
    assert '_' not in got
    assert '.' not in got
