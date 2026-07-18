"""Tests for guest developer tool provisioning helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from aivm.config import AgentVMConfig, dump_toml, load
from aivm.vm.lifecycle import (
    _guest_ensure_code_script,
    _guest_ensure_rust_script,
    _guest_ensure_uv_script,
    _guest_tool_code_enabled,
    _guest_tool_rust_enabled,
    _guest_tool_rust_spec,
    _guest_tool_uv_enabled,
    _uv_installer_url,
)


def test_uv_installer_url_latest_and_versioned() -> None:
    assert _uv_installer_url('latest') == 'https://astral.sh/uv/install.sh'
    assert _uv_installer_url('') == 'https://astral.sh/uv/install.sh'
    assert (
        _uv_installer_url('0.11.11')
        == 'https://astral.sh/uv/0.11.11/install.sh'
    )


def test_guest_uv_tool_spec_can_be_disabled() -> None:
    cfg = AgentVMConfig()
    assert _guest_tool_uv_enabled(cfg) is True
    cfg.tools.uv = 'off'
    assert _guest_tool_uv_enabled(cfg) is False
    setattr(cfg.tools, 'uv', False)
    assert _guest_tool_uv_enabled(cfg) is False


def test_guest_ensure_uv_script_is_standalone_and_not_snap() -> None:
    cfg = AgentVMConfig()
    cfg.tools.uv = '0.11.11'
    cfg.tools.bin_dir = '~/.local/aivm/bin'
    script = _guest_ensure_uv_script(cfg, ensure_transport=True)
    assert 'https://astral.sh/uv/0.11.11/install.sh' in script
    assert 'UV_INSTALL_DIR="$INSTALL_DIR"' in script
    assert 'UV_NO_MODIFY_PATH=1' in script
    assert '# >>> aivm tools PATH >>>' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert '~/.local/aivm/bin' in script
    assert 'snap' not in script.lower()


@pytest.mark.parametrize(
    ('bin_dir', 'expected'),
    [
        ('~/.local/bin', '/tmp/aivm-fakehome/.local/bin'),
        ('~/.local/aivm/bin', '/tmp/aivm-fakehome/.local/aivm/bin'),
        ('~', '/tmp/aivm-fakehome'),
        ('/opt/aivm/bin', '/opt/aivm/bin'),
    ],
)
def test_guest_ensure_uv_script_expands_tilde_install_dir(
    bin_dir: str, expected: str
) -> None:
    """Regression: ``${INSTALL_DIR#~/}`` tilde-expanded the pattern itself,
    so the prefix never matched and provision created a literal ``~``
    directory under ``$HOME``."""
    if shutil.which('bash') is None:
        pytest.skip('bash not available')
    cfg = AgentVMConfig()
    cfg.tools.bin_dir = bin_dir
    script = _guest_ensure_uv_script(cfg, ensure_transport=False)
    # Run only the tilde-resolution prologue so the test never invokes
    # curl/wget or the real uv installer.
    prologue_end = script.index('esac') + len('esac')
    prologue = script[:prologue_end] + '\necho "$INSTALL_DIR"\n'
    result = subprocess.run(
        ['bash', '-c', prologue],
        env={'HOME': '/tmp/aivm-fakehome', 'PATH': '/usr/bin:/bin'},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == expected


def test_guest_rust_tool_spec_can_be_enabled_or_disabled() -> None:
    cfg = AgentVMConfig()
    assert _guest_tool_rust_enabled(cfg) is False
    cfg.tools.rust = 'stable'
    assert _guest_tool_rust_enabled(cfg) is True
    assert _guest_tool_rust_spec(cfg) == 'stable'
    cfg.tools.rust = 'latest'
    assert _guest_tool_rust_spec(cfg) == 'stable'
    cfg.tools.rust = '1.83.0'
    assert _guest_tool_rust_spec(cfg) == '1.83.0'
    cfg.tools.rust = 'off'
    assert _guest_tool_rust_enabled(cfg) is False
    setattr(cfg.tools, 'rust', False)
    assert _guest_tool_rust_enabled(cfg) is False


def test_guest_ensure_rust_script_uses_rustup_and_not_snap() -> None:
    cfg = AgentVMConfig()
    cfg.tools.rust = '1.83.0'
    script = _guest_ensure_rust_script(cfg, ensure_transport=True)
    assert 'https://sh.rustup.rs' in script
    assert '--default-toolchain "$RUST_TOOLCHAIN"' in script
    assert 'RUST_TOOLCHAIN=1.83.0' in script
    assert '--profile minimal' in script
    assert '--no-modify-path' in script
    assert 'CARGO_HOME' in script
    assert 'RUSTUP_HOME' in script
    assert '# >>> aivm rust PATH >>>' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert 'snap' not in script.lower()


def test_guest_code_tool_default_off_and_opt_in() -> None:
    cfg = AgentVMConfig()
    # code is off by default — it is only useful for VS Code Remote Tunnels
    # users and should not be installed into every VM.
    assert _guest_tool_code_enabled(cfg) is False
    cfg.tools.code = 'latest'
    assert _guest_tool_code_enabled(cfg) is True
    cfg.tools.code = 'off'
    assert _guest_tool_code_enabled(cfg) is False
    setattr(cfg.tools, 'code', False)
    assert _guest_tool_code_enabled(cfg) is False


def test_guest_ensure_code_script_uses_microsoft_apt_repo_not_snap() -> None:
    cfg = AgentVMConfig()
    script = _guest_ensure_code_script(cfg, ensure_transport=True)
    assert 'packages.microsoft.com/keys/microsoft.asc' in script
    assert 'packages.microsoft.com/repos/code' in script
    assert '/etc/apt/keyrings/packages.microsoft.gpg' in script
    assert '/etc/apt/sources.list.d/vscode.sources' in script
    assert 'apt-get install -y code' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert 'snap' not in script.lower()


def test_tools_config_roundtrip(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.tools.uv = '0.11.11'
    cfg.tools.rust = 'stable'
    cfg.tools.code = 'latest'  # opt in (default is "off")
    cfg.tools.bin_dir = '~/.local/aivm/bin'
    text = dump_toml(cfg)
    assert '[tools]' in text
    assert 'uv = "0.11.11"' in text
    assert 'rust = "stable"' in text
    assert 'code = "latest"' in text
    assert 'bin_dir = "~/.local/aivm/bin"' in text
    assert 'install_uv' not in text
    assert 'uv_install_dir' not in text
    assert 'rust_install' not in text
    fpath = tmp_path / 'config.toml'
    fpath.write_text(text, encoding='utf-8')
    loaded = load(fpath)
    assert loaded.tools.uv == '0.11.11'
    assert loaded.tools.rust == 'stable'
    assert loaded.tools.code == 'latest'
    assert loaded.tools.bin_dir == '~/.local/aivm/bin'


def test_tools_config_default_dumps_code_off(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    text = dump_toml(cfg)
    assert 'code = "off"' in text
    fpath = tmp_path / 'config.toml'
    fpath.write_text(text, encoding='utf-8')
    assert load(fpath).tools.code == 'off'
