"""Optional Antigravity CLI provisioning without a real VM or network."""

from __future__ import annotations

import importlib
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.cli.vm_lifecycle import VMProvisionCLI
from aivm.config import AgentVMConfig
from aivm.vm.guest_tools import (
    GUEST_TOOL_REGISTRY,
    GuestToolSpecError,
    _build_antigravity_install_script,
)
from aivm.vm.provision import provision_guest_requirements
from tests.helpers import FakeCommandManager


def test_antigravity_opt_in_and_version_validation() -> None:
    cfg = AgentVMConfig()
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'antigravity')
    assert not resolved.enabled
    assert resolved.effective_spec == 'off'

    cfg.tools.antigravity = True
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'antigravity')
    assert resolved.enabled
    assert resolved.effective_spec == 'latest'
    assert resolved.definition.required_commands == ('agy',)

    for bad in ('stable', '1.4.0'):
        cfg.tools.antigravity = bad
        with pytest.raises(GuestToolSpecError, match='antigravity'):
            GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'antigravity')

    cfg.tools.antigravity = False
    assert not GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'antigravity').enabled



def test_antigravity_is_only_in_full_provision_when_configured() -> None:
    cfg = AgentVMConfig()
    assert not any(
        'antigravity.google/cli/install.sh' in script
        for script in GUEST_TOOL_REGISTRY.install_scripts(cfg)
    )
    cfg.tools.antigravity = 'latest'
    scripts = GUEST_TOOL_REGISTRY.install_scripts(cfg)
    assert sum('antigravity.google/cli/install.sh' in script for script in scripts) == 1
    assert 'curl' in GUEST_TOOL_REGISTRY.required_packages(cfg.tools)


def test_antigravity_script_bootstraps_curl_only_when_requested() -> None:
    cfg = AgentVMConfig()
    cfg.tools.bin_dir = '~/.custom/other-binaries'
    script = _build_antigravity_install_script(cfg, 'latest', True)
    assert 'apt-get install -y ca-certificates curl' in script
    assert 'if ! command -v curl >/dev/null 2>&1; then' in script
    assert (
        'curl -fsSL https://antigravity.google/cli/install.sh | '
        'bash -s -- --skip-aliases --skip-path'
    ) in script
    assert 'AGY_BIN="$HOME/.local/bin/agy"' in script
    assert '# >>> aivm antigravity PATH >>>' in script
    assert '"$AGY_BIN" --version' in script
    assert '~/.custom/other-binaries' not in script
    assert 'apt-get' not in _build_antigravity_install_script(
        cfg, 'latest', False
    )


def _fake_guest(tmp_path: Path, curl_body: str) -> tuple[dict[str, str], Path]:
    """Provide a fake curl so the real shell script cannot access the network."""
    home = tmp_path / 'guest home'
    home.mkdir(parents=True)
    fake_bin = tmp_path / 'stubs'
    fake_bin.mkdir()
    curl = fake_bin / 'curl'
    curl.write_text('#!/bin/sh\n' + curl_body, encoding='utf-8')
    curl.chmod(0o755)
    env = os.environ.copy()
    env.update(
        HOME=str(home),
        PATH=f'{fake_bin}:/usr/bin:/bin',
        CURL_LOG=str(tmp_path / 'curl.log'),
    )
    return env, home


def _run_guest(
    script: str, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ['bash', '-c', script],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_antigravity_shell_install_and_repeat_are_idempotent(
    tmp_path: Path,
) -> None:
    env, home = _fake_guest(
        tmp_path,
        r'''set -eu
printf '%s\n' "$*" >> "$CURL_LOG"
[ "$1" = '-fsSL' ]
[ "$2" = 'https://antigravity.google/cli/install.sh' ]
cat <<'INSTALLER'
set -eu
[ "$1" = '--skip-aliases' ]
[ "$2" = '--skip-path' ]
mkdir -p "$HOME/.local/bin"
printf '%s\n' '#!/bin/sh' 'echo agy-test-version' > "$HOME/.local/bin/agy"
chmod +x "$HOME/.local/bin/agy"
INSTALLER
''',
    )
    script = _build_antigravity_install_script(AgentVMConfig(), 'latest', False)

    first = _run_guest(script, env)
    assert first.returncode == 0, first.stderr
    assert 'agy-test-version' in first.stdout
    assert (home / '.local/bin/agy').is_file()
    profile = home / '.profile'
    assert profile.read_text().count('# >>> aivm antigravity PATH >>>') == 1
    assert (tmp_path / 'curl.log').read_text().splitlines() == [
        '-fsSL https://antigravity.google/cli/install.sh'
    ]

    second = _run_guest(script, env)
    assert second.returncode == 0, second.stderr
    assert profile.read_text().count('# >>> aivm antigravity PATH >>>') == 1
    assert len((tmp_path / 'curl.log').read_text().splitlines()) == 1

    login = _run_guest('. "$HOME/.profile"; command -v agy; agy --version', env)
    assert login.returncode == 0, login.stderr
    assert str(home / '.local/bin/agy') in login.stdout
    assert 'agy-test-version' in login.stdout


def test_antigravity_shell_refuses_failed_download_or_missing_executable(
    tmp_path: Path,
) -> None:
    for kind, curl_body in (
        ('download', 'exit 37\n'),
        ('missing', 'exit 0\n'),
    ):
        env, home = _fake_guest(tmp_path / kind, curl_body)
        script = _build_antigravity_install_script(
            AgentVMConfig(), 'latest', False
        )
        result = _run_guest(script, env)
        assert result.returncode != 0
        assert not (home / '.profile').exists()
        if kind == 'missing':
            assert '~/.local/bin/agy was not found' in result.stderr


def test_antigravity_status_probe_handles_non_login_path(tmp_path: Path) -> None:
    home = tmp_path / 'guest'
    (home / '.local/bin').mkdir(parents=True)
    agy = home / '.local/bin/agy'
    agy.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
    agy.chmod(0o755)
    env = os.environ.copy()
    env.update(HOME=str(home), PATH='/usr/bin:/bin')
    fragment = GUEST_TOOL_REGISTRY.require('antigravity').status_check
    assert fragment is not None
    assert _run_guest(fragment, env).returncode == 0
    agy.unlink()
    missing = _run_guest(fragment, env)
    assert missing.returncode == 11
    assert 'antigravity:agy' in missing.stderr


def test_antigravity_target_is_narrow_and_does_not_mutate_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    transport = SimpleNamespace(
        ssh_identity_file='/tmp/id_ed25519',
        ssh_target=lambda ip: f'agent@{ip}',
    )
    provision_mod = importlib.import_module('aivm.vm.provision')
    monkeypatch.setattr(
        provision_mod, 'guest_transport_from_effective_cfg',
        lambda cfg: transport,
    )
    monkeypatch.setattr(
        provision_mod, 'require_ssh_identity', lambda path: '/tmp/id_ed25519'
    )
    manager = FakeCommandManager()
    monkeypatch.setattr(provision_mod.CommandManager, 'current', lambda: manager)

    provision_guest_requirements(cfg, '10.77.0.103', tools=('antigravity',))
    assert len(manager.calls) == 1
    script = str(manager.calls[0][-1])
    assert 'https://antigravity.google/cli/install.sh' in script
    assert 'https://claude.ai/install.sh' not in script
    assert 'https://astral.sh/uv' not in script
    assert 'docker.io' not in script
    assert script.count('sudo apt-get update -y') == 1
    assert cfg.tools.antigravity == 'off'


def test_antigravity_is_valid_positional_cli_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    monkeypatch.setattr('aivm.cli.vm_lifecycle.load_cfg', lambda *a, **k: cfg)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.cfg_path', lambda *a, **k: cfg_path
    )
    captured: dict[str, object] = {}

    def fake_provision(
        received: AgentVMConfig,
        ip: str,
        *,
        packages: tuple[str, ...] = (),
        tools: tuple[str, ...] = (),
        dry_run: bool,
    ) -> None:
        captured.update(
            cfg=received, ip=ip, packages=packages, tools=tools,
            dry_run=dry_run,
        )

    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements', fake_provision
    )
    rc = VMProvisionCLI.main(
        argv=False, config=str(cfg_path), tools=['antigravity'], dry_run=True
    )
    assert rc == 0
    assert captured['tools'] == ('antigravity',)
    assert captured['packages'] == ()
    assert captured['dry_run'] is True
    assert cfg.tools.antigravity == 'off'
