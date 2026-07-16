"""Tests for interactive and non-interactive behavior of `aivm config init`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.cli.config import InitCLI
from aivm.config import AgentVMConfig
from tests.helpers import patch_ns, records, returns

INIT_NS = 'aivm.cli.config.init'


def _fake_defaults_cfg(tmp_path: Path) -> AgentVMConfig:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-init-test'
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.paths.ssh_pubkey_path = str(tmp_path / 'id_ed25519.pub')
    return cfg


def test_config_init_noninteractive_requires_yes_or_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(False),
        },
    )
    with pytest.raises(RuntimeError, match='--yes or --defaults'):
        InitCLI.main(
            argv=False, config=str(cfg_path), yes=False, defaults=False
        )


def test_config_init_noninteractive_defaults_flag_bypasses_prompt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(False),
        },
    )
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=True
    )
    assert rc == 0
    assert cfg_path.exists()
    text = cfg_path.read_text(encoding='utf-8')
    assert '[defaults.vm]' in text
    assert 'name = "aivm-init-test"' in text
    assert '[[vms]]' not in text


def test_config_init_interactive_shows_summary_and_accepts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg_path = tmp_path / 'config.toml'
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
        },
    )
    monkeypatch.setattr('builtins.input', lambda _: '')
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert 'Detected defaults for `aivm config init`' in out
    assert 'vm.name' in out
    assert 'aivm-init-test' in out
    assert 'ssh-keygen -t ed25519' in out


def test_config_init_interactive_can_create_dedicated_aivm_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    fake_home = tmp_path / 'home'
    ssh_dir = fake_home / '.ssh'

    def fake_defaults_missing_keys(
        cfg: AgentVMConfig, project_dir: Path
    ) -> AgentVMConfig:
        del cfg, project_dir
        out = AgentVMConfig()
        out.vm.name = 'aivm-init-test'
        out.paths.ssh_identity_file = ''
        out.paths.ssh_pubkey_path = ''
        return out

    class Proc:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = ''
            self.stderr = ''

    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> Proc:
        del kwargs
        normalized = [str(c) for c in cmd]
        if normalized[:2] == ['mkdir', '-p']:
            ssh_dir.mkdir(parents=True, exist_ok=True)
            return Proc()
        if normalized[:2] == ['chmod', '700']:
            return Proc()
        if normalized[:4] == ['ssh-keygen', '-q', '-t', 'ed25519']:
            key_path = Path(normalized[5])
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text('PRIVATE', encoding='utf-8')
            Path(str(key_path) + '.pub').write_text('PUBLIC', encoding='utf-8')
            return Proc()
        raise AssertionError(f'unexpected command: {cmd}')

    answers = iter(['', ''])
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': fake_defaults_missing_keys,
            'sys.stdin.isatty': returns(True),
        },
    )
    monkeypatch.setattr('aivm.services.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda _: next(answers))
    monkeypatch.setattr(
        'aivm.services.which', lambda cmd: '/usr/bin/ssh-keygen'
    )
    monkeypatch.setattr('aivm.commands.subprocess.run', fake_subprocess_run)
    monkeypatch.setattr(
        'aivm.services.Path.home', staticmethod(lambda: fake_home)
    )

    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )

    assert rc == 0
    text = cfg_path.read_text(encoding='utf-8')
    assert 'id_aivm_ed25519' in text


def test_config_init_defaults_warns_when_ssh_keys_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg_path = tmp_path / 'config.toml'
    log_calls: list[Any] = []
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(False),
            'log.warning': records(log_calls),
        },
    )
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=True
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert 'SSH keypair not detected' in out
    assert 'ssh-keygen -t ed25519' in out
    assert log_calls


def test_config_init_prompt_mentions_editor_and_prompt_shortcuts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
        },
    )
    prompts = []

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return ''

    monkeypatch.setattr('builtins.input', fake_input)
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )
    assert rc == 0
    assert any('(e=editor, p=prompt-by-prompt)' in p for p in prompts)


def test_config_init_interactive_edit_updates_hardware(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
        },
    )
    answers = iter(
        [
            'p',  # use prompt-by-prompt flow
            '',  # vm.name
            '',  # vm.user
            '2',  # vm.cpus
            '3072',  # vm.ram_mb
            '24',  # vm.disk_gb
            'n',  # vm.allow_password_login
            '',  # network.name
            '',  # network.subnet_cidr
            '',  # network.gateway_ip
            '',  # network.dhcp_start
            '',  # network.dhcp_end
            '',  # paths.ssh_identity_file
            '',  # paths.ssh_pubkey_path
            'y',  # confirm
        ]
    )
    monkeypatch.setattr('builtins.input', lambda _: next(answers))
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )
    assert rc == 0
    text = cfg_path.read_text(encoding='utf-8')
    assert 'cpus = 2' in text
    assert 'ram_mb = 3072' in text
    assert 'disk_gb = 24' in text


def test_config_init_logs_resource_warnings_from_shared_checker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    logged: list[Any] = []
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'vm_resource_warning_lines': returns(['resource warning test']),
            'log.warning': records(logged),
        },
    )
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=True
    )
    assert rc == 0
    assert any('resource warning test' in str(args) for args, _ in logged)


def test_config_init_summary_shows_password_login_default(
    tmp_path: Path,
) -> None:
    from aivm.cli.config import _render_init_default_summary

    cfg = _fake_defaults_cfg(tmp_path)
    cfg.vm.allow_password_login = True
    text = _render_init_default_summary(cfg, tmp_path / 'config.toml')
    assert 'vm.allow_password_login: true' in text
    assert 'enables password login on console and SSH' in text
    assert 'vm.password: (configured)' in text


def test_config_init_interactive_edit_updates_password_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
        },
    )
    answers = iter([
        'p',  # prompt-by-prompt values
        '',  # vm.name
        '',  # vm.user
        '',  # vm.cpus
        '',  # vm.ram_mb
        '',  # vm.disk_gb
        'y',  # vm.allow_password_login
        '',  # network.name
        '',  # network.subnet_cidr
        '',  # network.gateway_ip
        '',  # network.dhcp_start
        '',  # network.dhcp_end
        '',  # paths.ssh_identity_file
        '',  # paths.ssh_pubkey_path
        'y',  # confirm
    ])
    monkeypatch.setattr('builtins.input', lambda _: next(answers))
    monkeypatch.setattr(
        'aivm.cli.config.init.getpass.getpass', lambda _: 'debug-pass'
    )
    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )
    assert rc == 0
    text = cfg_path.read_text(encoding='utf-8')
    assert 'allow_password_login = true' in text
    assert 'password = "debug-pass"' in text


def test_config_init_editor_path_shows_full_table_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg_path = tmp_path / 'config.toml'

    def fake_edit(path: Path, command: list[str]) -> None:
        assert command == ['fake-editor']
        text = path.read_text(encoding='utf-8')
        path.write_text(text.replace('cpus = 4', 'cpus = 3'), encoding='utf-8')

    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
            'select_editor_command': returns(['fake-editor']),
            'edit_path': fake_edit,
        },
    )
    answers = iter(['e', 'y'])
    monkeypatch.setattr('builtins.input', lambda _: next(answers))

    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert out.count('Detected defaults for `aivm config init`') == 1
    assert 'Updated values' in out
    assert 'cpus = 3' in cfg_path.read_text(encoding='utf-8')


def test_config_init_editor_unavailable_falls_back_to_prompts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'

    def fake_prompt_edit(cfg: AgentVMConfig) -> AgentVMConfig:
        cfg.vm.cpus = 5
        return cfg

    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
            'select_editor_command': returns(None),
            '_edit_init_defaults_with_prompts': fake_prompt_edit,
        },
    )
    answers = iter(['e', 'y'])
    monkeypatch.setattr('builtins.input', lambda _: next(answers))

    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )

    assert rc == 0
    assert 'cpus = 5' in cfg_path.read_text(encoding='utf-8')


def test_config_init_invalid_editor_document_can_be_reopened(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    calls = 0

    def fake_edit(path: Path, command: list[str]) -> None:
        nonlocal calls
        del command
        calls += 1
        text = path.read_text(encoding='utf-8')
        if calls == 1:
            text = text.replace('cpus = 4', 'cpuz = 3')
        else:
            text = text.replace('cpuz = 3', 'cpus = 3')
        path.write_text(text, encoding='utf-8')

    patch_ns(
        monkeypatch,
        INIT_NS,
        {
            'cfg_path': returns(cfg_path),
            'auto_defaults': returns(_fake_defaults_cfg(tmp_path)),
            'sys.stdin.isatty': returns(True),
            'select_editor_command': returns(['fake-editor']),
            'edit_path': fake_edit,
        },
    )
    answers = iter(['e', '', 'y'])
    monkeypatch.setattr('builtins.input', lambda _: next(answers))

    rc = InitCLI.main(
        argv=False, config=str(cfg_path), yes=False, defaults=False
    )

    assert rc == 0
    assert calls == 2
    assert 'cpus = 3' in cfg_path.read_text(encoding='utf-8')
