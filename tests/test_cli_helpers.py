"""Tests for test cli helpers."""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

from aivm.config import AgentVMConfig
from aivm.cli._common import _confirm_external_file_update
from aivm.cli.main import _count_verbose, _normalize_argv
from aivm.cli.help import PlanCLI
from aivm.cli.vm import (
    _auto_share_tag_for_path,
    _parse_sync_paths_arg,
    _upsert_ssh_config_entry,
)


def test_normalize_argv_aliases() -> None:
    assert _normalize_argv(['init']) == ['config', 'init']
    assert _normalize_argv(['ls']) == ['list']
    assert _normalize_argv(['attach', '.']) == ['attach', '--host_src', '.']
    assert _normalize_argv(['code', '.']) == ['code', '--host_src', '.']
    assert _normalize_argv(['vm', 'wait-ip']) == ['vm', 'wait_ip']
    assert _normalize_argv(['vm', 'sync-settings']) == ['vm', 'sync_settings']


def test_count_verbose() -> None:
    assert _count_verbose([]) == 0
    assert _count_verbose(['--verbose']) == 1
    assert _count_verbose(['-v']) == 1
    assert _count_verbose(['-vvv', '--verbose']) == 4


def test_parse_sync_paths_arg() -> None:
    got = _parse_sync_paths_arg(' ~/.gitconfig, ,~/.bashrc,')
    assert got == ['~/.gitconfig', '~/.bashrc']


def test_auto_share_tag_collision() -> None:
    p = Path('/tmp/my project')
    tag1 = _auto_share_tag_for_path(p, set())
    tag2 = _auto_share_tag_for_path(p, {tag1})
    assert tag1 != ''
    assert tag2 != tag1
    assert len(tag2) <= 36


def test_confirm_external_file_update_yes_noninteractive(
    monkeypatch,
) -> None:
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    _confirm_external_file_update(
        yes=True,
        path=Path('/tmp/ssh-config'),
        purpose='Update SSH entry',
    )


def test_confirm_external_file_update_requires_yes_noninteractive(
    monkeypatch,
) -> None:
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    with pytest.raises(RuntimeError, match='Re-run with --yes'):
        _confirm_external_file_update(
            yes=False,
            path=Path('/tmp/ssh-config'),
            purpose='Update SSH entry',
        )


def test_confirm_external_file_update_abort(monkeypatch) -> None:
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr(builtins, 'input', lambda _: 'n')
    with pytest.raises(RuntimeError, match='Aborted by user'):
        _confirm_external_file_update(
            yes=False,
            path=Path('/tmp/ssh-config'),
            purpose='Update SSH entry',
        )


def test_upsert_ssh_config_no_confirm_when_unchanged(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('HOME', str(tmp_path))
    cfg = AgentVMConfig()
    _upsert_ssh_config_entry(cfg, dry_run=False, yes=True)

    # Should not require --yes when no file update is needed.
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    _upsert_ssh_config_entry(cfg, dry_run=False, yes=False)


def test_plan_omits_default_config_flag(monkeypatch, capsys) -> None:
    default = Path('/tmp/default-config.toml')
    monkeypatch.setattr(
        'aivm.cli.help._cfg_path',
        lambda p: default if p is None else Path(p),
    )
    PlanCLI.main(argv=False, config=None, yes=True)
    out = capsys.readouterr().out
    assert '--config' not in out
    assert f'Config: {default}' in out


def test_plan_includes_nondefault_config_flag(monkeypatch, capsys) -> None:
    default = Path('/tmp/default-config.toml')
    custom = Path('/tmp/custom-config.toml')
    monkeypatch.setattr(
        'aivm.cli.help._cfg_path',
        lambda p: default if p is None else Path(p),
    )
    PlanCLI.main(argv=False, config=str(custom), yes=True)
    out = capsys.readouterr().out
    assert f'--config {custom}' in out
