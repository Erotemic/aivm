"""Smoke tests that dry-run/help commands exit 0 without touching the host.

Each command runs against a sandboxed store with ``--yes`` (and
``--dry_run`` where the command would otherwise act), asserting the CLI
plans the work and returns success rather than executing it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.cli.config.show import ConfigFormatCLI
from tests.helpers import run_cli


@pytest.mark.parametrize(
    'argv',
    [
        pytest.param(['help', 'plan', '--yes'], id='help-plan'),
        pytest.param(['help', 'tree', '--yes'], id='help-tree'),
        pytest.param(['help', 'completion', '--yes'], id='help-completion'),
        pytest.param(
            ['host', 'net', 'create', '--yes', '--dry_run'],
            id='host-net-create',
        ),
        pytest.param(
            ['host', 'net', 'destroy', '--yes', '--dry_run'],
            id='host-net-destroy',
        ),
        pytest.param(
            ['host', 'fw', 'apply', '--yes', '--dry_run'],
            id='host-fw-apply',
        ),
        pytest.param(
            ['host', 'fw', 'remove', '--yes', '--dry_run'],
            id='host-fw-remove',
        ),
        pytest.param(['vm', 'wait_ip', '--yes', '--dry_run'], id='vm-wait_ip'),
        pytest.param(
            ['vm', 'flush_caches', '--yes', '--dry_run'],
            id='vm-flush_caches',
        ),
        pytest.param(['vm', 'delete', '--yes', '--dry_run'], id='vm-delete'),
        pytest.param(['vm', 'update', '--yes', '--dry_run'], id='vm-update'),
        pytest.param(
            ['vm', 'update', '--tpm', 'emulator', '--yes', '--dry_run'],
            id='vm-update-tpm',
        ),
        pytest.param(
            ['vm', 'provision', '--yes', '--dry_run'], id='vm-provision'
        ),
    ],
)
def test_dryrun_commands_with_yes(argv: list[str], cfg_path: Path) -> None:
    """Each planning command exits 0 against a sandboxed store."""
    assert run_cli([*argv, '--config', str(cfg_path)]) == 0


@pytest.mark.parametrize('tpm_args', [[], ['--tpm', 'emulator']])
@pytest.mark.parametrize('approval_args', [[], ['--yes']])
def test_vm_update_dryrun_skips_execution_and_preserves_store(
    monkeypatch: pytest.MonkeyPatch, cfg_path: Path,
    capsys: pytest.CaptureFixture[str], tpm_args: list[str],
    approval_args: list[str],
) -> None:
    before = cfg_path.read_bytes()

    def unexpected(*args, **kwargs):
        raise AssertionError('dry-run must not execute probes or prompt')

    monkeypatch.setattr('aivm.commands.subprocess.run', unexpected)
    monkeypatch.setattr('builtins.input', unexpected)
    monkeypatch.setattr('aivm.privilege.libvirt_without_sudo_ok', unexpected)
    assert run_cli([
        'vm', 'update', '--dry_run', '--config', str(cfg_path),
        *tpm_args, *approval_args,
    ]) == 0
    assert cfg_path.read_bytes() == before
    output = capsys.readouterr().out
    assert 'Live drift is unknown' in output
    assert 'already in sync' not in output
    assert 'Update complete' not in output
    if tpm_args:
        assert 'emulator TPM 2.0' in output
        assert 'virsh define --validate' in output


def test_help_tree_includes_one_line_descriptions(
    cfg_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`help tree` annotates each command with its one-line description."""
    assert run_cli(['help', 'tree', '--yes', '--config', str(cfg_path)]) == 0
    out = capsys.readouterr().out
    assert 'aivm help tree - Print the expanded aivm command tree.' in out
    assert (
        'aivm help raw - Print direct system-tool commands equivalent to common aivm checks.'
        in out
    )
    assert (
        'aivm help completion - Show shell-completion setup for aivm (argcomplete/kwconf).'
        in out
    )
    assert (
        'aivm vm ssh - SSH into the VM and start a shell in the mapped guest directory.'
        in out
    )


def test_common_short_aliases_parse_together(cfg_path: Path) -> None:
    """The conventional short forms map to the same CLI fields."""
    args = ConfigFormatCLI.cli(argv=['-n', '-y', '-c', str(cfg_path), '-f'])
    assert args.dry_run is True
    assert args.yes is True
    assert args.config == str(cfg_path)
    assert args.force is True
