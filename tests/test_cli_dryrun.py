"""Smoke tests that dry-run/help commands exit 0 without touching the host.

Each command runs against a sandboxed store with ``--yes`` (and
``--dry_run`` where the command would otherwise act), asserting the CLI
plans the work and returns success rather than executing it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import run_cli


@pytest.mark.parametrize(
    'argv',
    [
        pytest.param(['help', 'plan', '--yes'], id='help-plan'),
        pytest.param(['help', 'tree', '--yes'], id='help-tree'),
        pytest.param(
            ['help', 'completion', '--yes'], id='help-completion'
        ),
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
        pytest.param(
            ['vm', 'wait_ip', '--yes', '--dry_run'], id='vm-wait_ip'
        ),
        pytest.param(
            ['vm', 'flush_caches', '--yes', '--dry_run'],
            id='vm-flush_caches',
        ),
        pytest.param(
            ['vm', 'delete', '--yes', '--dry_run'], id='vm-delete'
        ),
        pytest.param(
            ['vm', 'provision', '--yes', '--dry_run'], id='vm-provision'
        ),
    ],
)
def test_dryrun_commands_with_yes(argv: list[str], cfg_path: Path) -> None:
    """Each planning command exits 0 against a sandboxed store."""
    assert run_cli([*argv, '--config', str(cfg_path)]) == 0


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
