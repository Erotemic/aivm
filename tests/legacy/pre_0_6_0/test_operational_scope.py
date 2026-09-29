"""Operational output compatibility for pre-0.6.0 stores."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.config_store import Store, save_store
from aivm.operational_scope import (
    announce_vm_machine_impact,
    vm_machine_impact,
)


def test_legacy_store_has_no_machine_impact_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / 'legacy.toml'
    save_store(Store(), path, reason='test legacy impact')

    assert vm_machine_impact(path, 'legacy-vm') is None
    announce_vm_machine_impact(path, 'legacy-vm', action='restart')
    assert capsys.readouterr().out == ''
