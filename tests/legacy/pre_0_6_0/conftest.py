"""Fixtures scoped to support for releases before AIVM 0.6.0."""

from __future__ import annotations

from pathlib import Path

import pytest

from .scenario import SharedMachineScenario, make_shared_machine_scenario


@pytest.fixture
def shared_machine_scenario(tmp_path: Path) -> SharedMachineScenario:
    return make_shared_machine_scenario(tmp_path)
