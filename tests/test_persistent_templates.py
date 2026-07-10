"""Determinism of the persistent replay helper and service-unit templates."""

from __future__ import annotations

import subprocess

from tests.persistent_helpers import _exec_guest_replay_helper


def test_exec_guest_replay_helper_does_not_leak_subprocess_run() -> None:
    from aivm.persistent_replay import persistent_replay_python

    original_run = subprocess.run
    ns = _exec_guest_replay_helper(persistent_replay_python())

    assert ns['subprocess'] is not subprocess
    ns['subprocess'].run = lambda *a, **k: None
    assert subprocess.run is original_run


def test_persistent_replay_templates_are_deterministic_in_process() -> None:
    from aivm.persistent_replay import (
        persistent_host_replay_python,
        persistent_host_replay_service_unit,
        persistent_replay_python,
        persistent_replay_service_unit,
    )

    helper_a = persistent_replay_python()
    helper_b = persistent_replay_python()
    host_helper_a = persistent_host_replay_python()
    host_helper_b = persistent_host_replay_python()
    unit_a = persistent_replay_service_unit()
    unit_b = persistent_replay_service_unit()
    host_unit_a = persistent_host_replay_service_unit(
        vm_name='vm',
        manifest_path='/tmp/manifest.json',
        export_root='/tmp/export-root',
    )
    host_unit_b = persistent_host_replay_service_unit(
        vm_name='vm',
        manifest_path='/tmp/manifest.json',
        export_root='/tmp/export-root',
    )

    assert helper_a == helper_b
    assert host_helper_a == host_helper_b
    assert unit_a == unit_b
    assert host_unit_a == host_unit_b


def test_persistent_replay_service_unit_waits_for_guest_manifest() -> None:
    from aivm.persistent_replay import (
        PERSISTENT_ATTACHMENT_GUEST_STATE_PATH,
        persistent_replay_service_unit,
    )

    unit = persistent_replay_service_unit()

    assert f'ConditionPathExists={PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}' in unit


def test_persistent_host_replay_service_unit_renders_values() -> None:
    from aivm.persistent_replay import (
        PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX,
        persistent_host_replay_service_unit,
    )

    unit = persistent_host_replay_service_unit(
        vm_name='vm',
        manifest_path='/tmp/manifest.json',
        export_root='/tmp/export-root',
    )

    assert (
        f'Description={PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX}-vm'
        in unit
    )
    assert 'ConditionPathExists=/tmp/manifest.json' in unit
    assert '{service_name}' not in unit
    assert '{manifest_path}' not in unit
