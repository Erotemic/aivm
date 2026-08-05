"""Fixtures scoped to support for releases before AIVM 0.6.0."""

from __future__ import annotations

from pathlib import Path

import pytest

from .scenario import SharedMachineScenario, make_shared_machine_scenario


@pytest.fixture
def shared_machine_scenario(tmp_path: Path) -> SharedMachineScenario:
    return make_shared_machine_scenario(tmp_path)


@pytest.fixture(autouse=True)
def _stub_domain_claim(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Neutralize the libvirt write that claims a migrated domain.

    ``virsh metadata --set`` is a genuine process boundary against a live
    domain, and it is the only real command apply would run in a suite that
    already injects the guest installer and runtime verifier. Tests that
    assert on the claim itself opt out with ``@pytest.mark.claims_domains``.
    """
    if request.node.get_closest_marker('claims_domains'):
        return
    monkeypatch.setattr(
        'aivm.legacy.pre_0_6_0.migration_apply.stamp_domain_authority',
        lambda *args, **kwargs: None,
    )
