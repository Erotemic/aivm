"""Guards and fixtures shared by the end-to-end suite."""

from __future__ import annotations

import pytest

from tests.e2e._helpers import REPO_ROOT


@pytest.fixture(autouse=True)
def _assert_repo_root_resolves() -> None:
    """Fail loudly if ``REPO_ROOT`` no longer points at the checkout.

    Every e2e CLI subprocess runs ``python -m aivm`` with
    ``cwd=REPO_ROOT``.  If this package moves and ``REPO_ROOT`` silently
    resolves one directory too shallow, those subprocesses would run from
    the wrong tree instead of failing obviously --- so pin it here where
    any e2e run trips over it immediately.
    """
    assert (REPO_ROOT / 'pyproject.toml').exists(), (
        f'REPO_ROOT resolved to {REPO_ROOT}, which has no pyproject.toml; '
        'the e2e helpers can no longer locate the repo checkout.'
    )
