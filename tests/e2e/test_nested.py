"""Opt-in end-to-end smoke test for nested VM workflows."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.e2e._helpers import (
    REPO_ROOT,
    _host_context_enabled,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
    apply_shared_image_cache,
    e2e_teardown,
    make_e2e_config,
    require_passwordless_sudo,
    save_e2e_store,
)

pytestmark = pytest.mark.e2e


def test_e2e_nested_smoke(tmp_path: Path) -> None:
    # Host-context e2e asserts the "normal developer machine" flow where tests
    # run directly on the host and manage one guest VM lifecycle.
    if not _host_context_enabled():
        pytest.skip(
            'Set AIVM_E2E_HOST_CONTEXT=1 (and AIVM_E2E=1) to run '
            'host-context e2e tests.'
        )

    home, priv, pub = _make_temp_ssh_material(tmp_path)
    env = os.environ.copy()
    env['HOME'] = str(home)

    # Require non-interactive sudo for unattended e2e.
    require_passwordless_sudo()

    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '2400'))
    _require_e2e_host_dependencies(cwd=REPO_ROOT, timeout_s=timeout_s, env=env)

    cfg_path = tmp_path / 'e2e-config.toml'
    cfg = make_e2e_config(tmp_path, priv=priv, pub=pub)
    apply_shared_image_cache(cfg)
    save_e2e_store(cfg_path, cfg)

    with e2e_teardown(cfg_path, env=env, timeout_s=timeout_s):
        _run_cli(
            ['host', 'net', 'create', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        _run_cli(
            ['vm', 'up', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        wait_res = _run_cli(
            ['vm', 'wait_ip', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        status_res = _run_cli(
            ['status', '--sudo', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        combined = (wait_res.stdout + '\n' + status_res.stdout).lower()
        assert 'vm ip' in combined or 'cached vm ip' in combined
        assert 'vm state' in combined
