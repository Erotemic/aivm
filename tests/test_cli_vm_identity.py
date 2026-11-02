"""``aivm vm identity_*``: expected refusals are error lines, never tracebacks.

Runs the real CLI against :func:`managed_world` -- a real machine store and
identity authority -- with only ssh and virsh faked at the process boundary.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aivm.errors import UserDeclinedError
from aivm.secrets_identity_vm import resolve_managed_identity
from aivm_secrets.identity.certificates import create_csr
from aivm_secrets.identity.enrollment import IdentityAuthority
from tests.helpers import FakeProc, capture_logs, patch_command_runtime, run_cli
from tests.test_secrets_vm_enrollment_transport import (
    UUID,
    ManagedWorld,
    managed_world,
)


def _enroll_out_of_band(world: ManagedWorld) -> None:
    """An already-enrolled guest: key, CSR and certificate installed."""
    subject = resolve_managed_identity(world.context, world.store,
                                       uuid_reader=lambda _: UUID).subject
    directory = world.identity_dir
    directory.mkdir(parents=True, mode=0o700)
    fingerprint = create_csr(private_key=directory / 'client.key',
                             request_file=directory / 'client.csr')
    record = IdentityAuthority(world.authority_root).enroll(
        subject=subject, csr=(directory / 'client.csr').read_bytes(),
        approve_fingerprint=fingerprint)
    (directory / 'client.pem').write_bytes(Path(record['certificate']).read_bytes())


def _argv(world: ManagedWorld, command: str, *extra: str) -> list[str]:
    return ['vm', command, '--vm', 'lab',
            '--identity_root', str(world.authority_root), *extra]


@pytest.mark.parametrize('command, enrolled', [
    pytest.param('identity_enroll', False, id='enroll'),
    pytest.param('identity_renew', True, id='renew'),
    pytest.param('identity_rotate_key', True, id='rotate_key'),
])
def test_old_forced_helper_is_an_error_line_and_exit_status_1(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, enrolled: bool) -> None:
    """B7: the actionable detail reaches the operator; no traceback."""
    world = managed_world(tmp_path, monkeypatch)
    if enrolled:
        _enroll_out_of_band(world)
    before = IdentityAuthority(world.authority_root).status()['subjects']
    # An existing guest whose helper predates identity-csr refuses it.
    world.host.hooks['bootstrap'] = lambda proceed: FakeProc(
        2, '', '{"error": "unsupported guestctl operation", "status": "error"}')
    errors = capture_logs(monkeypatch, 'aivm.cli.vm_identity.log',
                          levels=('error',))
    assert run_cli(_argv(world, command, '--yes')) == 1
    assert errors == [
        'Identity operation failed: Secret session guest setup failed. '
        '(forced CSR bootstrap failed; guest helper upgrade may be required)']
    assert IdentityAuthority(world.authority_root).status()['subjects'] == before


def test_enroll_reports_the_issued_certificate(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    world = managed_world(tmp_path, monkeypatch)
    assert run_cli(_argv(world, 'identity_enroll', '--yes')) == 0
    row = world.row()
    assert row is not None and row['active'] is True
    out = capsys.readouterr().out
    assert 'Enrolled certificate-bound identity for lab' in out
    assert f"Certificate SHA-256: {row['certificate_sha256']}" in out
    assert 'Enrollment epoch: 0' in out


def test_a_declined_prompt_is_the_users_refusal_not_an_error_line(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A refusal is never caught by the identity CLI or turned into exit 1."""
    world = managed_world(tmp_path, monkeypatch)
    prompts = patch_command_runtime(monkeypatch, world.host, answer='n')
    errors = capture_logs(monkeypatch, 'aivm.cli.vm_identity.log',
                          levels=('error',))
    with pytest.raises(UserDeclinedError):
        run_cli(_argv(world, 'identity_enroll'))
    assert prompts  # the forced-bootstrap step really asked
    assert not world.host.ran('bootstrap')
    assert errors == []
    assert world.row() is None


def test_rotate_key_cli_is_exported_with_its_siblings() -> None:
    import aivm.cli.vm as vm_cli

    assert {'VMIdentityEnrollCLI', 'VMIdentityRenewCLI',
            'VMIdentityRotateKeyCLI'} <= set(vm_cli.__all__)
    assert all(hasattr(vm_cli, name) for name in vm_cli.__all__)
