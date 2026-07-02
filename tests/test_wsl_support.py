"""Tests for WSL detection helpers and WSL-motivated error guidance."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.detect import running_under_wsl, systemd_is_pid1


def test_running_under_wsl_true_on_microsoft_kernel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / 'version'
    fake.write_text(
        'Linux version 6.18.33.2-microsoft-standard-WSL2 (root@host) ...\n',
        encoding='utf-8',
    )
    real_read_text = Path.read_text

    def fake_read_text(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(self) == '/proc/version':
            return real_read_text(fake, *args, **kwargs)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    assert running_under_wsl() is True


def test_running_under_wsl_false_on_plain_kernel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / 'version'
    fake.write_text(
        'Linux version 6.8.0-110-generic (buildd@lcy02) ...\n',
        encoding='utf-8',
    )
    real_read_text = Path.read_text

    def fake_read_text(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(self) == '/proc/version':
            return real_read_text(fake, *args, **kwargs)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    assert running_under_wsl() is False


def test_systemd_is_pid1_reads_proc_1_comm() -> None:
    # On any host able to run this suite, /proc/1/comm exists; the helper
    # must return a bool and agree with the file's content.
    comm = Path('/proc/1/comm').read_text(encoding='utf-8').strip()
    assert systemd_is_pid1() is (comm == 'systemd')


def test_doctor_wsl_diagnostics_silent_off_wsl(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from aivm.cli import host as host_cli

    monkeypatch.setattr(host_cli, 'running_under_wsl', lambda: False)
    assert host_cli._print_wsl_diagnostics() is False
    assert capsys.readouterr().out == ''


def test_doctor_wsl_diagnostics_flags_missing_kvm_and_systemd(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from aivm.cli import host as host_cli

    monkeypatch.setattr(host_cli, 'running_under_wsl', lambda: True)
    monkeypatch.setattr(host_cli, 'systemd_is_pid1', lambda: False)
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if str(self) == '/dev/kvm':
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, 'exists', fake_exists)
    assert host_cli._print_wsl_diagnostics() is True
    out = capsys.readouterr().out
    assert 'nestedVirtualization=true' in out
    assert 'systemd=true' in out


def test_attach_failure_guidance_mentions_vm_update_for_wrapper_drift() -> None:
    # The wrapper-drift hint lives in the live-attach failure text built in
    # _reconcile_attached_vm; assert the source carries the guidance so the
    # legacy-wrapper repair path (`aivm vm update`) is always suggested.
    repo_root = Path(__file__).resolve().parent.parent
    src = (repo_root / 'aivm' / 'attachments' / 'session.py').read_text(
        encoding='utf-8'
    )
    assert "virtiofsd-wrapper-" in src
    assert 'aivm vm update' in src
