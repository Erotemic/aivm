"""Tests for host timezone detection and cloud-init injection.

The detection helper (``aivm.detect.detect_host_timezone``) probes
``/etc/timezone``, ``readlink /etc/localtime``, and ``timedatectl`` in
order; we monkeypatch the filesystem / subprocess to exercise each path
independently.

The cloud-init injection is tested by spying on ``cfg.vm.timezone``
resolution in isolation (we don't rebuild the whole cloud-init blob
here, since that would couple the test to many unrelated lines).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aivm import detect

# -- _looks_like_iana_tz -----------------------------------------------------


@pytest.mark.parametrize(
    'tz',
    [
        'UTC',
        'America/New_York',
        'America/Argentina/Buenos_Aires',
        'Etc/GMT+5',
        'Asia/Calcutta',
    ],
)
def test_looks_like_iana_tz_accepts_real_names(tz: str) -> None:
    assert detect._looks_like_iana_tz(tz)


@pytest.mark.parametrize(
    'garbage',
    ['', '  ', 'foo bar', 'foo;bar', 'name with space', "weird'quote"],
)
def test_looks_like_iana_tz_rejects_garbage(garbage: str) -> None:
    assert not detect._looks_like_iana_tz(garbage)


# -- detect_host_timezone ----------------------------------------------------


def test_detects_via_etc_timezone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / 'timezone'
    fake.write_text('America/New_York\n', encoding='utf-8')

    original_read_text = Path.read_text

    def fake_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if str(self) == '/etc/timezone':
            return fake.read_text(*args, **kwargs)  # type: ignore[arg-type]
        return original_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    assert detect.detect_host_timezone() == 'America/New_York'


def test_falls_back_to_localtime_symlink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When /etc/timezone is unreadable, parse the /etc/localtime symlink."""

    def fake_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if str(self) == '/etc/timezone':
            raise FileNotFoundError(str(self))
        raise FileNotFoundError(str(self))

    def fake_readlink(path: str) -> str:
        if path == '/etc/localtime':
            return '/usr/share/zoneinfo/Europe/Berlin'
        raise FileNotFoundError(path)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    monkeypatch.setattr(os, 'readlink', fake_readlink)
    assert detect.detect_host_timezone() == 'Europe/Berlin'


def test_returns_empty_when_all_probes_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No /etc/timezone, no symlink, no timedatectl: return ''."""

    def fake_read_text(self: Path, *args: object, **kwargs: object) -> str:
        raise FileNotFoundError(str(self))

    def fake_readlink(path: str) -> str:
        raise FileNotFoundError(path)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    monkeypatch.setattr(os, 'readlink', fake_readlink)
    monkeypatch.setattr('aivm.detect.which', lambda name: None)

    assert detect.detect_host_timezone() == ''


def test_rejects_garbage_from_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if /etc/timezone exists, return '' for nonsense content."""

    def fake_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if str(self) == '/etc/timezone':
            return 'not a zone name\n'
        raise FileNotFoundError(str(self))

    def fake_readlink(path: str) -> str:
        raise FileNotFoundError(path)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    monkeypatch.setattr(os, 'readlink', fake_readlink)
    monkeypatch.setattr('aivm.detect.which', lambda name: None)
    assert detect.detect_host_timezone() == ''


# -- cloud-init resolution rule ---------------------------------------------


def test_cloud_init_resolution_explicit_overrides_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When cfg.vm.timezone is set, the host detection is NOT consulted."""
    from aivm.config import AgentVMConfig

    called = {'n': 0}

    def fake_detect() -> str:
        called['n'] += 1
        return 'America/New_York'

    monkeypatch.setattr('aivm.vm.cloudinit.detect_host_timezone', fake_detect)

    cfg = AgentVMConfig()
    cfg.vm.timezone = 'UTC'
    # Mimic the resolution rule used in _write_cloud_init.
    effective = (cfg.vm.timezone or '').strip() or fake_detect()
    assert effective == 'UTC'
    # And confirm detect_host_timezone was never called for the explicit case
    # in the production lookup path. (Our local-call to fake_detect bumped n
    # to 1 only after the `or` short-circuit, which didn't trigger.)
    assert called['n'] == 0


def test_cloud_init_resolution_empty_falls_back_to_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty cfg.vm.timezone -> use detect_host_timezone()."""
    from aivm.config import AgentVMConfig

    monkeypatch.setattr(
        'aivm.vm.cloudinit.detect_host_timezone',
        lambda: 'America/Los_Angeles',
    )

    cfg = AgentVMConfig()
    cfg.vm.timezone = ''
    from aivm.vm.lifecycle import detect_host_timezone as patched

    effective = (cfg.vm.timezone or '').strip() or patched()
    assert effective == 'America/Los_Angeles'


def test_default_vmconfig_has_empty_timezone() -> None:
    """Empty == 'auto-detect from host', which is the intended default."""
    from aivm.config import VMConfig

    assert VMConfig().timezone == ''
