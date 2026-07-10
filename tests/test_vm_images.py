"""Base-image fetching, caching, and checksum verification.

Covers ``aivm.vm.images.fetch_image``: staging a download to a ``.part``
file before an atomic move, reusing or re-downloading a cached image
based on its checksum, verifying the Ubuntu SHA-256, accepting a
registry-listed ``file://`` source, rejecting unknown URLs/digests, and
the grouped step summaries shown in the operation preview.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Callable

import pytest
from pytest import MonkeyPatch

from aivm.config import DEFAULT_UBUNTU_NOBLE_IMG_URL, AgentVMConfig
from aivm.vm import fetch_image
from tests.helpers import (
    FakeLog,
    FakeProc,
    activate_manager,
    command_recorder,
    noop,
    patch_ns,
    returns,
)

_EXPECTED = '7aa6d9f5e8a3a55c7445b138d31a73d1187871211b2b7da9da2e1a6cbf169b21'


def _noble_cfg(
    tmp_path: Path, *, base_dir: Path | None = None
) -> AgentVMConfig:
    """Build a config that fetches the default Ubuntu Noble base image."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(base_dir if base_dir is not None else tmp_path)
    cfg.image.cache_name = 'noble-base.img'
    cfg.image.ubuntu_img_url = DEFAULT_UBUNTU_NOBLE_IMG_URL
    return cfg


def _sha_route(digest: str) -> Callable[[list[str]], FakeProc]:
    """Answer a ``sha256sum <file>`` call with ``digest``."""

    def route(cmd: list[str]) -> FakeProc:
        return FakeProc(0, f'{digest}  {cmd[-1]}\n', '')

    return route


def test_fetch_image_uses_atomic_temp_then_move(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """The download stages into a ``.part`` file, then moves it into place."""
    activate_manager(monkeypatch)
    cfg = _noble_cfg(tmp_path)
    patch_ns(
        monkeypatch,
        'aivm.vm.images',
        {'_sudo_file_exists': returns(False), '_ensure_qemu_access': noop},
    )
    rec = command_recorder(
        monkeypatch, {'sha256sum': _sha_route(_EXPECTED)}, default=FakeProc(0)
    )

    out = fetch_image(cfg, dry_run=False)
    assert out.name == 'noble-base.img'
    curl_calls = [c for c in rec.normalized if c[:1] == ['curl']]
    mv_calls = [c for c in rec.normalized if c[:1] == ['mv']]
    sha_calls = [c for c in rec.normalized if c[:1] == ['sha256sum']]
    assert len(curl_calls) == 1
    assert len(mv_calls) == 1
    assert len(sha_calls) == 1
    tmp_target = str(out) + '.part'
    assert tmp_target in curl_calls[0]
    assert tmp_target in mv_calls[0]
    assert str(out) in mv_calls[0]


def test_fetch_image_revalidates_cached_image_before_reuse(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A cached image with a good checksum is reused without downloading."""
    activate_manager(monkeypatch)
    cfg = _noble_cfg(tmp_path)
    patch_ns(
        monkeypatch, 'aivm.vm.images', {'_sudo_file_exists': returns(True)}
    )
    rec = command_recorder(
        monkeypatch, {'sha256sum': _sha_route(_EXPECTED)}, default=FakeProc(0)
    )

    out = fetch_image(cfg, dry_run=False)
    assert out.name == 'noble-base.img'
    assert rec.ran('sha256sum')
    assert not rec.ran('curl')
    assert not rec.ran('cp', '--reflink=auto')


def test_fetch_image_redownloads_when_cached_hash_is_stale(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A cached image with a stale checksum is removed and re-downloaded."""
    activate_manager(monkeypatch)
    cfg = _noble_cfg(tmp_path)
    patch_ns(
        monkeypatch,
        'aivm.vm.images',
        {'_sudo_file_exists': returns(True), '_ensure_qemu_access': noop},
    )
    sha_calls = {'n': 0}

    def sha_route(cmd: list[str]) -> FakeProc:
        sha_calls['n'] += 1
        digest = ('bad' * 21 + 'b') if sha_calls['n'] == 1 else _EXPECTED
        return FakeProc(0, f'{digest[:64]}  {cmd[-1]}\n', '')

    rec = command_recorder(
        monkeypatch, {'sha256sum': sha_route}, default=FakeProc(0)
    )

    out = fetch_image(cfg, dry_run=False)
    assert out.name == 'noble-base.img'
    assert rec.count('sha256sum') >= 2
    assert rec.ran('rm', '-f')
    assert rec.ran('curl')
    assert rec.ran('mv', '-f')


@pytest.mark.parametrize(
    ('digest', 'expect_error'),
    [
        pytest.param(_EXPECTED, False, id='validates_ubuntu_checksum'),
        pytest.param(
            'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
            True,
            id='raises_on_checksum_mismatch',
        ),
    ],
)
def test_fetch_image_checksum(
    monkeypatch: MonkeyPatch, tmp_path: Path, digest: str, expect_error: bool
) -> None:
    """The downloaded image is validated against the expected SHA-256.

    A matching checksum completes the fetch; a mismatch raises and removes
    the corrupt staging file.
    """
    activate_manager(monkeypatch)
    cfg = _noble_cfg(tmp_path)
    patch_ns(
        monkeypatch,
        'aivm.vm.images',
        {'_sudo_file_exists': returns(False), '_ensure_qemu_access': noop},
    )
    rec = command_recorder(
        monkeypatch,
        {'curl': FakeProc(0), 'sha256sum': _sha_route(digest)},
        default=FakeProc(0),
    )

    if expect_error:
        with pytest.raises(RuntimeError, match='checksum mismatch'):
            fetch_image(cfg, dry_run=False)
        assert rec.ran('rm', '-f')
    else:
        out = fetch_image(cfg, dry_run=False)
        assert out.name == 'noble-base.img'
        assert rec.ran('sha256sum')


@pytest.mark.parametrize(
    ('is_file', 'match'),
    [
        pytest.param(
            False,
            'not in the built-in verified image registry',
            id='unsupported_url',
        ),
        pytest.param(
            True,
            'digest is not in the built-in verified image registry',
            id='unsupported_file_url_digest',
        ),
    ],
)
def test_fetch_image_rejects(
    monkeypatch: MonkeyPatch, tmp_path: Path, is_file: bool, match: str
) -> None:
    """Images outside the verified registry are refused.

    An unknown ``https`` URL is rejected by URL, and a ``file://`` source
    whose digest is unknown is rejected by digest.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    if is_file:
        cfg.paths.base_dir = str(tmp_path / 'base')
        cfg.image.cache_name = 'noble-base.img'
        local_img = tmp_path / 'bad.img'
        local_img.write_bytes(b'corrupt-partial')
        cfg.image.ubuntu_img_url = f'file://{local_img}'
    else:
        cfg.paths.base_dir = str(tmp_path)
        cfg.image.cache_name = 'base.img'
        cfg.image.ubuntu_img_url = 'https://example.com/custom.img'
    patch_ns(
        monkeypatch, 'aivm.vm.images', {'_sudo_file_exists': returns(False)}
    )

    with pytest.raises(RuntimeError, match=match):
        fetch_image(cfg, dry_run=False)


def test_fetch_image_accepts_supported_file_url(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A registry-listed ``file://`` source is copied in via reflink+move."""
    activate_manager(monkeypatch)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.image.cache_name = 'noble-base.img'
    local_img = tmp_path / 'source.img'
    local_img.write_bytes(b'e2e-source-image')
    digest = sha256(local_img.read_bytes()).hexdigest()
    cfg.image.ubuntu_img_url = f'file://{local_img}'
    monkeypatch.setattr(
        'aivm.vm.images.SUPPORTED_IMAGE_SHA256',
        {DEFAULT_UBUNTU_NOBLE_IMG_URL: digest},
    )
    patch_ns(
        monkeypatch,
        'aivm.vm.images',
        {'_sudo_file_exists': returns(False), '_ensure_qemu_access': noop},
    )
    rec = command_recorder(
        monkeypatch, {'sha256sum': _sha_route(digest)}, default=FakeProc(0)
    )

    out = fetch_image(cfg, dry_run=False)
    assert out.name == 'noble-base.img'
    assert rec.ran('cp', '--reflink=auto')
    assert rec.ran('mv', '-f')


def test_fetch_image_preview_uses_grouped_block_summaries(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """The fetch preview groups its work into numbered step summaries."""
    activate_manager(monkeypatch)
    cfg = _noble_cfg(tmp_path)
    patch_ns(
        monkeypatch,
        'aivm.vm.images',
        {'_sudo_file_exists': returns(False), '_ensure_qemu_access': noop},
    )
    messages: list[str] = []
    fake_log = FakeLog(messages, levels=('info', 'warning', 'error'))
    monkeypatch.setattr('aivm.commands.log.opt', lambda **kwargs: fake_log)
    command_recorder(
        monkeypatch, {'sha256sum': _sha_route(_EXPECTED)}, default=FakeProc(0)
    )

    fetch_image(cfg, dry_run=False)

    assert 'Step: Fetch and verify base image' in messages
    assert '  1. Create VM image directory' in messages
    assert '  2. Remove stale partial image file' in messages
    assert '  3. Download base image into staging file' in messages
    assert '  4. Move staged base image into cache' in messages
    assert '  5. Compute base image checksum' in messages
