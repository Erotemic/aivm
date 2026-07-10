"""Tests for the pure path and tag helpers used by attachment resolution.

These cover the side-effect-free helpers that turn a host path into its
lexical/canonical guest forms and into a virtiofs share tag:
``_default_primary_guest_dst``, ``_host_symlink_lexical_path``,
``_compute_mirror_home_symlink``, ``_auto_share_tag_for_path`` and
``logical_absolute_path``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

from aivm.attachments.resolve import (
    _compute_mirror_home_symlink,
    _default_primary_guest_dst,
    _host_symlink_lexical_path,
    logical_absolute_path,
)
from aivm.config import AgentVMConfig
from aivm.vm.share import _auto_share_tag_for_path


def _dpg_non_symlink(tmp: Path) -> tuple[Path, str]:
    """Non-symlink path returns its lexical absolute form."""
    d = tmp / 'mydir'
    d.mkdir()
    return d, str(d.expanduser().absolute())


def _dpg_symlink(tmp: Path) -> tuple[Path, str]:
    """Symlinked source returns the resolved real path."""
    real = tmp / 'real'
    real.mkdir()
    link = tmp / 'link'
    link.symlink_to(real)
    return link, str(real.resolve())


def _dpg_intermediate(tmp: Path) -> tuple[Path, str]:
    """Intermediate symlinks no longer affect the primary guest_dst.

    With the current design, guest_dst is always the canonical resolved
    path; intermediate-component symlinks become aliases instead.
    """
    real_parent = tmp / 'real_parent'
    real_parent.mkdir()
    real_child = real_parent / 'child'
    real_child.mkdir()
    link_parent = tmp / 'link_parent'
    link_parent.symlink_to(real_parent)
    return link_parent / 'child', str(real_child.resolve())


@pytest.mark.parametrize(
    'build',
    [
        pytest.param(_dpg_non_symlink, id='non_symlink'),
        pytest.param(_dpg_symlink, id='symlink'),
        pytest.param(
            _dpg_intermediate, id='intermediate_symlink_returns_resolved'
        ),
    ],
)
def test_default_primary_guest_dst(
    tmp_path: Path, build: Callable[[Path], tuple[Path, str]]
) -> None:
    """The primary guest_dst is the canonical resolved path."""
    src, expected = build(tmp_path)
    assert _default_primary_guest_dst(src) == expected


def _hsl_non_symlink(tmp: Path) -> tuple[Path, str | None]:
    """A plain directory has no lexical alias."""
    d = tmp / 'dir'
    d.mkdir()
    return d, None


def _hsl_symlink(tmp: Path) -> tuple[Path, str | None]:
    """A terminal-component symlink returns its lexical absolute path."""
    real = tmp / 'real'
    real.mkdir()
    link = tmp / 'link'
    link.symlink_to(real)
    return link, str(link.expanduser().absolute())


def _hsl_intermediate(tmp: Path) -> tuple[Path, str | None]:
    """An intermediate-component symlink in host_src must be detected.

    Regression: previously this helper only detected terminal-component
    symlinks, so a path like ``/data/users/.../proj`` where ``/data`` was
    a symlink would silently resolve through ``Path.absolute()`` and the
    lexical form was lost. The check now compares lexical vs resolved and
    returns the lexical typed path whenever they differ.
    """
    real_parent = tmp / 'real_parent'
    real_parent.mkdir()
    (real_parent / 'child').mkdir()
    link_parent = tmp / 'link_parent'
    link_parent.symlink_to(real_parent)
    typed = link_parent / 'child'
    # The leaf 'child' is NOT a symlink, but link_parent IS. The old
    # terminal-only check would miss this; the new one must catch it.
    assert not typed.is_symlink()
    assert str(typed) != str(typed.resolve())
    return typed, str(typed)


@pytest.mark.parametrize(
    'build',
    [
        pytest.param(_hsl_non_symlink, id='non_symlink'),
        pytest.param(_hsl_symlink, id='symlink'),
        pytest.param(_hsl_intermediate, id='intermediate_symlink'),
    ],
)
def test_host_symlink_lexical_path(
    tmp_path: Path, build: Callable[[Path], tuple[Path, str | None]]
) -> None:
    """The lexical alias is returned when the typed path differs from real."""
    src, expected = build(tmp_path)
    assert _host_symlink_lexical_path(src) == expected


@pytest.mark.parametrize(
    ('vm_user', 'home', 'host_src', 'guest_dst', 'is_default_dst', 'expected'),
    [
        pytest.param(
            'agent',
            '/home/joncrall',
            '/home/joncrall/code/foobar',
            '/custom/path',
            False,
            None,
            id='none_when_not_default_dst',
        ),
        pytest.param(
            'agent',
            None,
            '/home/joncrall/code/foobar',
            '/custom/path',
            False,
            None,
            id='none_when_explicit_dst',
        ),
        pytest.param(
            'agent',
            '/home/joncrall',
            '/data/external/project',
            '/data/external/project',
            True,
            None,
            id='none_when_path_not_under_home',
        ),
        pytest.param(
            'joncrall',  # guest home == host home
            '/home/joncrall',
            '/home/joncrall/code/foobar',
            '/home/joncrall/code/foobar',
            True,
            None,
            id='none_when_guest_home_equals_host_home',
        ),
        pytest.param(
            'agent',
            '/home/joncrall',
            '/home/joncrall/code/foobar',
            '/home/joncrall/code/foobar',
            True,
            '/home/agent/code/foobar',
            id='correct_path',
        ),
        # When the primary dst already matches the mirror path, skip.
        pytest.param(
            'agent',
            '/home/agent',
            '/home/agent/code/foobar',
            '/home/agent/code/foobar',
            True,
            None,
            id='none_when_mirror_equals_primary',
        ),
    ],
)
def test_compute_mirror_home_symlink(
    monkeypatch: pytest.MonkeyPatch,
    vm_user: str,
    home: str | None,
    host_src: str,
    guest_dst: str,
    is_default_dst: bool,
    expected: str | None,
) -> None:
    """The mirror-home symlink maps host-home paths into the guest home."""
    cfg = AgentVMConfig()
    cfg.vm.user = vm_user
    if home is not None:
        monkeypatch.setattr(
            'aivm.attachments.resolve.Path.home', lambda: Path(home)
        )
    result = _compute_mirror_home_symlink(
        cfg, Path(host_src), guest_dst, is_default_dst=is_default_dst
    )
    assert result == expected


def test_auto_tag_includes_hash_suffix(tmp_path: Path) -> None:
    """Fresh generated tags always include a hash to avoid basename collisions."""
    d = tmp_path / 'myproject'
    d.mkdir()
    tag = _auto_share_tag_for_path(d, set())
    assert tag.startswith('hostcode-myproject-')
    # Must contain a non-trivial hash portion (8 hex chars)
    parts = tag.split('-')
    assert len(parts[-1]) == 8
    assert all(c in '0123456789abcdef' for c in parts[-1])


def test_auto_tag_different_paths_same_basename_get_different_tags(
    tmp_path: Path,
) -> None:
    """Two directories with the same basename produce different tags."""
    d1 = tmp_path / 'a' / 'repo'
    d2 = tmp_path / 'b' / 'repo'
    d1.mkdir(parents=True)
    d2.mkdir(parents=True)
    tag1 = _auto_share_tag_for_path(d1, set())
    tag2 = _auto_share_tag_for_path(d2, set())
    assert tag1 != tag2


def test_logical_absolute_path_absolute_input_preserves_typed_form(
    tmp_path: Path,
) -> None:
    """An absolute input is returned via expanduser only, no resolve()."""
    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(real)
    typed = link / 'sub'
    # Path inside a symlinked parent. Logical capture must NOT canonicalize.
    result = logical_absolute_path(str(typed))
    assert str(result) == str(typed)


def test_logical_absolute_path_relative_uses_validated_pwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``cd /data/proj && aivm attach .`` keeps ``/data/proj`` when $PWD agrees.

    Reproduces the original symptom: relative ``.`` joined against
    ``os.getcwd()`` would already be the canonical path (symlinks resolved).
    The helper joins against ``$PWD`` when ``Path($PWD).resolve() ==
    Path(getcwd())``, preserving the typed lexical form.
    """

    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(real)

    monkeypatch.chdir(real)  # actual kernel cwd = real
    monkeypatch.setenv('PWD', str(link))  # shell-view = link

    result = logical_absolute_path('.')
    assert str(result) == str(link)


def test_logical_absolute_path_stale_pwd_falls_back_to_getcwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A $PWD that does not resolve to getcwd() is treated as untrusted."""

    real = tmp_path / 'real'
    real.mkdir()
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()

    monkeypatch.chdir(real)
    monkeypatch.setenv('PWD', str(elsewhere))  # diverges from kernel cwd

    result = logical_absolute_path('.')
    assert str(result) == str(real.resolve())
