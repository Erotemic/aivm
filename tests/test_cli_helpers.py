from __future__ import annotations

from pathlib import Path

from aivm.cli._common import (
    _auto_share_tag_for_path,
    _count_verbose,
    _normalize_argv,
    _parse_sync_paths_arg,
)


def test_normalize_argv_aliases() -> None:
    assert _normalize_argv(["init"]) == ["config", "init"]
    assert _normalize_argv(["ls"]) == ["list"]
    assert _normalize_argv(["attach", "."]) == ["attach", "--host_src", "."]
    assert _normalize_argv(["code", "."]) == ["code", "--host_src", "."]
    assert _normalize_argv(["vm", "wait-ip"]) == ["vm", "wait_ip"]
    assert _normalize_argv(["vm", "sync-settings"]) == ["vm", "sync_settings"]


def test_count_verbose() -> None:
    assert _count_verbose([]) == 0
    assert _count_verbose(["--verbose"]) == 1
    assert _count_verbose(["-v"]) == 1
    assert _count_verbose(["-vvv", "--verbose"]) == 4


def test_parse_sync_paths_arg() -> None:
    got = _parse_sync_paths_arg(" ~/.gitconfig, ,~/.bashrc,")
    assert got == ["~/.gitconfig", "~/.bashrc"]


def test_auto_share_tag_collision() -> None:
    p = Path("/tmp/my project")
    tag1 = _auto_share_tag_for_path(p, set())
    tag2 = _auto_share_tag_for_path(p, {tag1})
    assert tag1 != ""
    assert tag2 != tag1
    assert len(tag2) <= 36
