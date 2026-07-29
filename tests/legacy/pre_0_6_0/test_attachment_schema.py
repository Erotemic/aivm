"""Attachment schema compatibility for stores written before 0.6.0."""

from __future__ import annotations

from pathlib import Path

from aivm.config_store import load_store


def test_store_backward_compat_missing_lexical_path(
    tmp_path: Path,
) -> None:
    """Store loads cleanly from old TOML files that have no host_lexical_path field."""
    cfg_path = tmp_path / 'config.toml'
    # Minimal old-format store with no host_lexical_path
    cfg_path.write_text(
        'schema_version = 5\n'
        'active_vm = ""\n'
        '[behavior]\n'
        'yes_sudo = false\n'
        'auto_approve_readonly_sudo = true\n'
        'verbose = 1\n'
        'mirror_shared_home_folders = false\n'
        '[[attachments]]\n'
        'host_path = "/some/real/path"\n'
        'vm_name = "oldvm"\n'
        'mode = "shared"\n'
        'access = "rw"\n'
        'guest_dst = "/some/real/path"\n'
        'tag = "hostcode-path-abcd1234"\n',
        encoding='utf-8',
    )

    reg = load_store(cfg_path)
    assert len(reg.attachments) == 1
    att = reg.attachments[0]
    assert att.host_path == '/some/real/path'
    assert att.host_lexical_paths == []  # graceful default
