"""Attachment mirror-home precedence and persistence coverage."""

from __future__ import annotations

import tomllib
from pathlib import Path

from aivm.attachment_schema import (
    MIRROR_HOME_AUTO,
    resolve_mirror_home_enabled,
)
from aivm.attachments.resolve import _resolve_attachment
from aivm.config import AgentVMConfig
from aivm.config_store import (
    AttachmentEntry,
    Store,
    load_store,
    save_store,
    upsert_attachment,
)
from aivm.profile_store import (
    PROFILE_SCHEMA_VERSION,
    load_user_profile,
    parse_user_profile,
    save_user_profile,
)


def test_mirror_home_policy_precedence() -> None:
    assert resolve_mirror_home_enabled('yes', 'no', False) is True
    assert resolve_mirror_home_enabled('no', 'yes', True) is False
    assert resolve_mirror_home_enabled('auto', 'yes', False) is True
    assert resolve_mirror_home_enabled('auto', 'no', True) is False
    assert resolve_mirror_home_enabled('auto', 'auto', True) is True
    assert resolve_mirror_home_enabled('auto', 'auto', False) is False


def test_old_profile_defaults_mirror_preference_to_auto() -> None:
    profile = parse_user_profile(
        'schema_version = 1\n'
        'active_vm = "vm-a"\n'
        'ssh_identity_file = ""\n'
        'ssh_pubkey_path = ""\n'
        'state_dir = "~/.cache/aivm"\n'
        'default_guest_user = "agent"\n'
    )
    assert profile.mirror_shared_home_folders == MIRROR_HOME_AUTO


def test_profile_mirror_preference_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / 'profile.toml'
    profile = parse_user_profile('schema_version = 1\n')
    profile.mirror_shared_home_folders = 'yes'
    save_user_profile(profile, path)

    raw = tomllib.loads(path.read_text(encoding='utf-8'))
    assert raw['schema_version'] == PROFILE_SCHEMA_VERSION
    assert raw['mirror_shared_home_folders'] == 'yes'
    assert load_user_profile(path).mirror_shared_home_folders == 'yes'


def test_auto_attachment_policy_needs_no_persisted_field(tmp_path: Path) -> None:
    path = tmp_path / 'config.toml'
    store = Store()
    store.attachments.append(
        AttachmentEntry(host_path=str(tmp_path), vm_name='vm-a')
    )
    save_store(store, path)

    text = path.read_text(encoding='utf-8')
    assert 'mirror_home' not in text
    loaded = load_store(path)
    assert loaded.attachments[0].mirror_home == MIRROR_HOME_AUTO


def test_explicit_attachment_policy_roundtrip_bumps_schema(tmp_path: Path) -> None:
    path = tmp_path / 'config.toml'
    host = tmp_path / 'project'
    host.mkdir()
    store = Store(schema_version=12, store_kind='machine')
    upsert_attachment(
        store,
        host_path=host,
        vm_name='vm-a',
        mirror_home='yes',
    )
    assert store.schema_version == 13
    save_store(store, path)

    text = path.read_text(encoding='utf-8')
    assert 'mirror_home = "yes"' in text
    loaded = load_store(path)
    assert loaded.schema_version == 13
    assert loaded.attachments[0].mirror_home == 'yes'


def test_resolve_attachment_preserves_and_overrides_saved_policy(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg_path = tmp_path / 'config.toml'
    host = tmp_path / 'project'
    host.mkdir()

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str(host),
            vm_name=cfg.vm.name,
            mode='persistent',
            mirror_home='yes',
        )
    )
    save_store(store, cfg_path)

    inherited = _resolve_attachment(cfg, cfg_path, host, '')
    assert inherited.mirror_home == 'yes'

    overridden = _resolve_attachment(
        cfg,
        cfg_path,
        host,
        '',
        mirror_home_opt='no',
    )
    assert overridden.mirror_home == 'no'

    reset_to_auto = _resolve_attachment(
        cfg,
        cfg_path,
        host,
        '',
        mirror_home_opt='auto',
    )
    assert reset_to_auto.mirror_home == 'auto'
