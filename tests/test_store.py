"""Tests for test store."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.config_store import (
    AttachmentEntry,
    Store,
    find_attachment,
    find_attachment_for_vm,
    find_attachments,
    find_attachments_for_vm,
    find_vm,
    load_store,
    remove_attachment,
    save_store,
    upsert_attachment,
    upsert_vm,
)


def test_store_roundtrip(tmp_path: Path) -> None:
    store = Store()
    store.defaults = AgentVMConfig()
    store.defaults.vm.cpus = 2
    store.behavior.yes_sudo = True
    store.behavior.auto_approve_readonly_sudo = False
    store.behavior.verbose = 4
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-b'
    upsert_vm(store, cfg)
    cfg.vm.name = 'vm-a'
    upsert_vm(store, cfg)
    store.attachments.append(
        AttachmentEntry(host_path='/tmp/z', vm_name='vm-b', mode='shared')
    )
    store.attachments.append(
        AttachmentEntry(host_path='/tmp/a', vm_name='vm-a', mode='shared')
    )
    fpath = tmp_path / 'config.toml'
    save_store(store, fpath)

    loaded = load_store(fpath)
    assert loaded.defaults is not None
    assert loaded.defaults.vm.cpus == 2
    assert loaded.behavior.yes_sudo is True
    assert loaded.behavior.auto_approve_readonly_sudo is False
    assert loaded.behavior.verbose == 4
    assert [v.name for v in loaded.vms] == ['vm-a', 'vm-b']
    assert [a.host_path for a in loaded.attachments] == ['/tmp/a', '/tmp/z']
    assert find_vm(loaded, 'vm-a') is not None
    assert find_vm(loaded, 'missing') is None


def test_save_store_logs_reason(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    store = Store()
    store.defaults = AgentVMConfig()
    messages: list[str] = []

    def fake_info(fmt: str, *args: object) -> None:
        messages.append(fmt.format(*args))

    monkeypatch.setattr('aivm.config_store.io.log.info', fake_info)
    save_store(
        store,
        tmp_path / 'config.toml',
        reason='Persist runtime defaults after config hydration.',
    )

    assert messages == [
        f'Writing config store to {tmp_path / "config.toml"}',
        '  Reason: Persist runtime defaults after config hydration.',
    ]


def test_upsert_attachment_allows_multiple_vms_for_same_host(
    tmp_path: Path,
) -> None:
    store = Store()
    host = tmp_path / 'project'
    host.mkdir()
    upsert_attachment(store, host_path=host, vm_name='vm1')
    upsert_attachment(store, host_path=host, vm_name='vm2')

    atts = find_attachments(store, host)
    assert sorted(att.vm_name for att in atts) == ['vm1', 'vm2']

    vm2 = find_attachment_for_vm(store, host, 'vm2')
    assert vm2 is not None
    assert vm2.vm_name == 'vm2'

    att = find_attachment(store, host)
    assert att is not None
    assert att.vm_name in {'vm1', 'vm2'}


def test_find_attachments_for_vm_returns_sorted_entries(tmp_path: Path) -> None:
    store = Store()
    host_a = tmp_path / 'a'
    host_b = tmp_path / 'b'
    host_a.mkdir()
    host_b.mkdir()
    upsert_attachment(store, host_path=host_b, vm_name='vm1', tag='tag-b')
    upsert_attachment(store, host_path=host_a, vm_name='vm1', tag='tag-a')
    upsert_attachment(store, host_path=host_b, vm_name='vm2', tag='tag-c')

    atts = find_attachments_for_vm(store, 'vm1')

    assert [att.host_path for att in atts] == [
        str(host_a.resolve()),
        str(host_b.resolve()),
    ]


def test_remove_attachment_removes_single_vm_mapping(tmp_path: Path) -> None:
    store = Store()
    host = tmp_path / 'project'
    host.mkdir()
    upsert_attachment(store, host_path=host, vm_name='vm1')
    upsert_attachment(store, host_path=host, vm_name='vm2')

    changed = remove_attachment(store, host_path=host, vm_name='vm1')

    assert changed is True
    remaining = find_attachments(store, host)
    assert len(remaining) == 1
    assert remaining[0].vm_name == 'vm2'


def test_parse_nested_vm_attachments_equivalent_to_global(
    tmp_path: Path,
) -> None:
    """The future split-friendly nested schema keeps the flat model."""
    project = tmp_path / 'project'
    project.mkdir()
    text = f'''
schema_version = 5
active_vm = "vm-a"

[[vms]]
name = "vm-a"
network_name = "aivm-net"

[vms.vm]
cpus = 4

[[vms.attachments]]
host_path = "{project}"
mode = "shared-root"
access = "rw"
guest_dst = "/home/agent/code/project"
tag = "aivm-project"
host_lexical_path = "~/code/project"
'''
    from aivm.config_store import parse_store_toml

    store = parse_store_toml(text)

    assert [vm.name for vm in store.vms] == ['vm-a']
    assert len(store.attachments) == 1
    att = store.attachments[0]
    assert att.vm_name == 'vm-a'
    assert att.host_path == str(project.resolve())
    assert att.mode == 'shared-root'
    assert att.guest_dst == '/home/agent/code/project'
    assert att.tag == 'aivm-project'
    # Legacy singular `host_lexical_path` migrates into the new list field.
    assert att.host_lexical_paths == ['~/code/project']
    # Loading legacy data triggers a schema bump so the next save uses the
    # canonical plural shape.
    assert store.schema_version >= 7
    assert find_attachments_for_vm(store, 'vm-a') == [att]


def test_render_nested_vm_attachments_roundtrip(tmp_path: Path) -> None:
    """Nested rendering emits [[vms.attachments]] and parses back flat."""
    project = tmp_path / 'project'
    project.mkdir()
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=project,
        vm_name='vm-a',
        mode='shared-root',
        guest_dst='/home/agent/code/project',
        tag='tag-a',
    )
    from aivm.config_store import parse_store_toml, render_store_toml

    text = render_store_toml(store, attachment_style='nested')
    assert '[[vms.attachments]]' in text
    assert '[[attachments]]' not in text
    assert 'vm_name =' not in text

    loaded = parse_store_toml(text)
    assert [vm.name for vm in loaded.vms] == ['vm-a']
    assert len(loaded.attachments) == 1
    assert loaded.attachments[0].vm_name == 'vm-a'
    assert loaded.attachments[0].host_path == str(project.resolve())
    assert loaded.attachments[0].mode == 'shared-root'


def test_nested_attachment_rejects_conflicting_vm_name(tmp_path: Path) -> None:
    """Nested ownership should not silently disagree with vm_name."""
    project = tmp_path / 'project'
    project.mkdir()
    text = f'''
[[vms]]
name = "vm-a"
network_name = "aivm-net"

[[vms.attachments]]
vm_name = "vm-b"
host_path = "{project}"
'''
    from pytest import raises

    from aivm.config_store import parse_store_toml

    with raises(ValueError, match='vm_name mismatch'):
        parse_store_toml(text)


def test_load_split_layout_by_literal_concatenation(tmp_path: Path) -> None:
    """Split fragments load as the same canonical desired-state document."""
    config = tmp_path / 'config.toml'
    networks = tmp_path / 'networks.toml'
    vms_dir = tmp_path / 'vms'
    vms_dir.mkdir()
    project = tmp_path / 'project'
    project.mkdir()

    config.write_text(
        """
schema_version = 5
active_vm = "vm-a"

[behavior]
yes_sudo = true
""".lstrip(),
        encoding='utf-8',
    )
    networks.write_text(
        """
[[networks]]
name = "aivm-net"

[networks.network]
subnet_cidr = "10.77.0.0/24"
""".lstrip(),
        encoding='utf-8',
    )
    (vms_dir / 'vm-a.toml').write_text(
        f'''
[[vms]]
name = "vm-a"
network_name = "aivm-net"

[vms.vm]
cpus = 6
ram_mb = 12000

[[vms.attachments]]
host_path = "{project}"
mode = "shared-root"
'''.lstrip(),
        encoding='utf-8',
    )

    from aivm.config_store import load_config_document

    loaded = load_config_document(config)

    assert loaded.layout == 'split'
    assert [src.role for src in loaded.sources] == ['root', 'networks', 'vm']
    assert loaded.vm_sources['vm-a'] == vms_dir / 'vm-a.toml'
    assert loaded.network_sources['aivm-net'] == networks
    assert loaded.store.active_vm == 'vm-a'
    assert loaded.store.behavior.yes_sudo is True
    assert loaded.store.vms[0].cfg.vm.cpus == 6
    assert loaded.store.attachments[0].vm_name == 'vm-a'
    assert loaded.store.attachments[0].host_path == str(project.resolve())


def test_split_layout_rejects_duplicate_vm_definitions(tmp_path: Path) -> None:
    config = tmp_path / 'config.toml'
    vms_dir = tmp_path / 'vms'
    vms_dir.mkdir()
    config.write_text(
        """
[[vms]]
name = "vm-a"
network_name = "aivm-net"
""".lstrip(),
        encoding='utf-8',
    )
    (vms_dir / 'vm-a.toml').write_text(
        """
[[vms]]
name = "vm-a"
network_name = "aivm-net"
""".lstrip(),
        encoding='utf-8',
    )

    from pytest import raises

    from aivm.config_store import load_config_document

    with raises(ValueError, match='duplicate VM definition'):
        load_config_document(config)


def test_save_store_split_writes_concatenation_friendly_fragments(
    tmp_path: Path,
) -> None:
    """Split writer decomposes the logical store without changing meaning."""
    store = Store()
    store.defaults = AgentVMConfig()
    store.defaults.vm.cpus = 2
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg.vm.cpus = 8
    cfg.vm.ram_mb = 32768
    upsert_vm(store, cfg)
    project = tmp_path / 'project'
    project.mkdir()
    upsert_attachment(
        store,
        host_path=project,
        vm_name='vm-a',
        mode='shared-root',
        guest_dst='/home/agent/code/project',
    )

    from aivm.config_store import load_config_document, save_store_split

    root = tmp_path / 'config.toml'
    written = save_store_split(store, root)

    assert root in written
    assert tmp_path / 'defaults.toml' in written
    assert tmp_path / 'networks.toml' in written
    assert tmp_path / 'vms' / 'vm-a.toml' in written
    vm_text = (tmp_path / 'vms' / 'vm-a.toml').read_text(encoding='utf-8')
    assert vm_text.startswith('[[vms]]')
    assert '[[vms.attachments]]' in vm_text
    assert '[[attachments]]' not in vm_text

    loaded = load_config_document(root)
    assert loaded.layout == 'split'
    assert [vm.name for vm in loaded.store.vms] == ['vm-a']
    assert loaded.store.vms[0].cfg.vm.cpus == 8
    assert loaded.store.attachments[0].vm_name == 'vm-a'
    assert loaded.store.attachments[0].host_path == str(project.resolve())


def test_save_store_updates_existing_split_layout(tmp_path: Path) -> None:
    """Layout-aware save_store preserves split layout once fragments exist."""
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    upsert_vm(store, cfg)
    root = tmp_path / 'config.toml'

    from aivm.config_store import (
        load_config_document,
        save_store,
        save_store_split,
    )

    save_store_split(store, root)
    store.vms[0].cfg.vm.cpus = 12
    save_store(store, root)

    assert (tmp_path / 'defaults.toml').exists()
    assert (tmp_path / 'vms' / 'vm-a.toml').exists()
    assert '[[vms]]' in (tmp_path / 'vms' / 'vm-a.toml').read_text(
        encoding='utf-8'
    )
    loaded = load_config_document(root)
    assert loaded.layout == 'split'
    assert loaded.store.vms[0].cfg.vm.cpus == 12


def test_format_existing_config_migrates_monolith(tmp_path: Path) -> None:
    """Formatting rewrites config.toml as root fragment and creates split files."""
    store = Store()
    store.defaults = AgentVMConfig()
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg.vm.disk_gb = 80
    upsert_vm(store, cfg)
    project = tmp_path / 'project'
    project.mkdir()
    upsert_attachment(store, host_path=project, vm_name='vm-a')
    root = tmp_path / 'config.toml'
    save_store(store, root)

    from aivm.config_store import format_existing_config, load_config_document

    format_existing_config(root)

    assert (tmp_path / 'config.toml.bak').exists()
    assert (tmp_path / 'defaults.toml').exists()
    assert (tmp_path / 'networks.toml').exists()
    assert (tmp_path / 'vms' / 'vm-a.toml').exists()
    root_text = root.read_text(encoding='utf-8')
    assert '[[vms]]' not in root_text
    assert '[[attachments]]' not in root_text
    assert '[defaults.vm]' not in root_text
    defaults_text = (tmp_path / 'defaults.toml').read_text(encoding='utf-8')
    assert '[defaults.vm]' in defaults_text
    vm_text = (tmp_path / 'vms' / 'vm-a.toml').read_text(encoding='utf-8')
    assert '[[vms.attachments]]' in vm_text

    loaded = load_config_document(root)
    assert loaded.layout == 'split'
    assert loaded.store.vms[0].cfg.vm.disk_gb == 80
    assert loaded.store.attachments[0].vm_name == 'vm-a'


def test_save_store_split_rejects_orphaned_attachment(tmp_path: Path) -> None:
    """Split layout must not silently drop attachment records."""
    store = Store()
    store.attachments.append(
        AttachmentEntry(host_path=str(tmp_path), vm_name='missing-vm')
    )
    from pytest import raises

    from aivm.config_store import save_store_split

    with raises(ValueError, match='orphaned|attachment records'):
        save_store_split(store, tmp_path / 'config.toml')


def test_legacy_behavior_mirror_shared_home_folders_migrates_to_vmconfig(
    tmp_path: Path,
) -> None:
    """schema_version<6 stores keep mirror_shared_home_folders under [behavior].
    Loading such a file must lift the value onto defaults.vm and every VM."""
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text(
        'schema_version = 5\n'
        'active_vm = ""\n'
        '[behavior]\n'
        'yes_sudo = false\n'
        'auto_approve_readonly_sudo = true\n'
        'verbose = 1\n'
        'mirror_shared_home_folders = true\n'
        '[[vms]]\n'
        'name = "vm-old"\n'
        'network_name = "aivm-net"\n'
        '[vms.vm]\n'
        'name = "vm-old"\n',
        encoding='utf-8',
    )
    loaded = load_store(cfg_path)
    assert loaded.schema_version == 6
    assert loaded.defaults is not None
    assert loaded.defaults.vm.mirror_shared_home_folders is True
    assert loaded.vms[0].cfg.vm.mirror_shared_home_folders is True
    # The legacy key must not survive on BehaviorConfig.
    assert not hasattr(loaded.behavior, 'mirror_shared_home_folders')


def test_explicit_per_vm_override_wins_over_legacy_behavior_value(
    tmp_path: Path,
) -> None:
    """A hand-edited mixed file with both legacy and per-VM keys must honor the per-VM one."""
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text(
        'schema_version = 5\n'
        'active_vm = ""\n'
        '[behavior]\n'
        'mirror_shared_home_folders = true\n'
        '[[vms]]\n'
        'name = "vm-explicit"\n'
        'network_name = "aivm-net"\n'
        '[vms.vm]\n'
        'name = "vm-explicit"\n'
        'mirror_shared_home_folders = false\n',
        encoding='utf-8',
    )
    loaded = load_store(cfg_path)
    assert loaded.vms[0].cfg.vm.mirror_shared_home_folders is False


def test_match_host_user_ids_round_trips_per_vm(tmp_path: Path) -> None:
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-uid-match'
    cfg.vm.match_host_user_ids = False
    cfg.vm.mirror_shared_home_folders = True
    upsert_vm(store, cfg)
    fpath = tmp_path / 'config.toml'
    save_store(store, fpath)

    loaded = load_store(fpath)
    assert loaded.schema_version == 7
    [vm] = loaded.vms
    assert vm.cfg.vm.match_host_user_ids is False
    assert vm.cfg.vm.mirror_shared_home_folders is True


def test_host_lexical_paths_roundtrip(tmp_path: Path) -> None:
    """Schema 7 stores host_lexical_paths as a TOML array."""
    from aivm.config_store import (
        AttachmentEntry,
        Store,
        load_store,
        save_store,
    )

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path='/media/raid/proj',
            vm_name='vm-aliases',
            mode='persistent',
            guest_dst='/media/raid/proj',
            host_lexical_paths=['/data/proj', '/old/data/proj'],
        )
    )
    fpath = tmp_path / 'config.toml'
    save_store(store, fpath)

    loaded = load_store(fpath)
    assert loaded.schema_version >= 7
    [att] = loaded.attachments
    assert att.host_lexical_paths == ['/data/proj', '/old/data/proj']


def test_find_attachment_for_vm_matches_by_alias(tmp_path: Path) -> None:
    """Looking up an attachment by an alias path returns the same record."""
    from aivm.config_store import (
        AttachmentEntry,
        Store,
        find_attachment_for_vm,
    )

    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(real)

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str(real.resolve()),
            vm_name='vm-a',
            mode='persistent',
            guest_dst=str(real.resolve()),
            host_lexical_paths=[str(link)],
        )
    )
    # Direct match by canonical path
    canonical = find_attachment_for_vm(store, real.resolve(), 'vm-a')
    assert canonical is not None and canonical.host_path == str(real.resolve())
    # Match by stored alias
    via_alias = find_attachment_for_vm(store, link, 'vm-a')
    assert via_alias is canonical


def test_find_attachment_for_vm_matches_by_resolved_path(
    tmp_path: Path,
) -> None:
    """If a user later attaches a different symlink chain that resolves to the same
    canonical host_path, lookup must find the existing record so it can be updated
    rather than duplicated."""
    from aivm.config_store import (
        AttachmentEntry,
        Store,
        find_attachment_for_vm,
    )

    real = tmp_path / 'real'
    real.mkdir()
    link_a = tmp_path / 'link-a'
    link_a.symlink_to(real)
    link_b = tmp_path / 'link-b'
    link_b.symlink_to(real)

    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str(real.resolve()),
            vm_name='vm-b',
            mode='persistent',
            guest_dst=str(real.resolve()),
            host_lexical_paths=[str(link_a)],
        )
    )

    # link_b is not in aliases yet, but resolves to the same canonical path.
    via_other_symlink = find_attachment_for_vm(store, link_b, 'vm-b')
    assert via_other_symlink is not None
    assert via_other_symlink.host_path == str(real.resolve())


def test_save_store_rejects_stale_loaded_revision(tmp_path: Path) -> None:
    from aivm.config_store import ConcurrentStoreUpdateError

    path = tmp_path / 'config.toml'
    save_store(Store(), path)
    first = load_store(path)
    stale = load_store(path)

    first.active_vm = 'first-writer'
    save_store(first, path)
    stale.active_vm = 'stale-writer'

    with pytest.raises(ConcurrentStoreUpdateError):
        save_store(stale, path)

    assert load_store(path).active_vm == 'first-writer'


def test_save_store_uses_atomic_replace(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    import aivm.config_store.io as store_io

    path = tmp_path / 'config.toml'
    replacements: list[tuple[Path, Path]] = []
    original_replace = store_io.os.replace

    def record_replace(src: str, dst: str) -> None:
        replacements.append((Path(src), Path(dst)))
        original_replace(src, dst)

    monkeypatch.setattr(store_io.os, 'replace', record_replace)
    save_store(Store(active_vm='atomic'), path)

    assert replacements
    src, dst = replacements[-1]
    assert dst == path.resolve()
    assert src.parent == path.parent
    assert load_store(path).active_vm == 'atomic'
