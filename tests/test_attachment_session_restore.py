"""Tests for attached-session preparation and saved-attachment restore.

These exercise ``_prepare_attached_session`` (git companion/mirror-home
symlinks, fresh-VM bootstrap) and ``_restore_saved_vm_attachments`` (how
saved shared/shared-root/persistent attachments are re-applied, including
the lexical-path handling that survives host symlinks). The CLI-entry and
``_record_attachment`` unit tests live in ``test_attachment_session.py``.

These tests deliberately populate a *real* config store under ``tmp_path``
and let the real store/drift/resolve code run, asserting on the artifacts
the code leaves behind (store contents, files on disk, the recorded guest
commands). Only true process boundaries -- the SSH/virsh guest calls and
the heavy ``_reconcile_attached_vm`` orchestrator -- stay faked.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any

import pytest

from aivm.cli.vm_connect import _bootstrap_vm_for_folder
from aivm.config import AgentVMConfig
from aivm.config_store import (
    Store,
    load_store,
    save_store,
    upsert_attachment,
    upsert_vm,
)
from aivm.vm.share import AttachmentMode, ResolvedAttachment
from tests.helpers import (
    FakeProc,
    activate_manager,
    capture_logs,
    command_recorder,
    domain_xml_with_shares,
)


def test_git_mode_in_prepare_session_gets_companion_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Git mode in _prepare_attached_session creates a companion symlink for host symlinks.

    The real store resolution, ``_resolve_attachment`` and
    ``_record_attachment`` all run; only the guest-facing ``_ensure_guest_symlink``
    (an SSH boundary) is faked, so the recorded symlink call is the artifact.
    """
    from aivm.attachments.session import _prepare_attached_session

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git-companion'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    # Set up a real dir and a symlink pointing to it
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    link_dir = tmp_path / 'link'
    link_dir.symlink_to(real_dir)

    # Seed a real store: a defined VM plus the saved git attachment keyed on
    # the resolved (canonical) host path.
    store = Store()
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=real_dir,
        vm_name=cfg.vm.name,
        mode='git',
        access='rw',
        guest_dst=str(real_dir.resolve()),
        tag='',
    )
    save_store(store, cfg_path)

    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.GIT,
        source_dir=str(real_dir.resolve()),
        guest_dst=str(real_dir.resolve()),
        tag='',
    )

    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: type(
            'R',
            (),
            {
                'attachment': attachment,
                'cached_ip': '10.0.0.1',
                'shared_root_host_side_ready': False,
            },
        )(),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.maybe_offer_create_ssh_identity',
        lambda *a, **k: False,
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: type('P', (), {'ok': True})(),
    )

    git_calls: list = []
    monkeypatch.setattr(
        'aivm.attachments.session._ensure_git_clone_attachment',
        lambda *a, **k: git_calls.append(1) or (tmp_path, 'ssh', 'git'),
    )

    symlink_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_guest_symlink',
        lambda cfg_a, ip, *, symlink_path, target_path: symlink_calls.append(
            {'symlink_path': symlink_path, 'target_path': target_path}
        ),
    )

    monkeypatch.setattr(
        'aivm.attachments.session._restore_saved_vm_attachments',
        lambda *a, **k: None,
    )

    _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=link_dir,  # lexical symlink path
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=False,
        dry_run=False,
        yes=True,
    )

    assert git_calls, 'git clone should have been called'
    # companion symlink from lexical link path to resolved real path
    expected_link = str(link_dir.expanduser().absolute())
    expected_target = str(real_dir.resolve())
    assert any(
        c['symlink_path'] == expected_link
        and c['target_path'] == expected_target
        for c in symlink_calls
    ), (
        f'Expected companion symlink {expected_link} -> {expected_target}, got: {symlink_calls}'
    )


def test_git_mode_in_prepare_session_gets_mirror_home_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Git mode in _prepare_attached_session creates a mirror-home symlink when enabled.

    Store resolution and ``_record_attachment`` run for real against the
    seeded store; the mirror-home symlink call recorded at the SSH boundary
    is the observable artifact.
    """
    from aivm.attachments.session import _prepare_attached_session

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git-mirror'
    cfg.vm.user = 'agent'
    cfg.vm.mirror_shared_home_folders = True
    cfg_path = tmp_path / 'config.toml'

    host_src = tmp_path / 'code' / 'myproject'
    host_src.mkdir(parents=True)

    store = Store()
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode='git',
        access='rw',
        guest_dst=str(host_src.expanduser().absolute()),
        tag='',
    )
    save_store(store, cfg_path)

    guest_dst = str(host_src.expanduser().absolute())
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.GIT,
        source_dir=guest_dst,
        guest_dst=guest_dst,
        tag='',
    )

    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: type(
            'R',
            (),
            {
                'attachment': attachment,
                'cached_ip': '10.0.0.1',
                'shared_root_host_side_ready': False,
            },
        )(),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.maybe_offer_create_ssh_identity',
        lambda *a, **k: False,
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: type('P', (), {'ok': True})(),
    )

    monkeypatch.setattr(
        'aivm.attachments.session._ensure_git_clone_attachment',
        lambda *a, **k: (tmp_path, 'ssh', 'git'),
    )

    symlink_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_guest_symlink',
        lambda cfg_a, ip, *, symlink_path, target_path: symlink_calls.append(
            {'symlink_path': symlink_path, 'target_path': target_path}
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._restore_saved_vm_attachments',
        lambda *a, **k: None,
    )

    # Patch Path.home so we know what the mirror path will be
    host_home = tmp_path
    monkeypatch.setattr('aivm.attachments.resolve.Path.home', lambda: host_home)

    _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=False,
        dry_run=False,
        yes=True,
    )

    # Mirror symlink should point into /home/agent/code/myproject
    expected_mirror = '/home/agent/code/myproject'
    assert any(c['symlink_path'] == expected_mirror for c in symlink_calls), (
        f'Expected mirror symlink at {expected_mirror}, got: {symlink_calls}'
    )


def test_restore_shared_attachment_applies_guest_derived_symlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """_restore_saved_vm_attachments applies _apply_guest_derived_symlinks for shared mode.

    The restore set is read from a real store via ``_saved_vm_attachments``
    and the tag drift helpers run for real; only the virtiofs mapping probe
    and the two guest-side helpers stay faked.
    """
    from aivm.attachments.session import _restore_saved_vm_attachments

    activate_manager(monkeypatch)

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-restore-shared'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    host_src = tmp_path / 'proj'
    host_src.mkdir()

    primary = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=str(host_src),
        guest_dst=str(host_src),
        tag='tag-primary',
    )
    secondary_src = tmp_path / 'sec'
    secondary_src.mkdir()

    # Seed a real store with both the primary and the secondary shared
    # attachment. ``_saved_vm_attachments`` reads this to build the restore
    # set; the secondary is what should be re-applied.
    reg = Store()
    upsert_attachment(
        reg,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst=str(host_src),
        tag='tag-primary',
    )
    upsert_attachment(
        reg,
        host_path=secondary_src,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst=str(secondary_src),
        tag='tag-secondary',
    )
    save_store(reg, cfg_path)

    # Faked virtiofs probe returns a mapping that already lines up with the
    # secondary, so the real drift helpers report the share present and the
    # restore proceeds to the guest-symlink step.
    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings',
        lambda *a, **k: [(str(secondary_src.resolve()), 'tag-secondary')],
    )
    # The access check inside drift_attachment_has_mapping reads the domain
    # XML at the subprocess boundary; script the dumpxml reply with the same
    # rw device so no real virsh runs.
    command_recorder(
        monkeypatch,
        {
            'virsh dumpxml': FakeProc(
                0,
                domain_xml_with_shares(
                    [(str(secondary_src.resolve()), 'tag-secondary')]
                ),
            )
        },
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted', lambda *a, **k: None
    )

    derived_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.session._apply_guest_derived_symlinks',
        lambda cfg_a, ip, host_src_a, att, *, mirror_home: derived_calls.append(
            {'host_src': host_src_a, 'mirror_home': mirror_home}
        ),
    )

    _restore_saved_vm_attachments(
        cfg,
        cfg_path,
        ip='10.0.0.1',
        primary_attachment=primary,
        yes=True,
        mirror_home=True,
    )

    assert len(derived_calls) == 1
    assert derived_calls[0]['mirror_home'] is True
    # The secondary remains recorded in the store after restore.
    saved = load_store(cfg_path)
    assert any(
        a.host_path == str(secondary_src.resolve())
        for a in saved.attachments
    )


def test_restore_shared_root_attachment_passes_mirror_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """_restore_saved_vm_attachments passes mirror_home to _ensure_attachment_available_in_guest for shared-root.

    The secondary shared-root attachment is discovered from a real store; the
    guest-availability helper (an SSH/virsh boundary) is faked so its kwargs
    are the artifact.
    """
    from aivm.attachments.session import _restore_saved_vm_attachments

    activate_manager(monkeypatch)

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-restore-sr'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    host_src = tmp_path / 'proj'
    host_src.mkdir()

    primary = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        source_dir=str(host_src),
        guest_dst=str(host_src),
        tag='token-primary',
    )
    secondary_src = tmp_path / 'sec'
    secondary_src.mkdir()

    reg = Store()
    upsert_attachment(
        reg,
        host_path=secondary_src,
        vm_name=cfg.vm.name,
        mode='shared_root',
        access='rw',
        guest_dst=str(secondary_src),
        tag='token-secondary',
    )
    save_store(reg, cfg_path)

    ensure_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.session._ensure_attachment_available_in_guest',
        lambda cfg_a, host_src_a, att, ip, *, yes, dry_run, ensure_shared_root_host_side, allow_disruptive_shared_root_rebind, mirror_home, host_lexical_paths=(): (
            ensure_calls.append(
                {
                    'allow_disruptive': allow_disruptive_shared_root_rebind,
                    'mirror_home': mirror_home,
                }
            )
        ),
    )

    _restore_saved_vm_attachments(
        cfg,
        cfg_path,
        ip='10.0.0.1',
        primary_attachment=primary,
        yes=True,
        mirror_home=True,
    )

    assert len(ensure_calls) == 1
    assert ensure_calls[0]['mirror_home'] is True
    # Non-disruptive rebind must remain False during restore
    assert ensure_calls[0]['allow_disruptive'] is False


def test_restore_skips_unrestorable_entries_and_continues_past_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Restore skips unrestorable saved entries and continues past failures.

    The store carries several saved attachments that cannot be restored (a
    git-mode entry, a vanished host path, and a plain file where a directory
    is expected) alongside a persistent secondary whose replay fails and two
    shared secondaries -- one that mounts and one whose mount raises. The real
    ``_saved_vm_attachments`` filtering runs, and the observable artifacts are
    the recorded mounts plus the warning log messages for each skipped or
    failed entry.
    """
    from aivm.attachments.session import _restore_saved_vm_attachments

    activate_manager(monkeypatch)

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-restore-persistent-continue-on-error'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    primary_src = tmp_path / 'primary'
    primary_src.mkdir()
    primary = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=str(primary_src),
        guest_dst=str(primary_src),
        tag='tag-primary',
    )

    persistent_src = tmp_path / 'persistent'
    persistent_src.mkdir()
    shared_src = tmp_path / 'shared'
    shared_src.mkdir()
    shared_fail_src = tmp_path / 'shared-fail'
    shared_fail_src.mkdir()
    # A shared secondary absent from the VM mappings: restore must try to
    # attach it, and the attach itself fails.
    shared_noattach_src = tmp_path / 'shared-noattach'
    shared_noattach_src.mkdir()
    # A regular file where a shared directory is expected.
    not_a_dir = tmp_path / 'not-a-dir'
    not_a_dir.write_text('x', encoding='utf-8')
    # Two shared-root secondaries whose guest-availability step fails: one
    # with the "refusing to replace" guard, one with a generic error.
    sr_refuse_src = tmp_path / 'sr-refuse'
    sr_refuse_src.mkdir()
    sr_generic_src = tmp_path / 'sr-generic'
    sr_generic_src.mkdir()
    # A git-mode entry (unsupported for share-style restore).
    git_src = tmp_path / 'gitrepo'
    git_src.mkdir()

    reg = Store()
    upsert_attachment(
        reg,
        host_path=persistent_src,
        vm_name=cfg.vm.name,
        mode='persistent',
        access='rw',
        guest_dst='/workspace/persistent',
        tag='tag-persistent',
    )
    upsert_attachment(
        reg,
        host_path=shared_src,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst='/workspace/shared',
        tag='tag-shared',
    )
    upsert_attachment(
        reg,
        host_path=shared_fail_src,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst='/workspace/shared-fail',
        tag='tag-shared-fail',
    )
    upsert_attachment(
        reg,
        host_path=shared_noattach_src,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst='/workspace/noattach',
        tag='tag-noattach',
    )
    upsert_attachment(
        reg,
        host_path=sr_refuse_src,
        vm_name=cfg.vm.name,
        mode='shared_root',
        access='rw',
        guest_dst='/workspace/sr-refuse',
        tag='tok-sr-refuse',
    )
    upsert_attachment(
        reg,
        host_path=sr_generic_src,
        vm_name=cfg.vm.name,
        mode='shared_root',
        access='rw',
        guest_dst='/workspace/sr-generic',
        tag='tok-sr-generic',
    )
    # host path that no longer exists on disk (never created).
    upsert_attachment(
        reg,
        host_path=tmp_path / 'gone',
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst='/workspace/gone',
        tag='tag-gone',
    )
    upsert_attachment(
        reg,
        host_path=not_a_dir,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst='/workspace/not-a-dir',
        tag='tag-not-a-dir',
    )
    upsert_attachment(
        reg,
        host_path=git_src,
        vm_name=cfg.vm.name,
        mode='git',
        access='rw',
        guest_dst=str(git_src),
        tag='',
    )
    save_store(reg, cfg_path)

    mounted: list[tuple[str, str]] = []

    def fake_ensure_share_mounted(
        cfg_a: Any, ip_a: Any, *, guest_dst: str, **k: Any
    ) -> None:
        if guest_dst == '/workspace/shared-fail':
            raise RuntimeError('mount boom')
        mounted.append((guest_dst, k.get('tag', '')))

    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_persistent_attachments_in_guest',
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('persistent boom')),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings',
        lambda *a, **k: [
            (str(shared_src.resolve()), 'tag-shared'),
            (str(shared_fail_src.resolve()), 'tag-shared-fail'),
        ],
    )
    # Script the dumpxml reply the drift access check reads, mirroring the
    # faked mappings, so no real virsh runs at the subprocess boundary.
    command_recorder(
        monkeypatch,
        {
            'virsh dumpxml': FakeProc(
                0,
                domain_xml_with_shares(
                    [
                        (str(shared_src.resolve()), 'tag-shared'),
                        (str(shared_fail_src.resolve()), 'tag-shared-fail'),
                    ]
                ),
            )
        },
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted',
        fake_ensure_share_mounted,
    )
    monkeypatch.setattr(
        'aivm.attachments.session.attach_vm_share',
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('attach boom')),
    )

    def fake_ensure_available(
        cfg_a: Any, host_src_a: Any, att: Any, ip_a: Any, **k: Any
    ) -> None:
        if att.guest_dst == '/workspace/sr-refuse':
            raise RuntimeError(
                'Refusing to replace existing shared-root host bind mount '
                'during automatic restore'
            )
        raise RuntimeError('generic shared-root boom')

    monkeypatch.setattr(
        'aivm.attachments.session._ensure_attachment_available_in_guest',
        fake_ensure_available,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._apply_guest_derived_symlinks',
        lambda *a, **k: None,
    )
    warnings = capture_logs(monkeypatch, 'aivm.attachments.session.log')

    _restore_saved_vm_attachments(
        cfg,
        cfg_path,
        ip='10.0.0.1',
        primary_attachment=primary,
        yes=True,
        mirror_home=False,
    )

    # Persistent replay failure was warned about but did not abort restore.
    assert any('persistent-restore: VM' in msg for msg in warnings)
    # The healthy shared secondary mounted; the failing one did not.
    assert ('/workspace/shared', 'tag-shared') in mounted
    assert all(gd != '/workspace/shared-fail' for gd, _ in mounted)
    # Unrestorable entries were skipped with explanatory warnings.
    assert any('host path is missing' in msg for msg in warnings)
    assert any('host path is not a directory' in msg for msg in warnings)
    # The failing remount was reported.
    assert any(
        'Could not remount saved attachment inside guest' in msg
        for msg in warnings
    )
    # The share absent from the VM mappings triggered an attach that failed.
    assert any(
        'Could not restore saved attachment for VM' in msg for msg in warnings
    )
    # Shared-root restore failures were reported (guard + generic).
    assert any(
        'Skipping saved shared-root attachment restore' in msg
        for msg in warnings
    )
    assert any(
        'Could not restore shared-root attachment for VM' in msg
        for msg in warnings
    )


def test_record_attachment_persists_lexical_path_for_symlink(
    tmp_path: Path,
) -> None:
    """_record_attachment stores host_lexical_path when host_src is a symlink."""
    from aivm.attachments.session import _record_attachment

    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    link_dir = tmp_path / 'link'
    link_dir.symlink_to(real_dir)

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-lex-persist'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    _record_attachment(
        cfg,
        cfg_path,
        host_src=link_dir,
        mode='shared',
        access='rw',
        guest_dst=str(real_dir),
        tag='tag-lex',
    )

    reg = load_store(cfg_path)
    entries = [a for a in reg.attachments if a.vm_name == cfg.vm.name]
    assert len(entries) == 1
    assert entries[0].host_lexical_paths == [
        str(link_dir.expanduser().absolute())
    ]
    # host_path (the resolved canonical key) must be the real path
    assert entries[0].host_path == str(real_dir.resolve())
    # The VM and its network were recorded as a side effect.
    assert any(v.name == cfg.vm.name for v in reg.vms)
    assert any(n.name == cfg.network.name for n in reg.networks)


def test_record_attachment_no_lexical_path_for_non_symlink(
    tmp_path: Path,
) -> None:
    """_record_attachment leaves host_lexical_path empty for non-symlink paths."""
    from aivm.attachments.session import _record_attachment

    real_dir = tmp_path / 'real'
    real_dir.mkdir()

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-nolex'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    _record_attachment(
        cfg,
        cfg_path,
        host_src=real_dir,
        mode='shared',
        access='rw',
        guest_dst=str(real_dir),
        tag='tag-nolex',
    )

    reg = load_store(cfg_path)
    entries = [a for a in reg.attachments if a.vm_name == cfg.vm.name]
    assert len(entries) == 1
    assert entries[0].host_lexical_paths == []


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


def test_restore_uses_lexical_path_for_companion_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """After restore, companion guest symlink is created using the stored lexical path.

    The saved attachment (carrying a lexical alias) is read from a real store
    by ``_saved_vm_attachments``; the restore feeds the lexical path -- not
    the resolved source -- to the faked guest-symlink helper.
    """
    from aivm.attachments.session import _restore_saved_vm_attachments

    activate_manager(monkeypatch)

    real_dir = tmp_path / 'real' / 'proj'
    real_dir.mkdir(parents=True)
    link_dir = tmp_path / 'link' / 'proj'
    (tmp_path / 'link').mkdir()
    link_dir.symlink_to(real_dir)

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-lex-restore'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    # Set up store with saved attachment that has host_lexical_path
    reg = Store()
    upsert_attachment(
        reg,
        host_path=real_dir,  # resolved key
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst=str(real_dir),
        tag='tag-lex-restore',
        host_lexical_path=str(link_dir),
    )
    save_store(reg, cfg_path)

    primary_src = tmp_path / 'primary'
    primary_src.mkdir()
    primary = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=str(primary_src),  # different source so secondary runs
        guest_dst=str(primary_src),
        tag='tag-primary',
    )

    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings',
        lambda *a, **k: [(str(real_dir.resolve()), 'tag-lex-restore')],
    )
    # Script the dumpxml reply the drift access check reads, mirroring the
    # faked mappings, so no real virsh runs at the subprocess boundary.
    command_recorder(
        monkeypatch,
        {
            'virsh dumpxml': FakeProc(
                0,
                domain_xml_with_shares(
                    [(str(real_dir.resolve()), 'tag-lex-restore')]
                ),
            )
        },
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted', lambda *a, **k: None
    )

    derived_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.session._apply_guest_derived_symlinks',
        lambda cfg_a, ip, host_src_a, att, *, mirror_home: derived_calls.append(
            {'host_src': host_src_a}
        ),
    )

    _restore_saved_vm_attachments(
        cfg,
        cfg_path,
        ip='10.0.0.1',
        primary_attachment=primary,
        yes=True,
        mirror_home=False,
    )

    assert len(derived_calls) == 1
    # Must have received the lexical path, not the resolved source_dir
    assert derived_calls[0]['host_src'] == link_dir


def test_restore_non_symlink_attachment_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Non-symlink attachments without host_lexical_path use source_dir as before.

    Read back from a real store, the restore falls back to the resolved
    source directory when no lexical alias was persisted.
    """
    from aivm.attachments.session import _restore_saved_vm_attachments

    activate_manager(monkeypatch)

    real_dir = tmp_path / 'proj'
    real_dir.mkdir()

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-nolex-restore'
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'

    # No host_lexical_path in store
    reg = Store()
    upsert_attachment(
        reg,
        host_path=real_dir,
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst=str(real_dir),
        tag='tag-plain',
    )
    save_store(reg, cfg_path)

    primary_src = tmp_path / 'primary'
    primary_src.mkdir()
    primary = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=str(primary_src),
        guest_dst=str(primary_src),
        tag='tag-primary',
    )

    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings',
        lambda *a, **k: [(str(real_dir.resolve()), 'tag-plain')],
    )
    # Script the dumpxml reply the drift access check reads, mirroring the
    # faked mappings, so no real virsh runs at the subprocess boundary.
    command_recorder(
        monkeypatch,
        {
            'virsh dumpxml': FakeProc(
                0,
                domain_xml_with_shares([(str(real_dir.resolve()), 'tag-plain')]),
            )
        },
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted', lambda *a, **k: None
    )

    derived_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.session._apply_guest_derived_symlinks',
        lambda cfg_a, ip, host_src_a, att, *, mirror_home: derived_calls.append(
            {'host_src': host_src_a}
        ),
    )

    _restore_saved_vm_attachments(
        cfg,
        cfg_path,
        ip='10.0.0.1',
        primary_attachment=primary,
        yes=True,
        mirror_home=False,
    )

    assert len(derived_calls) == 1
    # Falls back to source_dir (resolved) since no lexical path stored
    assert derived_calls[0]['host_src'] == Path(str(real_dir.resolve()))


def test_prepare_session_fresh_create_passes_initial_attachment_to_create(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fresh attached bootstrap should create the VM with the requested share."""
    from aivm.attachments.session import _prepare_attached_session

    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    store = Store()
    store.defaults = AgentVMConfig()
    save_store(store, cfg_path)

    cfg = AgentVMConfig()
    cfg.vm.name = 'fresh-vm'
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(host_src.resolve()),
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    resolve_calls = {'count': 0}

    def fake_resolve_cfg_for_code(**kwargs: Any) -> tuple[AgentVMConfig, Path]:
        resolve_calls['count'] += 1
        if resolve_calls['count'] == 1:
            raise RuntimeError(
                f'No VM definitions found in config store: {cfg_path}. '
                'Run `aivm config init` then `aivm vm create` first.'
            )
        return cfg, cfg_path

    create_calls: list[dict] = []

    def fake_create_vm_from_defaults(path: Path, **kwargs: Any) -> int:
        create_calls.append({'path': path, **kwargs})
        return 0

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        fake_resolve_cfg_for_code,
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults',
        fake_create_vm_from_defaults,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        lambda *a, **k: attachment,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: type(
            'R',
            (),
            {
                'attachment': attachment,
                'cached_ip': None,
                'shared_root_host_side_ready': False,
            },
        )(),
    )

    session = _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='/workspace/proj',
        attach_mode_opt='persistent',
        attach_access_opt='ro',
        recreate_if_needed=False,
        ensure_firewall_opt=False,
        dry_run=True,
        yes=True,
        bootstrap_missing_vm=partial(
            _bootstrap_vm_for_folder,
            config_opt=str(cfg_path),
            vm_opt='',
            host_src=host_src,
            guest_dst_opt='/workspace/proj',
            attach_mode_opt='persistent',
            attach_access_opt='ro',
            yes=True,
            dry_run=True,
        ),
    )

    assert session.cfg is cfg
    assert create_calls
    create_kwargs = create_calls[0]
    assert create_kwargs['path'] == cfg_path
    assert create_kwargs['initial_attachment_host_src'] == host_src
    assert create_kwargs['initial_attachment_guest_dst'] == '/workspace/proj'
    assert create_kwargs['initial_attachment_mode'] == 'persistent'
    assert create_kwargs['initial_attachment_access'] == 'ro'
