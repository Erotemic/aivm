"""Behavior of the in-guest persistent-attachment replay helper.

Each test executes the rendered helper in-process against a simulated
mount table (see :mod:`tests.persistent_helpers`) and asserts on the
mounts it ends up creating and the diagnostics it writes to stderr.
"""

from __future__ import annotations

import json
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

import pytest

from tests.persistent_helpers import (
    _exec_guest_replay_helper,
    _make_guest_replay_fake_run,
)


def test_persistent_replay_helper_uses_guest_local_manifest_and_skips_bad_records(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    assert 'HOST_MANIFEST' not in source
    assert '/var/lib/aivm/attachments.json' in source

    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]
    ns['subprocess'].run = _make_guest_replay_fake_run({})  # type: ignore[index]

    mount_root = Path(ns['PERSISTENT_ROOT_MOUNT'])
    mount_root.mkdir(parents=True, exist_ok=True)
    for token in ['parent', 'dup-a', 'dup-b', 'unique']:
        (mount_root / token).mkdir(parents=True, exist_ok=True)

    payload = {
        'schema_version': 1,
        'vm_name': 'vm',
        'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
        'records': [
            {
                'guest_dst': '/workspace/proj',
                'shared_root_token': 'parent',
                'access': 'rw',
                'enabled': True,
            },
            {
                'guest_dst': '/workspace/proj/sub',
                'shared_root_token': 'unique',
                'access': 'ro',
                'enabled': True,
            },
            {
                'guest_dst': '/workspace/dup',
                'shared_root_token': '',
                'access': 'rw',
                'enabled': True,
            },
            {
                'guest_dst': '/workspace/dup',
                'shared_root_token': 'dup-a',
                'access': 'rw',
                'enabled': True,
            },
            {
                'guest_dst': '/workspace/dup',
                'shared_root_token': 'dup-b',
                'access': 'rw',
                'enabled': True,
            },
        ],
    }
    Path(ns['STATE_PATH']).write_text(json.dumps(payload), encoding='utf-8')

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    messages = stderr.getvalue()
    assert 'HOST_MANIFEST' not in messages
    assert 'missing shared_root_token' in messages
    assert (
        'nested persistent attachment child /workspace/proj/sub under /workspace/proj'
        in messages
    )
    assert (
        'duplicate persistent attachment guest_dst /workspace/dup' in messages
    )
    mounts = ns['subprocess'].run.mounts  # type: ignore[attr-defined]
    assert '/workspace/proj' in mounts
    assert '/workspace/dup' in mounts
    assert '/workspace/proj/sub' not in mounts


def test_persistent_replay_helper_treats_plain_root_directory_as_unmounted(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    desired_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'token')
    calls: list[list[str]] = []
    mounts: dict[str, dict[str, str]] = {}
    ns['subprocess'].run = _make_guest_replay_fake_run(  # type: ignore[index]
        mounts,
        calls=calls,
        root_mount=ns['PERSISTENT_ROOT_MOUNT'],
        register_root_mount=False,
        findmnt_target_always_root=True,
    )

    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True, exist_ok=True)
    Path(desired_source).mkdir(parents=True, exist_ok=True)
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/data/joncrall/dvc-repos/shitspotter_expt_dvc',
                        'shared_root_token': 'token',
                        'access': 'rw',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    assert any('--mountpoint' in call for call in calls)
    assert not any('--target' in call for call in calls)
    assert (
        mounts['/data/joncrall/dvc-repos/shitspotter_expt_dvc']['source']
        == desired_source
    )
    assert 'busy mount' not in stderr.getvalue()


def test_persistent_replay_helper_replaces_wrong_source_on_real_mountpoint(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    desired_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'desired-token')
    wrong_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'wrong-token')
    mounts = {
        '/workspace/proj': {
            'source': wrong_source,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(mounts)  # type: ignore[index]

    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True, exist_ok=True)
    Path(desired_source).mkdir(parents=True, exist_ok=True)
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/workspace/proj',
                        'shared_root_token': 'desired-token',
                        'access': 'rw',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    assert mounts['/workspace/proj']['source'] == desired_source
    assert 'busy mount' not in stderr.getvalue()


def test_persistent_replay_helper_keeps_correct_real_mountpoint(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    desired_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'desired-token')
    mounts = {
        '/workspace/proj': {
            'source': desired_source,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(mounts)  # type: ignore[index]

    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True, exist_ok=True)
    Path(desired_source).mkdir(parents=True, exist_ok=True)
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/workspace/proj',
                        'shared_root_token': 'desired-token',
                        'access': 'rw',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    assert mounts['/workspace/proj']['source'] == desired_source
    assert stderr.getvalue() == ''


def test_scoped_persistent_replay_leaves_unrelated_busy_mount_alone(
    tmp_path: Path,
) -> None:
    """Foreground replay may add one project without reconciling siblings."""
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    ambition_wrong = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'ambition-old')
    ambition_desired = str(
        Path(ns['PERSISTENT_ROOT_MOUNT']) / 'ambition-new'
    )
    new_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'new-project')
    mounts = {
        '/workspace/ambition': {
            'source': ambition_wrong,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(  # type: ignore[index]
        mounts,
        umount_busy=True,
    )

    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True, exist_ok=True)
    Path(ambition_desired).mkdir(parents=True, exist_ok=True)
    Path(new_source).mkdir(parents=True, exist_ok=True)
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 2,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/workspace/ambition',
                        'shared_root_token': 'ambition-new',
                        'access': 'rw',
                        'enabled': True,
                    },
                    {
                        'guest_dst': '/workspace/new-project',
                        'shared_root_token': 'new-project',
                        'access': 'rw',
                        'enabled': True,
                    },
                ],
            }
        ),
        encoding='utf-8',
    )

    code = ns['main'](['--only-guest-dst', '/workspace/new-project'])

    assert code == 0
    assert mounts['/workspace/new-project']['source'] == new_source
    assert mounts['/workspace/ambition']['source'] == ambition_wrong


def test_persistent_replay_helper_skips_busy_stale_prune_and_continues(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    stale_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'stale-token')
    mounts = {
        stale_source: {
            'source': stale_source,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(  # type: ignore[index]
        mounts,
        register_root_mount=False,
        umount_busy=True,
    )

    (Path(ns['PERSISTENT_ROOT_MOUNT']) / 'keep').mkdir(
        parents=True, exist_ok=True
    )
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/workspace/keep',
                        'shared_root_token': 'keep',
                        'access': 'rw',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    assert (
        f'WARNING: skipping busy stale persistent attachment mount {stale_source}'
        in stderr.getvalue()
    )
    assert '/workspace/keep' in mounts
    assert stale_source in mounts


def test_persistent_replay_helper_fails_when_source_replacement_is_busy(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    wrong_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'wrong-token')
    mounts = {
        '/workspace/proj': {
            'source': wrong_source,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(  # type: ignore[index]
        mounts,
        register_root_mount=False,
        umount_busy=True,
    )

    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True, exist_ok=True)
    (Path(ns['PERSISTENT_ROOT_MOUNT']) / 'desired-token').mkdir(
        parents=True, exist_ok=True
    )
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/workspace/proj',
                        'shared_root_token': 'desired-token',
                        'access': 'rw',
                        'enabled': True,
                    },
                    {
                        'guest_dst': '/workspace/keep',
                        'shared_root_token': 'desired-token',
                        'access': 'rw',
                        'enabled': True,
                    },
                ],
            }
        ),
        encoding='utf-8',
    )

    with pytest.raises(RuntimeError, match='could not unmount /workspace/proj'):
        ns['main']()

    # Records are normalized deterministically, so this valid sibling is
    # reconciled before /workspace/proj.  A hard failure must propagate, but
    # replay is not transactional and does not roll back earlier successes.
    assert '/workspace/keep' in mounts
    assert mounts['/workspace/proj']['source'] == wrong_source


def test_persistent_replay_helper_removes_nonbusy_stale_mount(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    stale_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'stale-token')
    mounts = {
        stale_source: {
            'source': stale_source,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(mounts)  # type: ignore[index]

    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [],
            }
        ),
        encoding='utf-8',
    )

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    assert stale_source not in mounts


def test_persistent_replay_helper_unmounts_guest_when_host_token_is_missing(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]

    missing_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'missing-token')
    mounts = {
        '/workspace/proj': {
            'source': missing_source,
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(mounts)  # type: ignore[index]
    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True, exist_ok=True)
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'schema_version': 1,
                'vm_name': 'vm',
                'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
                'records': [
                    {
                        'guest_dst': '/workspace/proj',
                        'shared_root_token': 'missing-token',
                        'access': 'rw',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )

    stderr = StringIO()
    with redirect_stderr(stderr):
        code = ns['main']()

    assert code == ns['DEGRADED_EXIT']
    assert '/workspace/proj' not in mounts
    assert 'source is unavailable in shared root' in stderr.getvalue()



def test_persistent_replay_helper_preserves_live_mount_when_source_temporarily_missing(
    tmp_path: Path,
) -> None:
    """Foreground entry keeps a usable live bind when its token cannot be re-probed."""
    from aivm.persistent_replay import persistent_replay_python

    ns = _exec_guest_replay_helper(persistent_replay_python())
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    calls: list[list[object]] = []
    mounts = {
        '/workspace/proj': {
            'source': '/stale/presentation',
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(
        mounts, calls=calls, umount_busy=True
    )
    Path(ns['PERSISTENT_ROOT_MOUNT']).mkdir(parents=True)
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'records': [
                    {
                        'guest_dst': '/workspace/proj',
                        'shared_root_token': 'missing-token',
                        'access': 'rw',
                        'enabled': True,
                    }
                ]
            }
        ),
        encoding='utf-8',
    )
    ns['mount_persistent_root'] = lambda: None

    stderr = StringIO()
    with redirect_stderr(stderr):
        code = ns['main'](
            [
                '--only-guest-dst',
                '/workspace/proj',
                '--preserve-live-mounts',
            ]
        )

    assert code == ns['DEGRADED_EXIT']
    assert '/workspace/proj' in mounts
    assert not any(call and call[0] == 'umount' for call in calls)
    assert 'existing live mount left untouched' in stderr.getvalue()


def test_persistent_replay_helper_allows_enabled_child_under_disabled_parent(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]
    ns['subprocess'].run = _make_guest_replay_fake_run({})  # type: ignore[index]

    mount_root = Path(ns['PERSISTENT_ROOT_MOUNT'])
    mount_root.mkdir(parents=True, exist_ok=True)
    for token in ['parent', 'child']:
        (mount_root / token).mkdir(parents=True, exist_ok=True)

    payload = {
        'schema_version': 1,
        'vm_name': 'vm',
        'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
        'records': [
            {
                'guest_dst': '/workspace/proj',
                'shared_root_token': 'parent',
                'access': 'rw',
                'enabled': False,
            },
            {
                'guest_dst': '/workspace/proj/sub',
                'shared_root_token': 'child',
                'access': 'rw',
                'enabled': True,
            },
        ],
    }
    Path(ns['STATE_PATH']).write_text(json.dumps(payload), encoding='utf-8')

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    messages = stderr.getvalue()
    assert 'ignoring nested persistent attachment child' not in messages
    mounts = ns['subprocess'].run.mounts  # type: ignore[attr-defined]
    assert '/workspace/proj/sub' in mounts
    assert '/workspace/proj' not in mounts


def test_persistent_replay_helper_ignores_enabled_child_under_enabled_parent(
    tmp_path: Path,
) -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    ns['os'].makedirs = lambda *a, **k: None  # type: ignore[attr-defined]
    ns['subprocess'].run = _make_guest_replay_fake_run({})  # type: ignore[index]

    mount_root = Path(ns['PERSISTENT_ROOT_MOUNT'])
    mount_root.mkdir(parents=True, exist_ok=True)
    for token in ['parent', 'child']:
        (mount_root / token).mkdir(parents=True, exist_ok=True)

    payload = {
        'schema_version': 1,
        'vm_name': 'vm',
        'shared_root_mount': ns['PERSISTENT_ROOT_MOUNT'],
        'records': [
            {
                'guest_dst': '/workspace/proj',
                'shared_root_token': 'parent',
                'access': 'rw',
                'enabled': True,
            },
            {
                'guest_dst': '/workspace/proj/sub',
                'shared_root_token': 'child',
                'access': 'rw',
                'enabled': True,
            },
        ],
    }
    Path(ns['STATE_PATH']).write_text(json.dumps(payload), encoding='utf-8')

    stderr = StringIO()
    with redirect_stderr(stderr):
        ns['main']()

    messages = stderr.getvalue()
    assert (
        'WARNING: ignoring nested persistent attachment child /workspace/proj/sub under /workspace/proj'
        in messages
    )
    mounts = ns['subprocess'].run.mounts  # type: ignore[attr-defined]
    assert '/workspace/proj' in mounts
    assert '/workspace/proj/sub' not in mounts



def test_persistent_replay_helper_accepts_same_object_when_findmnt_source_differs(
    tmp_path: Path,
) -> None:
    """Bind identity, not findmnt SOURCE spelling, decides convergence."""
    from aivm.persistent_replay import persistent_replay_python

    ns = _exec_guest_replay_helper(persistent_replay_python())
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    desired_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'token')
    Path(desired_source).mkdir(parents=True)
    calls: list[list[object]] = []
    mounts = {
        '/workspace/proj': {
            'source': '/dev/fuse[/token]',
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(mounts, calls=calls)
    ns['same_directory_object'] = lambda left, right: (
        left == desired_source and right == '/workspace/proj'
    )

    ns['ensure_record'](
        {
            'guest_dst': '/workspace/proj',
            'shared_root_token': 'token',
            'access': 'rw',
            'enabled': True,
        },
        preserve_live_mounts=True,
    )

    assert not any(call and call[0] == 'umount' for call in calls)
    assert mounts['/workspace/proj']['source'] == '/dev/fuse[/token]'


def test_persistent_replay_helper_preserves_conflicting_live_mount_in_foreground(
    tmp_path: Path,
) -> None:
    """Foreground session preparation diagnoses a conflict without unmounting it."""
    from aivm.persistent_replay import persistent_replay_python

    ns = _exec_guest_replay_helper(persistent_replay_python())
    ns['PERSISTENT_ROOT_MOUNT'] = str(tmp_path / 'mnt')
    ns['STATE_PATH'] = str(tmp_path / 'attachments.json')
    desired_source = str(Path(ns['PERSISTENT_ROOT_MOUNT']) / 'desired-token')
    Path(desired_source).mkdir(parents=True)
    calls: list[list[object]] = []
    mounts = {
        '/workspace/proj': {
            'source': 'none',
            'options': 'rw',
        }
    }
    ns['subprocess'].run = _make_guest_replay_fake_run(
        mounts, calls=calls, umount_busy=True
    )
    Path(ns['STATE_PATH']).write_text(
        json.dumps(
            {
                'records': [
                    {
                        'guest_dst': '/workspace/proj',
                        'shared_root_token': 'desired-token',
                        'access': 'rw',
                        'enabled': True,
                    }
                ]
            }
        ),
        encoding='utf-8',
    )
    ns['mount_persistent_root'] = lambda: None

    code = ns['main'](
        [
            '--only-guest-dst',
            '/workspace/proj',
            '--preserve-live-mounts',
        ]
    )

    assert code == ns['DEGRADED_EXIT']
    assert mounts['/workspace/proj']['source'] == 'none'
    assert not any(call and call[0] == 'umount' for call in calls)

def test_persistent_replay_helper_reports_source_unavailable_as_degraded() -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['mount_persistent_root'] = lambda: None
    ns['sync_state'] = lambda **kwargs: [
        'source is unavailable in shared root: /mnt/aivm-persistent/stale'
    ]

    stderr = StringIO()
    with redirect_stderr(stderr):
        code = ns['main']()

    assert code == ns['DEGRADED_EXIT']
    assert (
        'WARNING: persistent attachment replay skipped one record: '
        'source is unavailable in shared root: /mnt/aivm-persistent/stale'
        in stderr.getvalue()
    )


def test_persistent_replay_helper_does_not_swallow_mount_failure() -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['load_json'] = lambda _path: {'records': [{}]}
    ns['validate_records'] = lambda _records: [('/workspace/proj', True, {})]
    ns['prune_stale_mounts'] = lambda _targets: None

    def fail_after_reconcile_started(_record: dict[str, object], **_kwargs: object) -> None:
        raise RuntimeError('remount,bind,ro failed')

    ns['ensure_record'] = fail_after_reconcile_started

    with pytest.raises(RuntimeError, match='remount,bind,ro failed'):
        ns['sync_state']()


def test_persistent_replay_helper_isolates_only_source_unavailable() -> None:
    from aivm.persistent_replay import persistent_replay_python

    source = persistent_replay_python()
    ns = _exec_guest_replay_helper(source)
    ns['load_json'] = lambda _path: {'records': [{}]}
    ns['validate_records'] = lambda _records: [('/workspace/proj', True, {})]
    ns['prune_stale_mounts'] = lambda _targets: None

    def unavailable(_record: dict[str, object], **_kwargs: object) -> None:
        raise ns['SourceUnavailableError']('source identity changed')

    ns['ensure_record'] = unavailable

    assert ns['sync_state']() == ['source identity changed']
