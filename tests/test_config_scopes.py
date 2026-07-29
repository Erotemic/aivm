"""Tests for the transitional shared-machine runtime scope boundary."""

from __future__ import annotations

from pathlib import Path



def test_guest_runtime_modules_use_scope_boundary() -> None:
    """Keep legacy principal/path reads at persistence and creation seams."""
    root = Path(__file__).parents[1]
    runtime_modules = [
        'aivm/attachments/guest.py',
        'aivm/attachments/persistent/manifest.py',
        'aivm/attachments/persistent/transport.py',
        'aivm/attachments/resolve.py',
        'aivm/attachments/shared_root.py',
        'aivm/cli/vm_cache.py',
        'aivm/cli/vm_connect.py',
        'aivm/cli/vm_guard.py',
        'aivm/credentials/guest.py',
        'aivm/status.py',
        'aivm/vm/connectivity.py',
        'aivm/vm/provision.py',
        'aivm/vm/share.py',
        'aivm/vm/update/fdguard.py',
    ]
    forbidden = (
        'cfg.vm.user',
        'cfg.paths.ssh_identity_file',
        'cfg.paths.ssh_pubkey_path',
    )
    violations: list[str] = []
    for relpath in runtime_modules:
        text = (root / relpath).read_text(encoding='utf-8')
        for token in forbidden:
            if token in text:
                violations.append(f'{relpath}: {token}')
    assert not violations, '\n'.join(violations)


def test_session_entrypoints_keep_the_resolved_context() -> None:
    """The service/session seam must not reconstruct caller identity later."""
    root = Path(__file__).parents[1]
    session_text = (root / 'aivm/attachments/session.py').read_text(
        encoding='utf-8'
    )
    connect_text = (root / 'aivm/cli/vm_connect.py').read_text(
        encoding='utf-8'
    )
    services_text = (root / 'aivm/services.py').read_text(encoding='utf-8')

    assert 'def load_vm_context_with_path(' in services_text
    assert 'def resolve_context_for_code(' in services_text
    assert 'context: ResolvedVMContext' in services_text
    assert 'resolve_context_for_code(' in session_text
    assert 'resolve_cfg_for_code(' not in session_text
    assert 'session.context' in connect_text
    assert 'session.cfg' not in connect_text
