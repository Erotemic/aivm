"""The credential feature stays off the core VM/security code path.

Repository credentials are optional: nothing in :mod:`aivm.credentials` runs
unless a user grants a VM access to a repository. Reviewing the core VM,
network, firewall, and privilege code should therefore never require reasoning
about deploy keys, so the set of core modules that reach into the feature is
fixed here rather than left to drift. The audit boundary is described in
``aivm/credentials/__init__.py``; this asserts it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import aivm

_PACKAGE_ROOT = Path(aivm.__file__).parent
_FEATURE = 'aivm.credentials'

# Every core module allowed to reference the credential feature, and the only
# submodules it may import. Adding an entry here widens what a VM-security
# review has to read, so it needs a reason recorded in the review, not just a
# passing test.
_ALLOWED: dict[str, set[str]] = {
    # The store persists credential records, so it must validate them. Both
    # imported modules are pure and import nothing outward.
    'aivm/config_store/models.py': {'aivm.credentials.schema'},
    'aivm/config_store/parse.py': {
        'aivm.credentials.agent_schema',
        'aivm.credentials.schema',
        'aivm.credentials.validation',
    },
    # A VM must not be deleted or recreated out from under a live deploy key.
    # These reach the feature through its guard seam only.
    'aivm/cli/vm_lifecycle.py': {'aivm.credentials.guards'},
    'aivm/vm/create.py': {'aivm.credentials.guards'},
    'aivm/vm/deletion.py': {'aivm.credentials.guards'},
    # Config linting reports on credential blocks found in the store.
    # Foreground SSH/Remote-SSH is the narrow runtime seam that may expose
    # the dedicated host-only agent capability to its selected VM principal.
    'aivm/cli/vm_connect.py': {'aivm.credentials.agent_transport'},
    'aivm/cli/config/lint.py': {
        'aivm.credentials.schema',
        'aivm.credentials.validation',
    },
    # Released-store migration must preserve repository identity while
    # assigning principal-scoped IDs. It may use only the pure validator.
    'aivm/legacy/pre_0_6_0/migration.py': {'aivm.credentials.validation'},
}

# The feature's own command surfaces, exempt by definition.
_FEATURE_CLIS = {
    'aivm/cli/vm_creds.py',
    'aivm/cli/vm_agent_creds.py',
}


def _module_name(path: Path) -> str:
    relative = path.relative_to(_PACKAGE_ROOT.parent).with_suffix('')
    return '.'.join(relative.parts)


def _imported_modules(path: Path) -> set[str]:
    """Return absolute module names imported by one file."""
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    package = _module_name(path).rsplit('.', 1)[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                found.add(node.module or '')
                continue
            base = package.split('.')
            ascended = base[: len(base) - (node.level - 1)]
            found.add('.'.join([*ascended, node.module or '']).rstrip('.'))
    return found


def _core_sources() -> list[Path]:
    return sorted(
        path
        for path in _PACKAGE_ROOT.rglob('*.py')
        if 'credentials' not in path.relative_to(_PACKAGE_ROOT).parts
    )


def test_core_modules_reach_the_credential_feature_only_where_allowed() -> None:
    unexpected: dict[str, set[str]] = {}
    for path in _core_sources():
        relative = str(path.relative_to(_PACKAGE_ROOT.parent))
        if relative in _FEATURE_CLIS:
            continue
        used = {
            name
            for name in _imported_modules(path)
            if name == _FEATURE or name.startswith(f'{_FEATURE}.')
        }
        extra = used - _ALLOWED.get(relative, set())
        if extra:
            unexpected[relative] = extra

    assert not unexpected, (
        'These core modules gained credential imports outside the audit '
        f'boundary: {unexpected}. See aivm/credentials/__init__.py.'
    )


def test_shared_cli_option_surface_is_credential_free() -> None:
    """``cli._common`` runs for every command, including ones with no VM."""
    source = (_PACKAGE_ROOT / 'cli' / '_common.py').read_text(encoding='utf-8')

    assert 'credential' not in source.lower()


def test_the_credential_feature_does_not_depend_on_the_cli_layer() -> None:
    """Dependencies point inward, so the feature is reusable and skippable."""
    offenders: dict[str, set[str]] = {}
    for path in sorted((_PACKAGE_ROOT / 'credentials').rglob('*.py')):
        cli_imports = {
            name
            for name in _imported_modules(path)
            if name == 'aivm.cli' or name.startswith('aivm.cli.')
        }
        if cli_imports:
            offenders[path.name] = cli_imports

    assert not offenders, f'credentials imported the CLI layer: {offenders}'
