"""Guard AIVM's ordinary runtime against the experimental secrets package.

The two packages temporarily ship in one distribution. These checks guard
*runtime* independence; they do not claim that wheel extraction is complete.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AIVM = ROOT / 'aivm'

# Historical experimental entry points, not approval for more product coupling.
OPT_IN_ADAPTERS = {
    'aivm/cli/vm_connect.py',
    'aivm/cli/vm_identity.py',
    'aivm/secrets_transport.py',
    'aivm/secrets_identity_transport.py',
    'aivm/secrets_identity_vm.py',
}


def _cross_package_imports(path: Path) -> set[str]:
    """Detect Python import edges without loading experimental dependencies."""
    names = set()
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(
                item.name for item in node.names
                if item.name == 'aivm_secrets' or
                item.name.startswith('aivm_secrets.')
            )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module and (
                node.module == 'aivm_secrets' or
                node.module.startswith('aivm_secrets.')
            ):
                names.add(node.module)
    return names


def test_aivm_has_no_new_cross_package_imports() -> None:
    """Only the existing optional adapters may reference the error contract."""
    for path in sorted(AIVM.rglob('*.py')):
        names = _cross_package_imports(path)
        if not names:
            continue
        relative = path.relative_to(ROOT).as_posix()
        assert relative in OPT_IN_ADAPTERS, (relative, names)
        assert names == {'aivm_secrets.errors'}, (relative, names)


def test_aivm_core_install_has_no_secrets_requirements() -> None:
    """The current co-distribution is debt, not a mandatory dependency."""
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']
    dependencies = project['dependencies']
    assert all(
        not dependency.lower().replace('_', '-').startswith(
            ('aivm-secrets', 'cryptography'))
        for dependency in dependencies
    )
    assert 'secrets' in project['optional-dependencies']


def test_normal_cli_imports_with_secrets_completely_unavailable() -> None:
    """Import the real CLI in a fresh process that rejects secrets imports.

    In particular, vm_identity is registered by the ordinary VM command tree;
    do not let registration eagerly import its experimental implementation.
    """
    program = '''
import importlib.abc
import sys
from types import SimpleNamespace

class BlockSecrets(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if (fullname in {'aivm_secrets', 'cryptography'} or
                fullname.startswith(('aivm_secrets.', 'cryptography.'))):
            raise ModuleNotFoundError('optional broker/crypto unavailable',
                                      name=fullname)

sys.meta_path.insert(0, BlockSecrets())
import aivm.cli.main
from aivm.cli import vm_identity
assert 'aivm_secrets' not in sys.modules
assert 'cryptography' not in sys.modules
# Explicitly opting in must report the unavailable dependency, not a traceback.
assert vm_identity._run_identity(SimpleNamespace(identity_root='example'),
                                 renew=False) == 1
assert 'aivm_secrets' not in sys.modules
'''
    result = subprocess.run(
        [sys.executable, '-c', program], cwd=str(ROOT),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert 'requires optional AIVM secrets support' in result.stderr
