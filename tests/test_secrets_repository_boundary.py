"""Guard AIVM's ordinary runtime against the experimental secrets package.

Two separately installable distributions temporarily share one source tree.
Checks cover runtime independence and the contents/metadata of both wheels.
"""
from __future__ import annotations

import ast
from email.parser import Parser
import subprocess
import sys
import tarfile
import tomllib
import zipfile
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
    """Neither default install nor ordinary AIVM extras require secrets."""
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']
    dependencies = project['dependencies']
    assert all(
        not dependency.lower().replace('_', '-').startswith(
            ('aivm-secrets', 'cryptography'))
        for dependency in dependencies
    )
    extras = project['optional-dependencies']
    assert 'secrets' not in extras
    assert all('secrets' not in value.lower() for values in extras.values()
               for value in values)


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
    assert 'requires the separately installed' in result.stderr


def _wheel(project: Path, output: Path) -> zipfile.ZipFile:
    """Build an actual wheel offline; never rely only on pyproject text."""
    result = subprocess.run(
        [sys.executable, '-m', 'pip', 'wheel', '--no-index',
         '--no-build-isolation', '--no-deps', '--wheel-dir', str(output),
         str(project)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = sorted(output.glob('*.whl'))
    assert len(wheels) == 1, wheels
    return zipfile.ZipFile(wheels[0])


def test_distribution_wheels_are_separate(tmp_path: Path) -> None:
    """Core AIVM cannot co-install broker code through wheel packaging.

    This also makes the distribution extraction gate real: both wheel
    archives are inspected without importing or activating their contents.
    """
    core_dir = tmp_path / 'core'
    core_dir.mkdir()
    secrets_dir = tmp_path / 'secrets'
    secrets_dir.mkdir()
    with _wheel(ROOT, core_dir) as archive:
        names = archive.namelist()
        assert any(name.startswith('aivm/') for name in names)
        assert not any(name.startswith('aivm_secrets/') for name in names)
        info = next(name for name in names if name.endswith('/METADATA'))
        metadata = Parser().parsestr(archive.read(info).decode('utf-8'))
        assert metadata['Name'] == 'aivm'
        required = metadata.get_all('Requires-Dist', [])
        assert not any('aivm-secrets' in line.lower() for line in required)
        assert not any('cryptography' in line.lower() for line in required)
        entry = next(name for name in names if name.endswith('/entry_points.txt'))
        scripts = archive.read(entry).decode('utf-8')
        assert 'aivm = aivm.cli:main' in scripts
        assert 'aivm-secrets =' not in scripts

    with _wheel(ROOT / 'aivm_secrets', secrets_dir) as archive:
        names = archive.namelist()
        assert any(name.startswith('aivm_secrets/') for name in names)
        assert not any(name.startswith('aivm/') for name in names)
        info = next(name for name in names if name.endswith('/METADATA'))
        metadata = Parser().parsestr(archive.read(info).decode('utf-8'))
        assert metadata['Name'] == 'aivm-secrets'
        version_tree = ast.parse(
            (ROOT / 'aivm_secrets/__init__.py').read_text(encoding='utf-8')
        )
        runtime_version = next(
            ast.literal_eval(node.value)
            for node in version_tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == '__version__'
                    for target in node.targets)
        )
        assert metadata['Version'] == runtime_version
        assert any('cryptography' in value for value in
                   metadata.get_all('Requires-Dist', []))
        entry = next(name for name in names if name.endswith('/entry_points.txt'))
        scripts = archive.read(entry).decode('utf-8')
        assert 'aivm-secrets = aivm_secrets.cli:main' in scripts
        assert 'aivm = aivm.cli:main' not in scripts


def test_core_sdist_excludes_experimental_package(tmp_path: Path) -> None:
    """A source-distribution install cannot silently resurrect co-shipping."""
    # The AIVM release workflow uploads both a wheel and an sdist.
    script = (
        'from setuptools import build_meta; import sys; '
        'build_meta.build_sdist(sys.argv[1])'
    )
    result = subprocess.run(
        [sys.executable, '-c', script, str(tmp_path)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    archives = sorted(tmp_path.glob('aivm-*.tar.gz'))
    assert len(archives) == 1, archives
    with tarfile.open(archives[0], 'r:gz') as archive:
        names = archive.getnames()
        assert any('/aivm/' in name for name in names)
        assert not any('/aivm_secrets/' in name for name in names)
