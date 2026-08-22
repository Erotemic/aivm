"""Architectural guards for external command execution and runtime resources."""

from __future__ import annotations

import ast
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).parents[1] / 'aivm'
_COMMAND_AUTHORITY = _PACKAGE_ROOT / 'commands.py'
_RESOURCE_ROOT = _PACKAGE_ROOT / 'rc'


def _qualified_imports(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            for item in node.names:
                aliases[item.asname or item.name] = (
                    f'{module}.{item.name}' if module else item.name
                )
    return aliases


def _call_name(node: ast.Call, aliases: dict[str, str]) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = aliases.get(func.value.id, func.value.id)
        return f'{base}.{func.attr}'
    return None


def _is_external_execution(name: str) -> bool:
    if name.startswith('subprocess.'):
        return True
    if name.startswith('os.exec') or name.startswith('os.spawn'):
        return True
    if name in {
        'os.system',
        'os.popen',
        'os.posix_spawn',
        'os.posix_spawnp',
        'os.startfile',
        'pty.spawn',
    }:
        return True
    if name.startswith('asyncio.create_subprocess_'):
        return True
    return False


def test_host_external_execution_is_owned_by_command_manager() -> None:
    """Host package code may not grow another subprocess/exec escape hatch."""
    violations: list[str] = []
    for path in sorted(_PACKAGE_ROOT.rglob('*.py')):
        if path == _COMMAND_AUTHORITY or path.is_relative_to(_RESOURCE_ROOT):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        aliases = _qualified_imports(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    if item.name == 'subprocess':
                        violations.append(
                            f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                            'imports subprocess'
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module == 'subprocess':
                    violations.append(
                        f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                        'imports from subprocess'
                    )
            elif isinstance(node, ast.Call):
                name = _call_name(node, aliases)
                if name is not None and _is_external_execution(name):
                    violations.append(
                        f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                        f'calls {name}'
                    )
    assert violations == [], '\n'.join(violations)


def test_runtime_resource_modules_are_not_imported_by_host_code() -> None:
    """Standalone payload modules are read as files, never imported by AIVM."""
    violations: list[str] = []
    for path in sorted(_PACKAGE_ROOT.rglob('*.py')):
        if path.is_relative_to(_RESOURCE_ROOT):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names.extend(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.append(node.module)
            for name in names:
                if name == 'aivm.rc' or name.startswith('aivm.rc.'):
                    violations.append(
                        f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                        f'imports runtime resource module {name}'
                    )
    assert violations == [], '\n'.join(violations)


def test_runtime_resource_programs_are_standalone() -> None:
    """Copied programs may use stdlib but may not depend on the AIVM package."""
    violations: list[str] = []
    for path in sorted(_RESOURCE_ROOT.rglob('*.py')):
        if path.name == '__init__.py':
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    if item.name == 'aivm' or item.name.startswith('aivm.'):
                        violations.append(
                            f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                            f'imports {item.name}'
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    violations.append(
                        f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                        'uses a relative import'
                    )
                elif node.module == 'aivm' or (node.module or '').startswith(
                    'aivm.'
                ):
                    violations.append(
                        f'{path.relative_to(_PACKAGE_ROOT.parent)}:{node.lineno}: '
                        f'imports {node.module}'
                    )
    assert violations == [], '\n'.join(violations)
