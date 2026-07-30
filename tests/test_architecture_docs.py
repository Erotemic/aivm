"""Focused tests for the semi-automatic architecture documentation tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from dev.devcheck import architecture_docs as arch


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def _subsystem(
    subsystem: str,
    *,
    exact: list[str] | None = None,
    prefixes: list[str] | None = None,
) -> dict[str, object]:
    return {
        'id': subsystem,
        'label': subsystem.title(),
        'exact': exact or [],
        'prefixes': prefixes or [],
    }


def _minimal_architecture(
    *,
    subsystems: list[dict[str, object]],
    allowed_edges: dict[str, list[str]] | None = None,
    legacy_allowlist: list[dict[str, str]] | None = None,
    diagram_edges: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        'version': 1,
        'subsystems': subsystems,
        'excluded_modules': [],
        'allowed_edges': allowed_edges or {},
        'edge_annotations': [],
        'diagram_edges': diagram_edges or [],
        'legacy': {
            'package': 'aivm.legacy.pre_0_6_0',
            'test_root': 'tests/legacy/pre_0_6_0',
            'canonical_import_allowlist': legacy_allowlist or [],
        },
    }


def _write_specs(
    root: Path,
    architecture: dict[str, object],
    *,
    symbol: str = 'aivm.alpha.entry',
) -> arch.ArchitecturePaths:
    paths = arch.ArchitecturePaths.from_root(root)
    paths.architecture.parent.mkdir(parents=True, exist_ok=True)
    paths.architecture.write_text(
        yaml.safe_dump(architecture, sort_keys=False), encoding='utf-8'
    )
    paths.flows.write_text(
        yaml.safe_dump(
            {
                'version': 1,
                'flows': [
                    {
                        'id': 'synthetic',
                        'title': 'Synthetic flow',
                        'nodes': [
                            {'id': 'entry', 'label': 'Entry', 'symbol': symbol}
                        ],
                        'edges': [],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding='utf-8',
    )
    paths.state_ownership.write_text(
        yaml.safe_dump(
            {
                'version': 1,
                'owners': [{'id': 'state', 'label': 'State', 'symbol': symbol}],
                'items': [
                    {'label': 'Item', 'owner': 'state', 'symbol': symbol}
                ],
            },
            sort_keys=False,
        ),
        encoding='utf-8',
    )
    return paths


def test_package_prefix_classification_and_exact_override() -> None:
    config = _minimal_architecture(
        subsystems=[
            _subsystem('cli', prefixes=['aivm.cli']),
            _subsystem('special', exact=['aivm.cli.special']),
        ]
    )
    classifier = arch.ModuleClassifier(config)
    assert classifier.classify('aivm.cli.main') == 'cli'
    assert classifier.classify('aivm.cli.special') == 'special'


def test_unclassified_production_module_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(tmp_path, 'aivm/unclassified.py', '')
    modules = arch.discover_modules(tmp_path)
    config = _minimal_architecture(
        subsystems=[_subsystem('support', exact=['aivm'])]
    )
    errors = arch.validate_rules(tmp_path, modules, [], config)
    assert errors == ['Unclassified production module: aivm.unclassified']


def test_forbidden_subsystem_edge_names_modules_and_line(
    tmp_path: Path,
) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(tmp_path, 'aivm/high.py', 'from . import low\n')
    _write(tmp_path, 'aivm/low.py', 'VALUE = 1\n')
    modules = arch.discover_modules(tmp_path)
    imports = arch.collect_imports(modules)
    config = _minimal_architecture(
        subsystems=[
            _subsystem('high', exact=['aivm.high']),
            _subsystem('low', exact=['aivm.low']),
            _subsystem('support', exact=['aivm']),
        ]
    )
    errors = arch.validate_rules(tmp_path, modules, imports, config)
    assert len(errors) == 1
    assert 'Forbidden subsystem edge high -> low' in errors[0]
    assert 'aivm.high imports aivm.low' in errors[0]
    assert 'aivm/high.py:1' in errors[0]


def test_allowlisted_transitional_legacy_import(tmp_path: Path) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(
        tmp_path, 'aivm/canonical.py', 'from .legacy.pre_0_6_0 import shim\n'
    )
    _write(tmp_path, 'aivm/legacy/__init__.py', '')
    _write(tmp_path, 'aivm/legacy/pre_0_6_0/__init__.py', '')
    _write(tmp_path, 'aivm/legacy/pre_0_6_0/shim.py', 'VALUE = 1\n')
    modules = arch.discover_modules(tmp_path)
    imports = arch.collect_imports(modules)
    config = _minimal_architecture(
        subsystems=[
            _subsystem('canonical', exact=['aivm.canonical']),
            _subsystem('compatibility', prefixes=['aivm.legacy']),
            _subsystem('support', exact=['aivm']),
        ],
        allowed_edges={'canonical': ['compatibility']},
        legacy_allowlist=[
            {
                'importer': 'aivm.canonical',
                'imported_prefix': 'aivm.legacy.pre_0_6_0',
                'reason': 'Synthetic transition.',
            }
        ],
    )
    assert arch.validate_rules(tmp_path, modules, imports, config) == []


def test_nonlegacy_test_importing_legacy_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(tmp_path, 'aivm/legacy/__init__.py', '')
    _write(tmp_path, 'aivm/legacy/pre_0_6_0/__init__.py', '')
    _write(tmp_path, 'aivm/legacy/pre_0_6_0/shim.py', 'VALUE = 1\n')
    _write(
        tmp_path,
        'tests/test_canonical.py',
        'from aivm.legacy.pre_0_6_0 import shim\n',
    )
    modules = arch.discover_modules(tmp_path)
    imports = arch.collect_imports(modules)
    config = _minimal_architecture(
        subsystems=[
            _subsystem('compatibility', prefixes=['aivm.legacy']),
            _subsystem('support', exact=['aivm']),
        ]
    )
    errors = arch.validate_rules(tmp_path, modules, imports, config)
    assert any(
        'Non-legacy test imports compatibility implementation' in error
        for error in errors
    )


def test_type_checking_import_is_excluded(tmp_path: Path) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(
        tmp_path,
        'aivm/high.py',
        'from typing import TYPE_CHECKING\n'
        'if TYPE_CHECKING:\n'
        '    from . import low\n',
    )
    _write(tmp_path, 'aivm/low.py', 'VALUE = 1\n')
    imports = arch.collect_imports(arch.discover_modules(tmp_path))
    assert not any(record.imported == 'aivm.low' for record in imports)


def test_missing_symbol_reference_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(tmp_path, 'aivm/alpha.py', 'def entry():\n    return None\n')
    modules = arch.discover_modules(tmp_path)
    flows = {
        'flows': [
            {
                'id': 'missing',
                'nodes': [
                    {
                        'id': 'node',
                        'label': 'Missing',
                        'symbol': 'aivm.alpha.renamed',
                    }
                ],
                'edges': [],
            }
        ]
    }
    state = {'owners': [], 'items': []}
    with pytest.raises(
        arch.ArchitectureError, match='Missing documented symbol'
    ):
        arch.validate_curated_specs(flows, state, modules)


def test_generation_is_deterministic_and_stable_ordering(
    tmp_path: Path,
) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(
        tmp_path,
        'aivm/alpha.py',
        'from . import zeta\nfrom . import beta\ndef entry():\n    return None\n',
    )
    _write(tmp_path, 'aivm/beta.py', 'VALUE = 1\n')
    _write(tmp_path, 'aivm/zeta.py', 'VALUE = 1\n')
    architecture = _minimal_architecture(
        subsystems=[
            _subsystem('alpha', exact=['aivm.alpha']),
            _subsystem('beta', exact=['aivm.beta']),
            _subsystem('zeta', exact=['aivm.zeta']),
            _subsystem('support', exact=['aivm']),
        ],
        allowed_edges={'alpha': ['beta', 'zeta']},
        diagram_edges=[
            {'from': 'alpha', 'to': 'zeta'},
            {'from': 'alpha', 'to': 'beta'},
        ],
    )
    paths = _write_specs(tmp_path, architecture)
    first = arch.generated_outputs(paths)
    second = arch.generated_outputs(paths)
    assert first == second
    mermaid = first[paths.generated / 'component-dependencies.mmd']
    assert mermaid.index('alpha --> beta') < mermaid.index('alpha --> zeta')
    payload = json.loads(first[paths.generated / 'component-edges.json'])
    pairs = [(row['from'], row['to']) for row in payload['edges']]
    assert pairs == sorted(pairs)


def test_stale_generated_output_is_detected(tmp_path: Path) -> None:
    _write(tmp_path, 'aivm/__init__.py', '')
    _write(tmp_path, 'aivm/alpha.py', 'def entry():\n    return None\n')
    architecture = _minimal_architecture(
        subsystems=[
            _subsystem('alpha', exact=['aivm.alpha']),
            _subsystem('support', exact=['aivm']),
        ]
    )
    paths = _write_specs(tmp_path, architecture)
    arch.generate(paths)
    target = paths.generated / 'flow-synthetic.mmd'
    target.write_text('stale\n', encoding='utf-8')
    with pytest.raises(arch.ArchitectureError, match='stale generated file'):
        arch.check(paths)


def test_current_architecture_documentation_is_current() -> None:
    root = Path(__file__).resolve().parents[1]
    arch.check(arch.ArchitecturePaths.from_root(root))
