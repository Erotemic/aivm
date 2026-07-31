#!/usr/bin/env python3
"""Generate and validate AIVM's semi-automatic architecture documentation."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence, cast

import yaml  # type: ignore[import-untyped]


class ArchitectureError(RuntimeError):
    """Raised when architecture specifications or generated files are invalid."""


@dataclass(frozen=True, order=True)
class ModuleRecord:
    name: str
    path: Path


@dataclass(frozen=True, order=True)
class ImportRecord:
    importer: str
    imported: str
    line: int


@dataclass(frozen=True)
class SymbolRecord:
    module: str
    parts: tuple[str, ...]
    node: ast.AST
    path: Path


@dataclass(frozen=True)
class ArchitecturePaths:
    root: Path
    architecture: Path
    flows: Path
    state_ownership: Path
    generated: Path

    @classmethod
    def from_root(cls, root: Path) -> ArchitecturePaths:
        architecture_root = root / 'docs' / 'architecture'
        return cls(
            root=root,
            architecture=architecture_root / 'architecture.yaml',
            flows=architecture_root / 'flows.yaml',
            state_ownership=architecture_root / 'state-ownership.yaml',
            generated=architecture_root / 'generated',
        )


def _object_dict(value: object, *, context: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise ArchitectureError(f'{context} must be a string-keyed mapping')
    return cast(dict[str, object], value)


def _object_list(value: object, *, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ArchitectureError(f'{context} must be a list')
    return cast(list[object], value)


def load_yaml(path: Path) -> dict[str, object]:
    try:
        raw = yaml.safe_load(path.read_text(encoding='utf-8'))
    except (OSError, yaml.YAMLError) as ex:
        raise ArchitectureError(f'Could not read {path}: {ex}') from ex
    return _object_dict(raw, context=str(path))


def module_name_for_path(path: Path, root: Path) -> str:
    relative = path.relative_to(root).with_suffix('')
    parts = list(relative.parts)
    if parts[-1] == '__init__':
        parts.pop()
    return '.'.join(parts)


def discover_modules(
    root: Path, package: str = 'aivm'
) -> dict[str, ModuleRecord]:
    package_root = root / package.replace('.', '/')
    modules: dict[str, ModuleRecord] = {}
    for path in sorted(package_root.rglob('*.py')):
        name = module_name_for_path(path, root)
        modules[name] = ModuleRecord(name=name, path=path)
    return modules


def _is_type_checking_test(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == 'TYPE_CHECKING'
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == 'typing'
        and node.attr == 'TYPE_CHECKING'
    )


def _relative_import_base(
    importer: str,
    importer_path: Path,
    level: int,
    module: str | None,
) -> str:
    package = (
        importer
        if importer_path.name == '__init__.py'
        else importer.rsplit('.', 1)[0]
    )
    parts = package.split('.') if package else []
    up = level - 1
    if up:
        parts = parts[:-up]
    if module:
        parts.extend(module.split('.'))
    return '.'.join(parts)


class _ImportCollector(ast.NodeVisitor):
    def __init__(
        self,
        module: ModuleRecord,
        modules: dict[str, ModuleRecord],
    ) -> None:
        self.module = module
        self.modules = modules
        self.records: list[ImportRecord] = []
        self._type_checking_depth = 0

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_test(node.test):
            self._type_checking_depth += 1
            for item in node.body:
                self.visit(item)
            self._type_checking_depth -= 1
            for item in node.orelse:
                self.visit(item)
            return
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        if self._type_checking_depth:
            return
        for alias in node.names:
            self._add_target(alias.name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self._type_checking_depth:
            return
        if node.level:
            base = _relative_import_base(
                self.module.name,
                self.module.path,
                node.level,
                node.module,
            )
        else:
            base = node.module or ''
        candidates: set[str] = set()
        unresolved_alias = False
        for alias in node.names:
            candidate = f'{base}.{alias.name}' if base else alias.name
            if candidate in self.modules:
                candidates.add(candidate)
            elif alias.name != '*':
                unresolved_alias = True
        if base and (
            node.module is not None or unresolved_alias or not candidates
        ):
            candidates.add(base)
        for candidate in sorted(candidates):
            self._add_target(candidate, node.lineno)

    def _add_target(self, target: str, line: int) -> None:
        if not (target == 'aivm' or target.startswith('aivm.')):
            return
        resolved = target
        while resolved not in self.modules and '.' in resolved:
            resolved = resolved.rsplit('.', 1)[0]
        if resolved not in self.modules:
            return
        self.records.append(
            ImportRecord(
                importer=self.module.name,
                imported=resolved,
                line=line,
            )
        )


def collect_imports(
    modules: dict[str, ModuleRecord],
) -> list[ImportRecord]:
    records: set[ImportRecord] = set()
    for module in modules.values():
        tree = ast.parse(
            module.path.read_text(encoding='utf-8'),
            filename=str(module.path),
        )
        collector = _ImportCollector(module, modules)
        collector.visit(tree)
        records.update(collector.records)
    return sorted(records)


class ModuleClassifier:
    def __init__(self, config: dict[str, object]) -> None:
        self.exact: dict[str, str] = {}
        self.prefixes: list[tuple[str, str]] = []
        subsystem_rows = _object_list(
            config.get('subsystems', []), context='subsystems'
        )
        for raw in subsystem_rows:
            row = _object_dict(raw, context='subsystem')
            subsystem = str(row.get('id', '')).strip()
            if not subsystem:
                raise ArchitectureError('Every subsystem requires an id')
            for module in _object_list(row.get('exact', []), context='exact'):
                name = str(module)
                if name in self.exact:
                    raise ArchitectureError(
                        f'Module {name} has more than one exact classification'
                    )
                self.exact[name] = subsystem
            for prefix in _object_list(
                row.get('prefixes', []), context='prefixes'
            ):
                self.prefixes.append((str(prefix), subsystem))
        self.prefixes.sort(key=lambda item: (-len(item[0]), item[0]))
        self.excluded = {
            str(item)
            for item in _object_list(
                config.get('excluded_modules', []),
                context='excluded_modules',
            )
        }

    def classify(self, module: str) -> str | None:
        if module in self.excluded:
            return None
        if module in self.exact:
            return self.exact[module]
        for prefix, subsystem in self.prefixes:
            if module == prefix or module.startswith(prefix + '.'):
                return subsystem
        return ''


def subsystem_edges(
    imports: Iterable[ImportRecord],
    classifier: ModuleClassifier,
) -> dict[tuple[str, str], list[ImportRecord]]:
    result: dict[tuple[str, str], list[ImportRecord]] = {}
    for record in imports:
        source = classifier.classify(record.importer)
        target = classifier.classify(record.imported)
        if not source or not target or source == target:
            continue
        result.setdefault((source, target), []).append(record)
    return {
        key: sorted(value)
        for key, value in sorted(result.items(), key=lambda item: item[0])
    }


def _allowed_edges(config: dict[str, object]) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    rows = _object_dict(
        config.get('allowed_edges', {}), context='allowed_edges'
    )
    for source, raw_targets in rows.items():
        for target in _object_list(
            raw_targets, context=f'allowed_edges.{source}'
        ):
            result.add((source, str(target)))
    return result


def _edge_annotations(
    config: dict[str, object],
) -> dict[tuple[str, str], dict[str, object]]:
    result: dict[tuple[str, str], dict[str, object]] = {}
    for raw in _object_list(
        config.get('edge_annotations', []), context='edge_annotations'
    ):
        row = _object_dict(raw, context='edge annotation')
        key = (str(row.get('from', '')), str(row.get('to', '')))
        result[key] = row
    return result


def _legacy_allowlist(
    config: dict[str, object],
) -> list[tuple[str, str, str]]:
    legacy = _object_dict(config.get('legacy', {}), context='legacy')
    result = []
    for raw in _object_list(
        legacy.get('canonical_import_allowlist', []),
        context='legacy.canonical_import_allowlist',
    ):
        row = _object_dict(raw, context='legacy allowlist row')
        result.append(
            (
                str(row.get('importer', '')),
                str(row.get('imported_prefix', '')),
                str(row.get('reason', '')),
            )
        )
    return result


def validate_rules(
    root: Path,
    modules: dict[str, ModuleRecord],
    imports: list[ImportRecord],
    config: dict[str, object],
) -> list[str]:
    errors: list[str] = []
    classifier = ModuleClassifier(config)
    for module in sorted(modules):
        if classifier.classify(module) == '':
            errors.append(f'Unclassified production module: {module}')

    edges = subsystem_edges(imports, classifier)
    allowed = _allowed_edges(config)
    annotations = _edge_annotations(config)
    for edge, records in edges.items():
        if edge not in allowed:
            sample = records[0]
            errors.append(
                f'Forbidden subsystem edge {edge[0]} -> {edge[1]}: '
                f'{sample.importer} imports {sample.imported} at '
                f'{modules[sample.importer].path.relative_to(root)}:'
                f'{sample.line}; add an intentional allowed-edge policy or '
                'remove the dependency'
            )
        annotation = annotations.get(edge)
        if annotation and annotation.get('classification') == 'forbidden':
            sample = records[0]
            errors.append(
                f'Rule {annotation.get("id", "forbidden-edge")} forbids '
                f'{edge[0]} -> {edge[1]}: {sample.importer} imports '
                f'{sample.imported} at {sample.line}'
            )

    legacy = _object_dict(config.get('legacy', {}), context='legacy')
    legacy_prefix = str(legacy.get('package', 'aivm.legacy.pre_0_6_0'))
    allowlist = _legacy_allowlist(config)
    for record in imports:
        if record.importer.startswith(legacy_prefix):
            continue
        if not record.imported.startswith(legacy_prefix):
            continue
        permitted = any(
            record.importer == importer
            and (
                record.imported == prefix
                or record.imported.startswith(prefix + '.')
            )
            for importer, prefix, _reason in allowlist
        )
        if not permitted:
            errors.append(
                f'Canonical legacy import is not allowlisted: '
                f'{record.importer} imports {record.imported} at '
                f'{modules[record.importer].path.relative_to(root)}:'
                f'{record.line}'
            )

    legacy_test_root = root / str(
        legacy.get('test_root', 'tests/legacy/pre_0_6_0')
    )
    tests_root = root / 'tests'
    if tests_root.exists():
        production_names = set(modules)
        for path in sorted(tests_root.rglob('*.py')):
            if legacy_test_root in path.parents:
                continue
            pseudo = ModuleRecord(
                name=module_name_for_path(path, root), path=path
            )
            tree = ast.parse(path.read_text(encoding='utf-8'))
            collector = _ImportCollector(pseudo, modules)
            collector.visit(tree)
            for record in collector.records:
                if (
                    record.imported in production_names
                    and record.imported.startswith(legacy_prefix)
                ):
                    errors.append(
                        'Non-legacy test imports compatibility implementation: '
                        f'{path.relative_to(root)}:{record.line} imports '
                        f'{record.imported}'
                    )
    return errors


def _subsystem_labels(config: dict[str, object]) -> dict[str, str]:
    result = {}
    for raw in _object_list(config.get('subsystems', []), context='subsystems'):
        row = _object_dict(raw, context='subsystem')
        result[str(row['id'])] = str(row.get('label', row['id']))
    return result


def _semantic_python_bytes(path: Path) -> bytes:
    """Return a formatting-insensitive representation of Python source.

    Unparse rather than ``ast.dump``: the digest has to be reproducible on
    every interpreter that runs the check, and a dump exposes node fields, so
    it shifts whenever the *grammar* grows -- Python 3.15 added ``is_lazy`` to
    ``Import`` (PEP 810) and stopped printing the defaulted ``ctx=Load()``,
    which changed the digest of 138 of 139 modules and failed CI on the 3.15
    prerelease alone. Unparsed source only shifts when the *code* itself uses
    a new feature, which is the change we actually want to detect.
    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    return ast.unparse(tree).encode('utf-8')


def _generation_digest(
    modules: dict[str, ModuleRecord], specification_paths: Sequence[Path]
) -> str:
    digest = hashlib.sha256()
    digest.update(_semantic_python_bytes(Path(__file__)))
    for module in sorted(modules.values()):
        digest.update(module.name.encode())
        digest.update(_semantic_python_bytes(module.path))
    for path in specification_paths:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def render_component_edges_json(
    root: Path,
    modules: dict[str, ModuleRecord],
    edges: dict[tuple[str, str], list[ImportRecord]],
    config: dict[str, object],
    digest: str,
) -> str:
    annotations = _edge_annotations(config)
    rows = []
    for edge, records in edges.items():
        annotation = annotations.get(edge, {})
        rows.append(
            {
                'from': edge[0],
                'to': edge[1],
                'classification': annotation.get('classification', 'accepted'),
                'note': annotation.get('note', ''),
                'imports': [
                    {
                        'importer': record.importer,
                        'imported': record.imported,
                        'path': str(
                            modules[record.importer].path.relative_to(root)
                        ),
                        'line': record.line,
                    }
                    for record in records
                ],
            }
        )
    payload = {
        '_generated': {
            'warning': 'Generated by dev/devcheck/architecture_docs.py',
            'schema': 1,
            'input_digest': digest,
        },
        'edges': rows,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + '\n'


def _mermaid_id(value: str) -> str:
    return value.replace('-', '_').replace('.', '_')


def render_component_mermaid(
    edges: dict[tuple[str, str], list[ImportRecord]],
    config: dict[str, object],
    digest: str,
) -> str:
    labels = _subsystem_labels(config)
    annotations = _edge_annotations(config)
    diagram_rows = _object_list(
        config.get('diagram_edges', []), context='diagram_edges'
    )
    diagram_edges = {
        (
            str(_object_dict(row, context='diagram edge')['from']),
            str(_object_dict(row, context='diagram edge')['to']),
        )
        for row in diagram_rows
    }
    missing = sorted(diagram_edges - set(edges))
    if missing:
        raise ArchitectureError(
            f'Diagram edges are not present in the import graph: {missing}'
        )
    lines = [
        '%% GENERATED FILE - DO NOT EDIT',
        '%% source: Python imports under aivm/',
        f'%% generation schema: 1; input digest: {digest}',
        'flowchart LR',
    ]
    for subsystem, label in sorted(labels.items()):
        lines.append(f'    {_mermaid_id(subsystem)}["{label}"]')
    for source, target in sorted(diagram_edges):
        annotation = annotations.get((source, target), {})
        classification = str(annotation.get('classification', 'accepted'))
        arrow = (
            '-.->'
            if classification in {'transitional', 'known-debt'}
            else '-->'
        )
        label = ''
        if classification != 'accepted':
            label = f'|{classification}|'
        lines.append(
            f'    {_mermaid_id(source)} {arrow}{label} {_mermaid_id(target)}'
        )
    lines.extend(
        [
            '    classDef compatibility fill:#fff3cd,stroke:#8a6d3b;',
            '    class compatibility compatibility;',
            '',
            '%% The complete edge inventory is component-edges.json.',
        ]
    )
    return '\n'.join(lines) + '\n'


def _find_named_node(body: Sequence[ast.stmt], name: str) -> ast.AST | None:
    for node in body:
        if isinstance(
            node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            if node.name == name:
                return node
        elif isinstance(node, ast.AnnAssign) and isinstance(
            node.target, ast.Name
        ):
            if node.target.id == name:
                return node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node
    return None


def resolve_symbol(
    symbol: str, modules: dict[str, ModuleRecord]
) -> SymbolRecord:
    module_name = symbol
    parts: tuple[str, ...] = ()
    while module_name not in modules and '.' in module_name:
        module_name, tail = module_name.rsplit('.', 1)
        parts = (tail,) + parts
    if module_name not in modules:
        raise ArchitectureError(
            f'Unknown documented module or symbol: {symbol}'
        )
    module = modules[module_name]
    tree = ast.parse(module.path.read_text(encoding='utf-8'))
    node: ast.AST = tree
    body: Sequence[ast.stmt] = tree.body
    for part in parts:
        found = _find_named_node(body, part)
        if found is None:
            raise ArchitectureError(f'Missing documented symbol: {symbol}')
        node = found
        body = found.body if isinstance(found, ast.ClassDef) else ()
    return SymbolRecord(
        module=module_name, parts=parts, node=node, path=module.path
    )


def validate_symbol_reference(
    raw: dict[str, object], modules: dict[str, ModuleRecord]
) -> None:
    symbol = str(raw.get('symbol', '')).strip()
    if not symbol:
        reason = str(raw.get('unverified_reason', '')).strip()
        if not reason:
            raise ArchitectureError(
                f'Documentation row {raw.get("label", raw.get("id", "?"))!r} '
                'needs a symbol or unverified_reason'
            )
        return
    record = resolve_symbol(symbol, modules)
    expected_args = raw.get('parameters')
    if expected_args is None:
        return
    if not isinstance(record.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise ArchitectureError(
            f'Signature validation requires a function or method: {symbol}'
        )
    actual = [arg.arg for arg in record.node.args.args]
    actual.extend(arg.arg for arg in record.node.args.kwonlyargs)
    expected = [
        str(item)
        for item in _object_list(expected_args, context=f'{symbol}.parameters')
    ]
    missing = [item for item in expected if item not in actual]
    if missing:
        raise ArchitectureError(
            f'Documented parameters missing from {symbol}: {missing}'
        )


def _flow_rows(config: Mapping[str, object]) -> list[dict[str, object]]:
    return [
        _object_dict(item, context='flow')
        for item in _object_list(config.get('flows', []), context='flows')
    ]


def validate_curated_specs(
    flows: Mapping[str, object],
    state: Mapping[str, object],
    modules: dict[str, ModuleRecord],
) -> None:
    for flow in _flow_rows(flows):
        node_ids: set[str] = set()
        for raw in _object_list(flow.get('nodes', []), context='flow nodes'):
            node = _object_dict(raw, context='flow node')
            node_id = str(node.get('id', ''))
            if not node_id or node_id in node_ids:
                raise ArchitectureError(
                    f'Flow {flow.get("id")} has invalid duplicate node {node_id!r}'
                )
            node_ids.add(node_id)
            validate_symbol_reference(node, modules)
        for raw in _object_list(flow.get('edges', []), context='flow edges'):
            edge = _object_dict(raw, context='flow edge')
            source = str(edge.get('from', ''))
            target = str(edge.get('to', ''))
            if source not in node_ids or target not in node_ids:
                raise ArchitectureError(
                    f'Flow {flow.get("id")} edge references unknown nodes: '
                    f'{source} -> {target}'
                )
    owners = {
        str(_object_dict(raw, context='state owner').get('id', ''))
        for raw in _object_list(state.get('owners', []), context='owners')
    }
    for raw in _object_list(state.get('owners', []), context='owners'):
        validate_symbol_reference(_object_dict(raw, context='owner'), modules)
    for raw in _object_list(state.get('items', []), context='items'):
        item = _object_dict(raw, context='state item')
        if str(item.get('owner', '')) not in owners:
            raise ArchitectureError(
                f'State item {item.get("label")} has unknown owner '
                f'{item.get("owner")}'
            )
        validate_symbol_reference(item, modules)


def render_flow_mermaid(flow: dict[str, object], digest: str) -> str:
    lines = [
        '%% GENERATED FILE - DO NOT EDIT',
        f'%% generation schema: 1; input digest: {digest}',
        'flowchart TD',
    ]
    for raw in _object_list(flow.get('nodes', []), context='flow nodes'):
        node = _object_dict(raw, context='flow node')
        node_id = _mermaid_id(str(node['id']))
        label = str(node.get('label', node['id'])).replace('"', "'")
        symbol = str(node.get('symbol', '')).strip()
        if symbol:
            label += f'<br/><code>{symbol}</code>'
        kind = str(node.get('kind', 'operation'))
        if kind == 'state':
            lines.append(f'    {node_id}[("{label}")]')
        elif kind == 'external':
            lines.append(f'    {node_id}{{"{label}"}}')
        elif kind == 'lock':
            lines.append(f'    {node_id}[["{label}"]]')
        elif kind == 'failure':
            lines.append(f'    {node_id}>"{label}"]')
        else:
            lines.append(f'    {node_id}["{label}"]')
    for raw in _object_list(flow.get('edges', []), context='flow edges'):
        edge = _object_dict(raw, context='flow edge')
        source = _mermaid_id(str(edge['from']))
        target = _mermaid_id(str(edge['to']))
        label = str(edge.get('label', '')).replace('|', '/')
        connector = f'-->|{label}|' if label else '-->'
        lines.append(f'    {source} {connector} {target}')
    return '\n'.join(lines) + '\n'


def render_state_mermaid(state: dict[str, object], digest: str) -> str:
    lines = [
        '%% GENERATED FILE - DO NOT EDIT',
        f'%% generation schema: 1; input digest: {digest}',
        'flowchart LR',
    ]
    for raw in _object_list(state.get('owners', []), context='owners'):
        owner = _object_dict(raw, context='owner')
        owner_id = _mermaid_id(str(owner['id']))
        label = str(owner.get('label', owner['id']))
        lines.append(f'    {owner_id}["{label}"]')
    for index, raw in enumerate(
        _object_list(state.get('items', []), context='items')
    ):
        item = _object_dict(raw, context='state item')
        item_id = f'item_{index:02d}'
        label = str(item.get('label', '')).replace('"', "'")
        symbol = str(item.get('symbol', '')).strip()
        if symbol:
            label += f'<br/><code>{symbol}</code>'
        lines.append(f'    {item_id}(("{label}"))')
        lines.append(f'    {_mermaid_id(str(item["owner"]))} --> {item_id}')
    return '\n'.join(lines) + '\n'


def _agent_vm_config_references(
    root: Path, modules: dict[str, ModuleRecord]
) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    for module in modules.values():
        if module.name == 'aivm.config' or module.name.startswith(
            'aivm.legacy.'
        ):
            continue
        tree = ast.parse(module.path.read_text(encoding='utf-8'))
        aliases: set[str] = set()
        import_lines: set[int] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == 'aivm.config'
            ):
                for alias in node.names:
                    if alias.name == 'AgentVMConfig':
                        aliases.add(alias.asname or alias.name)
                        import_lines.add(node.lineno)
            elif isinstance(node, ast.ImportFrom) and node.level:
                base = _relative_import_base(
                    module.name, module.path, node.level, node.module
                )
                if base == 'aivm.config':
                    for alias in node.names:
                        if alias.name == 'AgentVMConfig':
                            aliases.add(alias.asname or alias.name)
                            import_lines.add(node.lineno)
        if not aliases:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name)
                and node.id in aliases
                and node.lineno not in import_lines
            ):
                result.append(
                    (
                        module.name,
                        str(module.path.relative_to(root)),
                        node.lineno,
                    )
                )
    return sorted(set(result))


def _store_scope_path_reconstructions(
    root: Path, modules: dict[str, ModuleRecord]
) -> list[tuple[str, str, int, str]]:
    result: list[tuple[str, str, int, str]] = []
    for module in modules.values():
        tree = ast.parse(module.path.read_text(encoding='utf-8'))
        aliases = {'resolve_store_scope'}
        imported = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                base = (
                    _relative_import_base(
                        module.name, module.path, node.level, node.module
                    )
                    if node.level
                    else node.module or ''
                )
                if base == 'aivm.scoped_store':
                    for alias in node.names:
                        if alias.name == 'resolve_store_scope':
                            aliases.add(alias.asname or alias.name)
                            imported = True
        if not imported and module.name != 'aivm.scoped_store':
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            if (
                not isinstance(node.func, ast.Name)
                or node.func.id not in aliases
            ):
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                if arg.func.id == 'str' and arg.args:
                    rendered = ast.unparse(arg.args[0])
                    result.append(
                        (
                            module.name,
                            str(module.path.relative_to(root)),
                            node.lineno,
                            rendered,
                        )
                    )
    return sorted(set(result))


def render_compatibility_inventory(
    root: Path,
    modules: dict[str, ModuleRecord],
    imports: list[ImportRecord],
    config: dict[str, object],
    digest: str,
) -> str:
    legacy = _object_dict(config.get('legacy', {}), context='legacy')
    legacy_prefix = str(legacy.get('package', 'aivm.legacy.pre_0_6_0'))
    legacy_imports = [
        record
        for record in imports
        if not record.importer.startswith(legacy_prefix)
        and record.imported.startswith(legacy_prefix)
    ]
    aggregate = _agent_vm_config_references(root, modules)
    reconstructions = _store_scope_path_reconstructions(root, modules)
    lines = [
        '<!-- GENERATED FILE - DO NOT EDIT -->',
        f'<!-- generation schema: 1; input digest: {digest} -->',
        '# Compatibility and transitional architecture inventory',
        '',
        'This inventory is observational. The legacy-import allowlist is enforced;',
        'the aggregate-config and scope-reconstruction lists are intended to shrink.',
        '',
        f'## Canonical imports of `{legacy_prefix}` ({len(legacy_imports)})',
        '',
        '| Importer | Imported module | Location |',
        '|---|---|---|',
    ]
    for record in legacy_imports:
        path = modules[record.importer].path.relative_to(root)
        lines.append(
            f'| `{record.importer}` | `{record.imported}` | '
            f'`{path}:{record.line}` |'
        )
    lines.extend(
        [
            '',
            f'## Canonical `AgentVMConfig` references ({len(aggregate)})',
            '',
            '`ResolvedVMContext.effective_cfg` deliberately carries this aggregate',
            'compatibility view while canonical runtime consumers are narrowed.',
            '',
            '| Module | Location |',
            '|---|---|',
        ]
    )
    for module, loc_path, line in aggregate:
        lines.append(f'| `{module}` | `{loc_path}:{line}` |')
    lines.extend(
        [
            '',
            f'## Path-based `StoreScope` reconstruction sites ({len(reconstructions)})',
            '',
            'These calls pass a stringified path back into `resolve_store_scope`.',
            'They are reported for visibility and are not yet forbidden.',
            '',
            '| Module | Argument | Location |',
            '|---|---|---|',
        ]
    )
    for module, loc_path, line, argument in reconstructions:
        lines.append(f'| `{module}` | `{argument}` | `{loc_path}:{line}` |')
    return '\n'.join(lines) + '\n'


def generated_outputs(paths: ArchitecturePaths) -> dict[Path, str]:
    architecture = load_yaml(paths.architecture)
    flows = load_yaml(paths.flows)
    state = load_yaml(paths.state_ownership)
    modules = discover_modules(paths.root)
    imports = collect_imports(modules)
    errors = validate_rules(paths.root, modules, imports, architecture)
    if errors:
        raise ArchitectureError('\n'.join(errors))
    validate_curated_specs(flows, state, modules)
    digest = _generation_digest(
        modules, [paths.architecture, paths.flows, paths.state_ownership]
    )
    classifier = ModuleClassifier(architecture)
    edges = subsystem_edges(imports, classifier)
    result = {
        paths.generated
        / 'component-dependencies.mmd': render_component_mermaid(
            edges, architecture, digest
        ),
        paths.generated / 'component-edges.json': render_component_edges_json(
            paths.root, modules, edges, architecture, digest
        ),
        paths.generated / 'state-ownership.mmd': render_state_mermaid(
            state, digest
        ),
        paths.generated / 'compatibility-inventory.md': (
            render_compatibility_inventory(
                paths.root, modules, imports, architecture, digest
            )
        ),
    }
    for flow in _flow_rows(flows):
        flow_id = str(flow.get('id', '')).strip()
        result[paths.generated / f'flow-{flow_id}.mmd'] = render_flow_mermaid(
            flow, digest
        )
    return result


def generate(paths: ArchitecturePaths) -> None:
    outputs = generated_outputs(paths)
    paths.generated.mkdir(parents=True, exist_ok=True)
    for path, text in sorted(outputs.items()):
        path.write_text(text, encoding='utf-8')
        print(f'wrote {path.relative_to(paths.root)}')


def check(paths: ArchitecturePaths) -> None:
    outputs = generated_outputs(paths)
    stale = []
    for path, expected in sorted(outputs.items()):
        try:
            actual = path.read_text(encoding='utf-8')
        except FileNotFoundError:
            stale.append(
                f'missing generated file: {path.relative_to(paths.root)}'
            )
            continue
        if actual != expected:
            stale.append(
                f'stale generated file: {path.relative_to(paths.root)}'
            )
    extra = sorted(
        path
        for path in paths.generated.glob('*')
        if path.is_file() and path not in outputs
    )
    stale.extend(
        f'unmanaged generated file: {path.relative_to(paths.root)}'
        for path in extra
    )
    if stale:
        raise ArchitectureError(
            '\n'.join(stale)
            + '\nRun: python dev/devcheck/architecture_docs.py generate'
        )
    print(f'architecture documentation check passed ({len(outputs)} files)')


def report(paths: ArchitecturePaths) -> None:
    architecture = load_yaml(paths.architecture)
    modules = discover_modules(paths.root)
    imports = collect_imports(modules)
    classifier = ModuleClassifier(architecture)
    edges = subsystem_edges(imports, classifier)
    annotations = _edge_annotations(architecture)
    print(f'Production modules: {len(modules)}')
    print(f'Internal imports: {len(imports)}')
    print(f'Subsystem edges: {len(edges)}')
    print('')
    print('Subsystem edges:')
    for edge, records in edges.items():
        classification = annotations.get(edge, {}).get(
            'classification', 'accepted'
        )
        print(
            f'  {edge[0]:16s} -> {edge[1]:16s} '
            f'{classification:12s} ({len(records)} imports)'
        )
    print('')
    aggregate = _agent_vm_config_references(paths.root, modules)
    scope_paths = _store_scope_path_reconstructions(paths.root, modules)
    print(f'Canonical AgentVMConfig references: {len(aggregate)}')
    print(f'Path-based StoreScope reconstruction calls: {len(scope_paths)}')


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['generate', 'check', 'report'])
    parser.add_argument(
        '--root',
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help='Repository root (defaults to the checkout containing this script)',
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    paths = ArchitecturePaths.from_root(args.root.resolve())
    try:
        if args.command == 'generate':
            generate(paths)
        elif args.command == 'check':
            check(paths)
        else:
            report(paths)
    except ArchitectureError as ex:
        print(f'architecture-docs: {ex}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
