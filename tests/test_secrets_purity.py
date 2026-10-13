"""Structural gates that keep the kernel extractable and the boundary real.

These tests read source, not behaviour. They fail when a change would make
the pure core impure, give some other module the ability to mint an
authorization, or make ``aivm_secrets`` depend on AIVM -- each of which
would silently invalidate the plan to port the kernel to verified Rust.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / 'aivm_secrets'
KERNEL = sorted((PACKAGE / 'kernel').glob('*.py'))
# The shared value primitives are in the kernel's trusted base, so they are
# held to the same extraction rules. Their conformance runner does I/O and
# therefore lives outside that package (``aivm_secrets/primitives_runner.py``).
PRIMITIVES = sorted((PACKAGE / 'primitives').glob('*.py'))
PURE = KERNEL + PRIMITIVES
HOST = sorted((PACKAGE / 'host').glob('*.py'))
ALL = sorted(PACKAGE.rglob('*.py'))

# Pure computation only: no clock, file, socket, process, randomness,
# environment, regular expressions or dynamic loading.
PURE_STDLIB = {
    '__future__',
    'dataclasses',
    'typing',
    'json',
    'hashlib',
    'ipaddress',
}


def imports(path: Path) -> list[tuple[int, str]]:
    """Every imported module as ``(relative level, dotted name)``."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            found += [(0, alias.name) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            found.append((node.level, node.module or ''))
    return found


def label(path: Path) -> str:
    """A kernel module by its name, as before; a primitive by its folder too."""
    return path.name if path.parent.name == 'kernel' else (
        f'{path.parent.name}/{path.name}'
    )


@pytest.mark.parametrize('path', PURE, ids=lambda path: label(path))
def test_kernel_modules_import_only_pure_code(path):
    for level, name in imports(path):
        if level == 0:
            assert name.split('.')[0] in PURE_STDLIB, (
                f'{path.name} imports {name}'
            )
        elif level == 1:
            pass  # a sibling kernel module
        else:
            # Shared value primitives are the only additional dependency.
            assert (level, name) == (2, 'errors') or (
                level == 2 and name.startswith('primitives.')
            ), f'{path.name} imports {name}'


@pytest.mark.parametrize('path', PURE, ids=lambda path: label(path))
def test_kernel_modules_use_no_ambient_authority(path):
    """No name that reads the world, even via an allowed import."""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    banned_calls = {'open', 'input', 'print', 'eval', 'exec', 'compile', '__import__',
                    'globals', 'locals', 'getattr', 'setattr', 'id'}  # fmt: skip
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in banned_calls, (
                f'{path.name}: {node.func.id}()'
            )
        assert not isinstance(node, (ast.Global, ast.Nonlocal, ast.AsyncFunctionDef,
                                     ast.Await, ast.Yield, ast.YieldFrom, ast.Lambda)), (
            f'{path.name}: line {getattr(node, "lineno", "?")} uses a construct '
            'the planned extraction does not support'
        )  # fmt: skip


@pytest.mark.parametrize('path', PURE, ids=lambda path: label(path))
def test_kernel_functions_are_first_order(path):
    """No closures: every function is defined at module or class level.

    Charon/Aeneas handle closures and dynamic dispatch poorly, so the kernel
    is written without them rather than refactored when extraction begins.
    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for outer in ast.walk(tree):
        if not isinstance(outer, ast.FunctionDef):
            continue
        for inner in ast.walk(outer):
            assert inner is outer or not isinstance(inner, ast.FunctionDef), (
                f'{path.name}: {outer.name} defines nested function {inner.name}'
            )


def test_kernel_state_is_immutable():
    """Every kernel dataclass is frozen: transitions return new values."""
    for path in PURE:
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if not isinstance(node, ast.ClassDef):
                continue
            for decorator in node.decorator_list:
                if 'dataclass' not in ast.unparse(decorator):
                    continue
                assert 'frozen=True' in ast.unparse(decorator), (
                    f'{path.name}: {node.name} is a mutable dataclass'
                )
    from dataclasses import FrozenInstanceError

    from aivm_secrets.kernel import machine

    state = machine.State.__new__(machine.State)
    with pytest.raises(FrozenInstanceError):
        setattr(state, 'active', False)


def constructions(name: str) -> dict[str, list[int]]:
    """Where in the package ``name(...)`` is called."""
    sites: dict[str, list[int]] = {}
    for path in ALL:
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if not isinstance(node, ast.Call):
                continue
            called = node.func
            label = (
                called.id
                if isinstance(called, ast.Name)
                else getattr(called, 'attr', '')
            )
            if label == name:
                sites.setdefault(str(path.relative_to(PACKAGE)), []).append(
                    node.lineno
                )
    return sites


def test_only_the_kernel_can_mint_an_authorization():
    """EFFECT-01, structurally: the private-constructor rule of the Rust port.

    ``AuthorizedEffect`` and ``Ticket`` are constructed in exactly one
    module. No host code, and no service spec, can fabricate permission to
    reach the executor.
    """
    assert set(constructions('AuthorizedEffect')) == {'kernel/machine.py'}
    assert set(constructions('Ticket')) == {'kernel/machine.py'}
    assert set(constructions('Grant')) == {'kernel/machine.py'}


def test_the_executor_is_reached_only_through_the_broker():
    callers = {
        str(path.relative_to(PACKAGE))
        for path in ALL
        if '.execute(' in path.read_text(encoding='utf-8')
    }
    assert callers == {'host/broker.py'}
    broker = (PACKAGE / 'host' / 'broker.py').read_text(encoding='utf-8')
    # Each call passes a value a kernel emission returned, never an Effect.
    assert broker.count('self._executor.execute(') == 2
    assert 'self._executor.execute(preflight, ' in broker
    assert 'self._executor.execute(final, ' in broker


def test_provider_knowledge_is_data_in_one_module():
    """There is one service mechanism, and no provider is compiled into it.

    The built-in GitHub support is a manifest in ``kernel/presets.py``,
    selected by schema number in ``kernel/service.py``. Nothing else in the
    package -- not the kernel's interpreter, the broker, the executor or the
    guest client -- may know that any particular provider or tool exists.
    """
    mentions = {
        str(path.relative_to(PACKAGE))
        for path in ALL
        if 'github' in path.read_text(encoding='utf-8').lower()
    }
    assert mentions == {
        'kernel/__init__.py',  # the module table in its docstring
        'kernel/presets.py',
        'kernel/service.py',
    }
    for path in ALL:
        if path.name == 'presets.py':
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not literals & {'gh', 'pr', 'glab'}, path.name
    # The preset itself is pure data construction: it imports no mechanism.
    preset = {name for _, name in imports(PACKAGE / 'kernel' / 'presets.py')}
    assert preset == {'__future__', 'typing', 'errors', '', 'model'}


def test_only_two_explicit_host_adapters_can_open_network_connections():
    """The OAuth acquisition client is a second deliberately trusted dialer.

    Pure URL parsing (urllib.parse in oauth_provider.py) is not egress. Both
    permitted connection owners must remain explicit and narrowly scoped:
    provider-token acquisition and authorized service API execution.
    """
    openers = set()
    for path in ALL:
        source = path.read_text(encoding='utf-8')
        if 'create_connection' in source or 'http.client' in source:
            openers.add(str(path.relative_to(PACKAGE)))
    assert openers == {'host/egress.py', 'identity/oauth_transport.py'}


def test_only_one_module_runs_a_program_and_never_through_a_shell():
    runners = set()
    for path in ALL:
        source = path.read_text(encoding='utf-8')
        assert 'shell=True' not in source and 'os.system' not in source, (
            path.name
        )
        assert 'os.popen' not in source and 'pty.' not in source, path.name
        if 'subprocess' in source:
            runners.add(str(path.relative_to(PACKAGE)))
    assert runners == {'host/sources.py'}


@pytest.mark.parametrize(
    'path', ALL, ids=lambda path: str(path.relative_to(PACKAGE))
)
def test_the_package_never_imports_aivm(path):
    """One-way dependency: the broker can be split out, or rewritten, alone."""
    for level, name in imports(path):
        if level == 0:
            top = name.split('.')[0]
            assert top != 'aivm', f'{path.name} imports {name}'
            assert top in sys.stdlib_module_names or top in (
                'cryptography',
                'aivm_secrets',
            ), f'{path.name} imports third-party module {name}'


def test_importing_the_package_initializes_nothing():
    import subprocess

    program = (
        'import sys\n'
        'already_loaded = set(sys.modules)\n'
        'import aivm_secrets, aivm_secrets.cli, aivm_secrets.kernel.machine\n'
        'loaded = [m for m in sys.modules if m not in already_loaded and '
        'm.split(".")[0] in ("cryptography", "ssl", '
        '"aivm", "http", "socketserver")]\n'
        'print(loaded)\n'
    )
    done = subprocess.run(
        [sys.executable, '-P', '-c', program],
        capture_output=True,
        text=True,
        cwd='/',
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == '[]'


def test_import_purity_from_cold_interpreter():
    """Do not let a site hook's pre-imported ssl mask an eager import.

    Disable ``site`` and explicitly locate the source package, so this test
    checks a fresh interpreter even when a virtualenv starts with ``ssl``.
    """
    import subprocess

    program = (
        'import sys\n'
        'already_loaded = set(sys.modules)\n'
        'import aivm_secrets, aivm_secrets.cli, aivm_secrets.kernel.machine\n'
        'loaded = [m for m in sys.modules if m not in already_loaded and '
        'm.split(".")[0] in ("cryptography", "ssl", '
        '"aivm", "http", "socketserver")]\n'
        'print(loaded)\n'
    )
    done = subprocess.run(
        [sys.executable, '-S', '-P', '-c', program],
        capture_output=True,
        text=True,
        cwd='/',
        env={'PYTHONPATH': str(ROOT)},
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == '[]'


def test_aivm_reaches_the_broker_only_as_a_process():
    """AIVM may import the fixed error table and nothing else from the broker."""
    seen = {}
    for path in sorted((ROOT / 'aivm').rglob('*.py')):
        names = [
            name
            for level, name in imports(path)
            if level == 0 and name.startswith('aivm_secrets')
        ]
        if names:
            seen[str(path.relative_to(ROOT))] = sorted(set(names))
    assert seen == {
        'aivm/cli/vm_connect.py': ['aivm_secrets.errors'],
        'aivm/secrets_transport.py': ['aivm_secrets.errors'],
        'aivm/secrets_identity_transport.py': ['aivm_secrets.errors'],
        'aivm/secrets_identity_vm.py': ['aivm_secrets.errors'],
    }


def test_host_modules_do_not_reach_around_the_kernel():
    """Host code may use kernel types, but only the broker drives transitions."""
    drivers = set()
    for path in HOST:
        source = path.read_text(encoding='utf-8')
        if (
            'machine.admit' in source
            or 'machine.emit_' in source
            or 'machine.approve' in source
        ):
            drivers.add(path.name)
    assert drivers == {'broker.py'}


def test_the_assumption_ledger_is_wellformed_and_points_at_real_files():
    """The trusted base is written down, and the ledger cannot rot silently."""
    import json

    ledger = json.loads(
        (
            ROOT / 'docs' / 'planning' / 'aivm-secrets-assumptions.json'
        ).read_text()
    )
    entries = ledger['assumptions']
    assert len(entries) >= 12
    assert len({entry['id'] for entry in entries}) == len(entries)
    fields = {'id', 'boundary', 'assumption', 'owner', 'if_false', 'checked_by'}
    for entry in entries:
        assert set(entry) == fields, entry['id']
        assert (ROOT / entry['owner']).is_file(), entry['owner']
        assert entry['checked_by'], entry['id']
        for path in entry['checked_by']:
            assert (ROOT / path).is_file(), (entry['id'], path)
    # Every boundary of the assurance plan's ledger is represented.
    assert {
        'Specification', 'Cryptography', 'Channel identity', 'Host isolation',
        'Time', 'Persistence', 'Provider', 'Executor', 'Files and audit',
    } <= {entry['boundary'] for entry in entries}  # fmt: skip


# Each Garrett policy document and the ledger obligations it settles.
GARRETT_POLICIES = {
    'aivm-secrets-garrett-rollback-clone-policy.md': ('ROLLBACK-01', 'CLONE-01'),
    'aivm-secrets-garrett-vtpm-policy.md': ('VTPM-01',),
    'aivm-secrets-garrett-issuer-api.md': ('ISSUER-API-01',),
    'aivm-secrets-garrett-operations-policy.md': (),
}


def test_garrett_policies_are_linked_and_their_obligations_recorded() -> None:
    """A policy that bounds a claim is reachable, and its obligations ledgered.

    Each policy is linked from the identity plan, names its obligations, and
    each obligation has a ledger entry that cites the policy back -- so a
    claim cannot outgrow its policy without a ledger edit somebody reviews.
    """
    import json

    planning = ROOT / 'docs' / 'planning'
    ledger = {
        entry['id']: entry
        for entry in json.loads(
            (planning / 'aivm-secrets-assumptions.json').read_text()
        )['assumptions']
    }
    plan = (planning / 'aivm-secrets-garrett-identity.md').read_text(
        encoding='utf-8'
    )
    for name, obligations in GARRETT_POLICIES.items():
        text = (planning / name).read_text(encoding='utf-8')
        assert f']({name})' in plan, f'{name} is not linked from the plan'
        for obligation in obligations:
            assert obligation in text, (name, obligation)
            assert obligation in ledger, f'{obligation} has no ledger entry'
            cited = ledger[obligation]['assumption']
            assert f'docs/planning/{name}' in cited, (obligation, name)


def test_aivm_never_names_the_key_destruction_verb() -> None:
    """Private keys are destroyed only by an operator running prune-keys.

    The issuer API policy reserves that verb for a direct operator
    invocation, so no AIVM code may spell it, not even behind a prompt.
    """
    found = []
    for path in sorted((ROOT / 'aivm').rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and 'prune-keys' in node.value
            ):
                found.append(f'{path.relative_to(ROOT)}:{node.lineno}')
    assert found == []
