"""Shared fakes for the aivm test suite.

The suite fakes subprocess execution at a single seam --- the
``aivm.commands`` module --- and asserts on the command lists that reach
it.  These helpers are that seam's vocabulary, promoted here so each test
file does not re-declare its own copy:

- :class:`FakeProc` stands in for ``subprocess.CompletedProcess``.
- :func:`activate_manager` activates a fresh ``CommandManager`` and pins
  the euid/isatty probes that decide sudo-prompt behavior.
- :func:`patch_command_runtime` is the heavier variant for tests that
  drive approval prompts on a manager instance directly.
- :func:`capture_logs` swaps a module's ``log`` for a recorder.
- :class:`FakeCommandManager` is a scripted stand-in for code that calls
  ``CommandManager.current()``.
- :func:`command_recorder` routes ``subprocess.run`` to a prefix-matched
  script and records what was run, normalized.
- :func:`patch_ns` patches many attributes of one module namespace.
- :func:`make_cfg`, :func:`write_store` and :func:`run_cli` build the
  config/store/CLI scaffolding that CLI tests need.

Keep these drop-in compatible with the historical per-file fakes
(``_Proc``, ``P``, ``_activate_manager``, ``_FakeLog``, ``FakeManager``);
tests that need different behavior should declare a local fake rather
than growing options here.
"""

from __future__ import annotations

import builtins
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Mapping

from pytest import MonkeyPatch

from aivm.commands import CommandManager
from aivm.runtime import SYSTEM_LIBVIRT_URI


class FakeProc:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(
        self, returncode: int = 0, stdout: str = '', stderr: str = ''
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def activate_manager(
    monkeypatch: MonkeyPatch,
    *,
    yes_sudo: bool = True,
    euid: int = 1000,
    isatty: bool = False,
    **manager_kwargs: Any,
) -> CommandManager:
    """Activate a fresh ``CommandManager`` with pinned runtime probes.

    Pins ``os.geteuid`` and ``sys.stdin.isatty`` as seen from
    ``aivm.commands`` so sudo-prefixing and prompt behavior are
    deterministic regardless of the environment running the tests.
    """
    mgr = CommandManager(yes_sudo=yes_sudo, **manager_kwargs)
    CommandManager.activate(mgr)
    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: euid)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: isatty)
    return mgr


def patch_command_runtime(
    monkeypatch: MonkeyPatch,
    fake_run: Callable[..., Any],
    *,
    euid: int = 1000,
    isatty: bool = True,
    answer: str = 'y',
    bypass_sudo_auth: bool = True,
) -> list[str]:
    """Patch the full command-execution runtime for approval-flow tests.

    Routes ``subprocess.run`` to ``fake_run``, pins euid/isatty, answers
    interactive prompts with ``answer``, and (by default) skips real sudo
    authentication.  Returns the list that captures prompt texts.
    """
    prompts: list[str] = []
    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: euid)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: isatty)
    monkeypatch.setattr(
        builtins, 'input', lambda prompt: prompts.append(prompt) or answer
    )
    if bypass_sudo_auth:
        monkeypatch.setattr(
            CommandManager, 'sudo_authentication_required', lambda self: False
        )
    return prompts


class FakeLog:
    """Log stand-in that records selected levels as formatted messages."""

    _LEVELS = ('trace', 'debug', 'info', 'success', 'warning', 'error')

    def __init__(
        self,
        messages: list[str],
        levels: tuple[str, ...] = ('info', 'warning'),
    ) -> None:
        self._messages = messages
        self._levels = set(levels)

    def _log(self, level: str, fmt: str, *args: Any) -> None:
        if level in self._levels:
            self._messages.append(fmt.format(*args) if args else fmt)

    def trace(self, fmt: str = '', *args: Any, **kw: Any) -> None:
        self._log('trace', fmt, *args)

    def debug(self, fmt: str = '', *args: Any, **kw: Any) -> None:
        self._log('debug', fmt, *args)

    def info(self, fmt: str = '', *args: Any, **kw: Any) -> None:
        self._log('info', fmt, *args)

    def success(self, fmt: str = '', *args: Any, **kw: Any) -> None:
        self._log('success', fmt, *args)

    def warning(self, fmt: str = '', *args: Any, **kw: Any) -> None:
        self._log('warning', fmt, *args)

    def error(self, fmt: str = '', *args: Any, **kw: Any) -> None:
        self._log('error', fmt, *args)


def capture_logs(
    monkeypatch: MonkeyPatch,
    target: str,
    *,
    levels: tuple[str, ...] = ('info', 'warning'),
) -> list[str]:
    """Replace ``target`` (a dotted ``...log`` attribute) with a recorder.

    Returns the list that accumulates messages logged at ``levels``.
    """
    messages: list[str] = []
    monkeypatch.setattr(target, FakeLog(messages, levels))
    return messages


class FakeCommandManager:
    """Scripted stand-in for ``CommandManager.current()`` call sites.

    ``handler`` receives each command (as a list) and returns the result
    object; when it returns ``None`` (or no handler is given) a bare
    ``SimpleNamespace(stdout='')`` is returned.  Commands are recorded on
    ``self.calls``; pass ``calls=`` to share an external list.
    """

    def __init__(
        self,
        handler: Callable[[list[Any]], Any] | None = None,
        *,
        calls: list[list[Any]] | None = None,
    ) -> None:
        self.calls = calls if calls is not None else []
        self._handler = handler

    def step(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return nullcontext()

    def run(self, cmd: list[Any], **kwargs: Any) -> Any:
        del kwargs
        cmd = list(cmd)
        self.calls.append(cmd)
        if self._handler is not None:
            result = self._handler(cmd)
            if result is not None:
                return result
        return SimpleNamespace(stdout='')


# ---------------------------------------------------------------------------
# Command recording
# ---------------------------------------------------------------------------


def normalize_cmd(cmd: Iterable[Any]) -> list[str]:
    """Strip the sudo and libvirt-URI noise from a command list.

    ``sudo``/``sudo -n`` prefixes and an explicit ``-c <uri>`` connection
    flag are how the command layer spells things, not what a test is
    trying to assert.  Reducing ``['sudo', '-n', 'virsh', '-c',
    'qemu:///system', 'domstate', 'vm']`` to ``['virsh', 'domstate',
    'vm']`` lets a test say what it means.

    Example:
        >>> normalize_cmd(['sudo', '-n', 'virsh', '-c', 'qemu:///system',
        ...                'domstate', 'vm'])
        ['virsh', 'domstate', 'vm']
        >>> normalize_cmd(['sudo', 'mount', '--bind', '/a', '/b'])
        ['mount', '--bind', '/a', '/b']
    """
    parts = [str(part) for part in cmd]
    if parts[:2] == ['sudo', '-n']:
        parts = parts[2:]
    elif parts[:1] == ['sudo']:
        parts = parts[1:]
    if parts[:1] == ['virsh'] and parts[1:3] == ['-c', SYSTEM_LIBVIRT_URI]:
        parts = ['virsh'] + parts[3:]
    return parts


Route = Any
"""A ``FakeProc``, a ``cmd -> FakeProc`` callable, or an exception to raise."""


class CommandRecorder:
    """Records commands sent to ``subprocess.run`` and scripts the replies.

    ``routes`` maps a command prefix to what running it should produce.
    A prefix is matched against the *normalized* command (see
    :func:`normalize_cmd`) and may be given as a string (``'virsh
    domstate'``) or a tuple.  The longest matching prefix wins, so a
    specific route can override a general one.

    A route value is either a :class:`FakeProc`, a callable taking the
    normalized command and returning one, or an exception instance to
    raise.  An unmatched command raises ``AssertionError`` unless
    ``default`` is given --- tests should be explicit about the command
    surface they expect.

    Attributes:
        calls: every command as it arrived, sudo prefix and all.
        normalized: the same commands with the noise stripped.  This is
            what assertions should compare against.
    """

    def __init__(
        self,
        routes: Mapping[Any, Route] | None = None,
        *,
        default: Route | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.normalized: list[list[str]] = []
        self._default = default
        self._routes: list[tuple[tuple[str, ...], Route]] = []
        for prefix, result in (routes or {}).items():
            self.route(prefix, result)

    def route(self, prefix: Any, result: Route) -> 'CommandRecorder':
        """Add or override a route; returns self so calls can chain."""
        key = tuple(prefix.split()) if isinstance(prefix, str) else tuple(prefix)
        self._routes = [(p, r) for (p, r) in self._routes if p != key]
        self._routes.append((key, result))
        self._routes.sort(key=lambda item: len(item[0]), reverse=True)
        return self

    def __call__(self, cmd: Iterable[Any], **kwargs: Any) -> FakeProc:
        del kwargs
        raw = [str(part) for part in cmd]
        normalized = normalize_cmd(raw)
        self.calls.append(raw)
        self.normalized.append(normalized)
        for prefix, result in self._routes:
            if tuple(normalized[: len(prefix)]) == prefix:
                return self._resolve(result, normalized)
        if self._default is not None:
            return self._resolve(self._default, normalized)
        raise AssertionError(f'unexpected command: {raw!r}')

    @staticmethod
    def _resolve(result: Route, normalized: list[str]) -> FakeProc:
        if isinstance(result, BaseException):
            raise result
        if callable(result) and not isinstance(result, FakeProc):
            return result(normalized)
        return result

    def ran(self, *prefix: str) -> bool:
        """True when some normalized command starts with ``prefix``."""
        return self.count(*prefix) > 0

    def count(self, *prefix: str) -> int:
        """How many normalized commands start with ``prefix``."""
        key = list(prefix)
        return sum(1 for c in self.normalized if c[: len(key)] == key)

    def only(self, *prefix: str) -> list[str]:
        """The single normalized command starting with ``prefix``."""
        matches = [c for c in self.normalized if c[: len(prefix)] == list(prefix)]
        assert len(matches) == 1, f'expected exactly one {prefix!r}: {matches!r}'
        return matches[0]


def command_recorder(
    monkeypatch: MonkeyPatch,
    routes: Mapping[Any, Route] | None = None,
    *,
    default: Route | None = None,
    target: str = 'aivm.commands.subprocess.run',
    stub_sudo_scope: bool = True,
) -> CommandRecorder:
    """Install a :class:`CommandRecorder` over ``target``.

    ``stub_sudo_scope`` neutralizes ``CommandManager.confirm_sudo_scope``
    so a recorder-driven test never blocks on an approval prompt.  Tests
    that *assert* on prompting want :func:`patch_command_runtime`
    instead, and should pass ``stub_sudo_scope=False`` if they use both.
    """
    recorder = CommandRecorder(routes, default=default)
    monkeypatch.setattr(target, recorder)
    if stub_sudo_scope:
        monkeypatch.setattr(
            'aivm.commands.CommandManager.confirm_sudo_scope',
            lambda self, **k: None,
        )
    return recorder


# ---------------------------------------------------------------------------
# Namespace patching
# ---------------------------------------------------------------------------


def patch_ns(
    monkeypatch: MonkeyPatch, module: str, mapping: Mapping[str, Any]
) -> None:
    """Patch several attributes of one module namespace.

    Test files tend to stub one seam module heavily; spelling the dotted
    prefix once keeps the interesting part --- the attribute and its
    stand-in --- on one line each.

    Example:
        >>> import types, sys
        >>> mod = types.ModuleType('_demo_ns')
        >>> mod.alpha, mod.beta = 1, 2
        >>> sys.modules['_demo_ns'] = mod
        >>> mp = MonkeyPatch()
        >>> patch_ns(mp, '_demo_ns', {'alpha': 10, 'beta': 20})
        >>> (mod.alpha, mod.beta)
        (10, 20)
        >>> mp.undo()
        >>> del sys.modules['_demo_ns']
    """
    for attr, value in mapping.items():
        monkeypatch.setattr(f'{module}.{attr}', value)


def noop(*args: Any, **kwargs: Any) -> None:
    """Accept anything, do nothing, return ``None``."""
    del args, kwargs


def returns(value: Any) -> Callable[..., Any]:
    """Build a stub that ignores its arguments and returns ``value``."""

    def _stub(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return value

    return _stub


def records(sink: list[Any], value: Any = None) -> Callable[..., Any]:
    """Build a stub that appends ``(args, kwargs)`` to ``sink``."""

    def _stub(*args: Any, **kwargs: Any) -> Any:
        sink.append((args, kwargs))
        return value

    return _stub


# ---------------------------------------------------------------------------
# Config / store / CLI scaffolding
# ---------------------------------------------------------------------------


def make_cfg(tmp_path: Path | None = None, **overrides: Any) -> Any:
    """Build an ``AgentVMConfig`` rooted at ``tmp_path``.

    ``overrides`` are dotted paths into the config, so
    ``make_cfg(tmp_path, **{'vm.name': 'vm-x'})`` reads the way the
    assertion does.  Passing ``tmp_path`` points every path in
    ``cfg.paths`` inside it, which is what keeps a test from touching the
    developer's real ``~/.config/aivm``.
    """
    from aivm.config import AgentVMConfig

    cfg = AgentVMConfig()
    if tmp_path is not None:
        cfg.paths.base_dir = str(tmp_path / 'libvirt')
        cfg.paths.state_dir = str(tmp_path / 'state')
        cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
        cfg.paths.ssh_pubkey_path = str(tmp_path / 'id_ed25519.pub')
    for dotted, value in overrides.items():
        target: Any = cfg
        *sections, leaf = dotted.split('.')
        for section in sections:
            target = getattr(target, section)
        setattr(target, leaf, value)
    return cfg


def write_store(
    cfg_path: Path,
    cfg: Any = None,
    *,
    defaults: Any = None,
    active_vm: str | None = None,
    extra_vms: Iterable[Any] = (),
) -> Path:
    """Write a store holding ``cfg`` (and friends) to ``cfg_path``."""
    from aivm.config_store import Store, save_store, upsert_vm

    store = Store()
    if cfg is not None:
        upsert_vm(store, cfg)
    for extra in extra_vms:
        upsert_vm(store, extra)
    if defaults is not None:
        store.defaults = defaults
    if active_vm is not None:
        store.active_vm = active_vm
    save_store(store, cfg_path)
    return cfg_path


def written_cfg(tmp_path: Path, **overrides: Any) -> Path:
    """Write a default single-VM store under ``tmp_path``; return its path.

    This is the scaffolding almost every CLI test opens with: a named VM
    whose paths live in the sandbox, saved to a ``config.toml`` that the
    CLI is then pointed at.
    """
    overrides.setdefault('vm.name', 'test-vm')
    overrides.setdefault('vm.user', 'agent')
    cfg = make_cfg(tmp_path, **overrides)
    return write_store(tmp_path / 'config.toml', cfg)


def run_cli(argv: list[str]) -> int:
    """Run the modal CLI over ``argv`` and return its exit code."""
    from aivm.cli import AgentVMModalCLI

    rc = AgentVMModalCLI.main(argv=argv, _noexit=True)
    return 0 if rc is None else int(rc)
