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

Keep these drop-in compatible with the historical per-file fakes
(``_Proc``, ``P``, ``_activate_manager``, ``_FakeLog``, ``FakeManager``);
tests that need different behavior should declare a local fake rather
than growing options here.
"""

from __future__ import annotations

import builtins
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any, Callable

from pytest import MonkeyPatch

from aivm.commands import CommandManager


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
