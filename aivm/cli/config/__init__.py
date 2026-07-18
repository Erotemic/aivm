"""Config-store CLI operations.

This command group owns the operator-facing lifecycle of the global store:
bootstrap defaults, inspect/edit state, discover unmanaged libvirt VMs, and
lint for schema drift. Each subcommand lives in its own submodule; this
package's ``__init__`` only wires the ``ConfigModalCLI`` and re-exports a
couple of helpers that tests import directly.
"""

from __future__ import annotations

import kwconf

from .discover import ConfigDiscoverCLI
from .edit import ConfigEditCLI
from .init import (
    InitCLI,
    _render_init_default_summary,
)
from .lint import ConfigLintCLI, _lint_store_file
from .paths import ConfigPathsCLI
from .show import ConfigFormatCLI, ConfigShowCLI


class ConfigModalCLI(kwconf.ModalCLI):
    """Config store management commands."""

    init = InitCLI
    discover = ConfigDiscoverCLI
    lint = ConfigLintCLI
    paths = ConfigPathsCLI
    format = ConfigFormatCLI
    show = ConfigShowCLI
    edit = ConfigEditCLI


__all__ = [
    'ConfigDiscoverCLI',
    'ConfigEditCLI',
    'ConfigFormatCLI',
    'ConfigLintCLI',
    'ConfigModalCLI',
    'ConfigPathsCLI',
    'ConfigShowCLI',
    'InitCLI',
    '_lint_store_file',
    '_render_init_default_summary',
]
