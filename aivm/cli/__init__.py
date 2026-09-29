"""CLI package exports for top-level command entry points."""

from __future__ import annotations

from .main import AgentVMModalCLI
from .main import main as main

# ``main`` stays importable but out of ``__all__``: autodoc would otherwise
# document the function as ``aivm.cli.main``, colliding with the module of
# the same name.
__all__ = ['AgentVMModalCLI']
