"""Public package exports for the aivm CLI."""

# NOTE: ``__version__`` is assigned before the ``.cli`` import because
# ``aivm.cli.main`` reads it back off this partially-initialized module to
# stamp the modal CLI's ``--version``. It also stays a plain literal
# assignment here: docs/source/conf.py and .github/workflows/release.yml
# parse this file's AST rather than importing it.
__version__ = '0.6.0'

from .cli import main  # noqa: E402

__all__ = ['main']
