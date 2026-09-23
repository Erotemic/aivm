"""Terminal presentation helpers with optional dependencies."""

from __future__ import annotations


def highlight_code(text: str, *, lexer_name: str) -> str:
    """Return ANSI-highlighted code when Pygments is installed.

    Historical provenance: AIVM previously called ``ubelt.highlight_code``.
    This is a fresh, minimal wrapper around Pygments rather than vendored ubelt
    code.  Plain text is deliberately the fallback because highlighting is an
    optional presentation feature.
    """
    try:
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pygments.lexers import get_lexer_by_name
    except ImportError:
        return text

    try:
        lexer = get_lexer_by_name(lexer_name)
    except Exception:
        return text
    return highlight(text, lexer, TerminalFormatter())
