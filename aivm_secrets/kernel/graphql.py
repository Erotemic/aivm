"""Admission of a single operator-fixed, named GraphQL *query*.

This is a deliberately conservative syntax check, not a GraphQL parser or a
proof that a provider's query resolvers have no side effects. The guest never
supplies query source: the admitted document is fixed in the host manifest,
bound to the policy digest, and sent with allowlisted scalar variables only.

This module stays first-order and pure for the planned Rust/Aeneas/Lean port.
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError
from . import grammar

_KINDS = ('query', 'mutation', 'subscription')
_IDENT = grammar.LOWER + grammar.UPPER + grammar.DIGIT + '_'


def _operation_names(document: str) -> list[str]:
    """Conservatively reject additional GraphQL operation keywords.

    This also rejects keywords in GraphQL strings/comments: false rejections
    are fine for reviewed, fixed manifests. It is *not* relied on to parse
    arbitrary input or establish the provider's read semantics.
    """
    found = []
    word = ''
    for char in document:
        if char in _IDENT:
            word += char
        else:
            if word in _KINDS:
                found.append(word)
            word = ''
    if word in _KINDS:
        found.append(word)
    return found


def validate(document: Any, operation: Any, *, code: str) -> tuple[str, str]:
    """Admit a fixed named query; reject mutations, batching and anonymity."""
    document = grammar.text(document, 8192, code=code)
    operation = grammar.token(
        operation, grammar.LOWER + grammar.UPPER + '_',
        grammar.ALNUM + '_', 64, code=code,
    )
    text = document.lstrip()
    if not text.startswith('query') or len(text) < 7 or not text[5].isspace():
        raise SecretsError(code)
    tail = text[5:].lstrip()
    index = 0
    while index < len(tail) and tail[index] in _IDENT:
        index += 1
    if tail[:index] != operation or not tail[index:].lstrip().startswith(('(', '{')):
        raise SecretsError(code)
    if _operation_names(document) != ['query']:
        raise SecretsError(code)
    return document, operation
