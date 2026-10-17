"""Total validators over closed character classes.

Every accepted string is described by an explicit loop over a fixed alphabet,
not a regular expression: each function here is meant to be ported to safe
Rust line for line and to carry a Lean refinement lemma (CODEC-01). Nothing in
this module reads a clock, a file, the environment, or a socket.

Validators either return the validated value or raise :class:`SecretsError`
with the caller's chosen fixed code. They never normalize silently, with the
single documented exception of :func:`lowered`.
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError

LOWER = 'abcdefghijklmnopqrstuvwxyz'
UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
DIGIT = '0123456789'
ALNUM = LOWER + UPPER + DIGIT
HEX = DIGIT + 'abcdef'
# RFC 3986 "unreserved": the only bytes that may appear in a constructed
# path segment or query value, so no percent-encoding is ever required and
# the request target is an injective function of its typed parts (ROUTE-01).
UNRESERVED = ALNUM + '-._~'

MAX_INT = 2**31 - 1
MAX_TEXT = 16384
MAX_SEGMENT = 128


def exact_keys(
    value: Any,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    *,
    code: str = 'invalid_request',
) -> dict[str, Any]:
    """Require a JSON object with exactly the permitted key set."""
    if type(value) is not dict:
        raise SecretsError(code)
    keys = frozenset(value)
    if not required <= keys or keys - required - optional:
        raise SecretsError(code)
    return value


def integer(
    value: Any, low: int, high: int, *, code: str = 'invalid_request'
) -> int:
    """Require a true integer in ``[low, high]``; ``bool`` is not an integer."""
    if type(value) is not int or not low <= value <= high:
        raise SecretsError(code)
    return value


def text(value: Any, limit: int, *, code: str = 'invalid_request') -> str:
    """Require 1..limit UTF-8 bytes with no NUL and no lone surrogate."""
    if type(value) is not str:
        raise SecretsError(code)
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        raise SecretsError(code) from None
    if not 1 <= size <= limit or '\x00' in value:
        raise SecretsError(code)
    return value


def byte_length(value: str) -> int:
    """UTF-8 length of an already validated string."""
    return len(value.encode('utf-8'))


def within(value: str, alphabet: str) -> bool:
    """True when every character of ``value`` is drawn from ``alphabet``."""
    for char in value:
        if char not in alphabet:
            return False
    return True


def token(
    value: Any,
    head: str,
    tail: str,
    limit: int,
    *,
    code: str = 'invalid_request',
) -> str:
    """Require ``head`` then zero or more ``tail`` characters, bounded."""
    if type(value) is not str or not 1 <= len(value) <= limit:
        raise SecretsError(code)
    if value[0] not in head or not within(value[1:], tail):
        raise SecretsError(code)
    return value


def operation_name(value: Any, *, code: str = 'invalid_request') -> str:
    return token(value, LOWER, LOWER + DIGIT + '_.-', 64, code=code)


def argument_name(value: Any, *, code: str = 'invalid_request') -> str:
    return token(value, LOWER, LOWER + DIGIT + '_', 32, code=code)


def segment(value: Any, *, code: str = 'invalid_request') -> str:
    """One literal path segment or query value: unreserved, never a dot path."""
    token(value, UNRESERVED, UNRESERVED, MAX_SEGMENT, code=code)
    if value in ('.', '..'):
        raise SecretsError(code)
    return value


def hex_string(
    value: Any, length: int, *, code: str = 'invalid_request'
) -> str:
    if type(value) is not str or len(value) != length or not within(value, HEX):
        raise SecretsError(code)
    return value


def lowered(value: str) -> str:
    """ASCII-only case folding; never Unicode case mapping."""
    out = []
    for char in value:
        index = UPPER.find(char)
        out.append(LOWER[index] if index >= 0 else char)
    return ''.join(out)


def hostname(value: Any, *, code: str = 'invalid_policy') -> str:
    """A canonical lowercase public DNS name: never an address or a bare label.

    The final label must contain a letter, so no dotted-decimal IPv4 literal
    is a hostname. ``.local`` and ``.localhost`` are refused because their
    resolution is not delegated from the public root.
    """
    if type(value) is not str or not 4 <= len(value) <= 253:
        raise SecretsError(code)
    labels = value.split('.')
    if len(labels) < 2:
        raise SecretsError(code)
    for label in labels:
        if not 1 <= len(label) <= 63:
            raise SecretsError(code)
        if not within(label, LOWER + DIGIT + '-'):
            raise SecretsError(code)
        if label[0] == '-' or label[-1] == '-':
            raise SecretsError(code)
    if within(labels[-1], DIGIT) or labels[-1] in ('local', 'localhost'):
        raise SecretsError(code)
    return value


def media_type(value: Any, *, code: str = 'invalid_policy') -> str:
    """``type/subtype`` with no parameters, as sent in ``Accept``."""
    if type(value) is not str or not 3 <= len(value) <= 96:
        raise SecretsError(code)
    parts = value.split('/')
    if len(parts) != 2:
        raise SecretsError(code)
    for part in parts:
        token(part, LOWER, LOWER + DIGIT + '.+-', 64, code=code)
    return value


def header_name(value: Any, *, code: str = 'invalid_policy') -> str:
    return token(value, ALNUM, ALNUM + '-', 64, code=code)


def header_value(value: Any, *, code: str = 'invalid_policy') -> str:
    """Printable ASCII without leading/trailing space: no folding, no CR/LF."""
    if type(value) is not str or not 1 <= len(value) <= 256:
        raise SecretsError(code)
    for char in value:
        if not ' ' <= char <= '~':
            raise SecretsError(code)
    if value[0] == ' ' or value[-1] == ' ':
        raise SecretsError(code)
    return value


def credential(value: Any, *, code: str = 'credential_source') -> str:
    """An opaque bearer secret: 16..4096 visible ASCII bytes, no whitespace.

    The absence of space, CR and LF is what makes a credential safe to place
    in exactly one HTTP header value.
    """
    if type(value) is not str or not 16 <= len(value) <= 4096:
        raise SecretsError(code)
    for char in value:
        if not '!' <= char <= '~':
            raise SecretsError(code)
    return value
