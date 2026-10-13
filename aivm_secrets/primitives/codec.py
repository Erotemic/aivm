"""Strict JSON with one canonical encoding.

Accepted bytes have exactly one meaning (CODEC-01): duplicate object keys,
non-finite numbers, invalid UTF-8, lone surrogates, trailing data, oversized
frames and deep nesting are all rejected before any typed parser runs.

Every accepted string is a sequence of Unicode scalar values. The UTF-8
decoder refuses an encoded surrogate, and :func:`loads` refuses a
``\\uD800``-``\\uDFFF`` escape that is not one half of a high/low pair, so a
decoded document always has a UTF-8 encoding (and a Rust ``String``).

``-0`` is a spelling of the integer zero, exactly as ``\\u0041`` is a spelling
of ``A``: it decodes to ``0`` and re-encodes as ``0``. It is never the float
``-0.0`` (which is written with a fraction or an exponent).

The canonical encoding is the input of every digest in this package:

* object keys sorted by Unicode code point, no insignificant whitespace;
* ASCII output only, every non-ASCII code point as ``\\uXXXX`` (surrogate
  pairs above the BMP);
* integers in decimal with no leading zeros.

:func:`loads` keeps finite floats, because a provider's response may contain
them, but :func:`digest` refuses one: the decimal rendering of a float is not
the same in every implementation. A digest also refuses an integer outside
the signed 64-bit range ``[-(2**63), 2**63 - 1]`` and an object key that is
not a string. Digested documents therefore contain only objects, arrays,
strings, booleans, ``null`` and 64-bit integers, which every implementation
encodes identically.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..errors import SecretsError

MAX_FRAME = 65536
MAX_DEPTH = 64
# The integers a digest admits: exactly those of a signed 64-bit word.
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError('non-finite number')


def _float(value: str) -> float:
    number = float(value)
    # ``1e999`` is syntactically a JSON number but has no finite meaning.
    if number != number or number in (float('inf'), float('-inf')):
        raise ValueError('non-finite number')
    return number


def _check_depth(data: bytes) -> None:
    # Bound nesting before the decoder allocates a recursive structure.
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('too deeply nested')
        elif byte in (93, 125):
            depth -= 1


def _scalar_text(value: str) -> None:
    # A lone surrogate is the one code point with no UTF-8 encoding.
    value.encode('utf-8')


def _check_text(value: Any) -> None:
    """Refuse a decoded document that holds a lone surrogate anywhere.

    The decoder pairs a high and a low ``\\u`` escape into one code point and
    leaves any other surrogate escape as a lone code point, in a key or a
    value at any depth. Only this walk sees them all.
    """
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            _scalar_text(item)
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is dict:
            for key, child in item.items():
                _scalar_text(key)
                pending.append(child)


def _check_digestible(value: Any) -> None:
    """Refuse a value outside the digest domain described above.

    Call only on a value :func:`dumps` has encoded: that proves it finite
    and acyclic, so this walk terminates.
    """
    pending = [value]
    while pending:
        item = pending.pop()
        kind = type(item)
        if kind is str:
            _scalar_text(item)
        elif kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise ValueError('integer outside the signed 64-bit range')
        elif kind is list or kind is tuple:
            pending.extend(item)
        elif kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise TypeError('object key is not a string')
                _scalar_text(key)
                pending.append(child)
        elif item is not None and kind is not bool:
            # A float, or anything else ``json`` would coerce.
            raise TypeError('not a digestible value')


def loads(
    data: bytes | str, *, limit: int = MAX_FRAME, code: str = 'invalid_request'
) -> Any:
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        if len(data) > limit:
            raise ValueError('too large')
        _check_depth(data)
        value = json.loads(
            data.decode('utf-8'),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
        )
        _check_text(value)
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise SecretsError(code) from None


def dumps(value: Any, *, code: str = 'invalid_request') -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
            allow_nan=False,
        ).encode('ascii')
    except (ValueError, TypeError, RecursionError):
        raise SecretsError(code) from None


def digest(value: Any) -> str:
    """SHA-256 of the canonical encoding, as 64 lowercase hex characters.

    Refuses, with ``invalid_request``, any value outside the digest domain
    (a float, an integer outside the signed 64-bit range, a non-string key or
    a lone surrogate), because another implementation could not compute the
    same digest of it.

    Proofs must treat this as an abstract collision-resistant identity, not
    as an injective function.
    """
    encoded = dumps(value)
    try:
        _check_digestible(value)
    except (ValueError, TypeError):
        raise SecretsError('invalid_request') from None
    return hashlib.sha256(encoded).hexdigest()
