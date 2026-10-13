"""Strict JSON with one canonical encoding.

Accepted bytes have exactly one meaning (CODEC-01): duplicate object keys,
non-finite numbers, invalid UTF-8, trailing data, oversized frames and deep
nesting are all rejected before any typed parser runs.

The canonical encoding is the input of every digest in this package:

* object keys sorted by Unicode code point, no insignificant whitespace;
* ASCII output only, every non-ASCII code point as ``\\uXXXX`` (surrogate
  pairs above the BMP);
* integers in decimal with no leading zeros.

Digested documents contain only objects, arrays, strings and integers, so the
encoding of floats never reaches a digest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..errors import SecretsError

MAX_FRAME = 65536
MAX_DEPTH = 64


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


def loads(
    data: bytes | str, *, limit: int = MAX_FRAME, code: str = 'invalid_request'
) -> Any:
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        if len(data) > limit:
            raise ValueError('too large')
        _check_depth(data)
        return json.loads(
            data.decode('utf-8'),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
        )
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

    Proofs must treat this as an abstract collision-resistant identity, not
    as an injective function.
    """
    return hashlib.sha256(dumps(value)).hexdigest()
