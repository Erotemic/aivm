"""Compatibility facade over the stand-alone aivm_secrets.primitives.grammar.

Security decisions are implemented only in the primitives package.
"""

from ..primitives.grammar import (
    LOWER,
    UPPER,
    DIGIT,
    ALNUM,
    HEX,
    UNRESERVED,
    MAX_INT,
    MAX_TEXT,
    MAX_SEGMENT,
    exact_keys,
    integer,
    text,
    byte_length,
    within,
    token,
    operation_name,
    argument_name,
    segment,
    hex_string,
    lowered,
    hostname,
    media_type,
    header_name,
    header_value,
    credential,
)

__all__ = ['LOWER', 'UPPER', 'DIGIT', 'ALNUM', 'HEX', 'UNRESERVED', 'MAX_INT', 'MAX_TEXT', 'MAX_SEGMENT', 'exact_keys', 'integer', 'text', 'byte_length', 'within', 'token', 'operation_name', 'argument_name', 'segment', 'hex_string', 'lowered', 'hostname', 'media_type', 'header_name', 'header_value', 'credential']
