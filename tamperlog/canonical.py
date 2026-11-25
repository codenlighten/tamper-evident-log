"""One deterministic byte encoding for JSON values, so that a hash or signature means one thing.

Rules: object keys sorted by Unicode code point, no whitespace, UTF-8, strings escaped by ``json``'s
standard rules. Floats are refused (their text form is not unique across languages), integers must fit in
53 bits so every JSON implementation reads them exactly, and nesting is limited. This is a simplified
cousin of RFC 8785, not a complete implementation of it.
"""

from __future__ import annotations

import json
from typing import Any

MAX_INT = 2**53 - 1
MAX_DEPTH = 32


class CanonicalError(ValueError):
    """The value cannot be encoded canonically (or the bytes are not canonical JSON)."""


def _check(value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError(f"nesting deeper than {MAX_DEPTH}")
    if value is None or isinstance(value, bool | str):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as err:
                raise CanonicalError("string contains a lone surrogate") from err
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalError(f"integer {value} does not fit in 53 bits")
        return
    if isinstance(value, float):
        raise CanonicalError("floating-point numbers are not allowed; use an integer or a string")
    if isinstance(value, list | tuple):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"object key {key!r} is not a string")
            _check(key, depth + 1)
            _check(item, depth + 1)
        return
    raise CanonicalError(f"cannot encode a value of type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """The canonical UTF-8 encoding of ``value``."""
    _check(value, 0)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate object key {key!r}")
        out[key] = value
    return out


def _no_constants(name: str) -> Any:
    raise CanonicalError(f"{name} is not valid JSON")


def parse_json(data: bytes) -> Any:
    """Parses JSON strictly: valid UTF-8, no duplicate keys, no NaN or Infinity, no floats."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise CanonicalError("not valid UTF-8") from err
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants, parse_float=_float)
    except json.JSONDecodeError as err:
        raise CanonicalError(f"not valid JSON: {err.msg}") from err
    except RecursionError as err:
        raise CanonicalError("nesting too deep") from err
    _check(value, 0)
    return value


def _float(text: str) -> Any:
    raise CanonicalError(f"floating-point number {text} is not allowed")


def parse_canonical(data: bytes) -> Any:
    """Parses ``data`` and requires it to be exactly the canonical encoding of what it contains."""
    value = parse_json(data)
    if canonical_json(value) != data:
        raise CanonicalError("valid JSON but not in canonical form")
    return value
