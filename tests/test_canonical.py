from __future__ import annotations

from typing import Any

import pytest

from tamperlog.canonical import CanonicalError, canonical_json, parse_canonical, parse_json


def test_keys_are_sorted_and_there_is_no_whitespace() -> None:
    assert canonical_json({"b": 1, "a": [1, 2, {"d": None, "c": True}]}) == b'{"a":[1,2,{"c":true,"d":null}],"b":1}'


def test_the_same_value_always_has_the_same_bytes() -> None:
    a = {"x": 1, "y": {"p": "é", "q": [3, 2, 1]}}
    b = {"y": {"q": [3, 2, 1], "p": "é"}, "x": 1}
    assert canonical_json(a) == canonical_json(b)


def test_unicode_is_kept_as_utf8_not_escaped() -> None:
    assert canonical_json({"k": "é😀"}) == '{"k":"é😀"}'.encode()


@pytest.mark.parametrize(
    "value",
    [1.5, float("nan"), float("inf"), 2**53, -(2**53), {1: "a"}, {"a": {1, 2}}, "\ud800", b"bytes", object()],
)
def test_values_that_could_encode_two_ways_are_refused(value: Any) -> None:
    with pytest.raises(CanonicalError):
        canonical_json(value)


def test_integers_up_to_53_bits_are_accepted() -> None:
    assert canonical_json([2**53 - 1, -(2**53 - 1), 0]) == b"[9007199254740991,-9007199254740991,0]"


def test_nesting_is_limited() -> None:
    deep: Any = 1
    for _ in range(40):
        deep = [deep]
    with pytest.raises(CanonicalError):
        canonical_json(deep)


@pytest.mark.parametrize(
    "text",
    [b'{"a":1,"a":2}', b"[NaN]", b"[Infinity]", b"[1.5]", b"[1e3]", b'{"a":', b"\xff\xfe", b"", b"[1,]", b"{'a':1}"],
)
def test_parsing_rejects_what_canonical_form_cannot_express(text: bytes) -> None:
    with pytest.raises(CanonicalError):
        parse_json(text)


def test_parse_canonical_requires_the_exact_canonical_bytes() -> None:
    assert parse_canonical(b'{"a":1,"b":[true]}') == {"a": 1, "b": [True]}
    for not_canonical in (b'{"a": 1}', b'{"b":1,"a":2}', b' {"a":1}', b'{"a":1}\n', b'{"a":1.0}'):
        with pytest.raises(CanonicalError):
            parse_canonical(not_canonical)


def test_deeply_nested_input_is_refused_without_crashing() -> None:
    with pytest.raises(CanonicalError):
        parse_json(b"[" * 100_000 + b"]" * 100_000)


def test_a_float_is_refused_with_advice_on_what_to_use_instead() -> None:
    with pytest.raises(CanonicalError, match="use an integer or a string"):
        canonical_json({"price": 1.5})
    with pytest.raises(CanonicalError, match="floating-point"):
        parse_json(b'{"price":1.5}')
